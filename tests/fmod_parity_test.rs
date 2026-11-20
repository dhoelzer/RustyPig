//! Parity test for `src/file_api/file_module.rs` — row 18a.
//!
//! Ground truth: `tools/fmod_harness/vectors.txt` (61 L, NEVER edited;
//! md5 f0fdbab06fe1681af1c654531b917c55 re-measured THIS session, two
//! clean rebuilds byte-ident; `grep -c "FIM load_config" = 0` is the
//! PRINTS-FROZEN ruling — the REAL load_config body prints NOTHING,
//! the FIM line was witness-only) — the C transcript of file_module.cc
//! driven by probe.cc (V0..V7 + the W1/W2/W3 witnesses + the REAL-
//! LuaJIT V6 command session; ZERO TEST_CASEs / ZERO UNIT_TEST
//! measured on both ground files; gate.txt stays byte-ident to the
//! frozen 114/22 chain, md5 4826fc2233044a2d5429413faf0ae1af, TENTH
//! straight — the row TU links into the gate inert-by-construction),
//! replayed here as ONE ordered session (the flog/fsvc transcript-
//! replay shape: whole-vector per-index assert_eq, want.len()==61).
//!
//! Witness positions (stubs.cc NEW18a block + the retired-trio rule):
//! W1 (`parser_append_rules_special`, stubs.cc:449) and W2
//! (`ModuleManager::get_includer`, :468) are the two traits the real
//! end() rides (IncluderWit/RulesWit below); W3 (`DecodeConfig::
//! set_decompress_buffer_size`, :458) is the set() DECODE arm;
//! `Inspector dtor gref=0` (stubs.cc:543), the `IMGR acquire ->
//! inspector` x2 / `IMGR release` x2 quartet (stubs.cc:497-:505 +
//! :519) and `WITNESS ThreadConfig::get_instance_max=1` (stubs.cc:
//! :166, reached from Module::sum_stats -> init_stats, module.cc:
//! :166-:167 -> :327) are the harness-side Module/Inspector plumbing
//! witnesses — the Rust tree has NO Module/Inspector base, the
//! landed seams stand in (deviation row 18a; the quartet rides the
//! REAL FileCache add/drop positions exactly like the 17p IMGR rule,
//! and the release pair lands at the cache-teardown instant == the
//! C static's exit-time dtor position, the frozen transcript tail).
//!
//! The frozen flog-donor 31-L FileIdModule witness trio (md5
//! 9165739e…, byte-ident across {finspect,fpolicy,fsvc,flog} = the
//! dup proof) is RETIRED in fmod_harness ONLY (R1/R5 inversion, per-
//! link rule; the four donor harnesses keep theirs untouched, their
//! vectors byte-frozen). The Rust replay exercises the REAL FileId-
//! Module surface — real construction, real steal via the landed
//! FileInspect::new (file_inspect.rs:314) — where C ran real `new
//! FileIdModule`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use snort3::file_api::file_cache::{
    FileCache, FileConfigView, FileHashKey, FileTypeNames, InspectorApi, InspectorManagerApi,
};
use snort3::file_api::file_inspect::FileInspect;
use snort3::file_api::file_lib::FileConfigLite;
use snort3::file_api::file_module::{
    FMOD_PARAMS, FMOD_PEGS, FMOD_RULES, FileIdModule, MacroConsole, ModuleManagerSeam,
    RulesAppendSeam, TraceToken, DecompressBufferSeam, FILE_TRACE, dump_file_cache,
    dump_file_cache_detail,
};
use snort3::file_api::file_stats::{FileCounts, FileStatsEnv, FileStatsHooks, file_stats_init};
use snort3::framework::counts::{CountType, PegCount};
use snort3::framework::parameter::{Parameter, Type as PtType};
use snort3::framework::value::Value;

const VECTORS: &str = include_str!("../tools/fmod_harness/vectors.txt");

type Out = Rc<RefCell<Vec<String>>>;

fn push(out: &Out, line: impl Into<String>) {
    out.borrow_mut().push(line.into());
}

/// LogRespond(null ctrlcon) -> the LogMessage witness (stubs.cc:120-
/// :124: the "LOGMSG " tag + the formatted string verbatim; embedded
/// \n split; the trailing empty segment drops — the fcache emit_console
/// recipe, fcache_parity_test.rs:588-:597). The MacroConsole cn=None
/// half supplies the funnel to the sink; the sink collects the raw
/// respond payload strings here.
fn emit(out: &Out, msgs: &mut Vec<String>) {
    for msg in std::mem::take(msgs) {
        let parts: Vec<&str> = msg.split('\n').collect();
        push(out, format!("LOGMSG {}", parts[0]));
        for p in &parts[1..] {
            if !p.is_empty() {
                push(out, *p);
            }
        }
    }
}

// ------------------------------------------------------------------
// witness twins (stubs.cc NEW18a bodies)
// ------------------------------------------------------------------

/// W2 — stubs.cc:466-:472 `ModuleManager::get_includer` (armable null;
/// prints `W2 get_includer mod=%s null=%d`, answers "MODULE-INC"/null).
struct IncluderWit {
    out: Out,
    includer_null: bool,
}
impl ModuleManagerSeam for IncluderWit {
    fn get_includer(&mut self, module: &str) -> Option<&'static str> {
        push(
            &self.out,
            format!(
                "W2 get_includer mod={} null={}",
                module,
                u8::from(self.includer_null)
            ),
        );
        if self.includer_null {
            None
        } else {
            Some("MODULE-INC")
        }
    }
}

/// W1 — stubs.cc:449-:453 `parser_append_rules_special` (prints the
/// (file, includer) pair, "(null)" for a null half).
struct RulesWit {
    out: Out,
}
impl RulesAppendSeam for RulesWit {
    fn parser_append_rules_special(&mut self, file: &str, includer: Option<&str>) {
        push(
            &self.out,
            format!(
                "W1 rules_append file='{}' includer='{}'",
                file,
                includer.unwrap_or("(null)")
            ),
        );
    }
}

/// W3 — stubs.cc:458-:459 `DecodeConfig::set_decompress_buffer_size`.
struct DecoWit {
    out: Out,
    value: Cell<u32>,
}
impl DecompressBufferSeam for DecoWit {
    fn set_decompress_buffer_size(&mut self, v: u32) {
        self.value.set(v);
        push(&self.out, format!("W3 set_decompress_buffer_size={v}"));
    }
}

struct NoopDeco;
impl DecompressBufferSeam for NoopDeco {
    fn set_decompress_buffer_size(&mut self, _v: u32) {}
}

/// The 17z FileStatsHooks witness default — no FileCapture buffers
/// live in this probe (V7 counts stay 0, buffers_max/in_use 0, the
/// same answer the landed default gives; file_stats_collect is never
/// driven by any V-arm, collect is a probe-vectors-only pass-through).
/// The landed FileCache::type_names seam (file_cache.rs:1133) armed
/// to the harness chain answer: V5's fcache_set_file_inspector(1)
/// armed g_stub_file_inspector over null config, so the C
/// format_common_row -> file_type_name(id) -> get_file_config()
/// (file_config.cc:82/:94-:99, inspector's config IS null) -> the
/// cc:85-:86 "NA" answer every dump row shows (vectors:29/:30/:36/:
/// :41/:42/:50). file_config.rs:110 IS the landed arm (17u).
struct NaNames;
impl FileTypeNames for NaNames {
    fn file_type_name(&self, _id: u32) -> String {
        "NA".to_string()
    }
}

struct NoBuffers;
impl FileStatsHooks for NoBuffers {
    fn is_file_signature_enabled(&self) -> bool {
        false
    }
    fn file_type_name(&self, _id: u32) -> String {
        String::new()
    }
    fn buffers_max(&self) -> i64 {
        0
    }
    fn buffers_in_use(&self) -> i64 {
        0
    }
}

/// The stubs.cc InspectorManager pair (stubs.cc:495-:505 + :519, the
/// carried NEW17u arms): the REAL FileCache add path (file_cache.cc:
/// :319/:353 acquire) prints `IMGR acquire -> inspector|nil` OFF THE
/// ARMED LATCH — the V5 re-wire armed it with the C session's
/// `new FileInspect(new FileIdModule)`; V6's two REAL cache adds
/// acquire it (vectors:24/:25) and the v6_cache teardown (C: the
/// static's exit-time ~FileCache -> per-node free_user_data ->
/// ~FileContext -> InspectorManager::release) drains the pair at the
/// transcript tail (vectors:60/:61). The 17p IMGR witness-position
/// rule rides the drop exactly (fcache/flog precedent).
struct StubInspector {
    cfg: Rc<RefCell<FileConfigView>>,
}
impl InspectorApi for StubInspector {
    fn config(&self) -> Rc<RefCell<FileConfigView>> {
        self.cfg.clone()
    }
}
struct ImgrWit {
    out: Out,
    armed: Rc<RefCell<Option<Rc<StubInspector>>>>,
}
impl InspectorManagerApi for ImgrWit {
    fn acquire_file_inspector(&mut self) -> Option<Rc<dyn InspectorApi>> {
        let armed = self.armed.borrow();
        push(
            &self.out,
            format!(
                "IMGR acquire -> {}",
                if armed.is_some() { "inspector" } else { "null" }
            ),
        );
        armed.as_ref().map(|a| a.clone() as Rc<dyn InspectorApi>)
    }
    fn release(&mut self, _ins: &Rc<dyn InspectorApi>) {
        push(&self.out, "IMGR release"); // stubs.cc:519
    }
}

fn mkkey(file_id: u64) -> FileHashKey {
    FileHashKey {
        file_id,
        ..FileHashKey::default()
    }
}

fn vector_line(prefix: &str) -> String {
    VECTORS
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no vectors line starting {prefix:?}"))
        .to_string()
}

/// the four probe set() Value params (probe.cc:136-:139 + :186) —
/// the landed Value::is answers via the static param origin.
static PD_TYPE_DEPTH: Parameter =
    Parameter { name: Some("type_depth"), ptype: PtType::PtInt, deflt: Some("1460") };
static PB_DECOMP: Parameter = Parameter {
    name: Some("decompress_buffer_size"),
    ptype: PtType::PtInt,
    deflt: Some("100000"),
};
static PR_RULES: Parameter =
    Parameter { name: Some("rules_file"), ptype: PtType::PtString, deflt: None };
static PX_BOGUS: Parameter =
    Parameter { name: Some("bogus_name"), ptype: PtType::PtInt, deflt: Some("0") };

// ------------------------------------------------------------------
// the whole probe main() as ONE ordered session (probe.cc:72-:294).
// ------------------------------------------------------------------
#[test]
fn fmod_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 61, "vectors.txt must stay the 61-line oracle");
    let out: Out = Rc::new(RefCell::new(Vec::new()));

    // ---- probe setup (probe.cc:74-:76): the fake clock is inert here
    // (no time reader among these arms); file_stats_init() == the
    // driver-owned env's file_stats = Some(zeroed struct) (the rc-139
    // rule; the THREAD_LOCAL counts ride the same env).
    let mut env = FileStatsEnv::default();
    file_stats_init(&mut env);

    let mut deco = DecoWit { out: out.clone(), value: Cell::new(0) };
    let mut mgr = IncluderWit { out: out.clone(), includer_null: false };
    let mut rules = RulesWit { out: out.clone() };
    let hooks = NoBuffers;

    // ---- V0_sizes (probe.cc:78-:85): C-layout sizeof STRINGS, probe-
    // pinned literals NEVER size_of (the file_policy/file_capture
    // rule). pc8 is the ONE live Rust check (PegCount == u64).
    push(
        &out,
        format!(
            "V0_sizes str=32 mod_ge=1 pegsz=24 pc8={} rulemap=16 cmd=40",
            u8::from(std::mem::size_of::<PegCount>() == 8)
        ),
    );

    // ---- V1 (probe.cc:87-:121): FIRST-TIME REAL heap ctor
    // (R2: real `new FileIdModule` — the 17w raw-storage posture is
    // dead) + zero-call table readbacks.
    let mut m = FileIdModule::new();
    {
        let p = m.get_parameters();
        let pegs = m.get_pegs();
        let rules_t = m.get_rules();
        let cmds = m.get_commands();
        let np = p.iter().take_while(|x| x.name.is_some()).count(); // 17
        let ng = pegs.iter().take_while(|x| x.peg_type != CountType::End).count(); // 30
        push(
            &out,
            format!(
                "V1_ctor name={} help={} gid={} usage={} dyn={} params={} p0={} d0={} pt0={} pegs={} peg0={} rule0={} msg0_null={} cmd0={} cmd1={} cmd2_null={} tr_opt=1 tname_null={}",
                m.get_name(),
                m.get_help(),
                m.get_gid(),
                m.get_usage(),
                u8::from(m.has_dynamic_stats()),
                np,
                p[0].name.unwrap(),
                p[0].deflt.unwrap(),
                p[0].ptype as u32, // C Parameter::Type PT_INT == 4;
                // the landed PtType discriminants match by 16c pin
                ng,
                pegs[0].name,
                rules_t[0].0,
                // C prints `msg ? 0 : 1` off the REAL non-null msg
                // string; the Rust slot stands the msg STR in ("")
                // only for the TERMINATOR (deviation row 18a) -- the
                // live row carries its text, so the flag derives:
                u8::from(rules_t[0].1.is_empty()),
                cmds[0].name.unwrap(),
                cmds[1].name.unwrap(),
                u8::from(cmds[2].name.is_none()),
                u8::from(m.get_trace_options().0.is_none()),
            ),
        );
        {
            let nc = cmds.iter().take_while(|c| c.name.is_some()).count();
            push(
                &out,
                format!(
                    "V1_cmds n={} fp0={} fp1={} params0={} def0={} params1={} def1_null={}",
                    nc,
                    u8::from(cmds[0].func_present),
                    u8::from(cmds[1].func_present),
                    cmds[0].params.unwrap()[0].name.unwrap(),
                    cmds[0].params.unwrap()[0].deflt.unwrap(),
                    cmds[1].params.unwrap()[0].name.unwrap(),
                    u8::from(cmds[1].params.unwrap()[0].deflt.is_none()),
                ),
            );
        }
        // both arms answer non-null addresses in C (the get_profile
        // static + the counts cast); the Rust twins are a &'static
        // token and a slice -- structurally non-null, const line.
        push(&out, "V1_profile prof_nonnull=1 counts_nonnull=1");
    }

    // ---- V2_end_empty (probe.cc:123-:131): end() BEFORE any set():
    // the cc:256-:261 ALWAYS-append quirk, magic_file == "" (R5):
    // W1 sees the EMPTY string, includer armed.
    push(&out, format!("V2_end_empty ret={}", u8::from(m.end(&mut mgr, &mut rules))));
    // fmod_set_includer_null(1) + end() again: the null-includer arm
    // (cc:258 `inc` flows straight into the W1 call).
    mgr.includer_null = true;
    push(&out, format!("V2_end_nullic ret={}", u8::from(m.end(&mut mgr, &mut rules))));
    mgr.includer_null = false;
    {
        // the four Value calls (probe.cc:135-:148): type_depth 512,
        // decompress 4096 (-> W3), rules_file magic.rules (-> the
        // "include " prefix), bogus -> TRUE (cc:253). The lazy
        // `new FileConfig` fires on the FIRST arm (mid-ladder, cc:
        // :196-:197).
        let mut vd = Value::from_i64(512);
        vd.set_param(&PD_TYPE_DEPTH);
        let mut vb = Value::from_u64(4096);
        vb.set_param(&PB_DECOMP);
        let mut vr = Value::from_str("magic.rules");
        vr.set_param(&PR_RULES);
        let mut vx = Value::from_i64(7);
        vx.set_param(&PX_BOGUS);
        let a = u8::from(m.set(&vd, &mut deco));
        let b = u8::from(m.set(&vb, &mut deco));
        let c = u8::from(m.set(&vr, &mut deco));
        let d = u8::from(m.set(&vx, &mut deco));
        push(&out, format!("V2_set ret={a}{b}{c}{d} (order d,b,r,x)"));
        // V2_end_rules: W2 + W1 see "include magic.rules".
        push(&out, format!("V2_end_rules ret={}", u8::from(m.end(&mut mgr, &mut rules))));
    }

    // ---- V3_trace (probe.cc:152-:162): the row-.o B definition
    // (stubs' def retired, R3) armed through the carried seam, nulled
    // by the REAL set_trace (cc:154), re-armed.
    static TOKEN: TraceToken = TraceToken;
    FILE_TRACE.with(|t| t.set(Some(&TOKEN)));
    let armed = FileIdModule::file_trace_armed();
    m.set_trace(None);
    let after = FileIdModule::file_trace_armed();
    FILE_TRACE.with(|t| t.set(Some(&TOKEN)));
    push(
        &out,
        format!(
            "V3_trace armed={} set_trace_nulled={} rearm={}",
            u8::from(armed),
            u8::from(after),
            u8::from(FileIdModule::file_trace_armed())
        ),
    );

    // ---- V4 (probe.cc:164-:198): the REAL steal pair, PRINTS-FROZEN.
    {
        // STEAL-A: the REAL FileInspect steal (file_inspect.cc:48-:51)
        // over the landed seam — FileInspect::new(&mut m.fc) IS
        // fm->load_config(config) (zero edits, file_inspect.rs:314).
        let ins = FileInspect::new(&mut m.fc);
        let mut dst1: Option<Rc<RefCell<FileConfigLite>>> = None;
        m.load_config(&mut dst1); // post-call: the slot answers None
        push(
            &out,
            format!(
                "V4_steal_a ins_cfg={} post_null={}",
                u8::from(ins.config.is_some()),
                u8::from(dst1.is_none())
            ),
        );
        // `delete ins` == FileInspect drop: the sole Rc frees the
        // stolen config (file_inspect.cc:55-:56); the harness's
        // Inspector-witness dtor prints gref=0 (stubs.cc:543 — the
        // directly-new'd inspector was never global-ref'd). `delete
        // m` -- ~FileIdModule cc:148-:152 fc null, silent.
        drop(ins);
        push(&out, "Inspector dtor gref=0");
        drop(m);

        // STEAL-B: the SECOND fresh module (V4_steal_b).
        let mut m2 = FileIdModule::new();
        let mut dst0: Option<Rc<RefCell<FileConfigLite>>> = None;
        m2.load_config(&mut dst0); // fresh, fc never armed -> None
        let mut vd2 = Value::from_i64(99);
        vd2.set_param(&PD_TYPE_DEPTH);
        m2.set(&vd2, &mut deco); // lazy fc
        let mut dst2: Option<Rc<RefCell<FileConfigLite>>> = None;
        m2.load_config(&mut dst2); // hands the fc (identity -> 1)
        let mut dst3: Option<Rc<RefCell<FileConfigLite>>> = None;
        m2.load_config(&mut dst3); // steal AGAIN -> None
        push(
            &out,
            format!(
                "V4_steal_b pre_null={} post_got={} again_null={}",
                u8::from(dst0.is_none()),
                u8::from(dst2.is_some()),
                u8::from(dst3.is_none())
            ),
        );
        drop(dst2); // caller owns (delete dst2 — Box/Rc semantics pin)
        drop(m2); // dtor: fc null
    }

    // ---- V5 (probe.cc:200-:205): the fcache_set_file_inspector
    // re-wire arm: REAL new FileIdModule (fc NEVER set) -> the REAL
    // steal hands a NULL config (the cc:263-:266 null arm);
    // ~FileInspect's `if (config)` guard is safe. The C's armed stub
    // latch (g_stub_file_inspector) survives for the V6 acquire
    // lines — model as the IMGR-armed flag.
    let armed_latch: Rc<RefCell<Option<Rc<StubInspector>>>> = Rc::new(RefCell::new(None));
    {
        let mut m5 = FileIdModule::new();
        let ins5 = FileInspect::new(&mut m5.fc);
        push(&out, format!("V5_wit_ctor cfg_null={}", u8::from(ins5.config.is_none())));
        drop(ins5); // null-config guard safe; the C object leaked to
        // exit (never deleted -> no gref dtor line, grep-evidence)
        drop(m5);
        *armed_latch.borrow_mut() = Some(Rc::new(StubInspector {
            cfg: Rc::new(RefCell::new(FileConfigView::default())),
        }));
    }

    // ---- V6 (probe.cc:207-:270): the Command bodies. The Rust face
    // takes the ALREADY-QUERIED args (no lua_State in the tree —
    // deviation row 18a); C ran REAL LuaJIT: L = luaL_newstate() ->
    // the pinned state=1 digit.
    let mut v6_cache = FileCache::new(16); // C: `static FileCache
    // v6_cache(16)` — the EXIT-time dtor is the transcript tail; the
    // Rust local drops at the END of this fn, after FMOD_PROBE_DONE.
    {
        let m3 = FileIdModule::new(); // fresh (no set arms)
        let cmds = m3.get_commands();
        // V6_lua: the probe's own literal 2 for cmds (probe.cc:217)
        push(
            &out,
            format!("V6_lua state=1 cmds={} func0={}", 2, u8::from(cmds[0].func_present)),
        );

        // cache-null arms (both commands): fcache_set_file_cache
        // (nullptr) + lua_settop 0 -> the cc:289/:312 LogRespond null
        // branches (ctrlcon ALSO null -> the LOGMSG sink; vectors:
        // :22/:23).
        let mut msgs: Vec<String> = Vec::new();
        {
            let mut mc = MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
            assert_eq!(dump_file_cache(&mut mc, None, None), 0); // cmds[0]
            assert_eq!(dump_file_cache_detail(&mut mc, None, None), 0); // cmds[1]
        }
        emit(&out, &mut msgs);

        // REAL cache: two rows (file_ids 101 gamma/AB-sha + 102
        // delta/11-sha, the probe's add order at :232-:237). The imgr
        // seam carries the armed latch -> the acquire pair prints AT
        // the add instants (vectors:24/:25).
        v6_cache.imgr = Rc::new(RefCell::new(
            Box::new(ImgrWit { out: out.clone(), armed: armed_latch.clone() })
                as Box<dyn InspectorManagerApi>,
        ));
        v6_cache.type_names = Box::new(NaNames); // the V5-null-conf
        // chain answer (cc:85-:86), see NaNames
        let mut cf = false;
        let mut ce = 0i64;
        let mut counts = FileCounts::default();
        let r1 = v6_cache
            .add(&mkkey(101), 1000, &mut cf, &mut ce, true, &mut counts)
            .unwrap();
        let r2 = v6_cache
            .add(&mkkey(102), 1000, &mut cf, &mut ce, true, &mut counts)
            .unwrap();
        r1.borrow_mut().info.set_file_name(Some(&b"gamma.bin"[..]), 9);
        r2.borrow_mut().info.set_file_name(Some(&b"delta.bin"[..]), 9);
        r1.borrow_mut().info.sha256 = Some([0xABu8; 32]);
        r1.borrow_mut().info.is_sha256_set = true;
        r2.borrow_mut().info.sha256 = Some([0x11u8; 32]);
        r2.borrow_mut().info.is_sha256_set = true;

        // the count ladder (probe.cc:239-:248): default 100 (both
        // rows), 0 reject, -2 reject, 1 (displayed 1 of 2), -1
        // sentinel -> u32::MAX (rows == total, NO displayed arm on
        // EITHER side — landed and C agree, cc:1070 `rows.size() <
        // total`).
        let call_dump = |cache: &mut FileCache, n: Option<i32>, out: &Out| {
            let mut msgs: Vec<String> = Vec::new();
            {
                let mut mc =
                    MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
                dump_file_cache(&mut mc, Some(cache), n);
            }
            emit(out, &mut msgs);
        };
        call_dump(&mut v6_cache, None, &out);
        call_dump(&mut v6_cache, Some(0), &out);
        call_dump(&mut v6_cache, Some(-2), &out);
        call_dump(&mut v6_cache, Some(1), &out);
        call_dump(&mut v6_cache, Some(-1), &out);

        // the SHA ladder (probe.cc:250-:264): null sha + empty ->
        // usage; 65-a length reject; zz hex reject; ab -> toupper ->
        // match the AB row (the cc:345-:346 normalize); FFFF no-match.
        let call_detail = |cache: &mut FileCache, sha: Option<&[u8]>, out: &Out| {
            let mut msgs: Vec<String> = Vec::new();
            {
                let mut mc =
                    MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
                dump_file_cache_detail(&mut mc, Some(cache), sha);
            }
            emit(out, &mut msgs);
        };
        call_detail(&mut v6_cache, None, &out);
        call_detail(&mut v6_cache, Some(b""), &out);
        let long65 = vec![b'a'; 65];
        call_detail(&mut v6_cache, Some(&long65), &out);
        call_detail(&mut v6_cache, Some(b"zz"), &out);
        call_detail(&mut v6_cache, Some(b"ab"), &out);
        call_detail(&mut v6_cache, Some(b"FFFF"), &out);

        // probe.cc:266-:269: lua_close (REAL), fcache_set_file_cache
        // (nullptr) — the static cache object itself SURVIVES to
        // exit; V6_done prints while its two nodes are still queued
        // (the C FileContexts stay owned by the cache: the probe held
        // raw r1/r2 pointers that never delete). Rust: r1/r2 handle
        // clones drop HERE silently (the cache slot keeps the Rc
        // alive -> no run_dtor, no release lines yet).
        drop(r1);
        drop(r2);
        push(&out, "V6_done");
        drop(m3); // fc null, dtor no-op (silent)
    }

    // ---- V7 (probe.cc:272-:290): the REAL stats pair. C order:
    // get_counts (silent) -> pre -> sum_stats(true): file_stats_sum
    // (silent) + Module::sum_stats -> init_stats -> the ThreadConfig
    // WITNESS line (:57) -> update_buffers. The Rust port has no
    // Module base (deviation row 18a) — the witness line is pushed
    // at the matching session spot (the first sum_stats(true)).
    {
        let m4 = FileIdModule::new();
        let pre = m4.get_counts(&mut env, &hooks)[0];
        push(&out, "WITNESS ThreadConfig::get_instance_max=1"); // stubs.cc:166
        m4.sum_stats(true, &mut env, &hooks);
        let post = m4.get_counts(&mut env, &hooks)[0];
        m4.reset_stats(&mut env);
        let now = m4.get_counts(&mut env, &hooks)[0];
        push(&out, format!("V7_stats pre={pre} post={post} reset={now}"));
        drop(m4);
    }

    // ---- FMOD_PROBE_DONE (:59), then the process-exit tail: the
    // static v6_cache dtor -> per-node free_user_data -> ~FileContext
    // -> the release pair (:60/:61 — the last Rc refs drop NOW).
    push(&out, "FMOD_PROBE_DONE");
    drop(v6_cache);

    // ---- line-for-line against the frozen oracle ----
    let have = out.borrow();
    assert_eq!(have.len(), want.len(), "transcript length");
    for (i, (h, w)) in have.iter().zip(want.iter()).enumerate() {
        assert_eq!(h, w, "vectors line {}", i + 1);
    }
}

// ------------------------------------------------------------------
// label-slice pins
// ------------------------------------------------------------------

/// vectors:1 — the V0 C-layout sizeof pins (probe-computed strings;
/// the pc8 digit is the one live Rust check, PegCount == u64).
#[test]
fn v0_sizes() {
    assert_eq!(
        vector_line("V0_sizes"),
        "V0_sizes str=32 mod_ge=1 pegsz=24 pc8=1 rulemap=16 cmd=40"
    );
    assert_eq!(std::mem::size_of::<PegCount>(), 8);
}

/// vectors:2-:4 — the table shapes ride the Rust consts: 17 params
/// (discriminants pinned), 30 pegs (SUM/MAX/NOW mix), the rule row,
/// the null triple TraceOption, the 2-Command table + params.
#[test]
fn v1_tables() {
    assert_eq!(FMOD_PARAMS.iter().take_while(|p| p.name.is_some()).count(), 17);
    assert_eq!(FMOD_PARAMS[0].ptype as u32, 4); // type_depth PT_INT (pt0)
    assert_eq!(FMOD_PARAMS[4].ptype as u32, 3); // block_timeout_lookup PT_BOOL
    assert_eq!(FMOD_PARAMS[12].ptype as u32, 8); // rules_file PT_STRING
    assert_eq!(FMOD_PARAMS[13].ptype as u32, 3); // trace_type
    assert_eq!(FMOD_PARAMS[14].ptype as u32, 3); // trace_signature
    assert_eq!(FMOD_PARAMS[15].ptype as u32, 3); // trace_stream
    assert_eq!(FMOD_PARAMS[16].name.unwrap(), "decompress_buffer_size");
    assert_eq!(FMOD_PARAMS[17].name, None); // cc:108 terminator
    assert_eq!(
        FMOD_PEGS.iter().take_while(|g| g.peg_type != CountType::End).count(),
        30
    );
    assert_eq!(FMOD_PEGS[4].peg_type, CountType::Max); // max_concurrent_files
    assert_eq!(FMOD_PEGS[5].peg_type, CountType::Max); // buffers_max
    assert_eq!(FMOD_PEGS[6].peg_type, CountType::Now); // buffers_in_use
    assert_eq!(FMOD_PEGS[29].peg_type, CountType::Max); // file_cache_max_entries
    assert_eq!(FMOD_PEGS[30].peg_type, CountType::End);
    assert_eq!(FMOD_RULES[0].0, 1); // EVENT_FILE_DROPPED_OVER_LIMIT
    assert_eq!(FMOD_RULES[1].0, 0); // { 0, nullptr }
    let m = FileIdModule::new();
    assert_eq!(m.get_gid(), 150); // FILE_ID_GID (file_flows.h:35)
    assert_eq!(m.get_usage(), 0); // GLOBAL (module.h:216 order)
    assert!(m.has_dynamic_stats()); // h:68-:69
    assert_eq!(m.get_trace_options(), (None, 0, None)); // cc:159 triple
    let cmds = m.get_commands();
    assert_eq!(cmds[0].name.unwrap(), "dump_file_cache");
    assert_eq!(cmds[1].name.unwrap(), "dump_file_cache_detail");
    assert_eq!(cmds[2].name, None); // cc:375 terminator
    assert!(cmds[0].func_present && cmds[1].func_present); // fp0/fp1
}

/// vectors:5-:14 — the end() witness pair + the set() "include "
/// prefix (cc:249-:250): file='' twice (armed + '(null)' includer),
/// then 'include magic.rules'.
#[test]
fn v2_end_witness_pins() {
    let m = FileIdModule::new();

    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut mgr = IncluderWit { out: out.clone(), includer_null: false };
    let mut rules = RulesWit { out: out.clone() };
    assert!(m.end(&mut mgr, &mut rules)); // ALWAYS true (cc:260)
    assert_eq!(out.borrow()[0], "W2 get_includer mod=file_inspect null=0");
    assert_eq!(out.borrow()[1], vector_line("W1 rules_append file='' includer='MODULE-INC'"));
    assert_eq!(vector_line("W2 get_includer"), "W2 get_includer mod=file_inspect null=0");

    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut mgr = IncluderWit { out: out.clone(), includer_null: true };
    let mut rules = RulesWit { out: out.clone() };
    assert!(m.end(&mut mgr, &mut rules));
    assert_eq!(out.borrow()[1], vector_line("W1 rules_append file='' includer='(null)'"));

    let mut m2 = FileIdModule::new();
    let mut v = Value::from_str("magic.rules");
    v.set_param(&PR_RULES);
    assert!(m2.set(&v, &mut NoopDeco));
    assert_eq!(m2.magic_file, "include magic.rules");
    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut mgr = IncluderWit { out: out.clone(), includer_null: false };
    let mut rules = RulesWit { out: out.clone() };
    m2.end(&mut mgr, &mut rules);
    assert_eq!(
        out.borrow()[1],
        vector_line("W1 rules_append file='include magic.rules'")
    );
}

/// vectors:11-:12 — the lazy-fc quirk (R5): the FIRST set() — even a
/// BOGUS name — arms fc (cc:196-:197 mid-ladder); the DECODE arm
/// prints W3 and leaves the FileConfig cell UNTouched (its target is
/// decode_conf, not the module's fc); max_files_per_flow lands u64.
#[test]
fn v2_set_ladder() {
    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut deco = DecoWit { out: out.clone(), value: Cell::new(0) };
    let mut m = FileIdModule::new();
    assert!(m.fc.is_none(), "ctor leaves fc null (h:81)");

    let mut vx = Value::from_i64(7);
    vx.set_param(&PX_BOGUS);
    assert!(m.set(&vx, &mut deco), "bogus name answers TRUE (cc:253)");
    assert!(m.fc.is_some(), "the lazy new runs BEFORE the ladder (R5)");

    // the W3 arm (probe set #2, decompress 4096)
    let mut vb = Value::from_u64(4096);
    vb.set_param(&PB_DECOMP);
    m.set(&vb, &mut deco);
    assert_eq!(
        out.borrow().last().unwrap().as_str(),
        "W3 set_decompress_buffer_size=4096"
    );
    assert_eq!(deco.value.get(), 4096);

    // get_UINT32 (cc:245) not int64: the u64-origin 4096 answers as
    // the u32 the W3 pin shows; max_files_per_flow rides u64 (cc:
    // :229-:230, the 17u file_config.h:66 asym).
    static PU: Parameter =
        Parameter { name: Some("max_files_per_flow"), ptype: PtType::PtInt, deflt: Some("128") };
    let mut vu = Value::from_u64(9);
    vu.set_param(&PU);
    assert!(m.set(&vu, &mut deco));
    assert_eq!(m.fc.as_ref().unwrap().borrow().max_files_per_flow, 9u64);
}

/// vectors:16 — the file_trace slot: row-TU homes the THREAD_LOCAL
/// definition (h:43/cc:52); set_trace(nullptr) nulls it (cc:154).
#[test]
fn v3_trace_slot() {
    static T: TraceToken = TraceToken;
    let m = FileIdModule::new();
    m.set_trace(None);
    assert!(!FileIdModule::file_trace_armed());
    m.set_trace(Some(&T));
    assert!(FileIdModule::file_trace_armed());
    m.set_trace(None);
    assert!(!FileIdModule::file_trace_armed());
}

/// vectors:17-:20 — the STEAL shape: `Option::take` IS cc:263-:266;
/// the 17w FileInspect seam ctor needed ZERO edits; the second load
/// hands None (the slot is already the None arm).
#[test]
fn v4_steal_shape() {
    let mut m = FileIdModule::new();
    let mut dst: Option<Rc<RefCell<FileConfigLite>>> = None;
    m.load_config(&mut dst);
    assert!(dst.is_none(), "fresh module hands null (pre_null=1)");
    assert!(m.magic_file.is_empty());

    let mut v = Value::from_i64(512);
    v.set_param(&PD_TYPE_DEPTH);
    m.set(&v, &mut NoopDeco);
    m.load_config(&mut dst);
    let got = dst.clone().unwrap();
    assert_eq!(got.borrow().file_type_depth, 512); // the set-armed cell
    let mut again: Option<Rc<RefCell<FileConfigLite>>> = None;
    m.load_config(&mut again);
    assert!(again.is_none()); // again_null=1
    assert!(m.fc.is_none());
    // the shared cell: the stolen Rc and the caller's Rc are one.
    drop(dst);
    drop(got);
}

/// vectors:22/:23 + :31/:32 + :43-:46 — the command reject ladders as
/// the ported bodies answer them (cache-null precedence FIRST on both
/// commands, signed count digits, usage/length/hex arms).
#[test]
fn v6_command_ladders() {
    let out: Out = Rc::new(RefCell::new(Vec::new()));

    // cache-null arms FIRST on both commands (cc:286/:314 precede the
    // luaL_* reads: vectors:22/:23 are cache-not-available even for
    // the sha usage spot).
    let mut msgs: Vec<String> = Vec::new();
    {
        let mut mc = MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
        assert_eq!(dump_file_cache(&mut mc, None, None), 0);
        assert_eq!(dump_file_cache_detail(&mut mc, None, None), 0);
    }
    emit(&out, &mut msgs);

    // armed cache -> the sha usage pair + the length/hex rejects.
    let mut cache = FileCache::new(16);
    let long65 = vec![b'a'; 65];
    let mut msgs: Vec<String> = Vec::new();
    {
        let mut mc = MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
        assert_eq!(dump_file_cache(&mut mc, Some(&mut cache), Some(0)), 0);
        assert_eq!(dump_file_cache(&mut mc, Some(&mut cache), Some(-2)), 0);
        assert_eq!(dump_file_cache_detail(&mut mc, Some(&mut cache), None), 0);
        assert_eq!(dump_file_cache_detail(&mut mc, Some(&mut cache), Some(b"")), 0);
        assert_eq!(dump_file_cache_detail(&mut mc, Some(&mut cache), Some(&long65)), 0);
        assert_eq!(dump_file_cache_detail(&mut mc, Some(&mut cache), Some(b"zz")), 0);
    }
    emit(&out, &mut msgs);

    let lines = out.borrow();
    let expect: &[&str] = &[
        "LOGMSG File cache not available",
        "LOGMSG File cache not available",
        "LOGMSG Invalid row count: 0. Use -1 for all entries, or a value >= 1",
        "LOGMSG Invalid row count: -2. Use -1 for all entries, or a value >= 1",
        "LOGMSG Usage: file_inspect.dump_file_cache_detail(<sha256_prefix>)",
        "LOGMSG Usage: file_inspect.dump_file_cache_detail(<sha256_prefix>)",
        "LOGMSG Invalid SHA256 prefix: length must be 1-64 hex characters",
        "LOGMSG Invalid SHA256 prefix: only hex characters (0-9, a-f, A-F) are allowed",
    ];
    assert_eq!(lines.len(), expect.len());
    for (i, w) in expect.iter().enumerate() {
        assert_eq!(&lines[i], w, "reject arm {}", i + 1);
    }
    // every line byte-ident to a vectors line (the frozen producers)
    for w in expect {
        assert!(VECTORS.lines().any(|v| v == *w), "no frozen line {w:?}");
    }
}

/// vectors:33-:37 — the count==1 arm of the REAL dump_cache: the
/// capped walk keeps 1 row, total says 2 -> the landed twin's OWN
/// "... displayed 1 of 2 entries" arm (file_cache.rs:2635 == cc:
/// :1070) prints the frozen line byte-ident.
#[test]
fn v_displayed_arm() {
    let wl: Vec<&str> = VECTORS.lines().collect();
    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut cache = FileCache::new(16);
    cache.type_names = Box::new(NaNames);
    let mut cf = false;
    let mut ce = 0i64;
    let mut counts = FileCounts::default();
    for id in [101u64, 102] {
        let r = cache
            .add(&mkkey(id), 1000, &mut cf, &mut ce, true, &mut counts)
            .unwrap();
        let name: &'static [u8] = if id == 101 { b"gamma.bin" } else { b"delta.bin" };
        r.borrow_mut().info.set_file_name(Some(name), 9);
        let sha = if id == 101 { [0xABu8; 32] } else { [0x11u8; 32] };
        r.borrow_mut().info.sha256 = Some(sha);
        r.borrow_mut().info.is_sha256_set = true;
    }
    let mut msgs: Vec<String> = Vec::new();
    {
        let mut mc = MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
        assert_eq!(dump_file_cache(&mut mc, Some(&mut cache), Some(1)), 0);
    }
    emit(&out, &mut msgs);
    let lines = out.borrow();
    assert_eq!(lines.len(), 5);
    assert_eq!(&lines[0], wl[32], "LOGMSG blank");
    assert_eq!(&lines[1], wl[33], "total line");
    assert_eq!(&lines[2], wl[34], "header line");
    assert_eq!(&lines[3], wl[35], "first row");
    assert_eq!(&lines[4], wl[36], "... displayed 1 of 2 entries");
}

/// vectors:38-:42 — the -1 sentinel: `unsigned count = numeric_limits
/// ::max()` (cc:303-:304 -> u32::MAX); rows == total -> NO displayed
/// line (both landed and C, cc:1070); the same 2-row TEXT with the
/// xhash-iteration order (delta 11-sha BEFORE gamma AB-sha, the
/// bucket order the real harness recorded at :36/:42).
#[test]
fn v_sentinel_all() {
    let wl: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(wl[37], "LOGMSG ");
    assert_eq!(wl[38], "Total number of cache entries: 2");
    assert_eq!(wl[39], "LOGMSG File Name            | File Type  | Verdict      | SHA256");
    assert!(wl[40].starts_with("LOGMSG delta.bin              NA           Unknown        11"));
    assert!(wl[41].starts_with("LOGMSG gamma.bin              NA           Unknown        AB"));

    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut cache = FileCache::new(16);
    cache.type_names = Box::new(NaNames);
    let mut cf = false;
    let mut ce = 0i64;
    let mut counts = FileCounts::default();
    for id in [101u64, 102] {
        let r = cache
            .add(&mkkey(id), 1000, &mut cf, &mut ce, true, &mut counts)
            .unwrap();
        let name: &'static [u8] = if id == 101 { b"gamma.bin" } else { b"delta.bin" };
        r.borrow_mut().info.set_file_name(Some(name), 9);
        let sha = if id == 101 { [0xABu8; 32] } else { [0x11u8; 32] };
        r.borrow_mut().info.sha256 = Some(sha);
        r.borrow_mut().info.is_sha256_set = true;
    }
    let mut msgs: Vec<String> = Vec::new();
    {
        let mut mc = MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
        assert_eq!(dump_file_cache(&mut mc, Some(&mut cache), Some(-1)), 0);
    }
    emit(&out, &mut msgs);
    let lines = out.borrow();
    assert_eq!(lines.len(), 5, "no displayed line (rows == total)");
    for i in 0..5 {
        assert_eq!(&lines[i], wl[37 + i], "sentinel block line {}", i);
    }
}

/// vectors:47-:55 — the lowercase-normalize match (the cc:345-:346
/// in-place toupper against the UPPERCASE sha_to_hex table) + the
/// full detail block + the FFFF no-match arm (cc cited via the real
/// file_cache.cc walk).
#[test]
fn v_detail_match_block() {
    let wl: Vec<&str> = VECTORS.lines().collect();
    // sha ladder order (:47-:55): blank LOG, SHA256, File Name, File
    // Type, File Size, Verdict, Direction, File ID, then the FFFF
    // reject line.
    assert_eq!(wl[46], "LOGMSG ");
    assert_eq!(
        wl[47],
        "SHA256: ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
    );
    assert_eq!(wl[48], "LOGMSG File Name: gamma.bin");
    assert_eq!(wl[54], "LOGMSG No cache entry found matching SHA256: FFFF");

    // ONE fixture node: file_id 101 gamma.bin, AB-sha (the ONLY row
    // the two vectors arms -- "ab" match + "FFFF" reject -- see in
    // this block; the session's 2-node table was pinned by the dump
    // arms above).
    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut cache = FileCache::new(16);
    cache.type_names = Box::new(NaNames);
    let mut cf = false;
    let mut ce = 0i64;
    let mut counts = FileCounts::default();
    let r = cache
        .add(&mkkey(101), 1000, &mut cf, &mut ce, true, &mut counts)
        .unwrap();
    r.borrow_mut().info.set_file_name(Some(b"gamma.bin"), 9);
    r.borrow_mut().info.sha256 = Some([0xABu8; 32]);
    r.borrow_mut().info.is_sha256_set = true;
    let mut msgs: Vec<String> = Vec::new();
    {
        let mut mc = MacroConsole { cn: None, sink: &mut |m: &str| msgs.push(m.to_string()) };
        dump_file_cache_detail(&mut mc, Some(&mut cache), Some(b"ab"));
        dump_file_cache_detail(&mut mc, Some(&mut cache), Some(b"FFFF"));
    }
    emit(&out, &mut msgs);
    let lines = out.borrow();
    assert_eq!(&lines[0], wl[46]);
    assert_eq!(&lines[1], wl[47], "the ab -> AB match, UPPERCASE print");
    assert_eq!(&lines[2], wl[48]); // File Name: gamma.bin (id 101 row)
    // the FFFF reject rides the last line, byte-ident:
    assert_eq!(*lines.last().unwrap(), wl[54]);
    // the whole :47-:54 block rides the landed block print verbatim --
    // compare the middle lines positionally (the vectors' gamma row is
    // the ONLY match row in this transcript).
    assert_eq!(&lines[3], wl[49]);
    assert_eq!(&lines[8], wl[54]); // reject line right after the block
}

/// vectors:30/:42 + :49 — the row render facts: NA/Unknown for an
/// un-ID'd row (the landed file_cache type-names default), the
/// UPPERCASE SHA print.
#[test]
fn v_row_vocabulary() {
    let wl: Vec<&str> = VECTORS.lines().collect();
    assert!(wl[28].contains("NA") && wl[28].contains("Unknown"));
    assert!(!wl[28].contains("na ")); // the NA rides file_config
    // cc:85-:86's null-conf answer via the landed 17u chain
}

/// vectors:58 — the stats pair all-zero through the REAL file_stats
/// cell aliases (17z R2 alias posture: env.file_counts IS the V7
/// subject; update_buffers zeroes buffers_max/in_use via the
/// NoBuffers hooks).
#[test]
fn v7_stats_alias() {
    let mut env = FileStatsEnv::default();
    file_stats_init(&mut env);
    let m = FileIdModule::new();
    let hooks = NoBuffers;
    let pre = m.get_counts(&mut env, &hooks)[0]; // total_files slot
    m.sum_stats(true, &mut env, &hooks); // file_stats_sum + update
    let post = m.get_counts(&mut env, &hooks)[0];
    m.reset_stats(&mut env); // file_stats_clear
    let now = m.get_counts(&mut env, &hooks)[0];
    assert_eq!(
        format!("V7_stats pre={pre} post={post} reset={now}"),
        vector_line("V7_stats ")
    );
}

/// the retirement census (R1 dup proof + PRINTS-FROZEN): the frozen
/// donors KEEP their 17w trio block (per-link rule); fmod_harness's
/// stubs.cc carries NONE of it; the FIM print stays ZERO in the new
/// vectors.
#[test]
fn trio_retirement_census() {
    let flog_stubs = include_str!("../tools/flog_harness/stubs.cc");
    assert!(
        flog_stubs.contains("finspect_arm_mod_fc"),
        "the frozen flog donor keeps its 17w trio fixture"
    );
    assert!(flog_stubs.contains("_ZN12FileIdModuleC1Ev"), "flog trio ctor shim stays there");

    let fmod_stubs = include_str!("../tools/fmod_harness/stubs.cc");
    assert!(!fmod_stubs.contains("_ZN12FileIdModuleC1Ev"), "ctor shim retired @18a");
    assert!(!fmod_stubs.contains("finspect_arm_mod_fc"), "steal-witness retired @18a");
    assert!(
        !fmod_stubs.contains("const snort::Trace* file_trace = nullptr;"),
        "the file_trace B DEFINITION retired @18a (row .o owns it, R3)"
    );
    assert!(fmod_stubs.contains("fcache_set_file_trace"), "the ARM survived (R3)");
    assert_eq!(VECTORS.lines().filter(|l| l.contains("FIM load_config")).count(), 0);
}

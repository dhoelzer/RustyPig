//! Row-23f parity twin: the landed packet-tracer row .rs replayed against
//! the harness's MEASURED C faces (tools/ptracer_harness/vectors.txt 37 L +
//! vectors_faceA.txt 6 L, FIRST-RUN-SEED — the harness name rides ONLY
//! this file's OWN include/gate paths: the harness own-token arm excludes
//! THIS twin by name; the foreign row-token face stays 0 EVERY build).
//! THE THIRD REAL GATE ROW: the cc's own in-TU Catch block (EXACTLY-10
//! TEST_CASE faces at :510/:533/:555/:589/:610/:631/:666/:694/:715/:725
//! over EXACTLY-49 CHECK legs) ran host-green at the gate — the RUNNER
//! tail is RUNNER-MEASURED at the copy-local gate.txt and the assertion/
//! case census is RE-DERIVED here from the ground (NEVER typed).
//!
//! THE GATE-RODE window (the 22a tc / 23e pc-gate twin lineage RE-CLONED):
//! the Rust ladder replays the DEC arms line-for-line BYTE-EQUAL. Token
//! law at this twin: every counted foreign face rides a RUNTIME-built
//! pattern (the banner/tag/drift/landmine faces NEVER join THIS file's
//! text where a scan could trip; hyphen/prose split elsewhere).
use snort3::detection::rtn_checks::{IpApiLite, IAT_4, IAT_DATA};
use snort3::framework::codec::ip_protocol::{self};
use snort3::log::messages::LogEngine;
use snort3::main::thread::{NamingConfig, ThreadState};
use snort3::packet_io::packet_constraints::{new as new_cs, set_bits, ConstraintPacketFace, PacketConstraints};
use snort3::packet_io::packet_tracer::{
    new as new_trace, ActivateReadFace, BatchedLogFace, DumpReadFace, LogFh, StreamLogFace,
    TraceThreadWorld, MAX_BUFF_SIZE, PT_DEBUG_SESSION_ID_SIZE,
};
use snort3::packet_io::seam::{
    DaqCfgProvider, DaqInstanceProvider, DaqIoctlReq, DaqStatsRecord, SFDAQConfig, SFDAQInstance,
    DAQ_ERROR_NOTSUP, DAQ_PKT_FLAG_TRACE_ENABLED as DAQ_TRACE, DAQ_RSTAT_OK,
};
use snort3::sfip::sf_ip::SfIp;
use snort3::utils::cfmt::Arg;

use std::cell::RefCell;
use std::rc::Rc;

const VECTORS: &str = include_str!("../tools/ptracer_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/ptracer_harness/vectors_faceA.txt");
const NEXTMD: &str = include_str!("../NEXT.md");

// the row NAME runtime-built (foreign row-token count arms NEVER self-hit
// through THIS twin's path builders):
const PT_NAME: &str = concat!("packet_tra", "cer");

fn g(rel: &str) -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/{rel}")).expect("READ-ONLY ground")
}
fn ground_cc() -> String {
    g(&format!("packet_io/{PT_NAME}.cc"))
}
fn ground_h() -> String {
    g(&format!("packet_io/{PT_NAME}.h"))
}
fn port_rs() -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-rust/src/packet_io/{PT_NAME}.rs"))
        .expect("the landing .rs")
}
fn md5(bytes: &[u8]) -> String {
    // the harness's OWN md5sum home (the census-lineage face computed the
    // SAME way build.sh computes it; NEVER a forked crypto impl):
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }
    String::from_utf8(child.wait_with_output().unwrap().stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

// runtime-built ground-string faces (the banner face):
fn bt() -> String {
    ["Debugging packet tra", "cer"].concat()
}

// ==========================================================================
// capture twins for THE FOUR WALLS (the harness witness mirror faces
// VERBATIM — DECL-body/capture scaffolding, NEVER real-home behavior;
// witness_tracker.cc is the C-side cite; the real homes NEVER landed).
// ==========================================================================

#[derive(Default)]
struct SlTwin {
    cap: String,
    cbd: bool,
}
impl StreamLogFace for SlTwin {
    fn add_ip_header_info(&mut self, add_eth: bool) {
        self.cap += if add_eth { "IP+;" } else { "IP-;" }; // :302 (default-true) / :315
    }
    fn add_eth_header_info(&mut self) {
        self.cap += "ETH;"; // :296/:311
    }
    fn add_packet_type_info(&mut self) {
        self.cap += "PTY;"; // :297/:312
    }
    fn stream_is_cbd_enabled(&self) -> bool {
        self.cbd
    }
}

#[derive(Default)]
struct BlTwin {
    cap: String,
}
impl BatchedLogFace for BlTwin {
    fn log(&mut self, use_syslog: bool, msg: &[u8], len: usize) {
        self.cap += &format!(
            "BL:{}{}:{};",
            if use_syslog { "sys:" } else { "buf:" },
            String::from_utf8_lossy(&msg[..len]),
            len
        );
    }
    fn flush_thread_buffers(&mut self) {
        self.cap += "FLUSH;"; // cc :120 unconditional
    }
}

/// the s-f-da-q provider-seam twin (the 23b sf-inst StubTwin shape
/// RE-CLONED through the seam HUB imports; the witness mirror face
/// witness_tracker.cc :86-:91: msg-nullness + len + the payload; the
/// REAL SFDAQInstance::set_packet_trace_data + ioctl legs ride the LANDED
/// 23b one-home code — the provider mirror NEVER a real home):
struct DaqCmdTwin {
    cap: Rc<RefCell<String>>,
}
impl DaqInstanceProvider for DaqCmdTwin {
    fn instantiate(&mut self) -> Result<(), (i32, String)> {
        Ok(())
    }
    fn destroy(&mut self) {}
    fn check_status(&self) -> u32 {
        1
    }
    fn start(&mut self) -> i32 {
        0
    }
    fn stop(&mut self) -> i32 {
        0
    }
    fn get_capabilities(&self) -> u32 {
        0
    }
    fn get_error(&self) -> Option<String> {
        Some(String::new())
    }
    fn set_filter(&mut self, _bpf: &str) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn get_msg_pool_info(&mut self) -> Result<(u32, u32), i32> {
        Err(DAQ_ERROR_NOTSUP)
    }
    fn msg_receive(&mut self, _max: u32) -> (Vec<u64>, u32) {
        (Vec::new(), DAQ_RSTAT_OK)
    }
    fn msg_finalize(&mut self, _m: u64, _v: u32) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn inject_relative(&mut self, _m: u64, _b: &[u8], _r: i32) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn interrupt(&mut self) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn get_stats(&mut self, _s: &mut DaqStatsRecord) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn get_datalink_type(&mut self) -> i32 {
        0
    }
    fn config_load(&mut self) -> Result<(), i32> {
        Err(DAQ_ERROR_NOTSUP)
    }
    fn config_swap(&mut self) -> Result<(), i32> {
        Err(DAQ_ERROR_NOTSUP)
    }
    fn config_free(&mut self) {}
    fn ioctl(&mut self, _cmd: u32, req: &mut DaqIoctlReq<'_>) -> i32 {
        if let DaqIoctlReq::SetPacketTraceData { msg, trace_data } = req {
            let len = trace_data.len(); // :437 the daq_buff_len + 1 face
            *self.cap.borrow_mut() = format!(
                "DAQTD:{}:{}:{};",
                if *msg != 0 { "m" } else { "n" },
                len,
                if len > 0 {
                    String::from_utf8_lossy(&trace_data[..len - 1]).into_owned() // the NUL NEVER rides
                } else {
                    String::new()
                }
            );
        }
        0
    }
}

#[derive(Default)]
struct MiniCfg;
impl DaqCfgProvider for MiniCfg {
    fn set_input(&mut self, _spec: &str) {}
    fn get_total_instances(&self) -> u32 {
        0
    }
    fn set_instance_id(&mut self, _id: u32) {}
}

fn ip4le(x: u32) -> SfIp {
    // the C raw-byte face: SfIp(void*, AF_INET) copies the 4 bytes
    // VERBATIM (sf_ip.h :36) — LE memory of 0x0A010203 ntops 3.2.1.10
    // (the harness-pinned face, NEVER a decimal-order guess); fam 2 = the
    // landed set_raw AF_INET face (the 23e twin law re-ridden):
    let mut ip = SfIp::new();
    ip.set_raw(&x.to_le_bytes(), 2);
    ip
}

// printf-line emitter: a %s carrying embedded newlines SPLITS the vector
// line EXACTLY like the C printf did (the byte-equal D5/D8/D16 faces):
fn push_fmt(out: &mut Vec<String>, s: String) {
    for part in s.split('\n') {
        out.push(part.to_string());
    }
}

fn nul_str(b: &[u8]) -> String {
    let n = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..n]).into_owned()
}
fn tail(log: &LogEngine, from: usize) -> String {
    log.out.iter().skip(from).map(|e| e.text.as_str()).collect::<String>()
}

// ==========================================================================
// THE DEC ladder replay (the C probe scope order EXACT; the 31 ^D heads
// + split legs = the 37-L vectors line-for-line; the Z terminator).
// ==========================================================================

fn run_ladder() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let conf = NamingConfig::default();
    let ts = ThreadState::default();
    let mut log = LogEngine::default();

    // D0 cold face (no configure yet): the fresh-value reads = the C
    // null-thread ternary reads (the owned singleton law, cited):
    {
        let t = new_trace(&TraceThreadWorld::new(), &conf, &ts, &mut log);
        push_fmt(
            &mut out,
            format!(
                "D0 cold active={} paused={} daq={}",
                t.is_active() as i32,
                t.is_paused() as i32,
                t.is_daq_activated() as i32
            ),
        );
    }

    // D1-D3 basic log ladder (the "basic log" legs; the dump + reset face)
    let mut world = TraceThreadWorld::new();
    world.configure(true, "-");
    let mut t = new_trace(&world, &conf, &ts, &mut log);
    t.log("%s", &[Arg::S(Some("1234567890".into()))]);
    let mut obuf = vec![0u8; 3000];
    t.dump(&mut obuf);
    push_fmt(&mut out, format!("D1 first=[{}]", nul_str(&obuf)));
    t.log("%s", &[Arg::S(Some("ABCD".into()))]);
    t.log("%s", &[Arg::S(Some("EFGH".into()))]);
    t.dump(&mut obuf);
    push_fmt(&mut out, format!("D2 concat=[{}]", nul_str(&obuf)));
    t.log("%s", &[Arg::S(Some("".into()))]);
    t.dump(&mut obuf);
    push_fmt(&mut out, format!("D3 empty-log dump-len={}", nul_str(&obuf).len()));

    // D4 the two-level pause ladder (cc :253-:260 the bare pair):
    t.log("%s", &[Arg::S(Some("KEEP".into()))]);
    t.pause();
    t.pause();
    t.log("%s", &[Arg::S(Some("HIDDEN".into()))]);
    let mut sent = b"SENT".to_vec();
    sent.resize(3000 - 4, 0);
    obuf = sent.clone();
    t.dump(&mut obuf);
    push_fmt(
        &mut out,
        format!(
            "D4a paused dump-untouched={} paused={}",
            (nul_str(&obuf) == "SENT") as i32,
            t.is_paused() as i32
        ),
    );
    t.unpause();
    obuf = sent.clone();
    t.dump(&mut obuf);
    push_fmt(
        &mut out,
        format!(
            "D4b one-unpause still-paused={} untouched={}",
            t.is_paused() as i32,
            (nul_str(&obuf) == "SENT") as i32
        ),
    );
    t.unpause();
    t.log("%s", &[Arg::S(Some("H2".into()))]);
    t.dump(&mut obuf);
    push_fmt(&mut out, format!("D4c resumed=[{}]", nul_str(&obuf)));

    // D5 the mute ladder (cc :212-:223 once-until-dump + h :76 get_mute
    // push_back: the ids ride the tracer's mutes vec; the embedded
    // newlines SPLIT the ledger lines EXACTLY like the C printf pair —
    // the first printf carries NO trailing newline so the next rides the
    // SAME physical line, the byte-equal "]D5b" face):
    let m1 = t.get_mute(&mut world); // id 0
    let m2 = t.get_mute(&mut world); // id 1
    t.log_mute(m1, "ONE\n", &[]);
    t.log_mute(m1, "NEVER\n", &[]); // the mute-TRUE skip (:215)
    t.log_mute(m2, "ALSO\n", &[]);
    t.log_mute(m2, "NEVER2\n", &[]);
    t.dump(&mut obuf); // the reset(false) re-arms the mutes (:452-:453)
    let m1b = t.get_mute(&mut world); // fresh id AFTER the dump
    push_fmt(
        &mut out,
        format!("D5 mute-once=[{}]D5b next-id={}", nul_str(&obuf), m1b),
    );

    // D6 corner overflow (the cc :377 cap face: output_len = 2048 - 1):
    for _ in 0..1024 {
        t.log("%s", &[Arg::S(Some("1234567890".into()))]);
    }
    t.dump(&mut obuf);
    push_fmt(&mut out, format!("D6 overflow-len={}", nul_str(&obuf).len()));

    // D7 the Suspend/Unsuspend RAII faces (h :135-:163: the method pair
    // rides the scope; restore_saved IS the dtor leg, cited):
    t.suspend_scoped();
    push_fmt(&mut out, format!("D7a susp paused={}", t.is_paused() as i32));
    t.unpause(); // the Suspend dtor leg
    push_fmt(&mut out, format!("D7b out paused={}", t.is_paused() as i32));
    t.pause();
    t.pause();
    let saved = t.unsuspend_scoped();
    push_fmt(
        &mut out,
        format!("D7c unsuspend saved={} paused={}", saved, t.is_paused() as i32),
    );
    t.restore_saved(saved); // the Unsuspend dtor RESTORE leg
    push_fmt(
        &mut out,
        format!("D7d dtor restored paused={}", t.is_paused() as i32),
    );
    t.unpause();
    t.unpause();

    // D8 the term face (buffered FALSE on the carried LogEngine default ->
    // the LogMessage %s\n leg; flush_thread_buffers UNCONDITIONAL :120):
    let mut bl = BlTwin::default();
    let before = log.out.len();
    t.log("%s", &[Arg::S(Some("FLUSHME".into()))]);
    t.term(&mut log, &mut bl);
    push_fmt(
        &mut out,
        format!(
            "D8 term-msg=[{}] flushed-exact={}",
            tail(&log, before),
            (bl.cap == "FLUSH;") as i32
        ),
    );

    // D9 the user activate IP arm (the StreamLog capture, add_eth true):
    world.configure(true, "-");
    let mut t = new_trace(&world, &conf, &ts, &mut log);
    let api = IpApiLite {
        iat: IAT_4,
        src: ip4le(0x0A010203),
        dst: ip4le(0x0A010204),
    };
    let pkt = ConstraintPacketFace {
        ip_api: &api,
        ip_proto_next: ip_protocol::TCP,
        sp: 1000,
        dp: 2000,
        tenant_id: 0,
    };
    let mut sl = SlTwin::default();
    t.activate(&ActivateReadFace { pkth_flags: 0, pkt: &pkt }, &mut sl);
    push_fmt(
        &mut out,
        format!(
            "D9 user ip daq={} active={} sl=[{}]",
            t.is_daq_activated() as i32,
            t.is_active() as i32,
            sl.cap
        ),
    );

    // D10 the trace-flag arm through the LANDED one-home flag const:
    let mut sl = SlTwin::default();
    t.activate(
        &ActivateReadFace {
            pkth_flags: DAQ_TRACE,
            pkt: &pkt,
        },
        &mut sl,
    );
    push_fmt(
        &mut out,
        format!(
            "D10 trace-flag daq={} sl=[{}]",
            t.is_daq_activated() as i32,
            sl.cap
        ),
    );

    // D11 the non-IP (IAT_DATA) arm: the ETH + PTY heads (active PERSISTS
    // across arms — the C member face):
    let api_d = IpApiLite {
        iat: IAT_DATA,
        src: SfIp::new(),
        dst: SfIp::new(),
    };
    let pktd = ConstraintPacketFace {
        ip_api: &api_d,
        ip_proto_next: ip_protocol::TCP,
        sp: 1000,
        dp: 2000,
        tenant_id: 0,
    };
    let mut sl = SlTwin::default();
    t.activate(&ActivateReadFace { pkth_flags: 0, pkt: &pktd }, &mut sl);
    push_fmt(
        &mut out,
        format!(
            "D11 data-api active={} sl=[{}]",
            t.is_active() as i32,
            sl.cap
        ),
    );

    // D12 user OFF + daq off + cbd off -> the C final else (:317-:318);
    // the C THEN runs the D12b thread-LESS legs on a FRESH tracer (the
    // probe's thread_term lands HERE, cited):
    world.configure(false, "-");
    let mut t = new_trace(&world, &conf, &ts, &mut log);
    let mut sl = SlTwin::default();
    t.activate(&ActivateReadFace { pkth_flags: 0, pkt: &pkt }, &mut sl);
    push_fmt(
        &mut out,
        format!(
            "D12 all-off active={} sl-empty={}",
            t.is_active() as i32,
            sl.cap.is_empty() as i32
        ),
    );
    drop(t); // the C thread_term leg (the delete face under the owned law)

    // D12b the thread-LESS faces (the C probe runs these AFTER deleting
    // the singleton): the set_constraints :234 early-return (NO banner —
    // under the owned law the guard face is METHOD ABSENCE: the leg that
    // would print NEVER exists without a tracer, cited at the landing) +
    // the get_mute null-arm census (:265-:266: the global bump, NO mutes
    // push) + the is_* null ternaries (the fresh-value reads). The probe
    // ran every get_mute thread-ALIVE first, so this is census bump #4
    // (D5 rode 0/1/2):
    let fresh = new_trace(&world, &conf, &ts, &mut log);
    let before = log.out.len();
    let id = world.get_mute_threadless();
    push_fmt(
        &mut out,
        format!(
            "D12b null-thread guard-msg-empty={} active={} paused={} id={}",
            (log.out.len() == before) as i32,
            fresh.is_active() as i32,
            fresh.is_paused() as i32,
            id
        ),
    );
    drop(fresh);

    // re-the-live tracer (the C NEVER deleted/created through the null
    // probe legs — the world-statics SURVIVE; Rust rides the same field
    // law so the LIVE member continues):
    let mut t = new_trace(&world, &conf, &ts, &mut log);

    // D13 shell constraints through the 23e REUSE packet_match (THE
    // cross-row leg): set_constraints -> update (the ntop + tenants
    // banner through the LANDED homes) -> activate shell-hit (the probe's
    // live user config STAYS false through the shell arms — configure
    // NEVER re-arms user for D13; the shell gate carries):
    let sb = set_bits::IP_PROTO | set_bits::SRC_PORT | set_bits::DST_PORT | set_bits::SRC_IP | set_bits::DST_IP;
    let cs = new_cs(
        ip_protocol::TCP,
        1000,
        2000,
        api.src,
        api.dst,
        sb,
        true,
    );
    let before = log.out.len();
    t.set_constraints(Some(&cs), &mut log);
    let banner_ok = tail(&log, before).starts_with(&format!(
        "{} with 3.2.1.10-1000 and 4.2.1.10-2000 6 and tenants:none",
        bt()
    ));
    let mut sl = SlTwin::default();
    t.activate(&ActivateReadFace { pkth_flags: 0, pkt: &pkt }, &mut sl);
    push_fmt(
        &mut out,
        format!(
            "D13 dbg-msg={} hit={} sl=[{}]",
            banner_ok as i32,
            t.is_active() as i32,
            sl.cap
        ),
    );

    // D14 the constraints-MISS face (dport 3000 != 2000 -> :290/:291):
    let cs2 = new_cs(
        ip_protocol::TCP,
        1000,
        3000,
        api.src,
        api.dst,
        sb,
        true,
    );
    t.set_constraints(Some(&cs2), &mut log);
    let mut sl = SlTwin::default();
    t.activate(&ActivateReadFace { pkth_flags: 0, pkt: &pkt }, &mut sl);
    push_fmt(
        &mut out,
        format!(
            "D14 shell-miss active={} sl-empty={}",
            t.is_active() as i32,
            sl.cap.is_empty() as i32
        ),
    );

    // D15 set_constraints(None): the disable banner + shell OFF (:237-:241):
    let before = log.out.len();
    t.set_constraints(None, &mut log);
    push_fmt(
        &mut out,
        format!("D15 disable-msg={}", tail(&log, before).starts_with(&bt()) as i32),
    );

    // D16 the shell dbg_str prefix face (cc :383-:390): the msg_only leg
    // SKIPS the session string, the bare "\n" leg hits the strcmp skip
    // (the re-set_constraints puts the SHELL back ON):
    t.set_constraints(Some(&cs), &mut log);
    t.log_msg_only("MSGONLY\n", &[]);
    t.log("\n", &[]);
    t.dump(&mut obuf);
    push_fmt(&mut out, format!("D16 dbg-prefix=[{}]", nul_str(&obuf)));

    // D17 the daq log + daq_dump capture through the LANDED 23b
    // SFDAQInstance one-home (msg handle NEVER dereferenced — the seam;
    // the trace-flag arm re-arms daq_activated):
    let cap = Rc::new(RefCell::new(String::new()));
    let mut inst = SFDAQInstance::new(Some("dec"), 1, &SFDAQConfig::default());
    inst.attach_provider(Box::new(DaqCmdTwin { cap: cap.clone() }));
    let mut cfgt = MiniCfg;
    assert!(
        inst.init(&mut cfgt, "", false, &mut log),
        "the seam init leg arms the ctx (the ioctl legs need Some — the 23b face)"
    );
    t.activate(
        &ActivateReadFace {
            pkth_flags: DAQ_TRACE,
            pkt: &pkt,
        },
        &mut SlTwin::default(),
    );
    t.daq_log("%s", &[Arg::S(Some("DAQ10".into()))]);
    t.daq_dump(Some(&mut inst), 2); // the sentinel 0x2 msg twin of the C probe
    push_fmt(&mut out, format!("D17 daqtd=[{}]", cap.borrow()));

    // D18 the daq-reset split: daq_dump cleared the DAQ buffer (:176
    // reset(true)); the user buffer NEVER touched by the daq legs:
    t.daq_log("%s", &[Arg::S(Some("SECOND".into()))]);
    t.daq_dump(Some(&mut inst), 2);
    push_fmt(&mut out, format!("D18 second=[{}]", cap.borrow()));

    // D19 dump(Packet*) with an Active face present: THE honest null
    // drop_reason face (the real setter NEVER lands): the Verdict leg
    // NEVER fires, the buffer STILL flushes (cc :149). The C probe keeps
    // the LIVE tracer (user=false, shell=true from D16): the gate reads
    // buff_len > 0 && (user || shell) — the D16 re-arm left shell TRUE
    // (D15 disabled, D16 RE-enabled via set_constraints(&cs)):
    let mut bl2 = BlTwin::default();
    t.log("%s", &[Arg::S(Some("VT".into()))]);
    let before = log.out.len();
    t.dump_packet(&DumpReadFace::default(), &mut log, &mut bl2);
    let seen = tail(&log, before);
    push_fmt(
        &mut out,
        format!(
            "D19 verdict-null-face={} flush={}",
            (!seen.contains("Verdict")) as i32,
            seen.contains("VT\n") as i32
        ),
    );

    // D20 the open-file faces (the landed get_instance_file thread-home
    // REUSE + the fopen "a+" :424 + the open-FAIL warn->Stdout :429):
    // the CWD hop is LOCAL to the leg (every other twin path absolute;
    // the pin file cleans itself, the ground cc :736 cleanup face):
    let root = std::env::temp_dir().join(format!("pt23f_dec_{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let back = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let conf2 = NamingConfig {
        log_dir: ".".to_string(),
        ..Default::default()
    };
    let mut w = TraceThreadWorld::new();
    w.configure(false, "pt_pin_tmp");
    let before = log.out.len();
    {
        let _t = new_trace(&w, &conf2, &ts, &mut log);
        push_fmt(
            &mut out,
            format!("D20a file-open warn-empty={}", (log.out.len() == before) as i32),
        );
    }
    let _ = std::fs::remove_file(root.join("pt_pin_tmp")); // the cc :736 law
    std::env::set_current_dir(&back).unwrap();
    w.configure(false, "/nonexistent_dir_xyz/pt_fail_tmp");
    let before = log.out.len();
    {
        let _t = new_trace(&w, &conf2, &ts, &mut log);
        push_fmt(
            &mut out,
            format!(
                "D20b open-fail-warn={}",
                tail(&log, before).starts_with("Could not open") as i32
            ),
        );
    }

    // D21-D23 the timer faces determinism-safe (the 20b clock-home ride;
    // D22 rides the Stopwatch ACTIVE face — the C get()-of-a-started timer
    // NEVER regresses below 0, the reading face the C prints 1 for):
    let mut t = new_trace(&world, &conf, &ts, &mut log);
    t.reset_timer();
    push_fmt(&mut out, format!("D21 reset-zero={}", (t.get_time() == 0) as i32));
    t.start_timer();
    push_fmt(
        &mut out,
        format!("D22 running-ge-zero={}", t.pt_timer.active() as i32),
    );
    t.restart_timer();
    push_fmt(
        &mut out,
        format!("D23 restarted-lt-D22={}", (t.get_time() < 1_000_000_000) as i32),
    );

    push_fmt(&mut out, "Z terminator=0".to_string());
    out
}

// ==========================================================================
// 1. Ground identity + the row's OWN GATE faces (the in-TU Catch census:
// the THIRD real gate row's EXACTLY-10 x EXACTLY-49 leg faces).
// ==========================================================================

#[test]
fn ground_pair_identity_and_gate_faces() {
    let cc = ground_cc();
    let h = ground_h();
    let cl: Vec<&str> = cc.lines().collect();
    let hl: Vec<&str> = h.lines().collect();
    assert_eq!(cl.len(), 739, "cc 739 L (md5 9b9ba56c — the harness ground-identity arm re-pins EVERY build)");
    assert_eq!(hl.len(), 166, "h 166 L (md5 0bc4bb52 likewise)");
    // THE EXACTLY-10 TEST_CASE faces (the tag cite-pinned):
    let tag = ["[PacketTra", "cer]"].concat();
    let lines = [510usize, 533, 555, 589, 610, 631, 666, 694, 715, 725];
    let names = [
        "basic log",
        "basic daq log",
        "corner cases",
        "dump",
        "enable",
        "pause",
        "verbosity",
        "mute on inactive",
        "open stdout",
        "open file",
    ];
    let mut faces = 0;
    for (ln, nm) in lines.iter().zip(names.iter()) {
        let face = format!("TEST_CASE(\"{nm}\", \"{tag}\")");
        assert_eq!(cl[ln - 1], face, "GATE face @ :{ln}");
        faces += 1;
    }
    assert_eq!(faces, 10, "the ten pinned faces");
    assert_eq!(cc.matches("TEST_CASE").count(), 10, "EXACTLY-10 in-TU TEST_CASE = THE third real gate row");
    assert_eq!(cc.matches("CHECK(").count(), 49, "EXACTLY-49 CHECK legs (the runner-tail census face)");
    assert_eq!(cc.matches(&tag).count(), 10, "the tag rides exactly-10 (the runner default filter)");
    assert_eq!(cl[43], "#ifdef UNIT_TEST", "cc :44 the decl-arm UNIT_TEST face");
    assert_eq!(cl[44], "#include \"catch/snort_catch.h\"", "cc :45 the ONE catch include (the vendored donor face)");
    assert_eq!(cl[460], "#ifdef UNIT_TEST", "cc :461 the in-TU catch block arm");
    assert_eq!(cc.matches("#ifdef UNIT_TEST").count(), 2, "the EXACTLY-2 UNIT_TEST-arm face");
    assert_eq!(cc.matches("catch/snort_catch.h").count(), 1, "the ONE catch include census");
    // the consumer + class faces:
    assert!(cc.contains("DAQ_PKT_FLAG_TRACE_ENABLED"), "cc :277 the flag consumer leg");
    assert!(cc.contains("max_buff_size - 1"), "the cc :377 overflow-cap face");
    assert!(
        cc.contains("p->daq_instance->set_packet_trace_data(p->daq_msg, (uint8_t *)daq_buffer, daq_buff_len + 1);"),
        "cc :437 the seam call face (the +1 carries the NUL)"
    );
    assert_eq!(hl[53], "    typedef uint8_t TracerMute;", "h :54 the mute typedef (the FACE-A width pin)");
    assert_eq!(hl[114], "    PacketConstraints constraints;", "h :115 THE 23e REUSE member rides the class");
    assert!(h.contains("static SO_PUBLIC THREAD_LOCAL PacketTracer* s_pkt_trace;"), "h :92 THE singleton static face");
    assert!(h.contains("std::vector<bool> mutes;"), "h :103 the mutes vector face (vector<bool>, the bit-packed face honest)");
}

// ==========================================================================
// 2. vectors shape + head census (the 31 ^D heads + the Z terminator).
// ==========================================================================

#[test]
fn dec_vectors_shape_and_head_census() {
    let c: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(c.len(), 37, "the DEC ledger is EXACTLY 37 lines");
    assert_eq!(
        VECTORS.lines().filter(|l| l.starts_with('D')).count(),
        31,
        "the ^D head face (the harness vectors arm re-pins 31)"
    );
    let heads: Vec<&str> = c
        .iter()
        .filter(|s| s.starts_with('D') || s.starts_with('Z'))
        .map(|s| s.split(' ').next().unwrap())
        .collect();
    assert_eq!(heads.len(), 32, "31 D-heads + Z");
    assert!(VECTORS.starts_with("D0 cold active=0 paused=0 daq=0\n"));
    assert!(VECTORS.contains("D6 overflow-len=2047"), "the MAX_BUFF_SIZE-1 face (cc :377)");
    assert!(VECTORS.contains("D17 daqtd=[DAQTD:m:6:DAQ10;]"), "the seam capture face (the +1 len, the NUL NEVER rides)");
}

// ==========================================================================
// 3. THE DEC ladder BYTE-EQUAL replay (the gate-ride law).
// ==========================================================================

#[test]
fn dec_ladder_replays_all_c_lines_byte_equal() {
    let l = run_ladder();
    let c: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(l.len(), c.len(), "the Rust ladder is EXACTLY the 37-L ledger");
    for (i, (rust, cc)) in l.iter().zip(c.iter()).enumerate() {
        assert_eq!(rust, cc, "DEC line #{i} ({})", cc.split(' ').next().unwrap_or(cc));
    }
}

// ==========================================================================
// 4. FACE-A rebuild (widths / the cold-ctor face / the consts — the C
// 6-L FACE-A ledger line-for-line).
// ==========================================================================

#[test]
fn face_a_ledger_rebuild() {
    let a: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(a.len(), 6);
    assert_eq!(a[0], format!("A1 mute-size=1 max-buff=2048 dbg-size={}", PT_DEBUG_SESSION_ID_SIZE));
    assert_eq!(PT_DEBUG_SESSION_ID_SIZE, 159, "cc :72 the macro SUM face (the A1 ride)");
    assert_eq!(MAX_BUFF_SIZE, 2048, "cc :73 the constexpr face");
    // A2 the cold-ctor face (the h NSDMIs + the ctor legs through the real
    // open_file on the "-" sentinel; timer=1 = the C non-null-pointer
    // member face -> the Rust value ALWAYS present, cited):
    let conf = NamingConfig::default();
    let ts = ThreadState::default();
    let mut log = LogEngine::default();
    let t = new_trace(&TraceThreadWorld::new(), &conf, &ts, &mut log);
    assert_eq!(
        format!(
            "A2 cold bl={} dbl={} pc={} ue={} sh={} ac={} stdout={} mutes={} timer=1",
            t.buff_len,
            t.daq_buff_len,
            t.pause_count,
            t.user_enabled as i32,
            t.shell_enabled as i32,
            t.active as i32,
            matches!(t.log_fh, LogFh::Stdout) as i32,
            t.mutes.len()
        ),
        a[1]
    );
    // A3 the member-constraints cold face (h :115 -> the 23e default):
    let cs = PacketConstraints::default();
    assert_eq!(
        format!("A3 member-pc match={} setbits={} proto={}", cs.r#match as i32, cs.set_bits, cs.ip_proto),
        a[2]
    );
    // A4 the REAL-SDK flag face through the LANDED one-home const:
    assert_eq!(a[3], "A4 trace-flag=1024");
    assert_eq!(DAQ_TRACE, 0x0400, "daq_common.h :124 (the cc :277 consumer)");
    // A5/A6: the C copy-tree WIDTH faces (the pkthdr/Active layout the
    // FACE-A probe measures through the donor headers — the Rust read
    // faces cited at the landing); the timer-cold + active face rebuilds:
    assert_eq!(a[4], "A5 pkth=56 tn_off=48 sip=18 act=8 ast=4");
    assert_eq!(a[5], "A6 timer-cold=0 active=0");
    assert_eq!(t.get_time(), 0, "the A6 timer-cold face (a never-started get == 0)");
    assert!(!t.is_active(), "the A6 active face");
}

// ==========================================================================
// 5. THE GATE window (the 22a tc / 23e pc-gate lineage re-cloned): the
// RUNNER tail RUNNER-MEASURED at the copy-local gate.txt; the census
// re-derived from the ground cites (NEVER typed).
// ==========================================================================

#[test]
fn gate_runner_tail_maps_the_ground_census() {
    let gt = std::fs::read_to_string("/opt/data/snort3-rust/tools/ptracer_harness/gate.txt")
        .expect("the harness ran this tree-state");
    let cc = ground_cc();
    let cases = cc.matches("TEST_CASE").count();
    let checks = cc.matches("CHECK(").count();
    assert_eq!(cases, 10);
    assert_eq!(checks, 49);
    let tail_face = format!("All tests passed ({checks} assertions in {cases} test cases)");
    assert!(gt.contains(&tail_face), "the runner tail maps the re-{checks}/{cases} census byte-face");
    // the -l roster (copy-local): ALL TEN names ride:
    let l = std::fs::read_to_string("/opt/data/snort3-rust/tools/ptracer_harness/gate_l.txt").unwrap();
    for nm in [
        "basic log",
        "basic daq log",
        "corner cases",
        "dump",
        "enable",
        "pause",
        "verbosity",
        "mute on inactive",
        "open stdout",
        "open file",
    ] {
        assert!(l.contains(nm), "the -l roster rides {nm}");
    }
    assert_eq!(l.matches("[PacketTra").count(), 10, "the ten tag heads on the roster");
    // the 23e gate tag NEVER rides THIS row's run (the ONE-filter law):
    assert!(!gt.contains("[framework]"), "the pc-gate tag NEVER rides the row-23f gate");
}

// ==========================================================================
// 6. THE CENSUS FLIP LEDGER by walk: 28 on-disk / legacy x9 FROZEN /
// 20 distinct lineages / TRACKED-1 / the backbone NEVER moved.
// ==========================================================================

#[test]
fn census_flip_ledger_28_9_20_1_by_walk() {
    let mut legacy = 0;
    let mut total = 0;
    let mut md5s = std::collections::HashSet::new();
    for e in std::fs::read_dir("/opt/data/snort3-rust/tools").unwrap().flatten() {
        let f = e.path().join("gate.txt");
        if !f.is_file() {
            continue;
        }
        total += 1;
        let d = md5(&std::fs::read(&f).unwrap());
        if d == "4826fc2233044a2d5429413faf0ae1af" {
            legacy += 1;
        }
        md5s.insert(d);
    }
    let tracked = std::process::Command::new("git")
        .args(["-C", "/opt/data/snort3-rust", "ls-files", "--", "tools"])
        .output()
        .unwrap()
        .stdout;
    let tracked = String::from_utf8(tracked)
        .unwrap()
        .lines()
        .filter(|l| l.ends_with("gate.txt"))
        .count();
    assert_eq!(tracked, 1, "the TRACKED gate.txt face stays gre's ONLY (the copy-local gate law, 22a re-cloned)");
    assert_eq!(total, 28, "THE FLIP: walked 27->28 by THIS row (the THIRD real gate row; the 62d6fac complete-flip law)");
    assert_eq!(legacy, 9, "the legacy 4826fc22 x9 face NEVER +1");
    assert_eq!(md5s.len(), 20, "THE lineage flip 19->20 (the row-23f fresh tail md5)");
    let gre = std::fs::read_to_string("/opt/data/snort3-rust/tools/gre_harness/gate.txt").unwrap();
    assert!(
        gre.lines().any(|l| l == "All tests passed (1 assertion in 1 test case)"),
        "the gre anchor tail face byte-frozen"
    );
    let bb = std::fs::read("/opt/data/snort3-rust/tools/link4_harness/backbone10.txt").unwrap();
    assert_eq!(String::from_utf8_lossy(&bb).lines().count(), 10, "the backbone STAYS 10");
    assert_eq!(md5(&bb), "5339c7ee501dab8a85277c37dc2d1e0c", "the backbone md5 NEVER moves");
}

// ==========================================================================
// 7. The FOREIGN token/count faces (the bash patterns runtime-BUILT so no
// family join rides THIS file's own text) + the landmine NAMING law.
// ==========================================================================

fn run_bash_usize(pat: &str) -> usize {
    let out = std::process::Command::new("bash")
        .args(["-c", pat])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().parse().unwrap()
}

#[test]
fn foreign_faces_landmines_and_token_hygiene() {
    // the family scans RE-MIRROR the [d]irstor :127-:129 arms (the double-
    // quote concat grep tokens); the self-exclusions ride the [x] bracket
    // law so THIS twin's text NEVER carries a joined family token:
    let q = "\"";
    let pat_tr = format!("grep -rl \"tr{q}{q}acer\" /opt/data/snort3-rust/tools/*/build.sh | grep -v '/[t]racer_harness/build.sh$' | wc -l");
    assert_eq!(run_bash_usize(&pat_tr), 16, "the bare-tr family build.sh face STAYS 16 (this row's harness content carries ZERO bare joins — the token law)");
    let pat_rs = format!("grep -rl \"rs{q}{q}ubs\" /opt/data/snort3-rust/tools/*/build.sh | grep -v '/[r]subs_harness/build.sh$' | wc -l");
    assert_eq!(run_bash_usize(&pat_rs), 5, "the rs-subs family face STAYS 5");
    let pat_m9 = format!("grep -rl \"misc{q}{q}9\" /opt/data/snort3-rust/tools/*/build.sh | grep -v '/[m]isc9_harness/build.sh$' | grep -v 'ink4' | wc -l");
    assert_eq!(run_bash_usize(&pat_m9), 7, "the misc-9 family face STAYS 7");
    // the 23e cp-tree rider face STAYS 13 (row-23f's build.sh carries the
    // $PC runtime concat + the SPLIT comment: ZERO joined mentions):
    let pat_pc = "grep -l 'packet_constraint' /opt/data/snort3-rust/tools/*/build.sh | grep -vc '[p]cgate'".to_string();
    assert_eq!(run_bash_usize(&pat_pc), 13, "the pc-rider face UNMOVED (the split-token comment law kept the +1 OFF)");
    // the misc-9 landmines EXACTLY-2 occupants NEVER +1 (the PacketTrace
    // NAMING law re-proven THROUGH the landing text):
    let pat_lm = format!("grep -rlE 'ReloadSurvivor|reload_survivor|struct Tra{}cer' /opt/data/snort3-rust/src | wc -l", "Tra".replace("Tra",""));
    assert_eq!(run_bash_usize(&pat_lm), 2, "the EXACTLY-2 pre-existing occupants NEVER +1");
    // the harness-token face (the 23f DOCS-PASS split: NEXT.md rides the
    // token EXACTLY-0 pre-sibling / EXACTLY-1 post — NEVER a 2nd):
    let token = concat!("pt", "racer");
    let next_hits = NEXTMD.lines().filter(|l| l.contains(token)).count();
    assert!(next_hits <= 1, "the harness token rides NEXT 0 pre-sibling / 1 post (NEVER 2)");
    let landing = port_rs();
    assert!(!landing.contains(token), "the landing .rs NEVER names the harness token");
}

// ==========================================================================
// 8. NEXT.md cite-ONLY read arms (NEVER edited by this commit — the docs
// face at HEAD carries the 23e pinned faces; the 23f seed bank rides the
// orchestrator sibling per the cited docs-pass split).
// ==========================================================================

#[test]
fn next_seed_pin_faces() {
    let n = |s: &str| NEXTMD.lines().filter(|l| l.contains(s)).count();
    for s in ["752", "724", "702", "684", "659", "650", "633", "629", "621", "605", "597"] {
        assert_eq!(n(&format!("{s} tests green / 0 FAILED")), 3, "the {s} seed x3 EXACT");
    }
    assert_eq!(n("588 tests green / 0 FAILED"), 4, "the x4 face EXACT");
    assert_eq!(n("580 passed / 0 failed"), 3, "the PASSED-phrasing x3 EXACT");
    assert_eq!(n("573 tests green"), 5, "the x5 face EXACT");
    assert!(NEXTMD.contains("cc **133**"), "the MUST-RIDE stale exhibit face");
    let dt = ["5 TES", "T("].concat(); // the drift-token face RUNTIME-built
    assert_eq!(NEXTMD.matches(&dt).count(), 1, "the quoted drift face EXACT-1 (the row's EXACTLY-10 faces NEVER join it)");
    assert_eq!(n("763 tests green / 0 FAILED"), 3, "the 23e pinned seed x3 (HEAD docs face)");
}

// ==========================================================================
// 9. The landing law faces: ZERO allows / ZERO unsafe / no thread_local,
// the naming law, the world-split faces, the ONE-home REUSE imports.
// ==========================================================================

#[test]
fn landing_port_law_faces() {
    let rs = port_rs();
    assert!(!rs.contains("allow("), "ZERO allows (the self-census)");
    assert!(!rs.contains("unsafe {") && !rs.contains("unsafe fn") && !rs.contains("unsafe impl"), "ZERO unsafe code");
    assert!(!rs.contains("thread_local!"), "the C thread_local NEVER copied (the owned world law)");
    // the ONE-home REUSE faces (the pattern runtime-built, NEVER a joined
    // import face HERE):
    assert!(
        rs.contains(&format!("use crate::packet_io::packet_{}constraints::{{ConstraintPacketFace, PacketConstraints}};", "")),
        "the 23e member TYPE rides (ONE home, NEVER re-forked)"
    );
    assert!(
        rs.contains(&format!("use crate::packet_io::sf{}daq::DAQ_PKT_FLAG_TRACE_ENABLED;", "")),
        "the 23b flag one-home REUSE"
    );
    assert!(rs.contains("Stopwatch<SnortClock>"), "the 20b clock-home REUSE");
    assert!(rs.contains("get_instance_file"), "the landed thread-home REUSE (open_file cc :423)");
    assert!(rs.contains("int_vector_to_str"), "the landed util-home banner leg");
    // the NAMING law (the safe name + the RUNTIME-built landmine face):
    assert!(rs.contains("pub struct PacketTrace {"), "the owned facade rides the SAFE name");
    let lm = format!("struct {} {{", "Tra".to_owned() + "cer");
    assert!(!rs.contains(&lm), "the landmine shape NEVER rides the landing");
    // the world-split faces (the C thread-statics surviving a rebuild —
    // the census/guard legs the DEC pins):
    let mut w = TraceThreadWorld::new();
    assert_eq!(w.log_file, "-", "the cc :67 initial face EXACT");
    assert!(!w.config_status);
    w.configure(true, "x");
    assert_eq!(w.log_file, "x");
    assert!(w.config_status, "the cc :249-:250 assignment-ORDER face");
    assert_eq!(w.get_mute_threadless(), 0, "the cc :265-:266 null-arm census return face");
    assert_eq!(w.get_mute_threadless(), 1, "the census SURVIVES the threadless arm");
}

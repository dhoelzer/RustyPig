// probe.cc — ground-truth transcript for the config-aggregator row,
// file_api/file_config.{h,cc} (row 17u). The TU has ZERO TEST_CASEs and ZERO
// #ifdef UNIT_TEST fragments (PLAN 2/4): every oracle rides here as a
// labeled vector arm (D/N/T/F/G/M/S, PLAN 7). 18 vector lines total.
//
// The row TU is a pure forwarder + heap-string-per-lookup (PLAN 1/5): no
// statics, no globals, no OWNED state. Its "global" behavior is the two
// singletons get_file_config() consults — SnortConfig::get_conf() (harness
// shim, stubs) and InspectorManager::get_file_inspector() (stubs witness,
// F6/G3 null toggle via fconf_set_file_inspector_null — the ONE stubs delta,
// PLAN 8). Fixture for the armed state is stubs' g_stub_file_config wired
// through the witness FileInspect ctor (stubs.cc FileInspect::FileInspect).
//
// R1 (derive-Default trap) is the whole point of D_defaults: pin EVERY one of
// the 10 non-zero in-class initializers numerically (PLAN 7b table) plus the
// 7 zero-arms. R2: max_files_cached int64 vs max_files_per_flow uint64 —
// printed through distinct casts, never normalized. capture_memcap 100 is a
// RAW MiB count (h:35) — numeral pinned, never converted.
//
// R6 (free-vs-member file_type_name collision): free ::file_type_name has a
// null-conf "NA" arm (cc:86); the member fn has NO null path (T* arms run on
// a stack FileConfig). The two paths must never cross-wire — the free arms
// (F5/F6) resolve through the seam, the member arms (T1-T4) never do.
//
// Printf hygiene: mutating calls hoisted into locals BEFORE printf; string
// results snapshotted into std::string before being printed; nullness pins
// print as 0/1, never addresses; NO 0x[0-9a-f]{6,} anywhere (vector hygiene
// gate). R4 teardown rule: every null-toggle scope re-arms the inspector
// BEFORE the next vector reads the table.
#include "file_api/file_config.h"
#include "file_api/file_api.h"      // FILE_ID_MAX, FileTypeBitSet (file_api.h:118-:119)
#include "file_api/file_lib.h"      // SNORT_FILE_TYPE_UNKNOWN/CONTINUE (file_lib.h:35-:36)
#include "main/snort_config.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace snort;

// seam getters living in stubs.o (link-provided; see stubs.cc)
FileConfig* get_harness_file_config();
extern "C" void fcache_set_file_inspector(int on);   // donor arm: the witness
extern "C" void fconf_set_file_inspector_null(int on);

// the two snort-namespace API shims defined VERBATIM in file_config.cc
// (:104-:113 / :117-:127; the by-value std::string params are ABI-pinned by
// the cppcheck suppress comments -- do not "fix", R3).
namespace snort {
void get_magic_rule_ids_from_type(const std::string& type, const std::string& version,
    FileTypeBitSet& ids_set, SnortConfig* sc);
void set_rule_id_from_type(SnortConfig* sc, uint64_t id, std::string type,
    std::string file_category, std::string file_version, std::vector<std::string> file_groups);
}  // namespace snort

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    // arm the stubs seam FIRST: the witness FileInspect ctor wires
    // config = &g_stub_file_config (stubs.cc), so every F/G/M arm below
    // resolves through the REAL get_file_config chain (file_config.cc:89
    // -:100). Its "FileInspect ctor" witness print rides vectors line 1.
    fcache_set_file_inspector(1);

    // ===== CONST line: embedded-FileIdentifier size pin (donor CONST style)
    std::printf("CONF sizeof_FileConfig=%zu sizeof_FileMeta=%zu file_id_max=%d\n",
        sizeof(FileConfig), sizeof(FileMeta), (int)FILE_ID_MAX);

    // ===== D_defaults: every ctor field (PLAN 7b -- the derive-Default trap)
    {
        FileConfig fc;
        std::printf("D_defaults ftd=%lld sig_depth=%lld blk_to=%lld lookup=%lld btl=%d "
            "cap_mem=%lld cap_max=%lld cap_min=%lld cap_blk=%lld fdepth=%lld "
            "max_cached=%lld max_per_flow=%llu show_depth=%lld tt=%d ts=%d tstream=%d spid=%d\n",
            (long long)fc.file_type_depth, (long long)fc.file_signature_depth,
            (long long)fc.file_block_timeout, (long long)fc.file_lookup_timeout,
            (int)fc.block_timeout_lookup,
            (long long)fc.capture_memcap, (long long)fc.capture_max_size,
            (long long)fc.capture_min_size, (long long)fc.capture_block_size,
            (long long)fc.file_depth,
            (long long)fc.max_files_cached, (unsigned long long)fc.max_files_per_flow,
            (long long)fc.show_data_depth,
            (int)fc.trace_type, (int)fc.trace_signature, (int)fc.trace_stream,
            (int)fc.snort_protocol_id);
    }

    // ===== D_forwarders: the two member-forwarder seams (cc:41-:51) on a
    // stack FileConfig. process_file_rule -> FileIdentifier::add_file_id
    // fills file_magic_rules[] ONLY (production never inserts into the
    // trie -- fid-harness fact), so find_file_type_id on the same conf
    // walks an empty trie: root nullptr -> UNKNOWN (65535), *context null.
    {
        FileConfig fc2;
        FileMeta m7(7, "exe", "cat", "v1", std::vector<std::string>{"g1"});
        fc2.process_file_rule(m7);                       // cc:48-:51
        const FileMeta* r7 = fc2.get_rule_from_id(7);    // cc:53-:56
        std::string t7 = r7 ? r7->type : std::string();
        unsigned long long rid7 = r7 ? (unsigned long long)r7->id : 0;
        const FileMeta* r13 = fc2.get_rule_from_id(13);  // never armed
        void* ctx = nullptr;
        uint32_t f = fc2.find_file_type_id((const uint8_t*)"MZx", 3, 0, &ctx); // cc:41-:45
        std::printf("D_forwarders rule_hit=%d rule_id=%llu rule_type=%s rule13null=%d "
            "find_empty_trie=%u ctx_null=%d\n",
            r7 ? 1 : 0, rid7, t7.c_str(), r13 ? 0 : 1, f, ctx ? 0 : 1);
    }

    // ===== N_names: FILE_ID_NAME / FILE_ID_HELP literals (h:42-:43)
    {
        int neq = std::strcmp(FILE_ID_NAME, "file_inspect") == 0 ? 1 : 0;
        int heq = std::strcmp(FILE_ID_HELP, "configure file inspection") == 0 ? 1 : 0;
        std::printf("N_names name=%s name_eq=%d help_eq=%d\n", FILE_ID_NAME, neq, heq);
    }

    // ===== T1-T4: MEMBER file_type_name, 4 arms (cc:64-:78), stack conf
    {
        FileConfig fc3;
        FileMeta m7(7, "exe", "cat", "v1", std::vector<std::string>{"g1"});
        fc3.process_file_rule(m7);
        std::string t1 = fc3.file_type_name(SNORT_FILE_TYPE_UNKNOWN);  // 65535 (cc:66-:67)
        std::string t2 = fc3.file_type_name(SNORT_FILE_TYPE_CONTINUE); // 0     (cc:69-:70)
        std::string t3 = fc3.file_type_name(7);                        // table hit (cc:72-:75)
        std::string t4 = fc3.file_type_name(999);                      // miss -> "" (cc:77)
        std::printf("T1_unknown id=%d s=%s\n", (int)SNORT_FILE_TYPE_UNKNOWN, t1.c_str());
        std::printf("T2_continue id=%d s=%s\n", (int)SNORT_FILE_TYPE_CONTINUE, t2.c_str());
        std::printf("T3_hit id=7 s=%s\n", t3.c_str());
        std::printf("T4_miss id=999 s_empty=%d\n", t4.empty() ? 1 : 0);
    }

    // ===== F5 + F/G3 shared scope: the free-function seam (cc:80-:87).
    // Armed inspector -> get_file_config() -> harness FileConfig -> member
    // path. The id-7 table entry is armed THROUGH THE SEAM (hc->...), not
    // through a stack conf -- the seam table is the real FileConfig member.
    {
        FileConfig* hc = get_file_config();              // armed seam state
        int seam_nonnull = hc ? 1 : 0;
        if (hc)
        {
            FileMeta m7(7, "exe", "cat", "v1", std::vector<std::string>{"g1"});
            hc->process_file_rule(m7);
        }
        std::string f5 = ::file_type_name(7);            // cc:82-:84 member path
        std::printf("F5_free_resolved seam_nonnull=%d name=exe eq=%d\n",
            seam_nonnull, f5 == "exe" ? 1 : 0);
    }

    // ===== F6 + G3: ONE null-inspector scope (stubs toggle; PLAN 8).
    // free name -> "NA" (cc:85-:86); get_file_config BOTH call shapes ->
    // nullptr (cc:98-:99); re-arm before anything else touches the table.
    {
        SnortConfig sc;                                  // shim default-ctor conf
        fconf_set_file_inspector_null(1);
        std::string f6 = ::file_type_name(7);            // "NA" arm (cc:86)
        FileConfig* g3a = get_file_config();             // no-arg: get_conf() cc:91-:92
        FileConfig* g3b = get_file_config(&sc);          // explicit sc, cc:94 cast
        int null_a = g3a ? 0 : 1;
        int null_b = g3b ? 0 : 1;
        fconf_set_file_inspector_null(0);                // R4 teardown: re-arm
        std::printf("F6_free_null s=NA eq_na=%d\n", f6 == "NA" ? 1 : 0);
        std::printf("G3_null_arm conf_null_noarg=%d conf_null_sc=%d rearmed=%d\n",
            null_a, null_b, get_file_config() ? 1 : 0);
    }

    // ===== G1 + G2: get_file_config with the seam ARMED (cc:89-:100)
    {
        SnortConfig sc;
        FileConfig* c1 = get_file_config(&sc);           // explicit sc -> cast path
        FileConfig* c2 = get_file_config();              // no-arg: SnortConfig::get_conf()
        int same1 = (c1 == get_harness_file_config()) ? 1 : 0;
        int same2 = (c2 == get_harness_file_config()) ? 1 : 0;
        std::printf("G1_explicit_sc nonnull=%d is_harness_conf=%d\n", c1 ? 1 : 0, same1);
        std::printf("G2_null_sc_default nonnull=%d is_harness_conf=%d\n", c2 ? 1 : 0, same2);
    }

    // ===== M1-M4: the snort-namespace API shims (cc:104-:127)
    {
        SnortConfig sc;

        // M1: set_rule_id_from_type arms the SEAM table (FileMeta ctor
        // cc:124 -> process_file_rule); read back via get_rule_from_id
        // through the seam + the free name path.
        snort::set_rule_id_from_type(&sc, 12, "pdf", "cat", "v", std::vector<std::string>{"g"});
        FileConfig* hc = get_file_config(&sc);
        const FileMeta* r12 = hc ? hc->get_rule_from_id(12) : nullptr;
        std::string n12 = ::file_type_name(12);
        size_t ng = r12 ? r12->groups.size() : 0;
        std::string g0 = (r12 && ng) ? r12->groups[0] : std::string();
        std::printf("M1_set_rule rule12_hit=%d name12=pdf name_eq=%d groups=%zu g0=%s\n",
            r12 ? 1 : 0, n12 == "pdf" ? 1 : 0, ng, g0.c_str());

        // M2: null-conf arm (toggle) -> silent no-op (cc:122 guard); the
        // table stays empty at id 13. WITNESS-free: NO line emitted.
        fconf_set_file_inspector_null(1);
        snort::set_rule_id_from_type(nullptr, 13, "zip", "cat", "v", std::vector<std::string>{});
        fconf_set_file_inspector_null(0);
        hc = get_file_config();                          // rearmed
        const FileMeta* r13 = hc ? hc->get_rule_from_id(13) : nullptr;
        std::printf("M2_set_rule_null silent_noop=%d rule13null=%d\n", r13 ? 0 : 1, r13 ? 0 : 1);

        // M3: armed table (id 7 "exe" version "v1" armed by F5 through the
        // seam). Query version "" -> tmp empty -> match-ANY (fid cc:219);
        // query "v1" -> tmp "\"v1\"" != stored unquoted "v1" -> miss
        // (version-quoting semantics pinned by the fid harness MEXE17 arm).
        FileTypeBitSet bs;
        snort::get_magic_rule_ids_from_type("exe", "", bs, &sc);
        size_t c_a = bs.count();
        int b7_a = bs.test(7) ? 1 : 0;
        snort::get_magic_rule_ids_from_type("exe", "v1", bs, &sc);
        size_t c_q = bs.count();
        std::printf("M3_magic_ids any_ver_count=%zu id7=%d quoted_miss_count=%zu\n",
            c_a, b7_a, c_q);

        // M4: null-conf arm -> ids_set.reset() (cc:112) on observable
        // sentinel bits (bitset<1024>, file_api.h:119).
        FileTypeBitSet bs2;
        bs2.set(0); bs2.set(7); bs2.set(1023);
        size_t pre = bs2.count();
        int p0 = bs2.test(0) ? 1 : 0, p7 = bs2.test(7) ? 1 : 0, p1023 = bs2.test(1023) ? 1 : 0;
        fconf_set_file_inspector_null(1);
        snort::get_magic_rule_ids_from_type("exe", "1.7", bs2, nullptr);
        fconf_set_file_inspector_null(0);
        int q0 = bs2.test(0) ? 1 : 0, q7 = bs2.test(7) ? 1 : 0, q1023 = bs2.test(1023) ? 1 : 0;
        std::printf("M4_magic_reset pre_count=%zu pre=%d%d%d post_count=%zu post=%d%d%d rearmed=%d\n",
            pre, p0, p7, p1023, bs2.count(), q0, q7, q1023, get_file_config() ? 1 : 0);
    }

    // ===== S1: the 15 file_module.cc:200-:242 load_config setter targets
    // on a FRESH conf (file_depth + snort_protocol_id are NEVER set there --
    // PLAN 6); every value differs from D_defaults (mutate half of 7b).
    {
        FileConfig fc;
        fc.file_type_depth = 2000;          fc.file_signature_depth = 20971520;
        fc.file_block_timeout = 172800;     fc.file_lookup_timeout = 4;
        fc.block_timeout_lookup = true;     fc.capture_memcap = 250;
        fc.capture_max_size = 2097152;      fc.capture_min_size = 4096;
        fc.capture_block_size = 65536;      fc.max_files_cached = 131072;
        fc.max_files_per_flow = 256;        fc.show_data_depth = 200;
        fc.trace_type = true;               fc.trace_signature = true;
        fc.trace_stream = true;
        int mutated = (fc.file_type_depth == 2000 && fc.file_signature_depth == 20971520
            && fc.file_block_timeout == 172800 && fc.file_lookup_timeout == 4
            && fc.block_timeout_lookup && fc.capture_memcap == 250
            && fc.capture_max_size == 2097152 && fc.capture_min_size == 4096
            && fc.capture_block_size == 65536 && fc.max_files_cached == 131072
            && fc.max_files_per_flow == 256 && fc.show_data_depth == 200
            && fc.trace_type && fc.trace_signature && fc.trace_stream) ? 1 : 0;
        std::printf("S1_load_config_setters ftd=%lld sig=%lld blk=%lld lut=%lld btl=%d "
            "cm=%lld cms=%lld cmin=%lld cbs=%lld mfc=%lld mpf=%llu sdd=%lld "
            "tt=%d tsig=%d tst=%d all_mutated=%d fdepth_untouched=%d spid_untouched=%d\n",
            (long long)fc.file_type_depth, (long long)fc.file_signature_depth,
            (long long)fc.file_block_timeout, (long long)fc.file_lookup_timeout,
            (int)fc.block_timeout_lookup,
            (long long)fc.capture_memcap, (long long)fc.capture_max_size,
            (long long)fc.capture_min_size, (long long)fc.capture_block_size,
            (long long)fc.max_files_cached, (unsigned long long)fc.max_files_per_flow,
            (long long)fc.show_data_depth,
            (int)fc.trace_type, (int)fc.trace_signature, (int)fc.trace_stream,
            mutated, fc.file_depth == 0 ? 1 : 0, fc.snort_protocol_id == 0 ? 1 : 0);
    }

    std::printf("FCONF_PROBE_DONE\n");
    return 0;
}

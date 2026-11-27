// probe.cc — row 24g DEC ladder: construct the REAL SnortConfig (the row
// .o owns the pair's EVERY non-inline body: ctor :243, the set_* family,
// merge :387-:515, verify :517, the statics :110-:112, get_static_name
// :1118, request/release_scratch :1025-:1038, the reload-id tracker
// :1073-:1080) and drive them through PUBLIC seats + the header INLINES.
// Determinism law: ZERO pointers, ZERO times — names, counts, hex masks
// only. NEVER driven: set_uid/set_gid (the getpwnam/getgrnam main-thread
// wall — witness-cited NF rows), setup()/post_setup()/generate_dump (the
// ParseRules + thread/getpid/time run face wall — the ctor/dtor legs ride
// the mirror echoes, the run face NEVER fires), the file-statics
// init_policy_mode/init_policies/generate_config_dump (cc-internal, NEVER
// callable — the policy-mode transition rides the CITE + FACE-A). NO
// [[noreturn]] leg ships in this pair (MEASURED at authoring: the row
// carries NO exit family). MERGE LAW pin: merge()'s state block (:512-:514)
// is a per-object ONCE face — NEVER merge onto a config already merged (the
// assert(!state) + state LEAK face; the walked per-pair law). The dialect
// legs (#ifdef SHELL cc :485-:504, h :79/:212/:534, cc :1102) NEVER
// compile at this posture: the cleanup_fatal_error() drive below proves
// the walked zero-gate at the vectors face (the FileService::close echo
// fires, the REG_TEST insides do NOT).
#include <cstdio>
#include <cstring>
#include <string>
#include <new>

#include "main/snort_config.h"
#include "main/policy.h"
#include "main/thread_config.h"
#include "packet_io/sfdaq_config.h"
#include "sfip/sf_cidr.h"
#include "helpers/scratch_allocator.h"
#include "log/messages.h"
#include "events/event_queue.h"
#include "filters/sfthreshold.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/detection_filter.h"

using namespace snort;

class ProbeAlloc : public ScratchAllocator
{
public:
    bool setup(SnortConfig*) override { printf("X alloc.setup\n"); return true; }
    void cleanup(SnortConfig*) override { printf("X alloc.cleanup\n"); }
    void update(SnortConfig*) override { printf("X alloc.update\n"); }
};

static SnortConfig* a = nullptr;    // the installed conf
static SnortConfig* b = nullptr;    // the command-line overlay conf

static int bit(const SnortConfig* s, RunFlag f) { return (s->run_flags & (unsigned)f) ? 1 : 0; }
static int obit(const SnortConfig* s, OutputFlag f) { return (s->output_flags & (unsigned)f) ? 1 : 0; }

int main()
{
    a = new SnortConfig();
    SnortConfig::set_conf(a);
    printf("D0 ctor run=%x out=%x warn=%x rid=%u\n", (unsigned)a->run_flags,
        (unsigned)a->output_flags, (unsigned)SnortConfig::warning_flags,
        SnortConfig::get_reload_id());

    // ---- the simple set_/get_ accessor walk (the REAL row bodies) ----
    a->set_alert_before_pass(true);
    printf("S1 abp=%d run=%x\n", (int)a->alert_before_pass(), (unsigned)a->run_flags);
    a->set_daemon(true);
    printf("S2 daemon=%d run_daemon=%d\n", (int)a->daemon_mode(), bit(a, RUN_FLAG__DAEMON));
    a->set_max_procs(23);
    printf("S3 max_procs=%u clamped=%d\n", (unsigned)a->max_procs, a->max_procs == 23 ? 0 : 1);
    a->set_watchdog(9);
    a->set_watchdog_min_thread_count(3);
    printf("S4 wd=%u wdmin=%u\n", (unsigned)a->watchdog_timer, (unsigned)a->watchdog_min_thread_count);
    a->set_umask(077);
    printf("S5 umask=%o\n", (unsigned)a->file_mask);
    a->set_dirty_pig(true);
    printf("S6 dirty_pig=%d\n", (int)a->dirty_pig);

    // ---- the output-flag mask walk (the h :88-:108 seats, REAL writers) ----
    a->set_utc(true);
    a->set_show_year(true);
    a->set_dump_payload(true);
    a->set_dump_chars_only(true);
    a->set_dump_payload_verbose(true);
    a->set_decode_data_link(true);
    a->set_no_logging_timestamps(true);
    printf("M1 out=%x utc=%d year=%d app=%d char=%d verb=%d dlink=%d nostamp=%d\n",
        (unsigned)a->output_flags, (int)a->output_use_utc(), (int)a->output_include_year(),
        (int)a->output_app_data(), (int)a->output_char_data(), (int)a->verbose_byte_dump(),
        (int)a->output_datalink(), (int)a->output_no_timestamp());
    a->set_obfuscation_mask("192.168.0.0/16");
    printf("M2 obf=%d out=%x netfam=%u netbits=%u\n", (int)a->obfuscate(),
        (unsigned)a->output_flags, (unsigned)a->obfuscation_net.get_family(),
        (unsigned)a->obfuscation_net.get_bits());
    a->set_obfuscate(false);
    printf("M3 obf=%d mask_stays_bit=%d out=%x\n", (int)a->obfuscate(),
        obit(a, OUTPUT_FLAG__OBFUSCATE), (unsigned)a->output_flags);

    // ---- the dst_mac legs (cc :664-:684; the dnet shim + the reject face) ----
    a->set_dst_mac("00:11:22:33:44:55");
    printf("G1 dst_mac set=%d b0=%02x b5=%02x\n", a->eth_dst ? 1 : 0,
        a->eth_dst ? a->eth_dst[0] : 0, a->eth_dst ? a->eth_dst[5] : 0);
    a->set_dst_mac("zz");                       // the ParseError reject face
    printf("G2 reject_keeps=%d\n", a->eth_dst ? 1 : 0);
    a->set_dst_mac(nullptr);
    printf("G3 cleared=%d\n", a->eth_dst ? 1 : 0);

    // ---- alert/log mode -> the output string + hook-identity face ----
    a->set_alert_mode("cmg");
    printf("A1M out_str=%s alerts=%d dlink=%d app=%d\n", a->output.c_str(),
        obit(a, OUTPUT_FLAG__ALERTS), obit(a, OUTPUT_FLAG__SHOW_DATA_LINK),
        obit(a, OUTPUT_FLAG__APP_DATA));
    a->set_log_mode("dump");                    // the LOG_DUMP -> LOG_CODECS face
    printf("A2M out_str=%s\n", a->output.c_str());

    // ---- tunnel_verdicts name-table + hex legs (cc :859-:909) ----
    a->set_tunnel_verdicts("gtp mpls");
    printf("T1 mask=%x gtp_bypass=%d gre_bypass=%d\n", (unsigned)a->tunnel_mask,
        (int)a->tunnel_bypass_enabled(TUNNEL_GTP), (int)a->tunnel_bypass_enabled(TUNNEL_GRE));
    a->set_tunnel_verdicts("BADproto");         // the reject face (mask UNCHANGED)
    printf("T2 mask=%x\n", (unsigned)a->tunnel_mask);

    // ---- include/plugin/script path appends + tweaks ----
    a->set_include_path("/inc");
    a->add_plugin_path("p1");
    a->add_plugin_path("p2");                   // the ':' concat face
    a->add_script_path("s1");
    a->add_script_path("s2");
    a->set_tweaks("t42");
    printf("P1 inc=%s plug=%s scripts=%zu tweaks=%s\n", a->include_path.c_str(),
        a->plugin_path.c_str(), a->script_paths.size(), a->tweaks.c_str());

    // ---- the merged-in conf (b) — the per-pair merge law (ONCE) ----
    b = new SnortConfig();
    b->set_run_flags(RUN_FLAG__PAUSE);
    b->set_run_flags(RUN_FLAG__PROCESS_ALL_EVENTS);
    b->pkt_cnt = 11; b->pkt_skip = 3; b->pkt_pause_cnt = 5;
    b->id_offset = 7; b->event_log_id = 2;
    b->id_subdir = true; b->id_zero = true;
    b->include_path = "/inc2"; b->run_prefix = "pfx"; b->stdin_rules = true;
    b->chroot_dir = "/ch"; b->bpf_filter = "inbound"; b->metadata_filter = "mf";
    b->log_dir.clear();                         // the DEFAULT_LOG_DIR fallback :507
    b->daq_config->set_batch_size(37); b->daq_config->set_mru_size(1400);
    b->policy_map->get_network_policy()->checksum_eval = CHECKSUM_FLAG__IP;
    a->event_queue_config = new EventQueueConfig{};
    a->threshold_config = new ThresholdConfig{};
    a->rate_filter_config = new RateFilterConfig();
    a->detection_filter_config = new DetectionFilterConfig{};
    b->set_umask(0);                            // the zero-guard face (:430)
    ThreadConfig::set_instance_max(3);
    unsigned run_before = a->run_flags, out_before = a->output_flags;
    a->merge(b);
    printf("V1 run %x|%x out %x|%x pause=%d pae=%d\n", run_before, (unsigned)a->run_flags,
        out_before, (unsigned)a->output_flags, bit(a, RUN_FLAG__PAUSE),
        (int)a->event_queue_config->process_all_events);
    printf("V2 logdir=%s orig=%s umask_kept=%o pkt=%llu skip=%llu pause_cnt=%llu imax_slots=%u\n",
        a->log_dir.c_str(), a->orig_log_dir.c_str(), (unsigned)a->file_mask,
        (unsigned long long)a->pkt_cnt, (unsigned long long)a->pkt_skip,
        (unsigned long long)a->pkt_pause_cnt, (unsigned)a->num_slots);
    printf("V3 cksum_eval=%x cksum_drop=%x chroot=%s bpf=%s mf=%s off=%o\n",
        (unsigned)a->policy_map->get_network_policy(0)->checksum_eval,
        (unsigned)a->policy_map->get_network_policy(0)->checksum_drop,
        a->chroot_dir.c_str(), a->bpf_filter.c_str(), a->metadata_filter.c_str(),
        (unsigned)a->offload_threads);
    a->post_setup();                            // EMPTY scratchers face (num_slots=3)
    printf("V4 scratchers=%zu slots=%u\n", a->scratchers.size(), (unsigned)a->num_slots);

    // ---- the get_conf-===-this verify() self-face (row :517-:565) ----
    printf("VFY ok=%d\n", (int)a->verify());

    // ---- the static logging/warning flag legs (h :732-:769 + cc :110-:112) ----
    SnortConfig::enable_log_syslog();
    SnortConfig::enable_log_verbose();
    printf("LG syslog=%d verbose=%d quiet0=%d\n", (int)SnortConfig::log_syslog(),
        (int)SnortConfig::log_verbose(), (int)SnortConfig::log_quiet());
    SnortConfig::set_log_quiet(true);
    printf("LQ quiet=%d\n", (int)SnortConfig::log_quiet());
    {
        SnortConfig::ScopedLogQuietBypass bypass;
        printf("LQ2 bypassed=%d\n", (int)SnortConfig::log_quiet());
    }
    printf("LQ3 restored=%d\n", (int)SnortConfig::log_quiet());
    SnortConfig::warning_flags |= 0x08;
    printf("WF warn=%x\n", (unsigned)SnortConfig::warning_flags);

    // ---- the reload-id tracker walk (ctor update_reload_id :1076-:1080) ----
    SnortConfig* c = new SnortConfig();          // the 3rd ctor tick
    printf("R1 rid_a=%u\n", SnortConfig::get_reload_id());
    SnortConfig::set_conf(c);
    printf("R2 rid_c=%u same_obj=%d\n", SnortConfig::get_reload_id(),
        SnortConfig::get_main_conf() == c ? 1 : 0);
    c->update_reload_id();
    printf("R3 rid_c2=%u\n", SnortConfig::get_reload_id());
    SnortConfig::set_conf(a);

    // ---- the get_static_name intern-identity legs (cc :1118-:1126) ----
    const char* n1 = SnortConfig::get_static_name("gamma");
    const char* n2 = SnortConfig::get_static_name("gamma");
    const char* n3 = SnortConfig::get_static_name("delta");
    printf("INT same=%d diff=%d n1=%s n3=%s\n", strcmp(n1, n2) == 0 ? 1 : 0,
        strcmp(n1, n3) == 0 ? 1 : 0, n1, n3);

    // ---- the request_scratch/release_scratch seats (cc :1025-:1038) ----
    ProbeAlloc pa;
    int s0 = SnortConfig::request_scratch(&pa);
    int s1 = SnortConfig::request_scratch(&pa);
    printf("SC s0=%d s1=%d\n", s0, s1);
    SnortConfig::release_scratch(s0);           // the null-out face
    a->update_scratch(nullptr);                 // ACScratchUpdate + broadcast (vtable face)
    printf("SC2 done\n");

    // ---- the cited-NEVER-driven walls (the walked face, NEVER fired) ----
    // NF: set_uid/set_gid (the getpwnam/getgrnam main-thread wall, cc :734-:799)
    // NF: setup()/post_setup-full (the ParseRules + OrderRuleLists wall :335-:367)
    // NF: generate_dump (the thread + getpid/time run face :211-:233/:1082-:1094)
    // NF: init_policy_mode (the cc-file-static, NEVER callable — FACE-A cites)
    printf("NF set_uid noreturn-false cited wall\n");
    printf("NF set_gid cited wall\n");
    printf("NF setup cited parse wall\n");
    printf("NF generate_dump cited thread wall\n");

    // ---- the cleanup face proves the zero-gate (cc :1096-:1113): the
    // FileService::close echo fires, the #ifdef REG_TEST insides NEVER do ----
    a->cleanup_fatal_error();
    printf("CL done\n");

    // ---- teardown (the dtor twin W-blocks, ONCE per object) ----
    SnortConfig::set_conf(nullptr);
    delete c;
    delete b;
    delete a;
    printf("fin=PASS\n");
    return 0;
}

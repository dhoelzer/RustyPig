// probe.cc (row 24a): drives the CLI-assembly row .o through the DEC order
// ladder. Captures are MIRROR rec() legs (order = the ground call order); the
// row statics are NEVER copied (read-only census via the public faces).
// stdout unbuffered; the mirror banners ride stderr so the stdout census is
// deterministic across -O0/-O2.
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "main.h"
#include <cstdio>
#include <string>
#include <vector>

using namespace snort;

extern std::vector<std::string> g_probe_trace;
extern bool exit_requested;
void probe_reset_trace();
void probe_set_verify(bool);

static void clear() { g_probe_trace.clear(); }
static std::string legs()
{
    std::string s;
    for (size_t i = 0; i < g_probe_trace.size(); ++i)
    { if (i) s += "|"; s += g_probe_trace[i]; }
    return s;
}
static int idx(const char* name)
{
    for (size_t i = 0; i < g_probe_trace.size(); ++i)
        if (g_probe_trace[i] == name) return (int)i;
    return -1;
}

static int hook_a = 0, hook_b = 0;
static void fa() { ++hook_a; g_probe_trace.emplace_back("hookA"); }
static void fb() { ++hook_b; g_probe_trace.emplace_back("hookB"); }

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    // D0 cold census (row statics BEFORE any boot): process_id 0, the three
    // file-static bools false, the ::exit_requested extern false.
    std::printf("D0 pid=%u exiting=%d reloading=%d dropped=%d exit_req=%d\n",
        Snort::get_process_id(), (int)Snort::is_exiting(), (int)Snort::is_reloading(),
        (int)Snort::has_dropped_privileges(), (int)Snort::exit_requested());

    // D1 the init-order ladder through the REAL row setup() (:603-:645):
    // set_main_thread -> OpenLogger -> init() ladder legs -> daemonize leg
    // (mode face) -> qexit(FALSE) -> TimeStart. Index faces pin the ORDER.
    clear();
    char* av[] = { (char*)"synth" };
    Snort::setup(1, av);
    std::printf("D1 n=%d mthread=%d sig=%d parse=%d sfinit=%d qfalse=%d getmod=%d daemon=%d\n",
        (int)g_probe_trace.size(), idx("proc.set_main_thread"), idx("proc.init_signals"),
        idx("parse_cmd_line"), idx("sf-daq.init"), idx("proc.qexit-false"),
        idx("pl.get_module"), idx("proc.daemonize"));
    std::printf("D1L %s\n", legs().c_str());
    std::printf("D1P exiting=%d reloading=%d dropped=%d\n",
        (int)Snort::is_exiting(), (int)Snort::is_reloading(), (int)Snort::has_dropped_privileges());

    // D2 the init_process_id CEIL ladder (the :410-:417 face) re-driven
    // probe-side through the REAL row fns + the storage-backed ThreadConfig
    // mirror: max=4 -> offsets 0/5/9/13/12 = 1/2/3/4/3; the :608-tail
    // restore face max=1 offset=0 -> pid 1.
    {
        SnortConfig* sc = const_cast<SnortConfig*>(SnortConfig::get_conf());
        ThreadConfig::set_instance_max(4);
        sc->id_offset = 0;  Snort::init_process_id(); unsigned p1 = Snort::get_process_id();
        sc->id_offset = 5;  Snort::init_process_id(); unsigned p2 = Snort::get_process_id();
        sc->id_offset = 9;  Snort::init_process_id(); unsigned p3 = Snort::get_process_id();
        sc->id_offset = 13; Snort::init_process_id(); unsigned p4 = Snort::get_process_id();
        sc->id_offset = 12; Snort::init_process_id(); unsigned p5 = Snort::get_process_id();
        ThreadConfig::set_instance_max(1);
        sc->id_offset = 0;  Snort::init_process_id(); unsigned p6 = Snort::get_process_id();
        std::printf("D2 m4=%u,%u,%u,%u m4o12=%u restore=%u\n", p1, p2, p3, p4, p5, p6);
    }

    // D3 drop_privileges default posture: empty chroot + uid/gid -1 -> the
    // EnterChroot/SetUidGid legs SKIPPED, ZERO legs, privileges_dropped flips.
    clear();
    bool dp = Snort::drop_privileges();
    std::printf("D3 dp=%d dropped=%d legs=%zu\n", dp, (int)Snort::has_dropped_privileges(), g_probe_trace.size());

    // D4 do_pidfile: default run_flags face -> ZERO CreatePidFile legs across
    // TWO calls; set_create_pid_file(true) -> EXACTLY-1 across TWO calls
    // (the fn-local pid_file_created once-face :295).
    clear();
    Snort::do_pidfile(); Snort::do_pidfile();
    size_t cold = g_probe_trace.size();
    const_cast<SnortConfig*>(SnortConfig::get_conf())->run_flags |= 0x40;  // RUN_FLAG__CREATE_PID_FILE (h :54)
    Snort::do_pidfile(); Snort::do_pidfile();
    std::printf("D4 cold=%zu created=%zu\n", cold, g_probe_trace.size() - cold);

    // D5 get_reload_config SUCCESS ladder (verify TRUE; the reload legs +
    // the icd.clear_ips_id leg from prepare_reload BEFORE it).
    clear();
    probe_set_verify(true);
    Snort::prepare_reload();
    SnortConfig* rc = Snort::get_reload_config("synth.conf");
    std::printf("D5 nonnull=%d reloading=%d icd=%d setconf=%d\n",
        rc != nullptr, (int)Snort::is_reloading(), idx("icd.clear_ips_id"),
        idx("sc.set_conf"));
    std::printf("D5L %s\n", legs().c_str());

    // D6 get_reload_config FAILURE ladder (verify flips FALSE -> the
    // reload_failure_cleanup legs (parser_term + set_default_policy +
    // abort_map) + nullptr + reloading cleared to false).
    clear();
    probe_set_verify(false);
    SnortConfig* rf = Snort::get_reload_config("other.conf");
    std::printf("D6 nonnull=%d reloading=%d abort=%d sdp=%d\n",
        rf != nullptr, (int)Snort::is_reloading(), idx("insp.abort_map"),
        idx("set_default_policy"));
    std::printf("D6L %s\n", legs().c_str());
    probe_set_verify(true);

    // D7 the exit_requested extern RIDE (main.h :24 -> the row :404 face).
    exit_requested = true;
    std::printf("D7 %d\n", (int)Snort::exit_requested());
    exit_requested = false;

    // D8 the shutdown-hook ladder: push_front REVERSE order (add fa then fb
    // -> fb runs FIRST); the hooks run INSIDE term() (call_shutdown_hooks
    // sits after FileService::close, before HostAttributesManager::term —
    // the :359-:363 order face); the SECOND setup->term NEVER re-runs the
    // hooks (the list was cleared).
    clear(); hook_a = hook_b = 0;
    Snort::add_shutdown_hook(fa);
    Snort::add_shutdown_hook(fb);
    Snort::cleanup();   // the PUBLIC door: cleanup -> clean_exit(0) -> term()
    int h0 = idx("hookB"), h1 = idx("hookA");
    std::printf("D8 hookA=%d hookB=%d b_first=%d bidx=%d aidx=%d fs=%d\n",
        hook_a, hook_b, (int)(h0 >= 0 && h1 >= 0 && h0 < h1), h0, h1,
        idx("fs.close"));
    std::printf("D8L %s\n", legs().c_str());

    // D9 term RE-ENTRY guard: already_exiting true -> ZERO new legs, hooks
    // NEVER re-run, exiting stays true.
    clear();
    Snort::cleanup();   // the cleanup-body legs re-run (6); the term()-body
                        // NEVER does (the already_exiting guard face)
    std::printf("D9 legs=%zu exiting=%d sfterm=%d close=%d\n", g_probe_trace.size(),
        (int)Snort::is_exiting(), idx("sf-daq.term"), idx("log.close_logger"));

    std::printf("Z terminator=0\n");
    return 0;
}

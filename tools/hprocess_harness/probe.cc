// probe.cc (row 24b): drives the signal/privilege row .o through the DEC
// order + face ladder. Captures are MIRROR rec() legs (order = the ground
// call order); the row statics are NEVER copied — the sig-ring census rides
// the PUBLIC faces (get_pending_signal / get_signal_name). The suicide legs
// (the exit-pronto printer + the oops re-raise) ride the fork+exec face:
// the re-exec'd helper binary prints the captured printer/signal lines to
// stdout; the parent NEVER dies (deterministic, -O0 == -O2).
// stdout unbuffered; mirror banners ride stderr so the stdout census stays
// deterministic. The family law: the row-name NEVER rides this file joined
// (proc-pair in comments).
#include "main/process.h"
#include "main/snort_config.h"
#include "main.h"
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace snort;

extern std::vector<std::string> g_probe_trace;
extern snort::SnortConfig* g_probe_conf;
extern unsigned g_log_count;
extern int g_pcre2_rc;
void probe_reset_trace();
const char* probe_legs();

static void clear() { g_probe_trace.clear(); }
static std::string legs()
{
    std::string s = probe_legs();
    for (size_t i = 0; i < g_probe_trace.size(); ++i)
        if (g_probe_trace[i] == "FatalError") return "FATAL";
    return s;
}

static char g_exe[4096] = { 0 };

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    // the re-exec path face: /proc/self/exe (the D14 chdir legs MOVE the
    // CWD — a relative helper path would miss; the honest harness face):
    ssize_t el = readlink("/proc/self/exe", g_exe, sizeof g_exe - 1);
    if (el > 0) g_exe[el] = 0;

    // the suicide helper face: re-exec this binary with the helper arg; the
    // parent captures the helper's stdout through popen (the row's OWN
    // code writes there: the SigSafePrinter banner + the re-raised death).
    if (argc > 1 && std::strcmp(argv[1], "--helper") == 0)
    {
        if (std::strcmp(argv[2], "pronto") == 0)
        {
            set_quick_exit(true);                    // cc :167 face
            init_signals();                          // installs exit_handler
            raise(SIGTERM);                          // exit_handler: pronto leg
            std::printf("H1 unreachable=1\n");       // NEVER prints (the _exit(0) face)
            return 3;
        }
        if (std::strcmp(argv[2], "oops") == 0)
        {
            install_oops_handler();                  // cc :424
            raise(SIGSEGV);                          // oops_handler: restore ->
            std::fprintf(stderr, "H2 unreachable=1\n"); // banner -> raise (death)
            return 3;
        }
        return 2;
    }

    // the conf boot leg (the subset rider face, the 22a tc / 24a precedent:
    // a REAL subset-ctor conf in the slot so get_main_conf legs deref):
    g_probe_conf = new SnortConfig("");

    // the popen-child disposition law (the honest harness rider face): the
    // in-proc SIGCHLD seats installed by the ladders MUST ride SIG_DFL so
    // a popen/fork child NEVER inherits a trap that deadlocks the wait:
    signal(SIGCHLD, SIG_DFL);

    clear();

    // D0 cold names census (the pig_sig_names table through the PUBLIC face:
    // all 8 + the error leg + the PIG_SIG_MAX boundary):
    for (int i = PIG_SIG_NONE; i <= PIG_SIG_MAX; ++i)
        std::printf("D0 %d %s\n", i, get_signal_name((PigSignal)i));

    // D1 cold ring census (sig_ring(4) face BEFORE any put: drained -> NONE):
    std::printf("D1 drained=%d\n", get_pending_signal() == PIG_SIG_NONE);

    // D2 the signal->ring mapping face: non-pronto exits push the PigSignal,
    // the dirty leg flags the conf first (the exit_pronto=false window):
    set_quick_exit(false);                            // cc :167 b=false
    clear();
    init_signals();                                   // cc :460 (oops + handlers)
    std::printf("D2 initlegs=%s\n", legs().c_str());
    clear();
    raise(SIGINT);   std::printf("D3 int=%d\n", get_pending_signal() == PIG_SIG_INT);
    raise(SIGTERM);  std::printf("D3 term=%d\n", get_pending_signal() == PIG_SIG_TERM);
    clear();
    raise(SIGQUIT);
    std::printf("D4 quit=%s dirty=%d ring=%d\n", legs().c_str(),
        (int)SnortConfig::get_main_conf()->dirty_pig,
        get_pending_signal() == PIG_SIG_QUIT);

    // D5 the ring(4) WRAP face (MEASURED face: RingLogic starts rx=0/wx=1
    // + the rx-cell is dead + the write guard next(wx)==rx -> capacity is
    // sz-2 = EXACTLY-2 slots of the 4): 4 raises push 2, DROP 2; the
    // drains ride SEQUENCED locals (one mutator per statement — NEVER four
    // get() legs inside one printf: the unsequenced face would eat the
    // ring):
    clear();
    int r1 = raise(SIGUSR1);                          // dump-stats push
    int r2 = raise(SIGUSR2);                          // rotate-stats push
    int r3 = raise(SIGHUP);                           // reload-config push -> FULL drop
    int r4 = raise(SIGURG);                           // reload-attrs push -> FULL drop
    int e1 = (get_pending_signal() == PIG_SIG_DUMP_STATS);
    int e2 = (get_pending_signal() == PIG_SIG_ROTATE_STATS);
    int e3 = (get_pending_signal() == PIG_SIG_NONE);
    int e4 = (get_pending_signal() == PIG_SIG_NONE);
    int e5 = (get_pending_signal() == PIG_SIG_NONE);
    std::printf("D5 raises=%d%d%d%d drained=%d,%d,%d,%d empty=%d\n",
        r1, r2, r3, r4, e1, e2, e3, e4, e5);

    clear();
    raise(SIGWINCH);                                  // default: -> return leg
    std::printf("D6 unhandled-drained=%d trace_empty=%d\n",
        get_pending_signal() == PIG_SIG_NONE, (int)g_probe_trace.empty());

    // D7 the help census (help(): the markup item leg fires EXACTLY-7 per
    // the ground help_signals face — counted through the witness rec):
    clear();
    help_signals();
    std::printf("D7 items=%zu\n", g_probe_trace.size());

    // D8 the banner face over the DECL riders (DisplayBanner: the pcre2
    // ok-leg + the LogMessage version-line census):
    clear();
    g_log_count = 0;
    int banner = DisplayBanner();
    std::printf("D8 banner_rc=%d log_lines=%u legs=%s\n", banner, g_log_count, legs().c_str());

    // D9 the pcre2 abort pre-arm is NEVER driven IN-PROCESS (the ground
    // cc :662 abort leg); the FATAL posture face rides the helper-free
    // arms below instead — the honest D9: no drive, the arm is witness-
    // closed (measured separately via the g_pcre2_rc flip = ZERO arms).
    std::printf("D9 pcre2_arm=undriven abort_face=find-0\n");

    // D10 the gmt2local face (TZ-pinned leg ONLY — the machine TZ NEVER
    // rides the seed: the pinned date lands inside EST, offset -18000):
    std::printf("D10 gmt2local=-18000 got=%d match=%d\n", gmt2local(1609459200),
        gmt2local(1609459200) == -18000);

    // D11 read_infile face (real-temp-file leg via the /tmp pid-jail seat):
    {
        const char* f = "/tmp/row24b_jail_infile.txt";
        FILE* fp = std::fopen(f, "w");
        std::fprintf(fp, "ip and tcp");
        std::fclose(fp);
        std::string s = read_infile("bpf-filter", f);
        std::printf("D11 read=%zd content=%d unlink=%d\n", s.size(),
            s == "ip and tcp", unlink(f) == 0);
    }

    // D11b the fatal-posture face NOT driven (the snort-free arms): the
    // read_infile open-fail leg rides the ErrorMessage (non-fatal):
    clear();
    std::string bad = read_infile("bpf-filter", "/nonexistent-row24b-jail");
    std::printf("D11b miss_empty=%d recs=%s\n", (int)bad.empty(), legs().c_str());

    // D12 the pid-file once-face over the /tmp jail (the .lck lock + the
    // PID-content + the ClosePidFile face):
    {
        SnortConfig* sc = SnortConfig::get_main_conf();
        sc->log_dir = "/tmp/row24b_jail";
        sc->pid_filename = "row24b.pid";
        mkdir("/tmp/row24b_jail", 0755);
        CreatePidFile(987654);
        FILE* fp = std::fopen("/tmp/row24b_jail/row24b.pid", "r");
        char buf[16] = { };
        size_t rd = fp ? std::fread(buf, 1, sizeof buf - 1, fp) : 0;
        if (fp) std::fclose(fp);
        std::printf("D12 pidfile_content=%d unlink=%d\n",
            rd && std::strcmp(buf, "987654\n") == 0,
            unlink("/tmp/row24b_jail/row24b.pid") == 0);
        unlink("/tmp/row24b_jail/row24b.pid.lck");
        rmdir("/tmp/row24b_jail");
        ClosePidFile();
    }

    // D13 the SetUidGid no-op arms (root-only faces NEVER driven — the uid
    // -1/-1 early-return + honest bank; the real-drop leg is host-bound):
    {
        bool a = SetUidGid(-1, -1);                   // both -1 -> true
        std::printf("D13 noop_true=%d drop_legs=uid-boundary-faces-only\n", (int)a);
        // boundary face: an INVALID uid set under uid-10000 MUST die false:
        bool b = SetUidGid(-2, -1);
        std::printf("D13 inval_got=%d false_face=%d\n", (int)b, (int)(!b));
    }

    // D14 the EnterChroot false legs (the parse-error arms BEFORE the jail
    // faces — non-root safe; the chroot-success legs NEVER reachable HERE):
    {
        SnortConfig* sc = SnortConfig::get_main_conf();
        std::string ld;
        clear();
        bool e1 = EnterChroot("/nonexistent-row24b-jail", ld);   // empty log_dir
        std::printf("D14 empty_false=%d recs=%s\n", (int)e1, legs().c_str());
        clear();
        ld = "/opt";
        bool e2 = EnterChroot("/tmp", ld);            // log dir OUTSIDE the jail
        std::printf("D14 outside_false=%d recs=%s\n", (int)e2, legs().c_str());
    }

    // D15 the daemonize once-guard face (the getppid()==1 early-return):
    // as an init child ppid==1 (the rc0 leg, ZERO forks — the process-
    // re-parent boundary face, NEVER a real fork on live CI):
    {
        // honest face: only the EARLY-RETURN arm is host-bound; NOT driven
        // (pid 1 never exists HERE as parent). Bank find-0 on the fork arm.
        std::printf("D15 daemon_once=undriven fork-arm=bound\n");
    }

    // D16 the helper-arms face (the suicide legs OUT OF PROC):
    {
        std::string cmd = std::string(g_exe) + " --helper pronto 2>/dev/null";
        FILE* p1 = popen(cmd.c_str(), "r");
        char buf[512]; size_t n = p1 ? std::fread(buf, 1, sizeof buf - 1, p1) : 0;
        if (p1) pclose(p1);
        if (n) buf[n] = 0;
        // (the size face NEVER prints: the oops banner embeds the PID
        // digit face -> a byte-count would make the seed PID-dependent;
        // the substring faces below are the stable census):
        std::printf("H1 pronto=%d exit0-line=%d\n",
            std::strstr(buf, "==> caught term signal, exiting") != nullptr,
            std::strstr(buf, "unreachable") == nullptr);
        // the oops banner rides the fd-2 WRITE face (raw write(2), NO stdio
        // buffer) — 2>&1 captures the death banner + the shell's death line;
        // the helper NEVER reaches its stderr tripwire print (the raise law):
        cmd = std::string(g_exe) + " --helper oops 2>&1";
        FILE* p2 = popen(cmd.c_str(), "r");
        n = p2 ? std::fread(buf, 1, sizeof buf - 1, p2) : 0;
        if (p2) pclose(p2);
        if (n) buf[n] = 0;
        std::printf("H2 oops-banner=%d segv-name=%d unreachable=%d\n",
            std::strstr(buf, "Snort (PID ") != nullptr && std::strstr(buf, "caught fatal signal") != nullptr,
            std::strstr(buf, "SIGSEGV (11)") != nullptr,
            std::strstr(buf, "unreachable") == nullptr);
    }

    // term_signals census: restore legs (non-printing, the trace stays clean
    // — the honest ZERO-rec face of the restore ladder):
    clear();
    term_signals();
    std::printf("D17 term_clean=%d\n", (int)g_probe_trace.empty());

    // the FatalError->Err cited law proof stays on the Rust side; the C side
    // D9/D15 undriven arms keep the honest faces above.
    return 0;
}

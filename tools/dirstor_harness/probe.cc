// row-23d probe.cc — THE DEC session for the helpers/directory + packet_io/
// trough two-pair (113+49 / 265+88 @ fe29cbe FRESH cps, md5s e0e4af65/
// f7eac140/c9aa106b/7931b6ef; cmp-proved in build.sh). BOTH .cc compile
// VERBATIM against the glibc faces (fnmatch/stat/dirent — ZERO SDK pulls).
// The link carries the REAL bodies: dir.o + trough.o (THE row homes — the
// file_count B-definition rides trough.o, the ONE home) + util.o
// (get_error, the landed-Rust-home glibc face). witness_dirstor.cc MIRRORS
// ONLY the NOT-landed snort homes: ErrorMessage (OWN-1 CAPTURE mirror —
// the trough error legs' messages) + the inert LogMessage (the util.o
// pull, one home per link). FatalError rides the carried witness_conf
// 4dd91018 family + the 23b noreturn jump rider — the probe ARMS
// fatal_jump/fatal_jump_armed and RE-ENTERS after each FatalError leg
// (the jump-site rider driven LIVE; the C FatalError NEVER returns, the
// port's Err(()) deviation is replayed Rust-side by the parity twin).
// THE fatal legs run in FORK-ed children (the C object_list survives a
// fatal leg — setup NEVER reaches :227 — so a parent-side fatal would
// contaminate EVERY later get_pcaps; the children inherit the LAST clean
// parent state + exit, the parent's statics stay un-contaminated: the
// honest per-leg isolation, pinned in PLAN.md). THE stderr-silent law:
// every fatal leg runs behind a dup2(/dev/null) swap — the witness
// FatalError's "FATAL: ..." stderr text belongs to the carried family,
// NEVER to this probe's receipts (DEC stderr stays EMPTY).
// argv[1] = the walk-tree root (build.sh passes "$H"/walk, REBUILT every
// run — the tree NEVER tracked). C++ eval-order law: mutating calls
// hoisted into locals BEFORE every printf.
#include "helpers/directory.h"        // THE row pair #1 (FRESH cp)
#include "packet_io/trough.h"         // THE row pair #2 (FRESH cp)
#include <csetjmp>                    // the jump-site arm (the 23b rider)
#include <limits.h>                   // PATH_MAX (the D5 guard face)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <algorithm>

// witness knobs (definitions live in witness_dirstor.cc; externs ONLY):
namespace snort {
extern char wmsg_buf[4096]; extern unsigned wmsg_calls;
}
// the carried witness_conf + the 23b rider jump sites (GLOBAL scope):
extern sigjmp_buf fatal_jump; extern bool fatal_jump_armed;

static std::string W;                 // argv[1] + "/"

static void mk(const std::string& p, const char* body) {
    FILE* f = fopen(p.c_str(), "w");
    if (f) { fputs(body, f); fclose(f); }
}
static void mkdirp(const std::string& p) { mkdir(p.c_str(), 0755); }
static void rmrf(const std::string& p) {
    std::string c = "rm -rf '" + p + "'"; int rc = system(c.c_str()); (void)rc;
}

static std::vector<std::string> walk(Directory& d) {
    std::vector<std::string> out;
    const char* s;
    while ((s = d.next())) out.push_back(s);
    std::sort(out.begin(), out.end());   // readdir order is fs-order; the
                                         // sorted SET is the pinned face
    return out;
}
static std::string join(const std::vector<std::string>& v) {
    std::string s;
    for (size_t i = 0; i < v.size(); i++) { if (i) s += ","; s += v[i]; }
    return s;
}

// fatal driver: stderr muted + jump armed; 1 == FatalError long-jumped.
static int try_fatal(void (*body)()) {
    fflush(stderr);
    int saved = dup(2);
    int null_fd = open("/dev/null", O_WRONLY);
    dup2(null_fd, 2); close(null_fd);
    int jumped = 0;
    fatal_jump_armed = true;
    if (sigsetjmp(fatal_jump, 1) == 0) {
        body();
        fatal_jump_armed = false;
    } else {
        jumped = 1;
        fatal_jump_armed = false;
    }
    fflush(stderr);
    dup2(saved, 2); close(saved);
    return jumped;
}

// the scripted fatal leg (file-static script CELLS — the probe's own
// script face, NEVER the row code): type + arg, then add_source + setup.
static int t_leg_type; static std::string t_leg_arg;
static void leg_body() {
    Trough::add_source((Trough::SourceType)t_leg_type, t_leg_arg.c_str());
    Trough::setup();
}

// run a fatal leg in a fork-ed child (the contamination law above); the
// child first CLEANS the inherited statics (cleanup + clear_file_count +
// set_filter(NONE) — the deterministic per-leg state face), prints its
// OWN captured face + the live queue at the jump site (C's partial
// queue-append side effects SURVIVE the long-jump — the honest
// get_pcaps-before-:221 state), the parent's statics stay clean.
static void fatal_leg(const char* tag, int type, const std::string& arg) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        Trough::cleanup(); Trough::clear_file_count(); Trough::set_filter(nullptr);
        t_leg_type = type; t_leg_arg = arg;
        int jumped = try_fatal(leg_body);
        unsigned q = Trough::get_queue_size();
        std::string last = snort::wmsg_buf;
        if (!last.empty() && last.back() == '\n') last.pop_back();  // the
            // format-string \n face; the capture itself keeps it (the vectors
            // face stays ONE physical line per leg -- cited law)
        printf("F %s jumped=%d msgs=%u q=%u last=[%s]\n",
               tag, jumped, snort::wmsg_calls, q, last.c_str());
        fflush(stdout);
        _exit(0);
    }
    int st = 0; waitpid(pid, &st, 0);
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stdout, "usage: probe <walk-root>\n"); return 2; }
    W = std::string(argv[1]);
    rmrf(W); mkdirp(W);
    const std::string root = W + "/root";
    mkdirp(root);
    mk(root + "/a.pcap", "a"); mk(root + "/b.cap", "b"); mk(root + "/zz.txt", "z");
    mk(root + "/.hidden", "h");
    mk(W + "/fileA.pcap", "A"); mk(W + "/fileB.cap", "B");
    mkdirp(root + "/sub1"); mk(root + "/sub1/d1.pcap", "d1"); mkdirp(root + "/sub1/deeper"); mk(root + "/sub1/deeper/e1.cap", "e1"); mk(root + "/sub1/d2.txt", "d2");
    mkfifo((root + "/fifo1").c_str(), 0644);
    symlink((W + "/gone.pcap").c_str(), (root + "/link_missing").c_str());

    // ---- D0 opendir errno faces (directory.cc :41) ----
    Directory noent("/no/such/dir-at-all-23d");
    int d0err = noent.error_on_open();               // ENOENT (2)
    Directory notdir((W + "/fileA.pcap").c_str());
    int d0b = notdir.error_on_open();                // ENOTDIR (20)
    printf("D0 noent=%d notdir=%d\n", d0err, d0b);

    // ---- D1 root walk, NO filter: dot skip :86, FIFO skip :101,
    // dangling-symlink stat skip :93, recursion :96-:99 ----
    Directory r1(root.c_str());
    std::vector<std::string> v1 = walk(r1);
    printf("D1 n=%zu set=%s\n", v1.size(), join(v1).c_str());

    // ---- D2 filter '*.cap' (the d_name fnmatch face :105) ----
    Directory r2(root.c_str(), "*.cap");
    std::vector<std::string> v2 = walk(r2);
    printf("D2 n=%zu set=%s\n", v2.size(), join(v2).c_str());

    // ---- D3 class filter 'd[12]*.pcap' ([...] classes) ----
    Directory r3(root.c_str(), "d[12]*.pcap");
    std::vector<std::string> v3 = walk(r3);
    printf("D3 n=%zu set=%s\n", v3.size(), join(v3).c_str());

    // ---- D4 the rewind face (:58-:65 rewinddir + sub delete) ----
    r1.rewind();
    std::vector<std::string> v4 = walk(r1);
    int d4same = (v4 == v1);
    printf("D4 n=%zu same=%d\n", v4.size(), d4same);

    // ---- D5 the PATH_MAX-1 guard LEG (:93): a 255-byte name chain —
    // the walk reports the caps under the depth Linux still resolves and
    // NEVER touches over-length paths (all lengths fixed at build =>
    // deterministic) ----
    const std::string chain = W + "/chain";
    mkdirp(chain);
    {
        std::string seg(255, 'x'); std::string p = chain;
        for (int i = 0; i < 20; i++) { p += "/" + seg; mkdirp(p); mk(p + "/f.cap", "f"); }
    }
    Directory rc5(chain.c_str(), "*.cap");
    std::vector<std::string> v5 = walk(rc5);
    size_t maxlen = 0;
    for (size_t i = 0; i < v5.size(); i++) if (v5[i].size() > maxlen) maxlen = v5[i].size();
    printf("D5 reported=%zu maxlen=%zu over=%d\n", v5.size(), maxlen,
           (int)(maxlen > PATH_MAX - 1));
    rmrf(chain);

    // ---- T0 THE DEFAULT-FILTER face, statics UNTOUCHED: pcap_filter
    // "*.*cap*" (cc :41) rides add_source's CURRENT-filter copy (:203) ->
    // SOURCE_DIR filters d_names through the Directory: b.cap + e1.cap
    // ONLY ('.cap' substring face — a.pcap/d1.pcap NEVER match) ----
    Trough::add_source(Trough::SOURCE_DIR, root.c_str());
    Trough::setup();                                  // :231 clears the filter NOW
    unsigned tq0 = Trough::get_queue_size();
    std::vector<std::string> t0w;
    while (Trough::has_next()) { const char* g = Trough::get_next(); if (!g) break; t0w.push_back(std::string(g).substr(root.size())); }
    printf("T0 q=%u walk=%s\n", tq0, join(t0w).c_str());

    // ---- T1 SOURCE_LIST + the '-' bypass (:146) + THE LOOP-WRAP arm
    // (:251-:255 loop_count 2) + THE file_count bump (:257) ----
    Trough::cleanup(); Trough::clear_file_count();
    Trough::add_source(Trough::SOURCE_LIST, (W + "/fileA.pcap " + W + "/fileB.cap -").c_str());
    Trough::setup();
    Trough::set_loop_count(2);
    std::string seq; unsigned surfaced = 0;
    while (Trough::has_next()) {
        const char* g = Trough::get_next();
        if (!g) break;
        std::string base(g); size_t slash = base.find_last_of('/');
        seq += (surfaced ? "," : ""); seq += (slash == std::string::npos ? base : base.substr(slash + 1));
        surfaced++;
    }
    unsigned t1fc = Trough::get_file_count();
    unsigned t1loop = Trough::get_loop_count();
    printf("T1 n=%u fc=%u loop=%u seq=%s\n", surfaced, t1fc, t1loop, seq.c_str());

    // ---- T2 the cleanup face (:237) — fc SURVIVES; clear is the :52 face ----
    Trough::cleanup(); Trough::clear_file_count();
    Trough::add_source(Trough::SOURCE_LIST, (W + "/fileA.pcap").c_str());
    Trough::setup();
    {
        const char* g = Trough::get_next();
        int got = g ? 1 : 0;
        unsigned fc_before = Trough::get_file_count();
        Trough::cleanup();
        int has = Trough::has_next() ? 1 : 0;
        unsigned fc_after = Trough::get_file_count();
        Trough::clear_file_count();
        unsigned fc_cleared = Trough::get_file_count();
        printf("T2 got=%d fc=%u,%u has_next=%d cleared=%u\n", got, fc_before, fc_after, has, fc_cleared);
    }

    // ---- T3 SOURCE_DIR with the filter ALREADY CLEARED (:231 face): the
    // tmp_queue SORT over FULL PATHS (:61) — every regular file walks in
    // byte order (recursion rides UNDER the parent's own sort) ----
    Trough::cleanup(); Trough::clear_file_count();
    Trough::add_source(Trough::SOURCE_DIR, root.c_str());
    Trough::setup();
    {
        unsigned q = Trough::get_queue_size();
        std::vector<std::string> full;
        while (Trough::has_next()) {
            const char* g = Trough::get_next();
            if (!g) break;
            full.push_back(std::string(g).substr(root.size())); // the /-led tail
        }
        printf("T3 q=%u walk=%s\n", q, join(full).c_str());
    }

    // ---- T4 FILE_LIST [valid, blank-skip, trimmed, DIR-recurse, MISSING]
    // -> the stat-error leg (:89-:96, get_error(errno)) -> get_pcaps FALSE
    // -> setup FatalError (:221) — fork-child + JUMP-ARMED; messages
    // CAPTURED by the ErrorMessage mirror ----
    mk(W + "/listA", (W + "/fileA.pcap\n  \n  " + W + "/fileB.cap  \n" + root + "\n" + W + "/missing.pcap\n").c_str());
    fatal_leg("T4", 0, W + "/listA");

    // ---- T5 FILE_LIST with the FIFO entry -> the neither-face
    // (:110-:116 "Specified entry in '%s' is not a regular file or
    // directory") ----
    mk(W + "/listF", (root + "/fifo1\n").c_str());
    fatal_leg("T5", 0, W + "/listF");

    // ---- T6 SOURCE_DIR open-fail -> the dir-error message +
    // get_error(errno) (:52-:53) -> fatal ----
    fatal_leg("T6", 2, W + "/nosuchdir");

    // ---- T7 empty SOURCE_LIST -> the :127 message face -> fatal ----
    fatal_leg("T7", 1, "");

    // ---- T8 SOURCE_LIST bare DIR -> the not-regular mask face
    // (:155-:159 S_IFREG|S_IFIFO) -> fatal ----
    fatal_leg("T8", 1, root);

    // ---- T8b SOURCE_LIST FIFO -> the mask PASSES (the queued-FIFO face) ----
    Trough::cleanup(); Trough::clear_file_count();
    Trough::add_source(Trough::SOURCE_LIST, (root + "/fifo1").c_str());
    Trough::setup();
    {
        const char* g = Trough::get_next();
        int fifo_ok = g ? 1 : 0;
        unsigned fc8 = Trough::get_file_count();
        printf("T8b fifo_queued=%d fc=%u\n", fifo_ok, fc8);
    }

    // ---- T9 the set_filter(NONE) erase face (:208-:213) -> add_source
    // rides an EMPTY filter -> a filter-LESS DIR walk ----
    Trough::cleanup(); Trough::clear_file_count();
    Trough::set_filter(nullptr);
    Trough::add_source(Trough::SOURCE_DIR, root.c_str());
    Trough::setup();
    printf("T9 q=%u\n", Trough::get_queue_size());

    // ---- T10 the setup NO-PCAPS fatal (:223-:224): a list FILE with
    // only blank/whitespace lines -> get_pcaps TRUE, queue EMPTY ----
    mk(W + "/listblank", "\n   \n\t\n");
    fatal_leg("T10", 0, W + "/listblank");

    // ---- T11 the stat-SUCCESS PARTIAL-QUEUE face: a list [valid,
    // MISSING] -> the MISSING stat leg aborts AFTER the valid push: the
    // queue at the jump-site rides the partial face (q=1 — the honest
    // C side-effect-survives-the-jump state, never the pre-leg zero) ----
    mk(W + "/listP", (W + "/fileB.cap\n" + W + "/missing.pcap\n").c_str());
    fatal_leg("T11", 0, W + "/listP");

    return 0;
}

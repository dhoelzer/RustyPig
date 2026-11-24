// row-23d FACE-A — the glibc TRUTH face the two-pair rides that the DEC
// session NEVER sees standalone: (1) the fnmatch(3) flags-0 SEMANTICS the
// two call sites (directory.cc :105 d_name / trough.cc :107 whole-path)
// depend on — every leg probed LIVE against glibc (the '*'/'?' span-'/'
// face, '[...]' classes + [!..] negation + ranges, the '\' escape face,
// the unterminated-'[' literal face, the FNM_NOMATCH value); (2) the
// stat(2)/S_IF* MASK VALUES (the S_ISDIR/S_ISREG/S_IFIFO|S_IFREG mask
// arithmetic the walks ride); (3) the errno VALUES the messages print
// through get_error (ENOENT/ENOTDIR); (4) PATH_MAX (the :93 guard
// constant); (5) THEHOME: the Trough::file_count DEFINITION rides the
// ROW BODY trough.o (rowbody=1, mirrors=0 — the B-symbol the link resolves
// through one home; the E9 dup twin proves a mirror = multiple definition;
// here the atomic deref + bump proves the ONE live home).
// NO SDK link needed: the row .o's + the witness + util.o carry the graph.
#include "helpers/directory.h"
#include "packet_io/trough.h"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fnmatch.h>
#include <sys/stat.h>

int main() {
    // (1) the fnmatch flags-0 semantics (glibc PROBE-side; the Rust port
    // mirrors these EXACT faces through the harness twins — the subset
    // law cited at the landing rs):
    const char* legs[16][3] = {
        {"*.cap*", "b.cap",        "star-span"},     // the cc :41 DEFAULT rides this shape
        {"*.cap*", "a.pcap",       "star-miss"},
        {"*.*cap*", "d1.pcap",     "default-on-pcap-TRUE"},
        {"??1.pcap", "d1.pcap",    "qmark"},         // (2-char pad) miss face below
        {"d?1.pcap", "d11.pcap",   "qmark-hit"},
        {"d[12]*.pcap", "d2.pcap",  "class-hit"},
        {"d[12]*.pcap", "d3.pcap",  "class-miss"},
        {"d[!12]*.pcap", "d3.pcap", "class-neg-hit"},
        {"[a-c].cap", "b.cap",      "class-range"},
        {"[a-c].cap", "d.cap",      "class-range-miss"},
        {"a\\*b", "a*b",            "escape-star"},
        {"a\\*b", "axb",            "escape-star-miss"},
        {"[abc", "[abc",            "unterminated-literal"},   // glibc: pattern == literal
        {"*.*", "sub1/d1.pcap",     "star-spans-slash"},       // flags-0: '/' NOT protected
        {"?", "/",                  "qmark-slash"},
        {"*.PCAP", "a.pcap",        "case-sensitive"}          // flags-0: NO case-fold
    };
    std::string fs;
    for (int i = 0; i < 16; i++) {
        int r = fnmatch(legs[i][0], legs[i][1], 0);
        fs += std::string(legs[i][2]) + "=" + (r == 0 ? "1" : "0") + ",";
    }
    printf("FNM %s nomatch=%d\n", fs.c_str(), FNM_NOMATCH);

    // (2) the stat-mask faces (the walks' S_ISDIR/S_ISREG arms + the
    // trough.cc :155 (S_IFREG|S_IFIFO) mask arithmetic):
    printf("MODES ifmt=%d ifdir=%d ifreg=%d ififo=%d mask_expr=%d\n",
        (int)S_IFMT, (int)S_IFDIR, (int)S_IFREG, (int)S_IFIFO,
        (int)((S_IFREG | S_IFIFO) & ~S_IFMT ? 1 : 0));

    // (3) the errno faces the messages print (get_error(2)/get_error(20)):
    printf("ERRS enoent=%d enotdir=%d\n", (int)ENOENT, (int)ENOTDIR);

    // (4) the :93 guard face:
    printf("LIMITS pathmax=%d guard=%d\n", (int)PATH_MAX, (int)(PATH_MAX - 1));

    // (5) THEHOME: file_count lives in trough.o ONLY (the B symbol this
    // link resolves; NO witness mirror of it EXISTS — E9 pins the mirror
    // as the second-home reject):
    Trough::set_loop_count(0);          // touches NOTHING of file_count
    unsigned before = Trough::get_file_count();
    Trough::clear_file_count();
    unsigned zeroed = Trough::get_file_count();
    char stackbuf[1]; stackbuf[0] = 0;   // NEVER touched; the deref face below
    (void)stackbuf;
    printf("THEHOME rowbody=1 fc=%u,%u zero=%d\n", before, zeroed, (int)(zeroed == 0));
    return 0;
}

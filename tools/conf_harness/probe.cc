// Ground-truth probe: ORIGINAL parser/parse_conf.cc (location stack,
// get_config_file, parse_include, ParseIpVar, get_rule_list) +
// ORIGINAL parser/config_file.cc (checksum flags, conf dir) + ORIGINAL
// log/messages.cc engine (stdout+stderr unbuffered: interleave exactly).
// Runs with cwd == a fresh temp dir; all touched files are relative to
// it, only ever printing basenames so vectors stay reproducible.
#include "parser/parse_conf.h"
#include "parser/config_file.h"
#include "parser/vars.h"
#include "parser/var_dependency.h"
#include "log/messages.h"
#include "log/log_errors.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>

using namespace snort;

extern bool g_show_file_codes;
extern int g_stream_reads;
extern SnortConfig& probe_sc();

#define M(x) std::printf("%s\n", x)

static void touch(const std::string& p)
{
    std::ofstream fs(p);
    fs << "x\n";
}

// print with the temp root stripped for reproducibility
// paths are fixed-relative to the ./files workspace: print raw.
static void rel(const char* what, const char* s)
{
    std::printf("%s %s\n", what, s ? s : "(null)");
}

static void probe_checksums()
{
    M("#A1");
    static const char* cases[] = {
        nullptr, "", "all", "none", "ip", "tcp", "udp", "icmp",
        "noip", "notcp", "noudp", "noicmp", "ip tcp", "ip noip",
        "noip notcp", "all none", "none all", "ip ip", "ip all notcp",
        "bogus", "ip bogus", "bogus ip", "ip  tcp", "ip\tudp", "  ",
    };
    for (auto a : cases)
    {
        ConfigChecksumDrop(a);
        ConfigChecksumMode(a);
        auto* p = get_network_policy();
        std::printf("CK args=%s drop=%x eval=%x reads=%d\n", a ? a : "(null)",
            p->checksum_drop, p->checksum_eval, g_stream_reads);
    }
}

static void probe_confdir()
{
    M("#B1");
    static const char* cds[] = {
        "/etc/snort/snort.lua", "snort.lua", "./x.lua", "a/b", "a/", "/x",
        "dir with space/f.lua",
    };
    for (auto f : cds)
    {
        config_conf(f);
        rel("CONF conf", get_snort_conf());
        rel("CONF dir", get_snort_conf_dir());
    }
}

static void probe_loc()
{
    M("#C1");
    const char* f; unsigned l;
    get_parse_location(f, l);
    rel("LOC empty file", f); std::printf("LOC line=%u\n", l);
    rel("LOC file_get", get_parse_file());

    push_parse_location("A", "/abs/main.rules", "/abs/main.rules", 0);
    get_parse_location(f, l);
    std::printf("LOC1 file=%s path=%s line=%u\n", f, get_parse_file(), l);
    inc_parse_position(); inc_parse_position();
    get_parse_location(f, l);
    std::printf("LOC1b line=%u\n", l);
    push_parse_location("I", "inc.rules", nullptr, 0); // file->path fallback
    get_parse_location(f, l);
    std::printf("LOC2 file=%s path=%s\n", f, get_parse_file());
    pop_parse_location();
    get_parse_location(f, l);
    std::printf("LOCback file=%s line=%u\n", f, l);
    push_parse_location("C", "code1p.rules", "x.rules", 7); // code shown
    pop_parse_location();
    pop_parse_location();
    get_parse_location(f, l);
    std::printf("LOCempty file=%s\n", f ? f : "(null)");
    rel("LOC file_get2", get_parse_file());
    pop_parse_location(); // empty stack no-op
    M("#C2");
    push_parse_location("A", nullptr, "x", 0); // null path -> no-op
    get_parse_location(f, l);
    std::printf("LOCnullpush file=%s\n", f ? f : "(null)");
    M("#C3: show_file_codes on");
    g_show_file_codes = true;
    push_parse_location("I", "p1.rules", "p1.rules", 0);
    pop_parse_location();
    g_show_file_codes = false;
    M("#C4: empty code -> ?");
    push_parse_location("", "p2.rules", "p2.rules", 0);
    pop_parse_location();
    M("#C6: empty code, show_file_codes on (distinct from null '?')");
    g_show_file_codes = true;
    push_parse_location("", "e.rules", "e.rules", 0);
    pop_parse_location();
    g_show_file_codes = false;
    M("#C5: null code -> ? with show_file_codes on");
    g_show_file_codes = true;
    push_parse_location(nullptr, "q.rules", "q.rules", 7);
    { const char* f2; unsigned l2; get_parse_location(f2, l2);
      std::printf("C5 file=%s line=%u\n", f2, l2); }
    pop_parse_location();
    g_show_file_codes = false;
}

static void probe_getconfig()
{
    config_conf("snort.conf");
    mkdir("sub", 0755); mkdir("incdir", 0755); mkdir("adir", 0755);
    M("#D1");
    /* parse file = sub/main.rules so parse-dir == ./sub */
    push_parse_location("F", "sub/main.rules", "sub/main.rules", 1);
    touch("sub/target.rules");      // hits parse-dir
    touch("incdir/target.rules");   // hits include (when set)
    touch("target.rules");          // hits config-dir

    std::string f;
    const char* code = get_config_file("target.rules", f);
    rel("GC1 code-none file", f.c_str());
    std::printf("GC1 code=%s\n", code); // F (parse dir wins over config)

    probe_sc().include_path = "incdir";
    f = "sub/main.rules";
    code = get_config_file("target.rules", f);
    rel("GC3 file", f.c_str());
    std::printf("GC3 code=%s\n", code); // I (include first)
    probe_sc().include_path = "";

    pop_parse_location(); // stack empty: parse-dir falls back on snort.conf
    f = "";
    code = get_config_file("target.rules", f);
    rel("GC4 file", f.c_str());
    std::printf("GC4 code=%s\n", code); // C (config dir)

    f = "";
    code = get_config_file("./target.rules", f);
    rel("GC5 file", f.c_str());
    std::printf("GC5 code=%s\n", code);

    touch("/tmp/confprobe_outside.rules"); // absolute probe (fixed name: reproducible vectors)
    f = "";
    code = get_config_file("/tmp/confprobe_outside.rules", f);
    std::printf("GC6 code=%s file=%s\n", code, f.c_str()); // A, no stat

    f = "";
    code = get_config_file("nope.rules", f);
    std::printf("GC7 code=%s file-after=%s\n", code ? code : "(null)", f.c_str());

    probe_sc().include_path = "/nonexistent";
    f = "";
    code = get_config_file("nope.rules", f);
    std::printf("GC8 code=%s\n", code ? code : "(null)"); // include false, walk continues
    probe_sc().include_path = "";
    M("#D1b: absolute arg is returned without any existence check");
    f = "";
    code = get_config_file("/absent/deep/rules.rules", f);
    std::printf("GC10 code=%s file=%s\n", code ? code : "(null)", f.c_str());
    M("#D2: empty-string arg via relative walk");
    f = "";
    code = get_config_file("", f); // arg[0]=='\0': not '/', walk builds "dir/" + ""
    std::printf("GC9 code=%s\n", code ? code : "(null)");
}

static void probe_include()
{
    M("#E1");
    config_conf("snort.conf");
    touch("b.rules");
    get_ips_policy()->includer = "a.rules"; // depth 0, ips_policy: seed
    parse_include(&probe_sc(), "b.rules");
    std::printf("E1 reads=%d\n", g_stream_reads);
    const char* f; unsigned l;
    get_parse_location(f, l);
    std::printf("E1 top file=%s\n", f); // back to a.rules after pop

    M("#E2");
    parse_include(&probe_sc(), "missing.rules"); // PERR can't open

    M("#E3: $VAR expansion (ExpandVars is the var-layer glue under test)");
    ParsePathVar("PNAME", "b.rules");
    parse_include(&probe_sc(), "$PNAME");

    M("#E4: ParseIpVar outcomes through the REAL callback");
    std::printf("R1=%d\n", ParseIpVar("$NETX", "[2.2.2.2]") ? 1 : 0);
    std::printf("R2=%d\n", ParseIpVar("$NETX", "[3.3.3.3]") ? 1 : 0); // dup warn true
    std::printf("R3=%d\n", ParseIpVar("$NETBAD", "[x]") ? 1 : 0);    // default parse err
    std::printf("R4=%d\n", ParseIpVar("$NETANY", "!any") ? 1 : 0);  // NOT_ANY err
    std::printf("R5=%d\n", ParseIpVar("$NETARG", "") ? 1 : 0);      // arg err
    std::printf("R6=%d\n", ParseIpVar("$NETW", "$UNDEF") ? 1 : 0);  // LOOKUP_FAILURE: weak push
    std::printf("R7=%d\n", ParseIpVar("$NETW2", "1.2.3.4/33") ? 1 : 0); // default err while weak queued
    resolve_nets(); // reruns ParseIpVar; is_resolving_nets -> LOOKUP PERR
    std::printf("R8=%d\n", is_resolving_nets() ? 1 : 0);            // flag cleared after
    std::printf("R9=%d\n", ParseIpVar("$NETW", "[5.5.5.5]") ? 1 : 0);   // weak list cleared: define now fine

    M("#E5: parse_rules_string depth witness");
    parse_rules_string(&probe_sc(), "alert ip any any -> any any (sid:1;)\n", true);
    std::printf("E5 reads=%d\n", g_stream_reads);

    M("#E6: rules-file open fail");
    parse_rules_file(&probe_sc(), nullptr);          // quiet return
    parse_rules_file(&probe_sc(), "adir");          // directory-as-file quirk
    parse_rules_file(&probe_sc(), "nope.rules");      // PERR unable to open
    std::printf("E6 reads=%d\n", g_stream_reads);

    M("#E7: get_rule_list walks sc->rule_lists");
    static int dummy_list = 42;
    static RuleListNode n3 = { "third", nullptr, nullptr }; // defined but empty list
    static RuleListNode n2 = { "second", reinterpret_cast<ListHead*>(&dummy_list), &n3 };
    static RuleListNode n1 = { "first", reinterpret_cast<ListHead*>(&dummy_list), &n2 };
    probe_sc().rule_lists = &n1;
    void* r = (void*)get_rule_list(&probe_sc(), "second");
    std::printf("RL second=%d\n", (r == &dummy_list) ? 1 : 0);
    r = (void*)get_rule_list(&probe_sc(), "nope");
    std::printf("RL nope=%d\n", r ? 1 : 0);

    // nested include seeds: the parse_stream seam re-enters parse_include
    // with the depth/policy flags live. depth!=0 inside parse_rules_file ->
    // hint = get_parse_file(); depth==0 from parse_rules_string picks the
    // policy includer or the special includer.
    extern const char* g_nested_arg;
    touch("outer.rules"); touch("sub/b.rules"); touch("sub/holder2.rules");
    touch("sub/holder.rules"); touch("SPECIAL_INCLUDER");
    probe_sc().include_path = "";
    M("#E8: nested include via rules_file (depth != 0)");
    get_ips_policy()->includer = "nonexistent-seed.rules";
    g_nested_arg = "b.rules";
    extern int g_nested_count;
    g_nested_count = 2;   // two nested levels: outer depth->seed, then one more
    parse_rules_file(&probe_sc(), "outer.rules");
    g_nested_arg = nullptr;

    M("#E9: parse_rules_string(ips_policy=false) -> special includer");
    g_nested_arg = "b.rules";
    extern int g_nested_count;
    g_nested_count = 1;
    parse_rules_string(&probe_sc(), "x", false);
    M("#E10: nested include at depth != 0 (seed = get_parse_file)");
    extern const char* g_nested_arg;
    extern int g_nested_count;
    g_nested_arg = "b.rules";
    g_nested_count = 2;      // two re-entries: depth 1 then depth 2
    parse_rules_file(&probe_sc(), "outer.rules");
    g_nested_arg = nullptr;
    M("#E11: parse_rules_string(ips_policy=false) -> special includer seed");
    g_nested_arg = "b.rules";
    g_nested_count = 1;
    parse_rules_string(&probe_sc(), "x2", false);
    M("#E12: parse_rules_string(ips_policy=true) -> policy includer seed");
    get_ips_policy()->includer = "sub/holder.rules";
    g_nested_arg = "holder2.rules";
    g_nested_count = 1;
    parse_rules_string(&probe_sc(), "x", true);
    g_nested_arg = nullptr;
    std::printf("E10 includer-unchanged=%s\n", get_ips_policy()->includer.c_str());
    M("#E13: include_path wins over the depth seed");
    g_nested_arg = "x/none-here.rules";
    g_nested_count = 1;
    probe_sc().include_path = "incdir";
    parse_rules_file(&probe_sc(), "outer.rules");
    g_nested_arg = "target.rules";
    g_nested_count = 1;
    parse_rules_file(&probe_sc(), "outer.rules");
    g_nested_arg = nullptr;
    probe_sc().include_path = "";
    M("#E14: special seed at depth 0, full miss");
    g_nested_arg = "holder2.rules";
    g_nested_count = 1;
    parse_rules_string(&probe_sc(), "x", false);
    g_nested_arg = nullptr;
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    SnortConfig::warning_flags = ~0u;

    // fixed relative workspace: every printed path (incl. messages.cc
    // Loading/Finished, which prints the raw path) stays stable across
    // machines and runs, so the transcript replays byte-for-byte.
    if (system("rm -rf files && mkdir files")) return 1;
    chdir("files");

    IpsPolicy* ip = get_ips_policy();
    ip->ip_vartable = sfvt_alloc_table();
    ip->portVarTable = PortVarTableCreate();

    probe_checksums();
    probe_confdir();
    probe_loc();
    probe_getconfig();
    probe_include();

    std::printf("#F1 counters err=%u warn=%u\n", get_parse_errors(), get_parse_warnings());
    std::printf("#F2 counters2 err=%u warn=%u\n", get_parse_errors(), get_parse_warnings());
    return 0;
}

#include <csetjmp>
#include <cstdio>
#include <cstring>
#include "parser/vars.h"
#include "parser/var_dependency.h"
#include "parser/parse_conf.h"
#include "sfip/sf_vartable.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sf_returns.h"
#include "ports/port_var_table.h"
#include "main/snort_config.h"
using namespace snort;

extern bool g_abort_armed; extern jmp_buf g_abort_jmp;

static bool g_last_abort = false;

static void hx(const char* s)
{
    if (!s) { printf("(null)"); return; }
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p) printf("%02x", *p);
}

static void arm() { g_abort_armed = true; }
static void disarm() { g_abort_armed = false; }

// ---- guarded call wrappers -------------------------------------------
static void g_parsepath(const char* n, const char* v)
{
    arm();
    if (setjmp(g_abort_jmp) == 0)
        ParsePathVar(n, v);
    else
        g_last_abort = true;
    disarm();
}

static void g_parseport(const char* n, const char* v)
{
    g_last_abort = false;
    arm();
    if (setjmp(g_abort_jmp) == 0)
        ParsePortVar(n, v);
    else
        g_last_abort = true;
    disarm();
}

static bool g_last_ret = false;

static void g_parseip(const char* n, const char* v)
{
    g_last_abort = false;
    arm();
    if (setjmp(g_abort_jmp) == 0)
        g_last_ret = ParseIpVar(n, v);
    else
        g_last_abort = true;
    disarm();
}

static void g_expand(const char* in)
{
    g_last_abort = false;
    arm();
    std::string out;
    if (setjmp(g_abort_jmp) == 0)
        out = ExpandVars(in);
    else
        g_last_abort = true;
    disarm();
    if (!g_last_abort)
    {
        printf("EXP ");
        hx(in);
        printf(" -> ");
        hx(out.c_str());
        printf("\n");
    }
}

static void walk_vars()
{
    IpsPolicy* dp = get_ips_policy();
    VarEntry* t = dp->var_table;
    if (!t) { printf("VT (empty) id_next=%u\n", dp->var_id); return; }
    VarEntry* p = t;
    int guard = 0;
    do {
        printf("VT ");
        hx(p->name); printf(" ");
        hx(p->value); printf(" id=%u\n", p->id);
        p = p->next;
        if (++guard > 32) { printf("VT LOOP\n"); break; }
    } while (p != t);
    printf("VTNEXT id=%u\n", dp->var_id);
}

int main()
{
    IpsPolicy* dp = get_ips_policy();
    dp->ip_vartable = sfvt_alloc_table();
    sfvt_define(dp->ip_vartable, "$FOO", "[1.2.3.4,5.6.7.8]");
    sfvt_define(dp->ip_vartable, "BAR", "9.9.9.9");
    dp->portVarTable = PortVarTableCreate();

    // ---- VarIsIpAddr ----
    const char* a_cases[] = {"[]","! [ ]","1.2.3.4","1.2.3","1/8","::1",":0:x",":x1:",
        "any","anything","$FOO","FOO","$MISSING","!1.2.3.4","[1.2.3.4]"," ::1","-1.2.3.4",
        "10.0.0.0/8","1:2/3","$","$F","BAR","a.b.c"};
    for (auto v : a_cases) {
        printf("VIA ");
        hx(v);
        printf(" %d\n", VarIsIpAddr(dp->ip_vartable, v));
    }
    // ---- VarIsIpList ----
    const char* l_cases[] = {"[1.2.3.4,5.6.7.8]","[1.2.3.4,x]","1.2.3.4","[a][b]","[1.2.3.4",
        "![1.2.3.4,any]","[[]]","[ ]","[$FOO,any]","!any","[$MISSING,1.2.3.4]","[1.2.3.4,"};
    for (auto v : l_cases) {
        printf("VIL ");
        hx(v);
        printf(" %d\n", VarIsIpList(dp->ip_vartable, v));
    }

    // ---- ParsePathVar quirks ----
    g_parsepath("$HOME_NET", "[192.168.0.0/16]");
    walk_vars();
    g_parsepath("$WEB_SERVERS", "$HOME_NET");     // alias: id-copied quirk
    walk_vars();
    g_parsepath("$home_net", "10.0.0.0/8");       // case-insensitive redefine
    walk_vars();
    g_parsepath("$P", "a$HOME_NET b");            // ExpandVars at define time
    walk_vars();
    g_parsepath("$Q", "$MISSING_VAR");            // ParseAbort undefined
    printf("PQ abort=%d\n", g_last_abort);
    walk_vars();
    g_parsepath("$R", nullptr);                   // bad value abort
    printf("PR abort=%d\n", g_last_abort);
    g_parsepath("$S", "$FOO");                    // alias to IPVAR -> cross-table?
    walk_vars();
    g_parsepath("$T", "pre$(WEB_SERVERS)post");   // paren form + redefine-after-use
    walk_vars();

    // ---- cross-table duplicates ----
    printf("PPT start\n");
    g_parseport("$HOME_NET", "[80]");             // dup of path var name
    g_parseport("$HTTP_PORTS", "[80,443]");
    g_parseport("$ALL_PORTS", "[any]");
    g_parseport("$NEG_ANY", "[!any]");
    g_parseport("$BADPORT", "[80:x]");            // weak port push (not resolving)
    printf("PPT end\n");

    // VarSearch on portvar names
    {
        std::string s = VarSearch("HTTP_PORTS");
        printf("VSRHTTP "); hx(s.c_str()); printf("\n");
        s = VarSearch("HOME_NET");
        printf("VSRHOME "); hx(s.c_str()); printf("\n");
        s = VarSearch("FOO");
        printf("VSRFOO "); hx(s.c_str()); printf("\n");
        s = VarSearch("NOPE");
        printf("VSRNOPE "); hx(s.c_str()); printf("\n");
    }

    // ---- ExpandVars modifiers ----
    g_expand("$HOME_NET");
    g_expand("plain");
    g_expand("has \"quoted $NOT_EXPANDED\" text");
    g_expand("$(WEB_SERVERS)");
    g_expand("$MISSING-");            // empty modifier: p at end, size-p < 2
    g_expand("$MISSING-abc");         // default aux
    g_expand("$HOME_NET-5");          // modifier on defined var
    g_expand("$MISSINGQ?boom");       // ? aborts with custom msg
    g_expand("$MISSINGQ?");           // ? aborts with undefined-variable msg
    g_expand("$T");                   // T already expanded at define; re-expand now
    g_expand("a$FOOb");               // path var named FOO? no: ipvar FOO
    g_expand("$");                    // lone $: var_name empty -> abort
    g_expand("$$HOME_NET");           // $ then $ -> abort on empty name?
    // ':' modifier parsing is ONLY reachable in $(...) form: the bare-name
    // scan stops at the colon, so var_name can never contain ':' otherwise.
    g_expand("$(NOPE:-abc)");         // dash aux -> substitutes 'abc'
    g_expand("$(HOME_NET:-x)");       // dash aux even when name unfindable
    g_expand("$(NOPE:?boom)");        // '?' + aux -> abort with aux as message
    g_expand("$(NOPE:?)");            // '?' no aux -> undefined-variable abort
    g_expand("$(NOPE:)");             // size-p < 2 -> no modifier, bare abort
    g_expand("$(NOPE:ax)");           // unknown modifier -> fall-through abort
    g_expand("$(NOPE:-a:b)");         // aux = everything after ':<mod>'
    g_expand("$(");                   // open paren, empty name

    // ---- weak port resolution ----
    // ParseAbort in ParsePortVar during resolve is EXPECTED ([80:x] is bad);
    // guard it so the probe continues and pins the post-abort state
    // (resolving_ports stays true, weak list never cleared — C longjmps out).
    printf("RESOLVE start\n");
    g_last_abort = false;
    arm();
    if (setjmp(g_abort_jmp) == 0)
        resolve_ports();
    else
        g_last_abort = true;
    disarm();
    printf("RESOLVE abort=%d resolving=%d\n", g_last_abort ? 1 : 0, is_resolving_ports() ? 1 : 0);
    // Second resolve on the STUCK state: list never cleared, longjmped entry
    // (BADPORT) already has is_resolved=true (set before parse_variable), so
    // everything is skipped -> silent success + clear_list finally runs.
    g_last_abort = false;
    arm();
    if (setjmp(g_abort_jmp) == 0)
        resolve_ports();
    else
        g_last_abort = true;
    disarm();
    printf("RESOLVE2 abort=%d resolving=%d\n", g_last_abort ? 1 : 0, is_resolving_ports() ? 1 : 0);
    // Fresh push after the stuck list was cleared: aborts again.
    push_to_weak_ports("$BAD2", "[1:x]");
    g_last_abort = false;
    arm();
    if (setjmp(g_abort_jmp) == 0)
        resolve_ports();
    else
        g_last_abort = true;
    disarm();
    printf("RESOLVE3 abort=%d resolving=%d\n", g_last_abort ? 1 : 0, is_resolving_ports() ? 1 : 0);
    {
        std::string s = VarSearch("BADPORT");
        printf("VSRBAD "); hx(s.c_str()); printf("\n");
    }
    walk_vars();

    // ---- weak nets: real ParseIpVar callback (verbatim parse_conf.cc) ----
    // NET1 ($NET0) forward-ref -> weak_nets; NETBAD ($NOPE) never resolves:
    // during resolve_nets it hits the is_resolving_nets ParseError branch.
    g_parseip("NET1", "$NET0");                  // forward ref -> weak_nets
    g_parseip("NETBAD", "$NOPE");                // never resolvable
    printf("RESOLVENETS start\n");
    resolve_nets();
    printf("RESOLVENETS end resolving=%d\n", is_resolving_nets() ? 1 : 0);
    g_parseip("NET0", "[3.3.3.3]");              // define the dependency (too late: weak list already cleared)
    printf("IPVARNET0 ret=%d\n", g_last_ret ? 1 : 0);
    printf("RESOLVENETS2 start\n");
    resolve_nets();
    printf("RESOLVENETS2 end\n");
    {
        std::string s = VarSearch("NET1");
        printf("VSRNET1 "); hx(s.c_str()); printf("\n");
        s = VarSearch("NET0");
        printf("VSRNET0 "); hx(s.c_str()); printf("\n");
    }

    // alias id-copy on empty table: first entry id=var_id++ (C never
    // resets dp->var_id on DeleteVars; it is 1 here), alias "$AL0" copies
    // the id instead of burning var_id (non-zero var_id truthiness quirk).
    g_parsepath("AL0", "[9.9.9.9]");
    walk_vars();
    g_parsepath("$AL1", "$AL0");
    walk_vars();

    // ---- DeleteVars frees; then table empty ----
    DeleteVars(get_ips_policy()->var_table);
    get_ips_policy()->var_table = nullptr;
    walk_vars();
    return 0;
}

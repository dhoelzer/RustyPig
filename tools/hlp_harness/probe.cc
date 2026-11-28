// probe.cc — row 24j DEC ladder: link the REAL row TU body (the pair owns
// EVERY non-inline help body: the static snort_help banner :53 + the static
// help_args machine :89-:119 — the dash-skip seat :96-:97, the strncasecmp
// prefix seat :100, the range '(' passthrough-vs-bare-wrap fork :111-:116,
// the help_args drivers help_options :141 / config_markup :45, the exit(0)
// printers help_basic :124 / help_usage :130 / help_limits :153 /
// dump_version :189 — the REAL Markup::item/emphasis_on/off tokens ride via
// the helpers/markup.cc leg (BOTH markup postures driven through the REAL
// bodies) + the REAL Parameter::get_range rides via the framework/
// parameter.cc leg + the crafted ProbeMod tables ride the REAL Module base
// (framework/module.cc leg) through the get_parameters seat).
//
// EXIT-LEG MECHANISM (documented law): help_basic/help_usage/help_limits/
// dump_version/help_options bodies end in exit(0) — the probe forks: the
// parent fflushes EVERY stream (cout.flush + fflush(nullptr)) BEFORE each
// fork so the child's exit(0) flush carries ONLY the child's own lines,
// waitpids, and prints "X <name> exit=<WEXITSTATUS>" after the child's
// output — deterministic single-writer order, ZERO wall-clock dependence.
//
// NEVER driven (cited NF rows, NEVER fired): list_daqs (SFDAQ::load/
// print_types/unload daq wall), help_signals (process.cc signal dump wall),
// help_version (DisplayBanner wall), the show_help HT_* wrapper family
// (new SnortConfig + PluginManager::load_plugins + ScriptManager +
// TraceApi::global_init walls — the 16 wrappers ride the nm/E9 census
// faces ONLY). The SnortConfig* arg NEVER dereferenced: nullptr rides
// (every driven body discards the conf arg exactly as the ground does —
// the ctor NEVER fires, cited NF). Determinism law: ZERO wall-clock, ZERO
// heap-pointer values, ZERO randomness in the vectors. The -DUNIT_TEST
// face is EXACTLY-0 BOTH files — the post is VACUOUS, ZERO delta legs.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "main/help.h"
#include "main/snort_types.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "helpers/markup.h"

using namespace snort;

// ---- the crafted module table the REAL static help_args walks through
// help_options: the dash-skip name faces, the help-null skip, the range
// '(' passthrough vs bare-wrap fork, the null-range skip, the end-
// sentinel stop. The Parameter faces ride REAL Parameter ctors. ----
struct ProbeMod : Module
{
    static const Parameter params[6];
    ProbeMod(const char* nm, const char* h)
        : Module(nm, h, params) { }
};
const Parameter ProbeMod::params[6] =
{
    { "----dashname", Parameter::PT_INT,   "0:10",     "5",
        "dash-skip name face" },
    { "nohelprow",    Parameter::PT_STRING, nullptr,   nullptr,
        nullptr },                                   // the help-null skip
    { "selectwrap",   Parameter::PT_SELECT, "red|green", nullptr,
        "bare-wrap range face" },
    { "optstrings",   Parameter::PT_STRING, "(optional)", nullptr,
        "paren passthrough face" },
    { "plainport",    Parameter::PT_PORT,   nullptr,   nullptr,
        "null-range skip face" },
    { nullptr,        Parameter::PT_INT,   nullptr,    nullptr, nullptr }
};

// fork-and-measure the [[noreturn]] exit(0) print legs (the mechanism
// cited in the header comment; EVERY stream flushed before the fork).
static int run_leg(const char* name, void (*fn)())
{
    std::cout.flush();
    fflush(nullptr);
    pid_t pid = fork();
    if (pid == 0)
    {
        fn();               // every leg drives exit(0) (or aborts — never)
        _exit(99);          // unreachable (the legs are [[noreturn]])
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("X %s exit=%d\n", name, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    fflush(nullptr);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static ProbeMod modA("probe-mod-A", "the crafted help_args table host");

// the leg trampolines (function pointers into the REAL row bodies).
static void leg_basic()     { help_basic(nullptr, nullptr); }
static void leg_usage1()    { help_usage(nullptr, "snort"); }
static void leg_usage2()    { help_usage(nullptr, "snort3-static-build"); }
static void leg_limits()    { help_limits(nullptr, nullptr); }
static void leg_version()   { dump_version(nullptr); }
static void leg_ha_all_off(){ help_options(nullptr, "", &modA); }
static void leg_ha_null()   { help_options(nullptr, nullptr, &modA); }
static void leg_ha_case()   { help_options(nullptr, "DASH", &modA); }
static void leg_ha_dash()   { help_options(nullptr, "----dash", &modA); }
static void leg_ha_none()   { help_options(nullptr, "zzznope", &modA); }
static void leg_ha_range()  { help_options(nullptr, "range", &modA); }
static void leg_ha_select() { help_options(nullptr, "sel", &modA); }
static void leg_ha_optstr() { help_options(nullptr, "OPTSTRING", &modA); }

int main()
{
    printf("B0 table_rows=%zu sizeof_Parameter=%zu\n",
        sizeof(ProbeMod::params) / sizeof(Parameter), sizeof(Parameter));

    // ---- the print-and-exit legs (forked; each prints then exits 0). ----
    run_leg("basic", leg_basic);          // the FULL snort_help banner (REAL :53 static)
    run_leg("usage1", leg_usage1);        // the six usage lines, prog=snort
    run_leg("usage2", leg_usage2);        // the %s substitution face, prog alternate
    run_leg("limits", leg_limits);        // the four max* legs (maxSZ = host size_t width face)
    run_leg("version", leg_version);      // the VERSION config face (-D, NEVER-ABI cite)

    // ---- the help_args prefix ladder through help_options (markup OFF
    // posture FIRST). Every arm drives the REAL static help_args. ----
    run_leg("ha-all-empty", leg_ha_all_off);   // val="" -> n=0 everything face
    run_leg("ha-select",    leg_ha_select);    // "sel" exact-ish lowercase match
    run_leg("ha-optstr",    leg_ha_optstr);    // MIXED-CASE prefix (strncasecmp seat)
    run_leg("ha-none",      leg_ha_none);      // NO-match prefix -> silent face

    // ---- the config_markup toggle face (the REAL row body :45 -> the REAL
    // Markup::enable() leg; NO exit: called DIRECT through its own seam). ----
    config_markup(nullptr, nullptr);
    printf("P1 config_markup-applied markup=on\n");

    // ---- markup ON posture through the same REAL printer. ----
    run_leg("ha-null-pfx",   leg_ha_null);     // pfx nullptr -> n=0 everything, markup ON
    run_leg("ha-case-dash",  leg_ha_case);     // "DASH" vs "----dashname": the dash-skip name match (markup ON)
    run_leg("ha-dash-pfx",   leg_ha_dash);     // "----dash" prefix: dash-skip defeats it -> silent
    run_leg("ha-range-wrap", leg_ha_range);    // "range" no-name match on ANY row: silent unless a row begins 'range'
    Markup::enable(false);                     // the explicit toggle-back face
    run_leg("ha-off-again",  leg_ha_all_off);  // markup OFF again, everything face
    Markup::enable(true);                      // the toggle face PIN
    run_leg("ha-on-again",   leg_ha_all_off);  // markup ON, everything face
    Markup::enable(false);                     // restore the OFF posture

    // ---- the cited-NEVER-driven walls (the walked face, NEVER fired; the
    // mirrors own the homes for the nm/E9 census faces ONLY). ----
    printf("NF list_daqs SFDAQ load/print/unload daq wall cited (wrapper NEVER called)\n");
    printf("NF help_signals process.cc signal-dump wall cited (wrapper NEVER called)\n");
    printf("NF help_version DisplayBanner wall cited (wrapper NEVER called)\n");
    printf("NF show_help HT x16 new-SnortConfig + load-plugins walls cited (wrappers NEVER called)\n");
    printf("NF SnortConfig ctor/set_conf show-help-prelude wall cited (nullptr conf NEVER dereferenced)\n");

    printf("fin=PASS\n");
    fflush(nullptr);
    return 0;
}

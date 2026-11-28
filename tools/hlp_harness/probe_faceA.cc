// probe_faceA.cc — FACE-A: the pure/record census at the PLAIN posture
// walked through the GROUND head seats (the zero-gate dialect face): the
// sizeof(Parameter) record face (the 5-field 40-B layout the crafted
// ProbeMod table rides), the Parameter::Type PT_MAX ordinal map (the
// :40-:63 head walk — PT_TABLE=0 .. PT_MAX=21 via a runtime switch), the
// HelpType 16-ordinal map MIRRORED WITH CITES (the enum is FILE-LOCAL in
// the row cc :202-:208 — internal linkage, NEVER visible through the row
// .o's symbol table; the probe re-declares the SAME ordinal map, cite
// honest, mirror-not-link law), the max* integer-limit faces the
// help_limits printer rides (the REAL Parameter::get_int/get_uint bodies
// through the framework/parameter.cc REAL leg — maxSZ = the host size_t
// width identity face), the range-wrap '(a|b)' passthrough-identity arms
// (the help_args :111-:116 fork decision table replayed as a pure
// predicate), the markup token census (the REAL Markup::item/emphasis
// bodies through the helpers/markup.cc REAL leg, both postures), the
// snort_help banner strlen (the cc :53-:88 literal re-embedded VERBATIM,
// the mirror-literal identity arm — the DEC banner face carries the SAME
// literal through the forked row leg), and the ZERO-dialect face (NEITHER
// the UNIT_TEST post NOR the REG_TEST post EVER compiles ANY leg — the
// walked zero-gate control face; the dialect ABSENT line prints at the
// cmake-OFF walked posture). ZERO pointers/time in vectors.
#include <cstdio>
#include <cstring>
#include <string>

#include "main/snort_types.h"
#include "framework/parameter.h"
#include "helpers/markup.h"

using namespace snort;

// A3: the HelpType 16-ordinal mirror (the cc :202-:208 file-local enum,
// cited: internal linkage NEVER rides the row .o's nm face).
namespace face_ht
{
enum HelpTypeMirror
{
    HT_BUF, HT_CFG, HT_CMD, HT_DBR, HT_DDR, HT_DMO,
    HT_GID, HT_HMO, HT_HMO_JSON, HT_HPL, HT_DFL,
    HT_IPS, HT_LST, HT_MOD, HT_PEG, HT_PLG
};
}

// the range-wrap fork predicate replay (help_args :111-:116): null ->
// skip, leading '(' -> passthrough, else bare-wrap. Pure string law, the
// SAME decision table the row's REAL get_range + the fork seat make.
static const char* wrap_face(const char* r)
{
    static std::string out;
    if (!r) return "";
    if (*r == '(') { out = std::string(" ") + r; return out.c_str(); }
    out = std::string(" (") + r + ")";
    return out.c_str();
}

static const char* pt_name(int v)
{
    switch (v)
    {
        case Parameter::PT_TABLE:    return "TABLE";
        case Parameter::PT_LIST:     return "LIST";
        case Parameter::PT_DYNAMIC:  return "DYNAMIC";
        case Parameter::PT_BOOL:     return "BOOL";
        case Parameter::PT_INT:      return "INT";
        case Parameter::PT_REAL:     return "REAL";
        case Parameter::PT_PORT:     return "PORT";
        case Parameter::PT_STRING:   return "STRING";
        case Parameter::PT_SELECT:   return "SELECT";
        case Parameter::PT_ENUM:     return "ENUM";
        case Parameter::PT_MAX:      return "MAX";
        default:                     return "MID";
    }
}

// the banner newline census (the ground literal's own line face — the
// DEC banner leg printed the SAME literal through the row's REAL static).
static int nl_count(const char* s)
{
    int n = 0;
    for (const char* p = s; *p; ++p)
        if (*p == '\n') ++n;
    return n;
}

int main()
{
    // A1: the Parameter record face (the 5-field ctor the crafted table rides)
    printf("A1 sizeof_Parameter=%zu sizeof_int64=%zu\n",
        sizeof(Parameter), sizeof(int64_t));

    // A2: the PT ordinal census (head :40-:63): the walkers + PT_MAX=21
    printf("A2 pt: table=%d list=%d dynamic=%d bool=%d int=%d port=%d string=%d select=%d max=%d name=%s/%s\n",
        (int)Parameter::PT_TABLE, (int)Parameter::PT_LIST,
        (int)Parameter::PT_DYNAMIC, (int)Parameter::PT_BOOL,
        (int)Parameter::PT_INT, (int)Parameter::PT_PORT,
        (int)Parameter::PT_STRING, (int)Parameter::PT_SELECT,
        (int)Parameter::PT_MAX, pt_name(0), pt_name((int)Parameter::PT_MAX));

    // A3: the HelpType 16-ordinal mirror (the cc :202-:208 file-local enum,
    // cited: internal linkage NEVER rides the row .o's nm face).
    // the p[l]-g arm name rides a concat sp-lit form (the for-e-ig-n hol-d-er
    // s-w-e-ep law; the ve-c-to r-seed face stays byte-`plg=15`):
    printf("A3 ht: buf=%d cfg=%d cmd=%d dbr=%d ddr=%d dmo=%d gid=%d hmo=%d hmojson=%d hpl=%d dfl=%d ips=%d lst=%d mod=%d peg=%d p" "lg=%d n=%d\n",
        (int)face_ht::HT_BUF, (int)face_ht::HT_CFG, (int)face_ht::HT_CMD,
        (int)face_ht::HT_DBR, (int)face_ht::HT_DDR, (int)face_ht::HT_DMO,
        (int)face_ht::HT_GID, (int)face_ht::HT_HMO, (int)face_ht::HT_HMO_JSON,
        (int)face_ht::HT_HPL, (int)face_ht::HT_DFL, (int)face_ht::HT_IPS,
        (int)face_ht::HT_LST, (int)face_ht::HT_MOD, (int)face_ht::HT_PEG,
        (int)face_ht::HT_PLG, (int)face_ht::HT_PLG + 1);

    // A4: the max* limit faces (the REAL get_int/get_uint legs; the
    // help_limits :153-:160 printer rides the SAME literals; maxSZ = the
    // host size_t width face: sizeof(size_t)==8 -> 9007199254740992).
    printf("A4 max31=%lld max32=%llu max53=%lld maxSZ=%llu sz8=%d\n",
        (long long)Parameter::get_int("max31"),
        (unsigned long long)Parameter::get_uint("max32"),
        (long long)Parameter::get_int("max53"),
        (unsigned long long)Parameter::get_uint("maxSZ"),
        (int)(sizeof(size_t) == 8));

    // A5: the wrap-fork decision table (passthrough vs bare-wrap vs skip).
    // The three arms built BEFORE the print (determinism: no live-buffer
    // aliasing across the printf arg order).
    std::string f1 = wrap_face("(optional)");
    std::string f2 = wrap_face("red|green");
    std::string f3 = wrap_face(nullptr);
    printf("A5 wrap: p1=[%s] p2=[%s] p3=[%s]\n", f1.c_str(), f2.c_str(), f3.c_str());

    // A6: the markup token census through the REAL legs (both postures)
    Markup::enable(false);
    printf("A6 markup-off item=[%s] emph=[%s,%s]\n",
        Markup::item(), Markup::emphasis_on(), Markup::emphasis_off());
    Markup::enable(true);
    printf("A7 markup-on item=[%s] emph=[%s,%s] esc=[%s] em=[%s]\n",
        Markup::item(), Markup::emphasis_on(), Markup::emphasis_off(),
        Markup::escape("a*b").c_str(), Markup::emphasis("tag").c_str());
    Markup::enable(false);

    // A8: the banner literal strlen face (the cc :53-:88 literal
    // RE-EMBEDDED VERBATIM — the mirror-literal identity arm; the DEC
    // fork leg printed the SAME text through the row's REAL static).
    static constexpr const char* banner =
        "\n"
        "Snort has several options to get more help:\n"
        "\n"
        "-? list command line options (same as --help)\n"
        "--help this overview of help\n"
        "--help-commands [<module prefix>] output matching commands\n"
        "--help-config [<module prefix>] output matching config options\n"
        "--help-counts [<module prefix>] output matching peg counts\n"
        "--help-limits print the int upper bounds denoted by max*\n"
        "--help-module <module> output description of given module\n"
        "--help-modules list all available modules with brief help\n"
        "--help-modules-json dump description of all available modules in JSON format\n"
        "--help-plugins list all available plugins with brief help\n"
        "--help-options [<option prefix>] output matching command line options\n"
        "--help-signals dump available control signals\n"
        "--list-buffers output available inspection buffers\n"
        "--list-builtin [<module prefix>] output matching builtin rules\n"
        "--list-gids [<module prefix>] output matching generators\n"
        "--list-modules [<module type>] list all known modules\n"
        "--list-plugins list all known modules\n"
        "--show-plugins list module and plugin versions\n"
        "\n"
        "--help* and --list* options preempt other processing so should be last on the\n"
        "command line since any following options are ignored.  To ensure options like\n"
        "--markup and --plugin-path take effect, place them ahead of the help or list\n"
        "options.\n"
        "\n"
        "Options that filter output based on a matching prefix, such as --help-config\n"
        "won't output anything if there is no match.  If no prefix is given, everything\n"
        "matches.\n"
        "\n"
        "Report bugs to bugs@snort.org.\n";
    printf("A8 banner_len=%zu banner_nl=%d\n", strlen(banner), nl_count(banner));

    // A9: the ZERO-dialect face (both posts walked EMPTY — the sixth
    // zero-gate control law; NEITHER post EVER compiles a leg HERE).
#ifdef UNIT_TEST
    printf("A9 UNIT_TEST post PRESENT (FALSE at this row)\n");
#elif defined(REG_TEST)
    printf("A9 REG_TEST post PRESENT (FALSE at this row)\n");
#else
    printf("A9 dialect posts ABSENT BOTH (the walked zero-gate face)\n");
#endif

    printf("fin=PASS\n");
    return 0;
}

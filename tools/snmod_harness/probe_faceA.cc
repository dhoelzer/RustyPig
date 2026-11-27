// probe_faceA.cc — FACE-A: the parameters-table walk at the PLAIN posture
// (s_params walked via the Module's PUBLIC get_parameters() seat — the
// dialect rows NEVER compiled in at this posture: SHELL 8 + REG_TEST 2 +
// UNIT_TEST 1 = 11 dialect rows ABSENT, walked live), + the s_help face
// (the #ifdef SHELL two-face macro: the plain leg 'command line
// configuration'), + the trace-options walk (DEBUG_MSGS OFF -> EXACTLY-1
// named row + sentinel), + the REAL SFDAQConfig defaults batch=64
// mru=1518 (the landed-home defaults face), + the profile-index census
// (get_profile 0..5: five named records + the nullptr tail).
#include <cstdio>
#include <cstring>

#include "framework/module.h"
#include "framework/parameter.h"
#include "trace/trace.h"
#include "main/snort_config.h"
#include "packet_io/sfdaq_config.h"
#include "snort_module.h"

using namespace snort;

int main()
{
    SnortModule mod;

    int named = 0, implied = 0, enumerated = 0;
    const char* first = nullptr;
    const char* last = nullptr;
    const Parameter* p = mod.get_parameters();
    for (; p->name; ++p)
    {
        if (!first) first = p->name;
        last = p->name;
        ++named;
        if (Parameter::PT_IMPLIED == p->type) ++implied;
        if (Parameter::PT_ENUM == p->type || Parameter::PT_SELECT == p->type) ++enumerated;
    }
    printf("A1 named=%d first=%s last=%s\n", named, first, last);
    printf("A2 sentinel type=%d name=%s\n", (int)p->type, p->name ? "nonnull" : "null");
    printf("A3 implied=%d enum_or_select=%d\n", implied, enumerated);

    // the s_help face: plain posture (SHELL OFF) rides 'command line
    // configuration'; the SHELL dialect face 'command line configuration
    // and shell commands' NEVER compiles in at this posture (cited).
    printf("A4 help=%s usage=%d\n", mod.get_help(), (int)mod.get_usage());

    // the trace-options walk (DEBUG_MSGS OFF: main/mime/conf legs DEAD)
    const TraceOption* t = mod.get_trace_options();
    int tn = 0;
    for (; t && t->name; ++t) { printf("A5 trace=%s id=%d\n", t->name, (int)t->id); ++tn; }
    printf("A6 trace_named=%d\n", tn);

    // the profile ladder: five named records + the nullptr tail at 5
    unsigned i = 0;
    for (;; ++i)
    {
        const char* n = nullptr; const char* pn = nullptr;
        if (!mod.get_profile(i, n, pn)) break;
        printf("A7 prof%u=%s parent=%s\n", i, n, pn ? pn : "null");
        if (i > 8) break;
    }
    printf("A8 prof_count=%u\n", i);

    // the REAL SFDAQConfig defaults (the 23a landed-home constants face)
    SFDAQConfig dcfg;
    printf("A9 batch=%u mru=%d timeout=%u\n",
        dcfg.get_batch_size(), dcfg.get_mru_size(), dcfg.timeout);

    printf("fin=PASS\n");
    return 0;
}

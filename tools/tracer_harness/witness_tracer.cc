// row-22b witness: the EXACTLY-3 own-new carrier arms the row link needs
// (plan q4 census: probe face = tracer.o + ipheavy-carried REAL .o's).
// (1) snort::snort_strdup -- util.h:119 decl; the REAL body lives in a LATER
//     utils TU the donor never compiled (util_cstring.cc has none) -> own
//     carrier (the sfd FOUND-0 face precedent, honest mirror body).
// (2) snort::layer::get_inner_ip6_frag() -- layer.h:143 decl; ip.cc:112 pull;
//     the real provider = src/protocols/layer.cc (NOT donor-resident). The
//     pull is UNREACHABLE on the tracer ladder (IpApi::set(const uint8_t*)
//     path NEVER called) -> DECL-body mirror returns nullptr, NEVER invented.
// (3) snort::ts_print -- util.h:122 decl, util.cc:140-:197 REAL provider home
//     (cited NOT linked: util.o dragged SnortConfig::get_conf -> the null-
//     config SEGV face the subagent survey pinned). The witness body MIRRORS
//     the util.cc:148-:165 + :192-:195 DEFAULT arm (thiszone=0, no UTC, no
//     year, yyyymmdd=false) over the FIXED anchor timeval the tracer.cc :69
//     nullptr-callsite would otherwise randomize (gettimeofday wall-clock) ->
//     byte-exact vectors. NEVER the real arm's face: honest witness mirror.
#include "utils/util.h"
#include "utils/util_cstring.h"   // SnortSnprintf (the REAL donor-resident provider)
#include "sfip/sf_ip.h"
#include "protocols/layer.h"
#include <cstdio>
#include <ctime>

namespace snort
{
char* snort_strdup(const char* s) { return s ? strdup(s) : nullptr; }

namespace layer
{
// the layer.h:143 arm rides namespace snort::layer (the mangled face
// _ZN5snort5layer19get_inner_ip6_fragEv — the plain-snort twin is the
// Packet* overload, NEVER pulled).
const ip::IP6Frag* get_inner_ip6_frag() { return nullptr; }
}

void ts_print(const struct timeval* tvp, char* timebuf, bool yyyymmdd)
{
    // FIXED anchor (the harness determinism face): 2024-03-14 09:00:00Z +123us
    struct timeval anchor = { 1710406800, 123 };
    const struct timeval* tv = tvp ? tvp : &anchor;

    // util.cc:155 thiszone=0 (SnortConfig default :346); :158-:160 UTC-off arm
    // NEVER flips it here; util.cc:163-:164 the day-remainder face:
    int s = (int)((tv->tv_sec + 0) % 86400);
    time_t Time = (time_t)(tv->tv_sec + 0) - s;
    struct tm ttm;
    struct tm* lt = gmtime_r(&Time, &ttm);
    if (!lt) { SnortSnprintf(timebuf, TIMEBUF_SIZE, "%lu", (unsigned long)tv->tv_sec); return; }

    if (yyyymmdd) {   // util.cc:184-:188 arm (tracer NEVER takes it -- :69 default arg)
        SnortSnprintf(timebuf, TIMEBUF_SIZE, "%04d-%02d-%02d %02d:%02d:%02d.%06u",
            lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday, s/3600, (s%3600)/60, s%60, (unsigned)tv->tv_usec);
        return;
    }
    // util.cc:172 output_include_year FALSE (output_flags default) ->
    // the util.cc:192-:195 face VERBATIM: "%02d/%02d-%02d:%02d:%02d.%06u"
    SnortSnprintf(timebuf, TIMEBUF_SIZE, "%02d/%02d-%02d:%02d:%02d.%06u",
        lt->tm_mon + 1, lt->tm_mday, s/3600, (s%3600)/60, s%60, (unsigned)tv->tv_usec);
}
}

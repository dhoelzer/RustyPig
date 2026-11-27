// probe_faceA.cc — FACE-A: the pure/ordinal census at the PLAIN posture
// walked through the GROUND head seats (the zero-gate dialect face): the
// clear_counter_type ENUM ordinal map (h :88-:99 — TYPE_INVALID=-1 ..
// TYPE_ALL=7 walked via a runtime switch, NO CATCH/TEST legs); the h :104
// clear_counter_type_string_map (the h-#define-less 'static' face — 7
// entries, the ordinal-vs-string arithmetic the RESET_STATS family rides);
// INET6_ADDRSTRLEN (45, the latency dtor's four format buffers' seat) +
// the DIOCTL struct sizeof faces (the wall mirror's arglen pin seat); the
// h :261 REG_TEST main_unicast_command DECL ABSENT face (the dialect NEVER
// compiled — the cmake REG_TEST-token-ABSENT walked face); the StatsOutput-
// Format 2-member census; the clear_counter_type_string_map size-vs-ordinal
// gap face (TYPE_ALL=7 PAST the 7-entry vector's end() — the row NEVER
// indexes the map with TYPE_ALL: cite law honest); + the analyzer-h inline
// policy faces read off a crafted handle (get_state/is_idling) and the
// SFDAQInstance ctor/dtor handle faces. ZERO pointers/time in vectors.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <arpa/inet.h>

#include "main/analyzer_command.h"
#include "main/analyzer.h"
#include "main/stats_output_format.h"
#include "main/reload_tuner.h"
#include "packet_io/sfdaq_instance.h"

using namespace snort;

extern "C" void witness_analyzer_ctor_state(int);

static const char* ordinal_name(int v)
{
    switch (v)
    {
        case TYPE_INVALID: return "INVALID";
        case TYPE_DAQ:     return "DAQ";
        case TYPE_MODULE:  return "MODULE";
        case TYPE_APPID:   return "APPID";
        case TYPE_FILE_ID: return "FILE_ID";
        case TYPE_SNORT:   return "SNORT";
        case TYPE_HA:      return "HA";
        case TYPE_MESSAGING: return "MESSAGING";
        case TYPE_ALL:     return "ALL";
        default:           return "OUT";
    }
}

int main()
{
    // the ENUM census (h :88-:99): the 9 walkers, ordinals printed
    clear_counter_type_t walk[] = { TYPE_INVALID, TYPE_DAQ, TYPE_MODULE,
        TYPE_APPID, TYPE_FILE_ID, TYPE_SNORT, TYPE_HA, TYPE_MESSAGING, TYPE_ALL };
    printf("A1 ordinals:");
    for (auto t : walk) printf(" %s=%d", ordinal_name((int)t), (int)t);
    printf("\n");

    // the h :104 string map (the SAME TU-scope 'static' the row .o defines —
    // the probe rides its OWN copy of the header's map through ITS own TU;
    // the identity law rides the SAME literal faces); the size-vs-ordinal
    // gap face: TYPE_ALL=7 sits PAST the 7-entry end() (NEVER indexed).
    printf("A2 map_sz=%zu map[0]=%s map[6]=%s all_gap=%d\n",
        clear_counter_type_string_map.size(), clear_counter_type_string_map[0],
        clear_counter_type_string_map[6],
        (int)TYPE_ALL >= (int)clear_counter_type_string_map.size() ? 1 : 0);

    // the buffer/struct face seat the dtor ladders + wall mirror ride
    printf("A3 strlen45=%d cpu_sz=%zu lat_sz=%zu proto_max=%d\n",
        INET6_ADDRSTRLEN, sizeof(DIOCTL_GetCpuProfileData),
        sizeof(DIOCTL_GetSnortLatencyData), (int)DAQ_SNORT_LATENCY_PROTO_MAX);

    // the StatsOutputFormat census (the ACGetStats format leg)
    printf("A4 statsfmt=%d,%d\n", (int)StatsOutputFormat::Text, (int)StatsOutputFormat::Json);

#ifdef REG_TEST
    printf("A5 REG_TEST decl PRESENT\n");
#else
    printf("A5 REG_TEST main_unicast_command DECL ABSENT (h :261 dialect, cmake OFF walked)\n");
#endif

    // the analyzer-h INLINE policy faces off the crafted handle (mirror
    // ctor stores its OWN privates; the row's gate rides these INLINES)
    witness_analyzer_ctor_state(2);
    Analyzer a(nullptr, 1, "fa");
    witness_analyzer_ctor_state(3);
    Analyzer b(nullptr, 2, "fb");
    printf("B1 state=%d,%d idling=%d src=%s,%s\n", (int)a.get_state(),
        (int)b.get_state(), b.is_idling() ? 1 : 0, a.get_source(), b.get_source());

    // the tuner constants (the RELOAD_MAX faces, h :77/:79)
    printf("B2 maxwork=%u,%u\n", ReloadResourceTuner::RELOAD_MAX_WORK_PER_PACKET,
        ReloadResourceTuner::RELOAD_MAX_WORK_WHEN_IDLE);

    // the string_map literal faces (the RESET_STATS name-table identity)
    const char* want[7] = { "daq", "module", "appid", "file_inspect", "snort",
        "high_availability", "mp_data_bus" };
    int same = 1;
    for (int i = 0; i < 7; ++i)
        if (strcmp(want[i], clear_counter_type_string_map[i]) != 0) same = 0;
    printf("B3 map_identity=%d\n", same);

    // the format_ip_addr determinism arm: the SAME inet_ntop calls the row's
    // REAL static (cc :60) makes, replayed on the crafted fixed addrs (the
    // v4-in-v6 first-4 form + the 2001:db8::1 face) — the vectors PROVE the
    // witness pokes' textual faces the dtor ladder printed match.
    char buf[INET6_ADDRSTRLEN];
    struct in6_addr v4ish; memset(&v4ish, 0, sizeof(v4ish));
    v4ish.s6_addr[0] = 203; v4ish.s6_addr[1] = 2; v4ish.s6_addr[2] = 113; v4ish.s6_addr[3] = 7;
    struct in_addr v4; memcpy(&v4, &v4ish, 4);
    inet_ntop(AF_INET, &v4, buf, INET6_ADDRSTRLEN);
    printf("C1 v4=%s\n", buf);
    const unsigned char v6[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    struct in6_addr a6; memcpy(&a6, v6, 16);
    inet_ntop(AF_INET6, &a6, buf, INET6_ADDRSTRLEN);
    printf("C2 v6=%s\n", buf);
    struct in6_addr z6; memset(&z6, 0, sizeof(z6));
    inet_ntop(AF_INET6, &z6, buf, INET6_ADDRSTRLEN);
    printf("C3 v6z=%s\n", buf);

    printf("fin=PASS\n");
    return 0;
}

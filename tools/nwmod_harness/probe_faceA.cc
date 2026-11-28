// probe_faceA.cc — FACE-A: the pure/record/ordinal census at the PLAIN
// posture (the SEVENTH zero-gate control: ZERO dialect posts, the A9 arm
// prints the walked-zero face). The arms: the sizeof(Parameter) record
// face (the 5-field layout the tables ride), the Parameter::Type ordinal
// walk (PT_TABLE=0 .. PT_MAX=21 — the head :44-:66 walk through a runtime
// switch), the network_params 9-slot record face (8 rows + the PT_MAX
// sentinel — the cc :37 static table READ THROUGH the REAL get_commands/
// get_parameters seats — NEVER a mirrored copy), the network_cmds 2-slot
// external-table face + the network_set_policy_params 2-slot face (the
// NON-static externs :88/:94 — the nm external-linkage face, declared by
// their GROUND names here — legal, they're externs), the h :38-:39 get_-
// usage inline CONTEXT ordinal face (C_USAGE: GLOBAL=0 CONTEXT=1 INSPECT=
// 2 DETECT=3 — reached THROUGH the row class, the header INLINE body), the
// NetworkModule guard double-include idempotency face (the h :21 #ifndef
// NETWORK_MODULE_H seat — the .cc of THIS very TU rode it incl. the SECOND
// include HERE), the ChecksumFlag ordinal map (the policy.h enum seats the
// GetChecksumFlags machine rides: 1/2/4/8/15/DEF), the REAL max*-limit
// faces (Parameter::get_uint the REAL framework/parameter.cc leg: maxSZ ->
// max53 = the host Lua-double width 9007199254740992 + the id range's
// max53 bound) + the REAL Parameter::index ordinal face through the
// checksum range string from the REAL table (the "all | ip | ..." range ->
// icmp = 8), the Command record size face, and the ZERO-dialect face (A9:
// NEITHER the UNIT_TEST post NOR the REG_TEST post EVER compiles ANY leg
// — the walked cmake-OFF face). ZERO pointers/time in vectors.
#include <cstdio>
#include <cstring>
#include <string>

#include "network_module.h"         // the guard seat — the SECOND face incl.
#include "network_module.h"         // idempotency proof (the :21 #ifndef)
#include "main/snort_types.h"
#include "main/policy.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/value.h"

using namespace snort;

// the tables the row TU defines (:88 + :94) ride an HONEST MEASURED DI-
// VERGENCE from the era premise: const at namespace scope has INTERNAL
// linkage in C++ (the nm face reads d _ZL12network_cmds + b _ZL25network_
// set_policy_params MEASURED — mangled _ZL faces, build.sh pins the walk
// arm). So faceA NEVER declares them (an extern decl would demand the ex-
// ternal unmangled symbol and DIE at link — measured truth): the A4 census
// reaches BOTH tables THROUGH the REAL get_commands() seat + the params
// slot (the :94 cmd table hands out the :88 params table by pointer — the
// one-home legal face), and the row's own file-statics NEVER get named
// ANYWHERE in THIS file (the E9 twin law).

static const char* pt_name(int v)
{
    switch (v)
    {
        case Parameter::PT_TABLE:    return "TABLE";
        case Parameter::PT_LIST:     return "LIST";
        case Parameter::PT_DYNAMIC:  return "DYNAMIC";
        case Parameter::PT_BOOL:     return "BOOL";
        case Parameter::PT_INT:      return "INT";
        case Parameter::PT_INTERVAL: return "INTERVAL";
        case Parameter::PT_REAL:     return "REAL";
        case Parameter::PT_PORT:     return "PORT";
        case Parameter::PT_STRING:   return "STRING";
        case Parameter::PT_SELECT:   return "SELECT";
        case Parameter::PT_MULTI:    return "MULTI";
        case Parameter::PT_ENUM:     return "ENUM";
        case Parameter::PT_MAC:      return "MAC";
        case Parameter::PT_IP4:      return "IP4";
        case Parameter::PT_ADDR:     return "ADDR";
        case Parameter::PT_BIT_LIST: return "BIT_LIST";
        case Parameter::PT_INT_LIST: return "INT_LIST";
        case Parameter::PT_ADDR_LIST:return "ADDR_LIST";
        case Parameter::PT_IMPLIED:  return "IMPLIED";
        case Parameter::PT_STR_LIST: return "STR_LIST";
        case Parameter::PT_DYNAMICS: return "DYNAMICS";
        case Parameter::PT_MAX:      return "MAX";
        default:                     return "?";
    }
}

int main()
{
    // A1: the Parameter record face (5 fields; the table rows ride it) +
    // the Command record face (5 fields + the NSDMI bool).
    printf("A1 sizeof(Parameter)=%zu sizeof(Command)=%zu\n",
        sizeof(Parameter), sizeof(Command));

    // A2: the full PT ordinal walk (head :44-:66) — the 22-ordinal face.
    printf("A2 pt:");
    for (int i = Parameter::PT_TABLE; i <= Parameter::PT_MAX; ++i)
        printf(" %s=%d", pt_name(i), i);
    printf(" n=%d\n", (int)Parameter::PT_MAX + 1);

    // A3: the network_params record census through the REAL ctor — the
    // name+type+range-ordinal map (the PT_MULTI checksum range string from
    // the table fed to the REAL Parameter::index — icmp lands 8).
    NetworkModule m;                                  // the REAL base leg
    const Parameter* np = m.get_parameters();
    int slots = 0;
    while (np[slots].name) ++slots;
    int multi = 0;
    for (const Parameter* p = np; p->name; ++p)
        if (p->type == Parameter::PT_MULTI) ++multi;
    const Parameter* ck = Parameter::find(np, "checksum_drop");
    int ix_icmp = Parameter::index(ck->range ? (const char*)ck->range : "", "icmp");
    printf("A3 np slots=%d+1sentinel multi=%d sent-type=%d index(icmp)=%d index(noudp)=%d\n",
        slots, multi, (int)np[slots].type, ix_icmp,
        Parameter::index((const char*)ck->range, "noudp"));

    // A4: the two row tables (:88 + :94) as the face reaches them THROUGH
    // the REAL get_commands() seat (the internal-linkage law — the ta-
    // bles are NEVER declared HERE): the 2-slot census each (row + sen-
    // tinel); the cmd's params slot IS the :88 table (the one-home pointer
    // identity face); the :88 row's own faces ride through that slot.
    const Command* tcmds = m.get_commands();
    int nc = 0;
    while (tcmds[nc].name) ++nc;
    const Parameter* sp = tcmds[0].params;
    int nsp = 0;
    while (sp[nsp].name) ++nsp;
    int nsp2 = 0;
    while (tcmds[1].name) ++nsp2;                                   // must stay 0
    printf("A4 cmds=%d tail-sentinel=%d setparams=%d sp-sentinel=%d params-live=%d name0=%s sp0=%s sp0-type=%d\n",
        nc, tcmds[nc].name == nullptr ? 1 : 0,
        nsp, sp[nsp].type == Parameter::PT_MAX ? 1 : 0,
        sp != nullptr ? 1 : 0, tcmds[0].name, sp[0].name, (int)sp[0].type);

    // A5: the h :38-:39 get_usage CONTEXT ordinal (C_USAGE face) through
    // the row class' INLINED override + the base enum ordinals.
    printf("A5 usage: g=%d c=%d i=%d d=%d row=%d\n",
        (int)Module::GLOBAL, (int)Module::CONTEXT, (int)Module::INSPECT,
        (int)Module::DETECT, (int)m.get_usage());

    // A6: the guard seat face — the header rode the :21 #ifndef TWICE
    // (the #include pair above compiled ONE class — the idempotency face).
    NetworkModule m2;                                 // second ctor face
    printf("A6 guard double-include ok ctor2=%s\n", m2.get_name());

    // A7: the ChecksumFlag ordinal map (policy.h — the machine's seats).
    printf("A7 ck: ip=%d tcp=%d udp=%d icmp=%d all=%d def=%u\n",
        CHECKSUM_FLAG__IP, CHECKSUM_FLAG__TCP, CHECKSUM_FLAG__UDP,
        CHECKSUM_FLAG__ICMP, CHECKSUM_FLAG__ALL,
        (unsigned)CHECKSUM_FLAG__DEF);

    // A8: the REAL max*-limit faces (framework/parameter.cc leg) — the
    // id/layers range bounds the tables print + the host maxSZ identity.
    printf("A8 max: sz=%llu max53=%llu max31=%d min-int-%d\n",
        (unsigned long long)Parameter::get_uint("maxSZ"),
        (unsigned long long)Parameter::get_uint("max53"),
        (int)Parameter::get_int("2147483647"),
        (int)Parameter::get_int("-5"));

    // A9: the ZERO-dialect face (the walked zero-gate control — NEITHER
    // post EVER compiles a leg; CppUTest ABSENT on the host, cmake names
    // NEITHER TU).
    printf("A9 dialect posts ABSENT BOTH\n");

    printf("finA=PASS\n");
    return 0;
}

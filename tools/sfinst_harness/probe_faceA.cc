// row-23b probe_faceA.cc — the C-ABI / gate-face ladder for the
// SFDAQInstance pair (the row-23a probe_faceA template shape). EVERY face
// here is MEASURED probe-side (the NEVER-size_of-as-the-pin law: the
// sizeofs/offsets PRINT, src/packet_io/sfdaq_instance.rs cites the
// measured faces). Faces: (1) the REAL DIOCTL record shapes the ioctl
// legs cc :321-:363 ride + the add_expected cc :365-:436 key/cef layout;
// (2) the key field OFFSETS — the address_space_id field EXISTS in the
// REAL struct (the 22b wall face) while cc :391 FIXIT-M NEVER fills it
// (the honest NEVER-printed-garbage law; the offset proves the field,
// the vectors prove the ABSENCE of any fill); (3) the DAQ_CAPA_* family
// the get_tunnel_capabilities cc :236-:255 map rides + the 10-DECODE
// sum; (4) the TunnelEncap enum face (snort_config.h :119-:128) + the
// 0x3FF all-ten ceiling of the cc :259-:261 AND-face; (5) the DIOCTL
// ordinals + DAQ_EFLOW_* flags + tunnel-type ordinals; (6) the REAL
// DAQ_State walk through the SDK state machine (the was_started
// cc :264-:271 hinge — raw daq_instance_* legs, the private `instance`
// field NEVER poked); (7) the NULL-instance SDK faces the pair's
// can_*/was_started/get_error ride UN guarded (sfdaq NEVER checks — the
// SDK does: caps 0 / UNKNOWN / NULL / NOCTX / NOCTX); (8) the
// set_filter NOTSUP -> FatalError leg (cc :93-:96) riding the carried
// witness_conf body on STDERR — the faceA_stderr.txt pin, NEVER the
// vectors face (the DEC SILENT-stderr law). THE 23b noreturn LAW: the
// ground messages.h:105 declares FatalError [[noreturn]] — the harness
// rides the build.sh RIDER on the carried witness body (print + jump),
// and the probe ARMS the jump site around init(): the REAL control face
// (init NEVER continues) at O0 AND O2; the carried return-face was UB
// (5/5 deterministic rc139 SIGSEGV at -O2, crash-proved at the row).
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_config.h"

#include <daq.h>
#include <daq_module_api.h>

#include <csetjmp>
#include <cstddef>
#include <cstdio>

#include "main/snort_config.h"

// ---- the FACE-A-only static module: set_filter NOTSUP ONLY (the
// FatalError driver; every other leg default-RESOLVES through the REAL
// resolve_instance_api law — the state walk rides the default
// start/stop SUCCESS); the DEC "inst" module NEVER touches this face:
static int f_load(const DAQ_BaseAPI_t*) { return DAQ_SUCCESS; }
static int f_inst(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) {
    static int ctx; *c = &ctx; return DAQ_SUCCESS;
}
static int f_set_filter(void*, const char*) { return DAQ_ERROR_NOTSUP; }
static void f_destroy(void*) { }
static DAQ_ModuleAPI_t fatal_mod = {
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t), 1, "fatal", 0,
    f_load, nullptr, nullptr, f_inst, f_destroy,
    f_set_filter,
};

using namespace snort;

int main() {
    DAQ_Module_h mods[2] = { &fatal_mod, nullptr };
    int nreg = daq_load_static_modules(mods);

    // (1) the REAL C-ABI record shapes (measured prints):
    printf("SIZES key=%zu cef=%zu sfo=%zu spvr=%zu sptd=%zu pool=%zu stats=%zu msg=%zu modapi=%zu instapi=%zu\n",
        sizeof(DAQ_EFlow_Key_t), sizeof(DIOCTL_CreateExpectedFlow),
        sizeof(DIOCTL_SetFlowOpaque), sizeof(DIOCTL_SetPacketVerdictReason),
        sizeof(DIOCTL_SetPacketTraceData), sizeof(DAQ_MsgPoolInfo_t),
        sizeof(DAQ_Stats_t), sizeof(DAQ_Msg_t), sizeof(DAQ_ModuleAPI_t),
        sizeof(DAQ_InstanceAPI_t));

    // (2) the key OFFSETS (the address_space_id field EXISTS @ off; the
    // cc NEVER populates it — the honest absence, cited NEVER printed):
    printf("OFFS key src_af=%zu dst_af=%zu sa=%zu da=%zu proto=%zu sport=%zu dport=%zu as=%zu tun=%zu vlan=%zu cnots=%zu\n",
        offsetof(DAQ_EFlow_Key_t, src_af), offsetof(DAQ_EFlow_Key_t, dst_af),
        offsetof(DAQ_EFlow_Key_t, sa), offsetof(DAQ_EFlow_Key_t, da),
        offsetof(DAQ_EFlow_Key_t, protocol), offsetof(DAQ_EFlow_Key_t, src_port),
        offsetof(DAQ_EFlow_Key_t, dst_port), offsetof(DAQ_EFlow_Key_t, address_space_id),
        offsetof(DAQ_EFlow_Key_t, tunnel_type), offsetof(DAQ_EFlow_Key_t, vlan_id),
        offsetof(DAQ_EFlow_Key_t, vlan_cnots));

    // (3) the DECODE-family caps map inputs (cc :236-:255) + the sum:
    printf("CAPA block=%x inject=%x inject_raw=%x unpriv=%x whitelist=%x replace=%x inject_drop=%x dsum=%x\n",
        DAQ_CAPA_BLOCK, DAQ_CAPA_INJECT, DAQ_CAPA_INJECT_RAW, DAQ_CAPA_UNPRIV_START,
        DAQ_CAPA_WHITELIST, DAQ_CAPA_REPLACE, DAQ_CAPA_INJECT_DROP,
        (unsigned)(DAQ_CAPA_DECODE_GTP | DAQ_CAPA_DECODE_TEREDO | DAQ_CAPA_DECODE_VXLAN |
                   DAQ_CAPA_DECODE_GRE | DAQ_CAPA_DECODE_4IN4 | DAQ_CAPA_DECODE_6IN4 |
                   DAQ_CAPA_DECODE_4IN6 | DAQ_CAPA_DECODE_6IN6 | DAQ_CAPA_DECODE_MPLS |
                   DAQ_CAPA_DECODE_GENEVE));

    // (4) the TunnelEncap face + the all-ten tunnel-mask ceiling face:
    printf("TUNNEL gtp=%d teredo=%d 6in4=%d 4in6=%d 4in4=%d 6in6=%d gre=%d mpls=%d vxlan=%d geneve=%d ceiling=%d\n",
        TUNNEL_GTP, TUNNEL_TEREDO, TUNNEL_6IN4, TUNNEL_4IN6, TUNNEL_4IN4,
        TUNNEL_6IN6, TUNNEL_GRE, TUNNEL_MPLS, TUNNEL_VXLAN, TUNNEL_GENEVE,
        TUNNEL_GTP|TUNNEL_TEREDO|TUNNEL_6IN4|TUNNEL_4IN6|TUNNEL_4IN4|
        TUNNEL_6IN6|TUNNEL_GRE|TUNNEL_MPLS|TUNNEL_VXLAN|TUNNEL_GENEVE);

    // (5) the DIOCTL ordinals (the ioctl legs' command face) + EFLOW flags:
    printf("DIO sfo=%d trace=%d reason=%d eflow=%d last=%d eflag float=%d multi=%d persist=%d bidir=%d ttype non=%d gtp=%d mpls=%d other=%d\n",
        (int)DIOCTL_SET_FLOW_OPAQUE, (int)DIOCTL_SET_PACKET_TRACE_DATA,
        (int)DIOCTL_SET_PACKET_VERDICT_REASON, (int)DIOCTL_CREATE_EXPECTED_FLOW,
        (int)LAST_BUILTIN_DIOCTL_CMD, DAQ_EFLOW_FLOAT, DAQ_EFLOW_ALLOW_MULTIPLE,
        DAQ_EFLOW_PERSIST, DAQ_EFLOW_BIDIRECTIONAL, DAQ_EFLOW_TUNNEL_TYPE_NON_TUNNEL,
        DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL, DAQ_EFLOW_TUNNEL_TYPE_MPLS_TUNNEL,
        DAQ_EFLOW_TUNNEL_TYPE_OTHER_TUNNEL);

    // (6) the REAL DAQ_State walk (raw legs — the private field NEVER
    // poked): instantiate -> INITIALIZED; start -> STARTED; stop ->
    // STOPPED; the cc :264-:271 hinge = s == DAQ_STATE_STARTED ONLY:
    DAQ_Config_h cfg;
    daq_config_new(&cfg);
    DAQ_ModuleConfig_h mc;
    daq_module_config_new(&mc, const_cast<DAQ_Module_h>(daq_find_module("fatal")));
    daq_config_push_module_config(cfg, mc);
    DAQ_Instance_h raw = nullptr;
    char errbuf[256] = "";
    int rinc = daq_instance_instantiate(cfg, &raw, errbuf, sizeof errbuf);
    int s0 = (int)daq_instance_check_status(raw);
    int st1 = daq_instance_start(raw);
    int s1 = (int)daq_instance_check_status(raw);
    int sp = daq_instance_stop(raw);
    int s2 = (int)daq_instance_check_status(raw);
    DAQ_MsgPoolInfo_t pi;
    int poolr = daq_instance_get_msg_pool_info(raw, &pi);   // default NOTSUP
    int dltr = daq_instance_get_datalink_type(raw);          // default DLT_NULL=0
    printf("STATE rinc=%d s_init=%d start=%d s_started=%d state_started=%d stop=%d s_stopped=%d pool=%d dlt=%d\n",
        rinc, s0, st1, s1, (int)DAQ_STATE_STARTED, sp, s2, poolr, dltr);

    // (7) the NULL-instance SDK faces (h :61 nullptr = the dead-wire
    // arithmetic the pair rides UN guarded):
    uint32_t cnull = daq_instance_get_capabilities(nullptr);
    int snull = (int)daq_instance_check_status(nullptr);
    const char* enull = daq_instance_get_error(nullptr);
    int fnull = daq_instance_msg_finalize(nullptr, nullptr, DAQ_VERDICT_PASS);
    int injnull = daq_instance_inject_relative(nullptr, nullptr, (const uint8_t*)"x", 1, 0);
    int inull = daq_instance_interrupt(nullptr);
    printf("NULLFACE caps=%u state=%d errnull=%d fin=%d inj=%d intr=%d\n",
        cnull, snull, enull == nullptr ? 1 : 0, fnull, injnull, inull);

    // (8) the cc :91-:97 set_filter-FatalError leg THROUGH THE PAIR: the
    // SFDAQInstance over the fatal module + a NON-empty bpf -> the REAL
    // daq_instance_set_filter NOTSUP + get_error feeds the FatalError
    // args; the carried witness_conf FatalError body writes STDERR (the
    // faceA_stderr pin line) and NEVER aborts (driverless) -> the
    // init-CONTINUES TRUE face. The raw instance above is destroyed by
    // THIS leg's sibling? NO — destroyed HERE (the real dtor leg):
    // THE noreturn face (the 23b honest re-ride): FatalError NEVER returns
    // (ground messages.h:105 [[noreturn]]) — the witness jump site is
    // armed, so init NEVER continues: the SAME control face at O0 and O2
    // (a returning witness was UB: deterministic O2 SIGSEGV, cited in
    // the deviations). The inst object is NEVER destructed HERE (longjmp
    // skips it — the honest jump face; the destroy face rides the raw leg
    // below):
    {
        extern sigjmp_buf fatal_jump;                       // the witness site (global)
        extern bool fatal_jump_armed;                       // the arming face (global)
        SFDAQConfig scfg;              // batch 0 -> 64 (the h :63 face)
        SFDAQInstance inst("iface", 0, &scfg);
        fatal_jump_armed = true;
        if (sigsetjmp(fatal_jump, 1) == 0)
            inst.init(cfg, "vlan 7");  // the NOTSUP -> FatalError NEVER-returns leg
        else
            printf("FATALLEG jumped=1 was=%d\n", inst.was_started() ? 1 : 0);
        // NOTE cfg NEVER destroyed HERE — the pair's dtor destroys only
        // the INSTANCE; daq_config_destroy runs below (the config belongs
        // to the caller, the sfdaq.cc daqcfg-static owner face):
    }   // the SFDAQInstance dtor runs on the normal path; the jump face
        // skips it (the raw destroy below rides the same REAL legs)
    daq_instance_destroy(raw);         // the raw-instance destroy face
    daq_config_destroy(cfg);
    printf("A2 reg=%d\n", nreg);
    return 0;
}

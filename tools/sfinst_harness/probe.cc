// row-23b probe.cc — THE real-SDK DEC ladder for the SFDAQInstance pair
// (packet_io/sfdaq_instance.cc 436 md5 0b2a92f5b16344794714cfeda2cae8ed +
// .h 105 md5 9497f39441174c4260d4db22e55740bf @ fe29cbe FRESH cps). THE
// seam-close row: the .cc compiles VERBATIM against the REAL libdaq SDK @
// c8d4083 re-cited copy-local (daq.h 35294a17 + daq_common.h 28789a3d +
// daq_dlt.h 57208729 + daq_module_api.h 1a617b3e + the generated
// daq_version.h 3.0.29 m4 face) and RUNS on the 5 REAL api .o
// (daq_base/daq_base_api/daq_config/daq_instance_api_defaults/daq_mod_ops)
// — every daq_instance_*/daq_config_* call in the bodies is the REAL SDK
// dispatch (daq_mod_ops.c/daq_config.c), the DAQ_State machine is REAL,
// and the instantiate instance-ID sanity (daq_mod_ops.c :182-:188) runs
// LIVE in T1b (the cc :82-:84 ErrorMessage leg). The probe SUPPLIES the
// acquisition side exactly as an SF packet module does: TWO copy-LOCAL
// static DAQ modules — "inst" drives the FULL instance API (per-instance
// Ctx from a static pool — the ground per-instance caps/counters face)
// and "stub" registers the REQUIRED load/instantiate/destroy trio ONLY —
// the OPTIONAL-fn resolve law (daq_mod_ops.c :84-:104 resolve_instance_api
// + daq_instance_api_defaults.c) then yields the REAL default faces: caps
// 0, start/stop SUCCESS, interrupt/ioctl/get_stats/pool-info/reload legs
// NOTSUP (-4), get_datalink_type DLT_NULL. The NOT-LANDED snort bodies
// (daq_stats THE sfdaq_module.cc home, layer::get_vlan_layer THE
// protocols/layer.cc body, Packet ctor/dtor THE packet.cc body — the 22b
// tracer mirror shape) close through witness_sfinst.cc OWN-3 — honest
// cite stand-ins, NEVER real bodies; the messages trio (LogMessage/
// ErrorMessage/ParseWarning) is witness-owned, the FatalError +
// SnortConfig::get_conf + SnortConfig::logging_flags + get_instance_id
// residues ride the carried witness_conf 4dd91018 family (NEVER doubled).
// The log_verbose arm (cc :185-:191) rides its FALSE face: enable_log_
// verbose is PRIVATE in snort_config.h :765 and the carried witness never
// raises LOGGING_FLAG__VERBOSE — honest cite, cited in KNOWN DEVIATIONS.
// Probe printf hygiene: mutating calls hoisted into locals BEFORE every
// printf (the env law — C++ arg-eval order).
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_module.h"   // the FRESH-cp DECL rider (DAQStats
                                      // :61-:87 + extern daq_stats :87) —
                                      // the cc :433 read; the BODY home
                                      // stays NOT-LANDED (witness-owned)
#include "packet_io/sfdaq_config.h"   // the 22a-era rider (fresh-cp NOW;
                                      // the get_batch_size face h :63-:64)
#include "protocols/packet.h"         // the Field-shape consumer (Packet
                                      // ctor/dtor witness-owned; ONLY the
                                      // daq_msg/proto_bits fields at cc
                                      // :372/:393-:406 are read)
#include "protocols/vlan.h"           // VlanTagHdr::vid() inline face (cc :407)
#include "sfip/sf_ip.h"               // THE REAL SfIp body (sf_ip.o link)

#include <daq.h>
#include <daq_module_api.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "main/snort_config.h"

// witness knobs (witness_sfinst.cc defines; probe reads externs):
namespace snort {
extern char wlog_buf[4096];   extern unsigned wlog_calls;
extern char werr_buf[4096];   extern unsigned werr_calls;
extern char wpw_buf[4096];    extern unsigned wpw_calls;
extern const vlan::VlanTagHdr* wvlan_ptr;
}

// ---- the copy-LOCAL static test modules (row-23a registration precedent): ----
struct Ctx {
    uint32_t caps;                    // scripted per-instance capability mask
    unsigned destroy_calls, filter_calls, start_calls, stop_calls;
    unsigned finalize_calls; DAQ_Verdict last_verdict;
    unsigned recv_calls; unsigned pool_size, pool_avail;
    char filter[128];
    int last_cmd; DIOCTL_CreateExpectedFlow cef; DIOCTL_SetFlowOpaque sfo;
    DIOCTL_SetPacketVerdictReason spvr; DIOCTL_SetPacketTraceData sptd;
    unsigned ioctl_calls;
    int inject_calls, inj_rev; uint32_t inj_len;
    int load_rc; unsigned load_calls, swap_calls, free_calls;
    uint64_t st_hw, st_rx, st_vblk;
};
static Ctx ctx_pool[8];
static unsigned ctx_n = 0;
static DAQ_Msg_t msg_store[2];        // the module-owned fake messages
static unsigned destroy_inst = 0, destroy_stub = 0;

static int m_load(const DAQ_BaseAPI_t*) { return DAQ_SUCCESS; }
static int m_instantiate(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) {
    *c = &ctx_pool[ctx_n++];
    return DAQ_SUCCESS;
}
static int s_instantiate(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) {
    Ctx* x = &ctx_pool[ctx_n++];      // the ALL-ZERO ctx (the resolve-law
    memset(x, 0, sizeof *x);          // face: NOTHING scripted)
    *c = x;
    return DAQ_SUCCESS;
}
static int m_set_filter(void* h, const char* f) {
    Ctx* x = (Ctx*)h;
    x->filter_calls++; snprintf(x->filter, sizeof x->filter, "%s", f);
    return DAQ_SUCCESS;
}
static int m_start(void* h) { ((Ctx*)h)->start_calls++; return DAQ_SUCCESS; }
static int m_stop(void* h)  { ((Ctx*)h)->stop_calls++;  return DAQ_SUCCESS; }
static uint32_t m_caps(void* h) { return ((Ctx*)h)->caps; }
static int m_dlt(void*) { return 228; }                // DLT_IPV4 (REAL)
static int m_pool(void* h, DAQ_MsgPoolInfo_t* i) {
    Ctx* x = (Ctx*)h; i->size = x->pool_size; i->available = x->pool_avail;
    i->mem_size = 1024;
    return DAQ_SUCCESS;
}
static unsigned m_recv(void* h, const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rs) {
    Ctx* x = (Ctx*)h; x->recv_calls++;
    unsigned n = 2 < max_recv ? 2 : max_recv;
    for (unsigned i = 0; i < n; i++) msgs[i] = &msg_store[i];
    *rs = DAQ_RSTAT_OK;
    return n;
}
static int m_fin(void* h, const DAQ_Msg_t*, DAQ_Verdict v) {
    Ctx* x = (Ctx*)h; x->finalize_calls++; x->last_verdict = v; return DAQ_SUCCESS;
}
static int m_injrel(void* h, const DAQ_Msg_t*, const uint8_t*, uint32_t len, int rev) {
    Ctx* x = (Ctx*)h; x->inject_calls++; x->inj_rev = rev; x->inj_len = len;
    return DAQ_SUCCESS;
}
static int m_stats(void* h, DAQ_Stats_t* s) {
    Ctx* x = (Ctx*)h;
    s->hw_packets_received = x->st_hw; s->packets_received = x->st_rx;
    s->verdicts[DAQ_VERDICT_BLOCK] = x->st_vblk;
    return DAQ_SUCCESS;
}
static int m_cfgload(void* h, void** nc) {
    Ctx* x = (Ctx*)h; x->load_calls++; *nc = (void*)0xABCD; return x->load_rc;
}
static int m_cfgswap(void* h, void*, void** oc) {
    Ctx* x = (Ctx*)h; x->swap_calls++; *oc = (void*)0x1234; return DAQ_SUCCESS;
}
static int m_cfgfree(void* h, void*) { ((Ctx*)h)->free_calls++; return DAQ_SUCCESS; }
static int m_ioctl(void* h, DAQ_IoctlCmd cmd, void* arg, size_t) {
    Ctx* x = (Ctx*)h; x->ioctl_calls++; x->last_cmd = (int)cmd;
    switch (cmd) {
        case DIOCTL_SET_FLOW_OPAQUE:            x->sfo  = *(DIOCTL_SetFlowOpaque*)arg; break;
        case DIOCTL_SET_PACKET_VERDICT_REASON:  x->spvr = *(DIOCTL_SetPacketVerdictReason*)arg; break;
        case DIOCTL_SET_PACKET_TRACE_DATA:      x->sptd = *(DIOCTL_SetPacketTraceData*)arg; break;
        case DIOCTL_CREATE_EXPECTED_FLOW:       x->cef  = *(DIOCTL_CreateExpectedFlow*)arg; break;
        default: return DAQ_ERROR_NOTSUP;
    }
    return DAQ_SUCCESS;
}
static void m_destroy(void*)  { destroy_inst++; }
static void s_destroy(void*)  { destroy_stub++; }

static DAQ_ModuleAPI_t inst_mod = {
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t), 1, "inst", 0,
    m_load, nullptr, nullptr, m_instantiate, m_destroy,
    m_set_filter, m_start, nullptr, m_injrel, nullptr, m_stop, m_ioctl,
    m_stats, nullptr, nullptr, m_caps, m_dlt, m_cfgload, m_cfgswap, m_cfgfree,
    m_recv, m_fin, m_pool,
};
static DAQ_ModuleAPI_t stub_mod = {   // REQUIRED trio ONLY (the resolve law):
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t), 1, "stub", 0,
    m_load, nullptr, nullptr, s_instantiate, s_destroy,
};

// note: ctx defaults ride memset-zero for the stub; the "inst" pool fields
// are scripted per-leg right after each init (the ground per-instance face
// — pool 8/8, load_rc SUCCESS, stats 7/1/9, caps per-leg).

using namespace snort;

static DAQ_Config_h mk_cfg(const char* modname, unsigned total) {
    DAQ_Config_h cfg;
    daq_config_new(&cfg);
    DAQ_ModuleConfig_h mc;
    // the REAL registration-table lookup (dq daq_base.c :104-:112 face;
    // the const_cast is the C++ header-shape law of the C API):
    daq_module_config_new(&mc, const_cast<DAQ_Module_h>(daq_find_module(modname)));
    daq_config_push_module_config(cfg, mc);
    if (total) daq_config_set_total_instances(cfg, total);
    return cfg;
}

static std::string squash(const std::string& s) {
    std::string o;
    for (char c : s) if (c != '\n') o += c;
    return o;
}

int main() {
    DAQ_Module_h mods[3] = { &stub_mod, &inst_mod, nullptr };
    int nreg = daq_load_static_modules(mods);
    printf("T0 reg=%d\n", nreg);

    SFDAQConfig cfg;                  // the 22a config TU rides LINK real
    // (default: batch_size 0 -> get_batch_size() = 64 the h :63 face)

    // ---- T0b the ctor face (cc :40-:48): the instance_id 0->1-based +
    // the pre-init legs (instance NULL: the getter defaults + can_*
    // FALSE through daq_instance_get_capabilities(NULL) = 0 the SDK face
    // daq_mod_ops.c :389-:390, and get_error(NULL) = the NULL char*):
    {
        SFDAQInstance i0("ethA", 0, &cfg);
        const char* e0 = i0.get_error();
        printf("T0b spec=[%s] bs=%u avail=%u base=%d ci=%d cir=%d cr=%d cu=%d cd=%d cw=%d errnull=%d\n",
            i0.get_input_spec(), i0.get_batch_size(),
            i0.get_pool_available(), i0.get_base_protocol(), i0.can_inject() ? 1 : 0,
            i0.can_inject_raw() ? 1 : 0, i0.can_replace() ? 1 : 0,
            i0.can_start_unprivileged() ? 1 : 0, i0.can_invoke_inject_drop() ? 1 : 0,
            i0.can_whitelist() ? 1 : 0, e0 == nullptr ? 1 : 0);
    }   // dtor: instance NULL -> daq_instance_destroy NEVER fires (cc :53-:54)

    // ---- T1 the init ladder (REAL daq_config legs + instantiate + the
    // passive DAQ_ValidateInstance early-true + set_filter): total=2 ->
    // the 0->1-based instance_id face rides (cc :78-:79, instance 1 ->
    // DAQ id 2 <= 2 PASSES the REAL sanity gate):
    Ctx& xa = ctx_pool[0];            // the inst-A ctx (instantiate order)
    bool okA = false;
    const char* in_after = nullptr; unsigned iid = 0; int fc = 0;
    {
        SFDAQInstance instA("ethA", 1, &cfg);
        DAQ_Config_h dcfg = mk_cfg("inst", 2);
        okA = instA.init(dcfg, "bpf-in");
        in_after = daq_config_get_input(dcfg);
        iid = daq_config_get_instance_id(dcfg);
        const char* err = instA.get_error();   // the zeroed-errbuf face ""
        fc = (int)xa.filter_calls;
        printf("T1 init=%d input=[%s] iid=%u fc=%d filt=[%s] err=[%s] was=%d\n",
            okA ? 1 : 0, in_after, iid, fc, xa.filter, err ? err : "(null)",
            instA.was_started() ? 1 : 0);
        daq_config_destroy(dcfg);

        // script the inst-A legs NOW (before start): caps the FULL DECODE
        // family + BLOCK/INJECT/etc + the reload/stats faces:
        xa.caps = DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
                  DAQ_CAPA_WHITELIST | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_INJECT_RAW |
                  DAQ_CAPA_INJECT_DROP | DAQ_CAPA_DECODE_GTP | DAQ_CAPA_DECODE_TEREDO |
                  DAQ_CAPA_DECODE_VXLAN | DAQ_CAPA_DECODE_GRE | DAQ_CAPA_DECODE_4IN4 |
                  DAQ_CAPA_DECODE_6IN4 | DAQ_CAPA_DECODE_4IN6 | DAQ_CAPA_DECODE_6IN6 |
                  DAQ_CAPA_DECODE_MPLS | DAQ_CAPA_DECODE_GENEVE;
        xa.pool_size = 8; xa.pool_avail = 8; xa.load_rc = DAQ_SUCCESS;
        xa.st_hw = 7; xa.st_rx = 1; xa.st_vblk = 9;

        // ---- T2 the start ladder (cc :163-:196): pool 8/8 + the verbose
        // conf FALSE face (see the header cite) + the REAL DLT 228 + the
        // can_* caps face (the REAL daq_instance_get_capabilities walk):
        bool started = instA.start();
        int pa = (int)instA.get_pool_available(); unsigned bs = instA.get_batch_size();
        int bp = instA.get_base_protocol();
        printf("T2 started=%d was=%d avail=%d bs=%u base=%d ci=%d cir=%d cr=%d cu=%d cd=%d cw=%d\n",
            started ? 1 : 0, instA.was_started() ? 1 : 0, pa, bs, bp,
            instA.can_inject() ? 1 : 0, instA.can_inject_raw() ? 1 : 0,
            instA.can_replace() ? 1 : 0, instA.can_start_unprivileged() ? 1 : 0,
            instA.can_invoke_inject_drop() ? 1 : 0, instA.can_whitelist() ? 1 : 0);

        // ---- T2b the tunnel-mask ladder (cc :229-:257 the 10 DECODE ->
        // TUNNEL map + :259-:261 the AND face; proto 0 -> the 0-bit miss):
        printf("T2b tb gtp=%d teredo=%d v6in4=%d v4in6=%d v4in4=%d v6in6=%d gre=%d mpls=%d vxlan=%d geneve=%d zero=%d\n",
            instA.get_tunnel_bypass(TUNNEL_GTP) ? 1 : 0, instA.get_tunnel_bypass(TUNNEL_TEREDO) ? 1 : 0,
            instA.get_tunnel_bypass(TUNNEL_6IN4) ? 1 : 0, instA.get_tunnel_bypass(TUNNEL_4IN6) ? 1 : 0,
            instA.get_tunnel_bypass(TUNNEL_4IN4) ? 1 : 0, instA.get_tunnel_bypass(TUNNEL_6IN6) ? 1 : 0,
            instA.get_tunnel_bypass(TUNNEL_GRE) ? 1 : 0, instA.get_tunnel_bypass(TUNNEL_MPLS) ? 1 : 0,
            instA.get_tunnel_bypass(TUNNEL_VXLAN) ? 1 : 0, instA.get_tunnel_bypass(TUNNEL_GENEVE) ? 1 : 0,
            instA.get_tunnel_bypass(0) ? 1 : 0);

        // ---- T4 receive_messages (cc :198-:211): the 32>pool 8 CLAMP +
        // the next_message walk-to-null + the pool-decrement face:
        DAQ_RecvStatus rs = instA.receive_messages(32);
        DAQ_Msg_h m0 = instA.next_message();
        DAQ_Msg_h m1 = instA.next_message();
        DAQ_Msg_h m2 = instA.next_message();
        int avail4 = (int)instA.get_pool_available(); unsigned rc = xa.recv_calls;
        printf("T4 rstat=%d m0=%d m1=%d m2=%d avail=%d recv_calls=%u\n",
            (int)rs, m0 ? 1 : 0, m1 ? 1 : 0, m2 ? 1 : 0, avail4, rc);

        // ---- T5 finalize (cc :213-:222): the null guard -7 + the OK leg
        // + the pool++ face:
        int f_null = instA.finalize_message(nullptr, DAQ_VERDICT_PASS);
        int f_ok = instA.finalize_message(m0, DAQ_VERDICT_BLOCK);
        int avail5 = (int)instA.get_pool_available();
        unsigned fcl = xa.finalize_calls; int lv = (int)xa.last_verdict;
        printf("T5 fnul=%d fok=%d avail=%d fin_calls=%u verdict=%d\n",
            f_null, f_ok, avail5, fcl, lv);

        // ---- T6 inject (cc :289-:301): the null guard -7 + the relative
        // rev/len capture through REAL daq_instance_inject_relative:
        int inj_null = instA.inject(nullptr, 1, (const uint8_t*)"xx", 2);
        int inj_ok = instA.inject(m0, -1, (const uint8_t*)"abc", 3);
        printf("T6 injnull=%d inj=%d calls=%d rev=%d len=%u\n",
            inj_null, inj_ok, xa.inject_calls, xa.inj_rev, xa.inj_len);

        // ---- T7 the three ioctls (cc :321-:363) + the trio of null
        // guards, riding the REAL daq_instance_ioctl dispatch:
        int sfo = instA.modify_flow_opaque(m0, 0xBEEF);
        int spvr = instA.set_packet_verdict_reason(m0, 3);
        char tbuf[6] = { 1, 2, 3, 4, 5, 6 };
        int sptd = instA.set_packet_trace_data(m0, (uint8_t*)tbuf, 5);
        int sfo_n = instA.modify_flow_opaque(nullptr, 1);
        int spvr_n = instA.set_packet_verdict_reason(nullptr, 1);
        int sptd_n = instA.set_packet_trace_data(nullptr, (uint8_t*)tbuf, 5);
        int cmd_fin = xa.last_cmd; unsigned ioctls = xa.ioctl_calls;
        printf("T7 sfo=%d val=%x spvr=%d reason=%u sptd=%d tlen=%u nulls=%d%d%d lastcmd=%d ioctls=%u\n",
            sfo, xa.sfo.value, spvr, (unsigned)xa.spvr.verdict_reason, sptd,
            (unsigned)xa.sptd.trace_data_len, sfo_n, spvr_n, sptd_n, cmd_fin, ioctls);

        // ---- T8 add_expected (cc :365-:436 THE key-build heart): v4-cli
        // -> v6-srv, GTP+VLAN arms (the vlan read rides the NOT-LANDED
        // get_vlan_layer mirror — vid() = ntohs & 0xFFF); the daq_stats
        // EXTERN (witness-owned NOT-LANDED home) counts at :433; the
        // REAL in_addr/sf_ip faces ride the REAL sf_ip.o body legs:
        vlan::VlanTagHdr vth; vth.vth_pri_cfi_vlan = htons(0x0FFA);
        wvlan_ptr = &vth;
        Packet ctrl; ctrl.daq_msg = m0;
        ctrl.proto_bits = PROTO_BIT__GTP | PROTO_BIT__VLAN;
        SfIp cli, srv;
        cli.pton(AF_INET, "10.1.2.3"); srv.pton(AF_INET6, "2001:db8::feed:ffee");
        int ae1 = instA.add_expected(&ctrl, &cli, 111, &srv, 222,
            (IpProtocol)6, 5000, DAQ_EFLOW_ALLOW_MULTIPLE | DAQ_EFLOW_PERSIST);
        const DAQ_EFlow_Key_t& k = xa.cef.key;
        char sa6[48] = ""; snprintf(sa6, sizeof sa6, "%02x%02x%02x%02x",
            ((const uint8_t*)&k.sa.src_ip6)[0], ((const uint8_t*)&k.sa.src_ip6)[1],
            ((const uint8_t*)&k.sa.src_ip6)[2], ((const uint8_t*)&k.sa.src_ip6)[3]);
        // NOTE: address_space_id NEVER printed — cc :391 FIXIT-M the key
        // field is NEVER populated (uninitialized stack garbage); the
        // honest face is the ABSENCE, cited here and in KNOWN DEVIATIONS:
        printf("T8 ae=%d ctrl=%d src_af=%u ip4=%x [%s] sp=%u dst_af=%u dp=%u proto=%d tun=%d vlan=%x cnots=%u flags=%x tmo=%u ef=%llu cmd=%d cmsg=%d\n",
            ae1, ctrl.daq_msg ? 1 : 0, (unsigned)k.src_af, (unsigned)ntohl(k.sa.src_ip4.s_addr),
            sa6, (unsigned)k.src_port, (unsigned)k.dst_af, (unsigned)k.dst_port,
            (int)k.protocol, (int)k.tunnel_type, (unsigned)k.vlan_id,
            (unsigned)k.vlan_cnots, xa.cef.flags,
            xa.cef.timeout_ms, (unsigned long long)daq_stats.expected_flows,
            xa.last_cmd, xa.cef.ctrl_msg ? 1 : 0);

        // ---- T8b the MPLS + NO-VLAN + v6-cli/v4-srv arms (cc :395-:396
        // the MPLS tunnel leg + :408-:409 the 0xFFFF vlan-else face + the
        // :386/:388 faces) + the flags ladder :414-:421 with a NON-
        // matching 0x1000 riding ZERO extra bits:
        ctrl.proto_bits = PROTO_BIT__MPLS;
        SfIp cli6, srv4;
        cli6.pton(AF_INET6, "2001:db8::cafe"); srv4.pton(AF_INET, "192.0.2.9");
        int ae2 = instA.add_expected(&ctrl, &cli6, 1, &srv4, 2, (IpProtocol)17,
            10, DAQ_EFLOW_BIDIRECTIONAL | 0x1000);
        const DAQ_EFlow_Key_t& k2 = xa.cef.key;
        char da6[48] = ""; snprintf(da6, sizeof da6, "%02x%02x%02x%02x",
            ((const uint8_t*)&k2.da.dst_ip6)[0], ((const uint8_t*)&k2.da.dst_ip6)[1],
            ((const uint8_t*)&k2.da.dst_ip6)[2], ((const uint8_t*)&k2.da.dst_ip6)[3]);
        printf("T8b ae=%d src_af=%u dst_af=%u dst_ip4=%x [%s] dstip6first4=%x tun=%d vlan=%x flags=%x proto=%d ef=%llu\n",
            ae2, (unsigned)k2.src_af, (unsigned)k2.dst_af, (unsigned)ntohl(k2.da.dst_ip4.s_addr),
            da6, (unsigned)ntohl(k2.sa.src_ip4.s_addr), (int)k2.tunnel_type,
            (unsigned)k2.vlan_id, xa.cef.flags, (int)k2.protocol,
            (unsigned long long)daq_stats.expected_flows);

        // ---- T9 reload (cc :102-:116): load-OK -> swap-OK -> free-OLD;
        // then load NOTSUP -> the swap/free NEVER-fire dead arm:
        instA.reload();
        unsigned first3 = xa.load_calls + xa.swap_calls + xa.free_calls;
        xa.load_rc = DAQ_ERROR_NOTSUP;
        instA.reload();
        printf("T9 reload l=%u s=%u f=%u first3=%u\n",
            xa.load_calls, xa.swap_calls, xa.free_calls, first3);

        // ---- T10 get_stats (cc :308-:319): the OK fills ride m_stats
        // through REAL daq_instance_get_stats:
        const DAQ_Stats_t* st = instA.get_stats();
        unsigned stz = (unsigned)st->hw_packets_dropped;
        printf("T10 stats hw=%llu rx=%llu vblk=%llu zero=%u\n",
            (unsigned long long)st->hw_packets_received,
            (unsigned long long)st->packets_received,
            (unsigned long long)st->verdicts[DAQ_VERDICT_BLOCK], stz);
    }   // instA dtor fires HERE: destroy_inst++ (the destroy-the-REAL-
        // instance face, daq_instance_destroy -> module destroy)

    // ---- T1b the REAL instantiate instance-ID sanity REJECT (daq_mod_
    // ops.c :182-:188): instance id 3 -> DAQ id 4 > total 2 -> INVAL ->
    // the cc :82-:84 ErrorMessage leg + init FALSE + the dtor never
    // destroying (instance stayed NULL) + m_instantiate NEVER reached
    // (the sanity gate fires BEFORE the module loop — ctx_n stays):
    {
        unsigned ctxn_before = ctx_n;              // the NEVER-instantiated face
        SFDAQInstance bad("ethX", 3, &cfg);
        werr_buf[0] = 0;
        DAQ_Config_h bcfg = mk_cfg("inst", 2);
        bool bok = bad.init(bcfg, "bpf-x");
        std::string we = squash(werr_buf);
        const char* e = bad.get_error();           // the NULL-instance SDK face (h :61)
        daq_config_destroy(bcfg);
        printf("T1b init=%d werr=[%s] errnull=%d ctx_same=%d\n",
            bok ? 1 : 0, we.c_str(), e == nullptr ? 1 : 0,
            ctx_n == ctxn_before ? 1 : 0);
    }   // dtor: instance NULL -> destroy NEVER fires

    // ---- T3b the INLINE-mode ParseWarning leg (cc :61-:67): the REAL
    // conf read adaptor_inline_mode via set_run_flags (the public
    // setter, the row-23a probe precedent) + caps WITHOUT BLOCK ->
    // ParseWarning(WARN_DAQ, ...) captured; ValidateInstance still
    // returns TRUE (cc :67) -> init continues (the never-fatal face):
    {
        SnortConfig* c = const_cast<SnortConfig*>(SnortConfig::get_conf());
        c->set_run_flags(RUN_FLAG__INLINE);
        Ctx& pwc = ctx_pool[ctx_n];               // the next-instantiate slot
        pwc.caps = DAQ_CAPA_INJECT;               // NO BLOCK bit
        SFDAQInstance pw("ethC", 0, &cfg);
        DAQ_Config_h pcfg = mk_cfg("inst", 0);
        bool pok = pw.init(pcfg, "");              // EMPTY bpf -> set_filter NEVER
        std::string wp = squash(wpw_buf);
        daq_config_destroy(pcfg);
        c->clear_run_flags(RUN_FLAG__INLINE);
        printf("T3b init=%d wpw=[%s] wpw_calls=%u started=%d\n",
            pok ? 1 : 0, wp.c_str(), wpw_calls, pw.was_started() ? 1 : 0);
    }   // T3b instance REAL -> destroy FIRES (destroy_inst 2 WITH instA)

    // ---- T11 the stub instance (REQUIRED-only registration): the
    // resolve law IN ACTION — can_* ALL false (default caps 0), the
    // pool-info NOTSUP -> the start-FAILS arm (cc :175-:181):
    // ErrorMessage + stop() (was_started TRUE -> the REAL stop leg ->
    // STOPPED) + FALSE; the dlt NEVER READ (start died before cc :192)
    // stays the h :100 -1 face; reload ALL-NOTSUP dead legs (-4/-4/-4
    // NEVER fire counters); get_stats NOTSUP -> the cc :313-:315
    // LogMessage + the ptr-always-returned face; interrupt the default
    // NOTSUP false; the state walk INITIALIZED -> (failed start) ->
    // STOPPED-after-cc-stop (was_started FALSE again, the cc :277-:278
    // TRUE early-out face):
    {
        Ctx& sctx = ctx_pool[ctx_n];              // the stub slot (memset-zero
        SFDAQInstance sinst("ethS", 9, &cfg);     //  by s_instantiate)
        DAQ_Config_h scfg = mk_cfg("stub", 0);
        bool iok = sinst.init(scfg, "");           // EMPTY bpf -> NEVER
        werr_buf[0] = 0; wlog_buf[0] = 0;
        bool st2 = sinst.start();                  // the pool-NOTSUP fail arm
        std::string werrS = squash(werr_buf);
        bool wasA = sinst.was_started();           // STOPPED != STARTED -> false
        bool stp = sinst.stop();                   // the TRUE early-out face
        const DAQ_Stats_t* sst = sinst.get_stats();// NOTSUP -> the log arm
        std::string w = squash(wlog_buf);
        bool intr = sinst.interrupt();
        sinst.reload();                            // ALL-NOTSUP dead legs
        daq_config_destroy(scfg);
        printf("T11 init=%d start=%d was=%d stop=%d ci=%d cw=%d base=%d tb=%d intr=%d stats_ptr=%d statelog=[%s] start_err=[%s] cfgl=%d,%d,%d\n",
            iok ? 1 : 0, st2 ? 1 : 0, wasA ? 1 : 0, stp ? 1 : 0,
            sinst.can_inject() ? 1 : 0, sinst.can_whitelist() ? 1 : 0,
            sinst.get_base_protocol(), sinst.get_tunnel_bypass(TUNNEL_GTP) ? 1 : 0,
            intr ? 1 : 0, sst ? 1 : 0, w.c_str(), sinst.get_error() ? sinst.get_error() : "(null)",
            sctx.load_calls, sctx.swap_calls, sctx.free_calls);
    }   // the stub instance is REAL -> its dtor destroy FIRES (T12)

    printf("T12 destroy_inst=%u destroy_stub=%u filterA=%d pw_calls=%u err_calls=%u log_calls=%u\n",
        destroy_inst, destroy_stub, xa.filter_calls, wpw_calls, werr_calls, wlog_calls);
    return 0;
}

// 18i THE new witness face (PLAN 5: witness delta = EXACTLY 4 backbone-side,
// first-ever daq_msg witnesses in the lineage). Bodies SYNTHETIC by design
// (the 17d seam: raw.daq_msg provenance stays open; meta pointers synthetic
// in the probe ONLY; real DAQ lands row 20 and MUST re-cite the SDK header):
// (1)+(2) daq_msg_get_meta/_data -- ZERO fn-witness precedent (the fmod
//     daq_common.h 16 L + vocab daq_dlt.h 5 L grafts were header-ONLY);
//     the meta_enabled switch + probe-visible fake pdd/napt/payload drive
//     BOTH DAQ faces of the DEC arms (null-meta fallback vs synthetic
//     valid -> checksum_bypassed PEG face, NOT the tunnel_bypass hook --
//     the 18h peg-vs-hook correction stands; nm census asserts 0 x3).
// (3) snort::get_network_policy -> PINNED raw NetworkPolicy storage (the
//     fcap stubs.cc:517-:523 precedent; the real ctor/dtor live in the NEVER
//     -compiled main/policy.cc monolith). NSDMI face hand-seeded from
//     policy.h :233/:234 so the INLINE udp/icmp_checksums() gates
//     (policy.h :205/:211) read the ground default at the three ground
//     gate faces cd_udp.cc:367 / cd_icmp4.cc:159 / cd_icmp6.cc:197.
// (4) snort::Value::get_bits x3 overloads -> empty reset (ZERO precedent:
//     whole-tools witness grep = 0 bodies; cd_udp.cc set() :209/:214/:219
//     server_ports is the FIRST codec caller = the params seam, 18i never
//     vectorizes through it -- R4 honest record; the arms that exercise the
//     symbol are the L1/L2/L3 staged-LINK census, not a DEC arm).
#include <daq.h>
static const uint8_t fake_payload[512] = {0};
static DAQ_PktDecodeData_t fake_pdd;
static DAQ_NAPTInfo_t      fake_napt;
static int meta_enabled = 0;   // 0 => get_meta returns nullptr (fallback arm)
extern "C++" const void* daq_msg_get_meta(const struct _daq_msg*, DAQ_MetaType t)
{
    if (!meta_enabled) return nullptr;
    return t == DAQ_PKT_META_DECODE_DATA ? (const void*)&fake_pdd
                                         : (const void*)&fake_napt;
}
extern "C++" const uint8_t* daq_msg_get_data(const struct _daq_msg*)
{ return fake_payload; }
// probe-side control surface (probe-visible fakes = the dual-face arms):
DAQ_PktDecodeData_t* probe_fake_pdd()   { return &fake_pdd; }
DAQ_NAPTInfo_t*      probe_fake_napt()  { return &fake_napt; }
void               probe_daq_enable(int on) { meta_enabled = on; }

#include "main/policy.h"
#include "framework/value.h"
namespace snort {
alignas(NetworkPolicy) static unsigned char g_np_storage[sizeof(NetworkPolicy)];
static NetworkPolicy* get_np() {
    NetworkPolicy* p = reinterpret_cast<NetworkPolicy*>(g_np_storage);
    p->checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF;   // policy.h :233 NSDMI face
    p->checksum_drop = CHECKSUM_FLAG__DEF;                        // policy.h :234
    return p;
}
NetworkPolicy* get_network_policy() { return get_np(); }
void Value::get_bits(PortBitSet& b) const { b.reset(); }
void Value::get_bits(VlanBitSet& b) const { b.reset(); }
void Value::get_bits(ByteBitSet& b) const { b.reset(); }
}

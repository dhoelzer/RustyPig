// 18j THE new witness face (PLAN 6/7): snort::PacketManager::get_proto_name
// (IpProtocol) -- the MEASURED EXACTLY-+1 witness delta (scratch receipts
// row18j R-J: nm mangled residue vs the daq3 OBJS+WIN face = cd_icmp4_ip
// EXACTLY 1 / cd_icmp6_ip 0; the staged L1 undefined-DISTINCT face EXACTLY-1,
// L1_undefined.txt / L2_b_link.txt). The two ground call sites cd_icmp4_ip.cc
// :179 + :297 BOTH pass ip4h->proto() which returns IpProtocol (ip.h:116,
// R-K) -- the ProtocolId overload (packet_manager.h :123) is NEVER referenced
// by these objs, so NO stub for it lands: a witness for a symbol no obj
// references = dead weight + a census lie (R2; the scratch R-L protonly-stub
// face PROVED the census discriminates the overloads: that stub leaves the
// symbol undefined).
// R1 fidelity record (scratch row18j bodytest, the REAL-body attempt): the
// ground body (protocols/packet_manager.cc :1004-:1008: CodecManager::
// get_instance() -> s_proto_map -> get_codec -> get_name) does NOT compile on
// the resident header chain: managers/codec_manager.h was NEVER cp'd (the
// probe-pulls-no-codec/manager-object rule inherited; cc1plus rc1 "'Codec-
// Manager' was not declared in this scope"). Compiling the real TU = REJECT:
// 1,047 L + its own closure, and find tools -name packet_manager.cc = 0 in
// EVERY donor ever (R-H never-compiled face; the future real-TU row owns it).
// -> cited minimal observable stub face (the scratch w_18j.cc R-M face): a
// probe-visible fixed string. The log arms' OUTPUT is cite-never-vectorize
// (the probes NEVER call log(); the body exists so the staged link CLOSES).
#include "protocols/packet_manager.h"
namespace snort {
const char* PacketManager::get_proto_name(IpProtocol p)
{ static const char* n = "witness_proto"; (void)p; return n; }
}

// row23e FACE-A probe (harness stageable): the vocabulary/value family the
// port re-derives — the SetBits enum decimals (h :37-:42), the NSDMI cold
// map (cc P0 legs), the u8 width faces (the (uint8_t)~(DST_IP) + (uint8_t)-1
// gate operands :166/:179), the SetBits : uint8_t UNDERLYING width, the
// REAL-SDK pkthdr carrier widths the packet face leans on (the 23a-23c
// re-cite ledger face: DAQ_PktHdr_t 56B / tenant_id @ 48 — pinned HERE so a
// future graft-face swap can NEVER silently move the packet_match tenant
// read), and the sizeof family (C ABI face, NEVER size_of from air).
#include <cstdio>
#include <cstddef>
#include <type_traits>
#include <daq_common.h>   // the REAL-SDK pkthdr carrier face (the re-cite law)
#include "packet_io/packet_constraints.h"
#include "sfip/sf_ip.h"

int main() {
    using namespace snort;
    printf("SETBITS proto=%d sip=%d dip=%d sport=%d dport=%d ten=%d\n",
        (int)PacketConstraints::SetBits::IP_PROTO,
        (int)PacketConstraints::SetBits::SRC_IP,
        (int)PacketConstraints::SetBits::DST_IP,
        (int)PacketConstraints::SetBits::SRC_PORT,
        (int)PacketConstraints::SetBits::DST_PORT,
        (int)PacketConstraints::SetBits::TENANT);
    // the underlying-type width face: enum SetBits : uint8_t (h :36)
    printf("UNDER width=%zu signed=%d\n", sizeof(PacketConstraints::SetBits),
        (int)std::is_signed<PacketConstraints::SetBits>::value);
    // the gate operands: (uint8_t)~(SetBits::DST_IP) :166/:179 + (uint8_t)-1
    printf("OPS notdst=%d allset=%d notten=%d\n",
        (int)(uint8_t)~PacketConstraints::SetBits::DST_IP,
        (int)(uint8_t)-1,
        (int)(uint8_t)~PacketConstraints::SetBits::TENANT);
    // struct size family (C ABI real, via the REAL header)
    printf("SIZES pc=%zu sip=%zu tenants_off_ge=%d\n",
        sizeof(PacketConstraints), sizeof(SfIp),
        (int)(offsetof(PacketConstraints, tenants) >= sizeof(uint8_t) * 8));
    // the REAL SDK pkthdr carrier face (23a-23c ledger re-armed at THIS row:
    // the tenant_id read pc.cc :115 rides pkth -> REAL u32; ext#4 graft has
    // ZERO tenant member = the flipped-assert wall face measured EVERY build)
    DAQ_PktHdr_t ph = {};
    printf("PKTH sz=%zu tn_off=%zu\n", sizeof(DAQ_PktHdr_t),
        (size_t)((char*)&ph.tenant_id - (char*)&ph));
    // SfIp cold face (the default-leg the port's SfIp::new mirrors)
    SfIp z;
    printf("SIPCOLD fam=%d isset=%d\n", (int)z.get_family(), (int)z.is_set());
    // IpProtocol ordinals the ports ride (codec home REUSE; ground face)
    printf("PROTO tcp=%d udp=%d icmp=%d notset=%d\n",
        (int)IpProtocol::TCP, (int)IpProtocol::UDP,
        (int)IpProtocol::ICMPV4, (int)IpProtocol::PROTO_NOT_SET);
    return 0;
}

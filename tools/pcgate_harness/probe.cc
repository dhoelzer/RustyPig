// row-23e DEC probe: the packet_constraints ladder over the REAL pc.o
// (the row body, the ONE home of operator==/packet_match/flow_match --
// the E9 twin flipped-asserts the reject on the link leg). Legs P0-P12:
// the NSDMI/copy/assign/self-assign + the real operator== mask ladder
// (the gate's own comparison sections re-driven through the .o, PLUS
// the copy-ctor/copy-assign faces the gate NEVER executes) + the
// packet_match arms the gate NEVER takes (match=false, the no-IP TENANT-
// only TRUE face (TENANT ABSENT from the :102 five-bit set), the two-
// order swapped OR cc :118, the find_if tenant miss/hit + the anonymous-
// tenant scan skip). Legs F0-F5: flow_match through the REAL .o (the
// :129 key fallback, the session-wins face, the :123 match=false arm,
// and the SINGLE-ORDER directionality: the flow face NEVER gets packet
// match's swapped second chance -- the exact F5=0 asymmetry vs the P9=1
// two-order face). The scaffolding mirrors (Packet/Flow/FlowDataStore/
// FlowStash DECL bodies + get_inner_ip6_frag + the message pair) live
// ONLY in witness_pcgate.cc; snort_strdup (util.cc :119), the
// SnortSnprintf family (util_cstring.cc) and sf_ip are the REAL donor-
// resident bodies cp-linked (the 22b/23-era law: mirrored ZERO).
#include <cstdio>
#include "packet_io/packet_constraints.h"
#include "protocols/packet.h"
#include "protocols/layer.h"
#include "protocols/ipv4.h"
#include "flow/flow.h"
#include "flow/flow_key.h"
#include "sfip/sf_ip.h"

static void mk_ip4(snort::SfIp& ip, uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint32_t v = ((uint32_t)a << 24) | (b << 16) | (c << 8) | d;
    ip.set(&v, AF_INET);
}

int main() {
    using namespace snort;

    // P0 the NSDMI default face (h :60-:70) through the REAL ctor
    {
        PacketConstraints cs;
        printf("P0 def match=%d setbits=%d ipproto=%d tenants=%zu sp=%d dp=%d\n",
            (int)cs.match, (int)cs.set_bits, (int)cs.ip_proto, cs.tenants.size(),
            (int)cs.src_port, (int)cs.dst_port);
    }

    // P1 comparison ladder via the REAL operator== (cc :84-:93): the
    // gate CASE 1 sections re-driven, PLUS the copy-ctor/copy-assign legs
    {
        PacketConstraints a(IpProtocol::TCP, 10, 20, SfIp(), SfIp(), 0, true);
        PacketConstraints b(IpProtocol::UDP, 30, 40, SfIp(), SfIp(), 0, true);
        printf("P1 allunset eq=%d\n", (int)(a == b));
        uint32_t ip1 = 0x01010101, ip2 = 0x02020202, ip3 = 0x03030303;
        uint8_t mask = (uint8_t)~PacketConstraints::SetBits::DST_IP;
        PacketConstraints e(IpProtocol::PROTO_NOT_SET, 10, 20, SfIp(&ip1, AF_INET), SfIp(&ip2, AF_INET), mask, true);
        PacketConstraints f(IpProtocol::PROTO_NOT_SET, 10, 20, SfIp(&ip1, AF_INET), SfIp(), mask, true);
        printf("P2 dstunset mask=%d eq=%d\n", (int)mask, (int)(e == f));
        PacketConstraints g(IpProtocol::PROTO_NOT_SET, 0, 0, SfIp(&ip1, AF_INET), SfIp(&ip2, AF_INET), (uint8_t)-1, true);
        PacketConstraints h(IpProtocol::PROTO_NOT_SET, 0, 0, SfIp(&ip3, AF_INET), SfIp(&ip2, AF_INET), (uint8_t)-1, true);
        printf("P3 neq allset=%d eq=%d\n", (int)(uint8_t)-1, (int)(g == h));
        g.tenants.push_back(100); g.tenants.push_back(200);
        PacketConstraints copy(g);           // copy-ctor cc :61-:65
        PacketConstraints asg; asg = copy;   // operator= cc :67-:82
        PacketConstraints selfas = g; selfas = selfas;  // self-assign guard :69-:70
        printf("P4 tenants eq1=%d eq2=%d self=%d\n", (int)(g == copy), (int)(g == asg), (int)(g == selfas));
    }

    // packet_match legs the GATE NEVER executes (match=false / no-IP /
    // TENANT-only / the REAL two-order OR)
    SfIp A, B;
    mk_ip4(A, 10, 1, 1, 1);
    mk_ip4(B, 10, 1, 1, 2);

    {
        // P5 match=false gate (cc :97)
        PacketConstraints cs(IpProtocol::PROTO_NOT_SET, 0, 0, SfIp(), SfIp(), 0, false);
        Packet p(false);
        printf("P5 nomatch=%d\n", (int)cs.packet_match(p));
    }
    {
        // P6 no-IP packet TENANT-only set -> TRUE (:102 TENANT-absent mask)
        PacketConstraints cs;
        cs.set_bits = PacketConstraints::SetBits::TENANT;
        cs.tenants.push_back(7);
        Packet p(false);  // ip_api default IAT_NONE
        printf("P6 noopkg tenantonly=%d\n", (int)cs.packet_match(p));
        // P7 no-IP with IP_PROTO armed -> false (:103)
        cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
        cs.ip_proto = IpProtocol::TCP;
        printf("P7 noopkg protoset=%d\n", (int)cs.packet_match(p));
    }
    {
        // full-match packet (IAT_DATA face: ptrs via the REAL IpApi set)
        PacketConstraints cs;
        cs.set_bits = PacketConstraints::SetBits::IP_PROTO | PacketConstraints::SetBits::SRC_PORT
            | PacketConstraints::SetBits::DST_PORT | PacketConstraints::SetBits::SRC_IP
            | PacketConstraints::SetBits::DST_IP;
        cs.ip_proto = IpProtocol::TCP; cs.src_port = 100; cs.dst_port = 200;
        cs.src_ip = A; cs.dst_ip = B;
        DAQ_PktHdr_t ph = {}; ph.tenant_id = 100;
        {
            // P8 forward order match
            Packet p(false);
            static snort::ip::IP4Hdr h4 = {}; h4.ip_src = 0x0a010101; h4.ip_dst = 0x0a010102;
            p.ptrs.ip_api.set(&h4);   // ip.cc:41 the REAL IAT_4 face (is_ip TRUE)
            p.ptrs.sp = 100; p.ptrs.dp = 200;
            p.ip_proto_next = IpProtocol::TCP;
            p.pkth = &ph;
            printf("P8 fwd match=%d\n", (int)cs.packet_match(p));
        }
        {
            // P9 THE TWO-ORDER OR (cc :118): packet (B,A)/ports swapped ->
            // TRUE ONLY through the swapped match_constraints call
            Packet p(false);
            static snort::ip::IP4Hdr h4s = {}; h4s.ip_src = 0x0a010102; h4s.ip_dst = 0x0a010101;  // swapped addrs
            p.ptrs.ip_api.set(&h4s);
            p.ptrs.sp = 200; p.ptrs.dp = 100;
            p.ip_proto_next = IpProtocol::TCP;
            p.pkth = &ph;
            printf("P9 swap two-order=%d\n", (int)cs.packet_match(p));
        }
        {
            // P10 TENANT armed + tenant MISS (find_if both orders) -> false
            cs.set_bits |= PacketConstraints::SetBits::TENANT;  // now the TENANT gate is ARMED
            cs.tenants.push_back(111); cs.tenants.push_back(222);
            ph.tenant_id = 42;
            static snort::ip::IP4Hdr h4b = {}; h4b.ip_src = 0x0a010101; h4b.ip_dst = 0x0a010102;
            Packet p(false);
            p.ptrs.ip_api.set(&h4b);
            p.ptrs.sp = 100; p.ptrs.dp = 200;
            p.ip_proto_next = IpProtocol::TCP;
            p.pkth = &ph;
            printf("P10 tenant-miss=%d\n", (int)cs.packet_match(p));
            // P11 anonymous tenant (id 0) SKIPS the scan (:45)
            ph.tenant_id = 0;
            printf("P11 tenant-anon-skip=%d\n", (int)cs.packet_match(p));
            // P12 tenant HIT (42 in the list) -> res survives -> 1
            ph.tenant_id = 222;
            printf("P12 tenant-hit=%d\n", (int)cs.packet_match(p));
        }
    }

    // flow_match: the :129 fallback + the :123 match gate + single-order
    // directionality (the client/server face the gate covers + one leg it
    // never takes: swapped ports NO second chance on the flow face)
    {
        FlowKey key = {};
        key.ip_protocol = (uint8_t)IpProtocol::ICMPV4;
        key.tenant_id = 5;
        Flow flow;
        flow.key = &key;
        {
            PacketConstraints cs; cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
            cs.ip_proto = IpProtocol::ICMPV4;
            printf("F0 flow keyfallback=%d\n", (int)cs.flow_match(flow));
            cs.ip_proto = IpProtocol::TCP;
            printf("F1 flow keyfallback-miss=%d\n", (int)cs.flow_match(flow));
        }
        {
            // session value WINS face (:129)
            flow.ip_proto = (uint8_t)IpProtocol::TCP;
            key.ip_protocol = (uint8_t)IpProtocol::UDP;
            PacketConstraints cs; cs.set_bits = PacketConstraints::SetBits::IP_PROTO;
            cs.ip_proto = IpProtocol::TCP;
            printf("F2 flow session-wins=%d\n", (int)cs.flow_match(flow));
        }
        {
            // :123 match=false leg the GATE NEVER takes
            PacketConstraints cs; cs.set_bits = 0; cs.match = false;
            printf("F3 flow nomatch=%d\n", (int)cs.flow_match(flow));
            // single-order flow face: client/server swapped -> FALSE
            // (no second OR on the flow path, unlike packet_match :118)
            cs.match = true;
            cs.set_bits = PacketConstraints::SetBits::SRC_IP;
            mk_ip4(flow.client_ip, 10, 0, 0, 1);
            cs.src_ip = flow.client_ip;
            // F4: the constraint built FROM the client side, matched against
            // the client/server face (the :134 client-port leg = 0/0 unset
            // ports, mask SRC_IP ONLY) -> the single-order HIT face = 1
            cs.dst_ip = SfIp();
            printf("F4 flow same-dir=%d\n", (int)(cs.flow_match(flow)));
            cs.src_ip = SfIp(); flow.client_ip = SfIp();
            uint32_t x = 0x0a000001, y = 0x0a000002;
            flow.client_ip.set(&x, AF_INET); flow.server_ip.set(&y, AF_INET);
            cs.src_ip.set(&y, AF_INET);  // constraint wants SERVER's addr
            printf("F5 flow swapped=%d\n", (int)cs.flow_match(flow));
        }
    }

    printf("Z terminator=0\n");
    return 0;
}

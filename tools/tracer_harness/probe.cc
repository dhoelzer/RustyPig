// row-22b DEC probe: the print_ntuple / print_timestamp / flag-flip ladder
// over the REAL tracer.o + the pkth-EXTENDED graft daq_common.h + the
// witness trio (witness_tracer.cc) + ipheavy-carried REAL .o's.
// NEVER-double law: the packet scaffolding (Packet ctor/dtor + the two
// PacketManager/layer statics) mirrors live HERE; the 3 provider arms live
// ONLY in witness_tracer.cc.
#include <cstdio>
#include "framework/tracer.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "sfip/sf_ip.h"

namespace snort
{
// the Packet scaffolding mirrors (packet.cc ctor body face, minimal arms the
// tracer reads touch): PacketManager::max_layers static (packet_manager.h:168;
// DEFAULT_LAYERMAX 40 packet.h:121) -- NOT packet.cc (it derefs the FULL
// Active/Layer world the row never reaches).
uint8_t PacketManager::max_layers = DEFAULT_LAYERMAX;

// minimal Packet ctor face: NO packet_data allocs (the tracer NEVER reads
// pkt/data); pkth is OWNED by the probe and hand-set (the real ctor arms
// alloc a DAQ_PktHdr_t -- face RE-RIDDEN by the probe's extended struct).
Packet::Packet(bool) { }
Packet::~Packet() { }

class ProbeLogger final : public TraceLoggerPlug
{
public:
    ProbeLogger() : TraceLoggerPlug("probe") { }
    void log(const char*, const char*, uint8_t, const char*, const Packet*) override { }
    // the pure log() must stay pure-overridden; the print_* ride the BASE
    // face verbatim (tracer.cc:30 / :63).
};
}

int main()
{
    using namespace snort;
    SfIp s, d;
    s.pton(AF_INET, "203.0.113.7");     // the PARSE face (sf_ip.h:64) -- set() is the RAW-16B copy face
    d.pton(AF_INET, "198.51.100.23");
    SfIp s6, d6;
    s6.pton(AF_INET6, "2001:db8::cafe");
    d6.pton(AF_INET6, "2001:db8::feed");

    ProbeLogger lg;

    // T0: flag ladder pre-arms: ntuple OFF -> "" ; timestamp OFF -> ""
    {
        Packet p;
        p.ptrs.ip_api.set(s, d);
        printf("T0 ntuple_off=[%s] ts_off=[%s]\n",
            lg.print_ntuple(&p).c_str(), lg.print_timestamp().c_str());
    }

    // T1: v4 TCP full face (sp/dp set, AS + TN emitted, proto_next=6)
    DAQ_PktHdr_t ph1; ph1.address_space_id = 7; ph1.tenant_id = 42;
    {
        lg.set_ntuple(true);
        Packet p;
        p.ptrs.ip_api.set(s, d);
        p.proto_bits = PROTO_BIT__IP | PROTO_BIT__TCP;
        p.ptrs.sp = 1234; p.ptrs.dp = 80;
        p.ip_proto_next = IpProtocol::TCP;
        p.pkth = &ph1;
        printf("T1 v4tcp=[%s]\n", lg.print_ntuple(&p).c_str());
    }

    // T2: UDP proto_bits -> ports ride; proto_next=17
    {
        Packet p;
        p.ptrs.ip_api.set(s, d);
        p.proto_bits = PROTO_BIT__IP | PROTO_BIT__UDP;
        p.ptrs.sp = 5353; p.ptrs.dp = 53;
        p.ip_proto_next = IpProtocol::UDP;
        p.pkth = &ph1;
        printf("T2 udp=[%s]\n", lg.print_ntuple(&p).c_str());
    }

    // T3: proto_bits WITHOUT TCP|UDP (e.g. ICMP only) -> ports STAY 0
    {
        Packet p;
        p.ptrs.ip_api.set(s, d);
        p.proto_bits = PROTO_BIT__IP | PROTO_BIT__ICMP;
        p.ptrs.sp = 1234; p.ptrs.dp = 80;   // NEVER copied (cc :44 gate)
        p.ip_proto_next = IpProtocol::ICMPV4;
        p.pkth = &ph1;
        printf("T3 icmp_ports0=[%s]\n", lg.print_ntuple(&p).c_str());
    }

    // T4: tenant_id == 0 -> the TN= arm NEVER fires; AS= ALWAYS does (0)
    DAQ_PktHdr_t ph2; ph2.address_space_id = 0; ph2.tenant_id = 0;
    {
        Packet p;
        p.ptrs.ip_api.set(s, d);
        p.proto_bits = PROTO_BIT__IP | PROTO_BIT__TCP;
        p.ip_proto_next = IpProtocol::TCP;
        p.pkth = &ph2;
        printf("T4 tn0=[%s]\n", lg.print_ntuple(&p).c_str());
    }

    // T5: ip_api NOT set (IAT_NONE) -> is_valid() FALSE -> ""
    {
        Packet p;
        p.pkth = &ph1;
        printf("T5 api_none=[%s]\n", lg.print_ntuple(&p).c_str());
    }

    // T6: null-packet guard -> ""
    printf("T6 nullp=[%s]\n", lg.print_ntuple(nullptr).c_str());

    // T7: v6 end-to-end + AS=65535 UINT16 ceiling + TN=MAX UINT32 ceiling
    DAQ_PktHdr_t ph3; ph3.address_space_id = 65535; ph3.tenant_id = 4294967295u;
    {
        Packet p;
        p.ptrs.ip_api.set(s6, d6);
        p.proto_bits = PROTO_BIT__IP | PROTO_BIT__UDP;
        p.ptrs.sp = 1; p.ptrs.dp = 2;
        p.ip_proto_next = IpProtocol::UDP;
        p.pkth = &ph3;
        printf("T7 v6_ceils=[%s]\n", lg.print_ntuple(&p).c_str());
    }

    // T8: the timestamp ON face -- the witness-anchored deterministic ts + ":"
    lg.set_timestamp(true);
    printf("T8 ts_on=[%s]\n", lg.print_timestamp().c_str());

    // T9: the lifecycle face: thread-type map P/C/O + instance + name + flags flip-off
    lg.set_thread_type(STHREAD_TYPE_PACKET); char a = lg.get_thread_type();
    lg.set_thread_type(STHREAD_TYPE_MAIN);    char b = lg.get_thread_type();
    lg.set_thread_type('X');                  char c = lg.get_thread_type();
    lg.set_instance_id(7);
    lg.set_ntuple(false);
    {
        Packet p;
        p.ptrs.ip_api.set(s, d);
        p.pkth = &ph1;
        printf("T9 map=%c%c%c id=%u name=%s ntuple_backoff=[%s] api_null=%d\n",
            a, b, c, lg.get_instance_id(), lg.get_name().c_str(),
            lg.print_ntuple(&p).c_str(), lg.get_api() == nullptr);
    }
    return 0;
}

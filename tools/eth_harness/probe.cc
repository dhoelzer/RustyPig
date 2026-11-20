#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include <cstdio>
extern const snort::BaseApi* cd_eth[]; extern const snort::BaseApi* cd_arp[];
using namespace snort;
int main(){
    SnortConfig conf("");
    const CodecApi* ea = (const CodecApi*)cd_eth[0];
    printf("API eth type=%d size=%u ver=%u name=%s\n", (int)ea->base.type, ea->base.size, ea->base.api_version, ea->base.name);
    printf("HELP %s\n", ea->base.help);
    Codec* eth = ea->ctor(nullptr);
    uint8_t pkt[64]={0};
    RawData r0(nullptr, pkt, 12); CodecData cd0(&conf, ProtocolId::ETHERTYPE_NOT_SET); DecodeData dd0;
    bool a = eth->decode(r0, cd0, dd0); printf("ETH short -> %d\n", (int)a);
    pkt[12]=0x08; pkt[13]=0x00;
    RawData r1(nullptr, pkt, 14); CodecData cd1(&conf, ProtocolId::ETHERTYPE_NOT_SET); DecodeData dd1;
    bool b = eth->decode(r1, cd1, dd1);
    printf("ETH v4 -> %d next=%u lyr=%u bits=%llu\n", (int)b, (unsigned)cd1.next_prot_id, (unsigned)cd1.lyr_len, (unsigned long long)cd1.proto_bits);
    pkt[12]=0x00; pkt[13]=0x05;   // <= ETHERTYPE_MINIMUM arm (0x0005)
    RawData r2(nullptr, pkt, 14); CodecData cd2(&conf, ProtocolId::ETHERTYPE_NOT_SET); DecodeData dd2;
    bool c = eth->decode(r2, cd2, dd2);
    printf("ETH llc -> %d next=%u\n", (int)c, (unsigned)cd2.next_prot_id);
    std::vector<int> v; eth->get_data_link_type(v);
    for (int d : v) printf("DLT %d\n", d);
    std::vector<ProtocolId> pv; eth->get_protocol_ids(pv);
    printf("PIDS %u n=%u\n", (unsigned)pv[0], (unsigned)pv.size());
    const CodecApi* aa = (const CodecApi*)cd_arp[0];
    printf("API arp name=%s\n", aa->base.name);
    printf("HELPARP %s\n", aa->base.help);
    Codec* arp = aa->ctor(nullptr);
    RawData r3(nullptr, pkt, 27); CodecData cd3(&conf, ProtocolId::ETHERTYPE_NOT_SET); DecodeData dd3;
    bool d = arp->decode(r3, cd3, dd3); printf("ARP short -> %d\n", (int)d);
    RawData r4(nullptr, pkt, 28); CodecData cd4(&conf, ProtocolId::ETHERTYPE_NOT_SET); DecodeData dd4;
    bool e = arp->decode(r4, cd4, dd4);
    printf("ARP ok -> %d lyr=%u bits=%llu\n", (int)e, (unsigned)cd4.lyr_len, (unsigned long long)cd4.proto_bits);
    CodecModule m; const RuleMap* rm = m.get_rules();
    int n=0; while (rm[n].sid) n++;
    printf("MOD rules=%d gid=%u help=%s trace=%s\n", n, m.get_gid(), m.get_help(), m.get_trace_options()?"on":"null");
    return 0;
}

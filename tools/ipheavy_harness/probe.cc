// 20h FACE-A probe (mpls-18o shape clone, TRIO feed): the cd_ipv4[]/cd_ipv6[]/
// cd_tcp[] STATIC-arm tables (cd_ipv4.cc :785 / cd_ipv6.cc :728 / cd_tcp.cc :834
// -- the cd_tcp table UNCONDITIONAL: BUILDING_SO block COMMENTED OUT :831/:832/
// :833/:835, the grep-c-lies face rides build.sh) fed by &ipv4_api.base :783 /
// &ipv6_api.base :726 / &tcp_api.base :837. TRUE-NAME tables (file base == table
// symbol, 18n equality law; nm D-faces in build.sh).
// THE VECTORS-NAME FLIP (PLAN sec-3): the vocab/ext frozen vectors pin the STUB
// names LOAD cd_ipv4_stub/cd_ipv6_stub/cd_tcp_stub (vocab vectors.txt :25-:27 +
// ext vectors_faceII.txt :2-:4, FROZEN untouched); THIS probe loads the REAL
// tables -> LOAD ipv4 / LOAD ipv6 / LOAD tcp (the BaseApi NAME defines
// cd_ipv4.cc :47 / cd_ipv6.cc :37 / cd_tcp.cc :42 -- the stub-table-name vs
// real-table-NAME flip; LOADS 3 vs the frozen vocab LOADS 5 face).
// HELP faces: ipv4/ipv6 carry the ADD_DLT face (framework/codec.h :52):
// "support for Internet protocol v4 (DLT 228)" / "... v6 (DLT 229)" -- the DLT
// NUMBERS are the ext#4 daq_dlt.h SYNTHETIC CITE (228/229 = libpcap-master,
// NEVER ABI truth; row 20 re-cites the real SDK); cd_tcp.cc :43 HELP has NO
// ADD_DLT (the HELP asymmetry face).
// T-ARM census sec-4: ipv4_codec_tinit/tterm REAL at :776/:777 (the ONLY one of
// the three with non-null t-arms); cd_ipv6 :719-:720 + cd_tcp :825-:826 nullptr.
// mod arms REAL for ALL THREE (ipv4 :771/:772? arms :771 mod_ctor -- sed pins in
// build.sh); ctor(Module*) IGNORES Module (cd_ipv4.cc :754 -- the anti-18o
// config-threading drift cite, contrast mpls :347).
// GETIDS ORDER-PINNED emplace faces: ipv4 = ETHERTYPE_IPV4 2048 + IPIP 4
// (cc :157-:158); ipv6 = ETHERTYPE_IPV6 34525 + IPV6 41 (:127-:128); tcp = TCP 6
// (:152) (protocol_ids.h :144/:151/:60-:63). GETDLT (the ext#4 DLT member face):
// ipv4 emplaces DLT_IPV4 228 (cc :152), ipv6 emplaces DLT_IPV6 229 (:123), tcp
// NEVER overrides get_data_link_type (framework/codec.h :268 empty base) -> n=0.
// PARAMS n=0 faces: NONE of the trio declares a Parameter table (BaseCodecModule
// params nullptr -- the anti-18o face).
// NAPT REAL-ADDR arms (the ext#4 member face, PLAN sec-6 FACE-A): meta ENABLED,
// fake napti ip_layer 1 == ++codec.ip_layer_cnt -> real_src/real_dst SfIp::set
// (&napti->src_addr, daq_napt_info_src_addr_family) -- cd_ipv4.cc :247-:253,
// cd_ipv6.cc :213-:219; the tcp FACE is the PORT arm cd_tcp.cc :282-:284
// (snort.sp/dp = ntohs(napti->src_port/dst_port)). Observables = the DECODEDATA
// ip_api accessors (framework/decode_data.h :176 public ip_api; protocols/ip.h
// :88-:97 get_src/get_dst; sfip/sf_ip.h :70 get_ip4_value) -- ip.cc :86 IpApi::
// update OVERWRITES src/dst, so the printed v4-values ARE the napti fields.
#include <cstdio>
#include <vector>
#include <daq.h>
#include "codecs/codec_module.h"     // the RuleMap faces (ipv4_rules :69 / ipv6_rules :44 / tcp_rules :74 walks)
#include "framework/base_api.h"
#include "framework/codec.h"
#include "framework/module.h"        // Module::get_name/get_help/get_rules/get_parameters
#include "framework/parameter.h"
#include "framework/value.h"
#include "main/snort_config.h"    // the conf face for the NAPT arms
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_ipv4[];
extern const BaseApi* cd_ipv6[];
extern const BaseApi* cd_tcp[];
// the carried daq3 witness observables (tools/daq3_harness/witness_daq.cc):
DAQ_PktDecodeData_t* probe_fake_pdd();
DAQ_NAPTInfo_t*      probe_fake_napt();
void                 probe_daq_enable(int);
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_ipv4);            // the trio feeds -- the
    PluginManager::load_plugins(cd_ipv6);            // LOAD ipv4/ipv6/tcp FLIP
    PluginManager::load_plugins(cd_tcp);             printf("LOADS 3\n");
    const BaseApi* tabs[3] = { cd_ipv4[0], cd_ipv6[0], cd_tcp[0] };
    const char* nm[3] = { "ipv4", "ipv6", "tcp" };
    for (int i = 0; i < 3; ++i) {
        const BaseApi* a = tabs[i];
        const CodecApi* ca = reinterpret_cast<const CodecApi*>(a);
        printf("API %s type=%d size=%u ver=%u features=%llu name=%s\n", nm[i],
            (int)a->type, (unsigned)a->size, (unsigned)a->api_version,
            (unsigned long long)a->features, a->name);
        printf("HELP %s %s\n", nm[i], a->help);       // the (DLT 228)/(229)/NO-DLT faces
        printf("%s mod_ctor=%d mod_dtor=%d\n", nm[i], a->mod_ctor?1:0, a->mod_dtor?1:0);
        printf("%s ctor=%d dtor=%d\n", nm[i], ca->ctor?1:0, ca->dtor?1:0);
        printf("TARM %s tinit=%d tterm=%d\n", nm[i], ca->tinit?1:0, ca->tterm?1:0);
        Module* m = a->mod_ctor();
        printf("NAME %s mod=%s help=%s\n", nm[i], m->get_name(), m->get_help());
        const RuleMap* r = m->get_rules(); int n = 0; while (r[n].sid) n++;
        printf("RULES %s n=%d first=%u last=%u\n", nm[i], n, r[0].sid, r[n-1].sid);
        const Parameter* p = m->get_parameters(); int np = 0;
        for (; p && p->name && p->type != Parameter::PT_MAX; ++p) np++;
        printf("PARAMS %s n=%d\n", nm[i], np);
        std::vector<ProtocolId> ids; Codec* c0 = ca->ctor(nullptr);
        c0->get_protocol_ids(ids);
        for (auto id : ids) printf("GETIDS %s %u\n", nm[i], (unsigned)id);
        printf("GETIDS_n %s %u\n", nm[i], (unsigned)ids.size());
        std::vector<int> dlts; c0->get_data_link_type(dlts);
        for (auto d : dlts) printf("GETDLT %s %d\n", nm[i], d);   // 228/229 ext CITE face
        printf("GETDLT_n %s %u\n", nm[i], (unsigned)dlts.size());
        ca->dtor(c0);
        a->mod_dtor(m);
    }
    // stamp the carried witness fakes (the daq3 observable surface): the
    // pdd bits drive the checksum-BYPASS path (the ext#4 l3/l4 fields ARE
    // consumed -- the E4 daq.h-drop INVERSION driver) and the napti fields
    // drive the NAPT arms. napt ip_layer = 1: the ipv4/ipv6 decode arms
    // match at ++ip_layer_cnt == 1 (cc :248/:214 gates -> the REAL-ADDR
    // face, IpApi::update OVERWRITES the printed src/dst = napti fields);
    // the tcp decode NEVER increments ip_layer_cnt (0) -> FACE-A NAPTTCP
    // rides the WITNESS MISMATCH (sp/dp = the header-path face cd_tcp.cc
    // :286-:287 = raw 25001/25002) while the PORT-match arm rides DEC IC18
    // (napt re-stamped ip_layer 0 there -> 7/9). Honest split-census.
    DAQ_PktDecodeData_t* pdd = probe_fake_pdd();
    DAQ_NAPTInfo_t* napt = probe_fake_napt();
    pdd->flags.bits.l3_checksum = 1; pdd->flags.bits.l3 = 1;
    pdd->flags.bits.ipv4 = 1; pdd->flags.bits.ipv6 = 1;
    pdd->flags.bits.tcp = 1; pdd->flags.bits.l4_checksum = 1; pdd->flags.bits.l4 = 1;
    pdd->l3_offset = DAQ_PKT_DECODE_OFFSET_INVALID;    // skip the offset re-check
    pdd->l4_offset = DAQ_PKT_DECODE_OFFSET_INVALID;
    napt->ip_layer = 1;                                 // == ++codec.ip_layer_cnt (v4/v6)
    napt->src_addr_family = AF_INET; napt->dst_addr_family = AF_INET;
    napt->src_addr = 0x0A010102; napt->dst_addr = 0x0AFFFF01;  // 10.1.1.2 / 10.255.255.1
    napt->src_port = htons(7); napt->dst_port = htons(9);      // the FACE-A-NEVER face (mismatch)
    probe_daq_enable(1);
    SnortConfig conf("");
    uint8_t v4[20] = {0x45,0,0,20, 0,0, 0x40,0, 64,6, 0,0, 1,1,1,1, 2,2,2,2};
    const CodecApi* a4 = reinterpret_cast<const CodecApi*>(cd_ipv4[0]);
    { Codec* c = a4->ctor(nullptr); RawData r(nullptr,v4,20);
      CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
      bool b=c->decode(r,cd,d);
      printf("NAPT4 rc=%d src=%u dst=%u fam4=%d\n",(int)b,
        (unsigned)d.ip_api.get_src()->get_ip4_value(),
        (unsigned)d.ip_api.get_dst()->get_ip4_value(),
        d.ip_api.get_src()->is_ip4()?1:0);
      a4->dtor(c); }
    // v4 header: ver/hlen 0x45, ip_len 20, DF (0x4000), ttl 64, proto TCP 6,
    // src 1.1.1.1 dst 2.2.2.2 (cd_ipv4.cc ip::IP4Hdr layout, protocols/ipv4.h)
    uint8_t v6[40] = {0x60};                          // ver 6, payload_len 0,
    v6[6] = 6; v6[7] = 64;                            // next=6 TCP (VALID: no
                                                      // 281 -- :230 is_valid_next_header), hop 64
    const CodecApi* a6 = reinterpret_cast<const CodecApi*>(cd_ipv6[0]);
    { Codec* c = a6->ctor(nullptr); RawData r(nullptr,v6,40);
      CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
      bool b=c->decode(r,cd,d);
      printf("NAPT6 rc=%d src=%u dst=%u fam4=%d\n",(int)b,
        (unsigned)d.ip_api.get_src()->get_ip4_value(),
        (unsigned)d.ip_api.get_dst()->get_ip4_value(),
        d.ip_api.get_src()->is_ip4()?1:0);
      a6->dtor(c); }
    uint8_t t20[20] = {0};
    ((uint16_t*)t20)[0]=htons(25001); ((uint16_t*)t20)[1]=htons(25002);
    t20[12] = 0x50;                            // data offset 5
    t20[13] = 0x10;                            // ACK ONLY (no flag-event arms)
    const CodecApi* ac = reinterpret_cast<const CodecApi*>(cd_tcp[0]);
    { Codec* c = ac->ctor(nullptr); RawData r(nullptr,t20,20);
      CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
      bool b=c->decode(r,cd,d);
      printf("NAPTTCP rc=%d sp=%u dp=%u\n",(int)b,(unsigned)d.sp,(unsigned)d.dp);
      ac->dtor(c); }
    probe_daq_enable(0);
    return 0;
}

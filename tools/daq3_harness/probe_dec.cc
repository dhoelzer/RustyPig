// 18i decode-face probe -- EXTENDED dual-face arms, drawn from the ground
// call-site census (NEVER guessed; receipts row18i R1/R3/R6): udp cc:316 and
// cc:320/:328/:334 + gate :367 + NAPT :420-:424 + misc :472-:481; icmp4
// cc:147-:151 gate + :159 + switch :169-:212 + :220-:235 + Addr :247-:266
// + Misc :276-:329; icmp6 cc:125-:131 daq + gate :197 + NOT_IP6 :191 +
// switch :218-:407 + NDP walk :141-:176. THE row's dual-face headline:
// the SAME bad-checksum packet reads D-flags=4/8 with DAQ meta OFF (real C
// path, DECODE_ERR_CKSUM_*: decode_data.h :133/:134) vs decode-SUCCEEDS
// dflags=0 with the SYNTHETIC DAQ-valid pdd (valid_checksum_from_daq true
// -> checksum_bypassed PEG face -- PEG not the tunnel_bypass HOOK, 18h
// correction; nm census asserts 0 tunnel_bypass x3 in build.sh). Offset-
// mismatch face (l4_offset 0 vs raw.data-data) = the C fallback arm.
// R6 eval-order rule (tun/small4): decode stored to bool VAR before any
// printf; all-decimal print face. The icmp4 sweep is the arm-dense face:
// all 18 unique event names + the shared-105 rider ride 20 arms.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include "protocols/udp.h"
#include <daq.h>
#include <cstdio>
extern const snort::BaseApi* cd_udp[];
extern const snort::BaseApi* cd_icmp4[];
extern const snort::BaseApi* cd_icmp6[];
DAQ_PktDecodeData_t* probe_fake_pdd();
DAQ_NAPTInfo_t*      probe_fake_napt();
void               probe_daq_enable(int on);
using namespace snort;

static void set_ip4(DecodeData& d, uint8_t* b)
{ for (int i=0;i<20;++i) b[i]=0; b[0]=0x45; b[12]=10; b[16]=20; b[9]=17; d.ip_api.set(b); }
static void set_ip6(DecodeData& d, uint8_t* b)
{ for (int i=0;i<40;++i) b[i]=0; b[0]=0x60; d.ip_api.set(b); }

int main(){
  SnortConfig conf("");
  const CodecApi* ua=(const CodecApi*)cd_udp[0];
  const CodecApi* ia=(const CodecApi*)cd_icmp4[0];
  const CodecApi* sa=(const CodecApi*)cd_icmp6[0];
  uint8_t b4[20]; (void)b4;
  uint8_t z[4096]={0};

  // ---- UDP: the length-guard ladder (cc:316/:320/:328/:334) ----
  Codec* uc=ua->ctor(nullptr);
  { RawData r(nullptr,z,7); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    bool b=uc->decode(r,c,d); printf("UDP short7 -> %d\n",(int)b); }
  { uint8_t p[12]={0}; p[4]=0; p[5]=4;   // uh_len 4 < 8 -> cc:320 EV 96
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    bool b=uc->decode(r,c,d); printf("UDP badlen4 -> %d\n",(int)b); }
  { uint8_t p[12]={0}; p[4]=0; p[5]=20;  // uh_len 20 > raw.len 12 -> cc:328 EV 97
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    bool b=uc->decode(r,c,d); printf("UDP uhlen20 -> %d\n",(int)b); }
  { uint8_t p[12]={0}; p[4]=0; p[5]=10;  // uh_len 10 < raw.len 12 -> cc:334 EV 98
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    bool b=uc->decode(r,c,d); printf("UDP uhlen10 -> %d\n",(int)b); }
  // DUAL FACE, ONE PACKET (uh_chk 0xFFFF fold-invalid, uh_len == raw.len):
  // daq-OFF -> gate cc:367 true (witness netpol NSDMI face) -> real path ->
  // DECODE_ERR_CKSUM_UDP (decode_data.h:133 = 4); gate face printed LIVE.
  { uint8_t p[12]={0}; p[0]=0x22;p[1]=0x23;p[2]=0x22;p[3]=0x23;p[4]=0;p[5]=12;p[6]=0xFF;p[7]=0xFF;
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(0);
    bool b=uc->decode(r,c,d); printf("UDP cksumbad-daqoff -> %d dflags=%u gate=%u\n",(int)b,(unsigned)d.decode_flags,(unsigned)get_network_policy()->udp_checksums()); }
  // same packet, synthetic DAQ-valid pdd -> valid_checksum_from_daq TRUE ->
  // checksum_bypassed PEG rides (stats statics file-local = cite-never-
  // vectorize, R2 decision, small4 pgm tri-state precedent), decode proceeds.
  DAQ_PktDecodeData_t* f=probe_fake_pdd();
  f->flags.bits.l4_checksum=1; f->flags.bits.udp=1; f->flags.bits.icmp=1; f->flags.bits.l4=1;
  f->l4_offset=DAQ_PKT_DECODE_OFFSET_INVALID;
  DAQ_NAPTInfo_t* napt=probe_fake_napt();   // ONE deterministic fake face for ALL daq-ON arms
  napt->src_port=htons(3000); napt->dst_port=htons(6000); napt->ip_layer=0;  // ground cc:422-424 ntohs face
  { uint8_t p[12]={0}; p[0]=0x22;p[1]=0x23;p[2]=0x22;p[3]=0x23;p[4]=0;p[5]=12;p[6]=0xFF;p[7]=0xFF;
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(1);
    bool b=uc->decode(r,c,d); printf("UDP cksumbad-daqvalid -> %d dflags=%u next=%u\n",(int)b,(unsigned)d.decode_flags,(unsigned)c.next_prot_id); }
  // offset-mismatch fallback face: l4_offset 0 != (raw.data - fake_payload)
  // -> valid_checksum_from_daq FALSE -> SAME flags=4 face as daq-OFF.
  { uint8_t p[12]={0}; p[0]=0x22;p[1]=0x23;p[2]=0x22;p[3]=0x23;p[4]=0;p[5]=12;p[6]=0xFF;p[7]=0xFF;
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    f->l4_offset=0;
    bool b=uc->decode(r,c,d);
    f->l4_offset=DAQ_PKT_DECODE_OFFSET_INVALID;    printf("UDP daqoffsetmismatch -> %d dflags=%u\n",(int)b,(unsigned)d.decode_flags); }
  // ip6 zero-checksum face (cc:392 EV 406, valid=false -> flag+false)
  { uint8_t p[12]={0}; p[4]=0; p[5]=12; uint8_t b6[40]={0};
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip6(d,b6);
    probe_daq_enable(0);
    bool b=uc->decode(r,c,d); printf("UDP ip6zero -> %d dflags=%u\n",(int)b,(unsigned)d.decode_flags); }
  // NAPT hit/miss pair (cc:420-:424): fake napt ip_layer 0 == c.ip_layer_cnt
  { uint8_t p[12]={0}; p[0]=0x22;p[1]=0x23;p[2]=0x22;p[3]=0x23;p[4]=0;p[5]=12;
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(1);   // napt face pinned once above (3000/6000, layer 0)
    bool b=uc->decode(r,c,d); printf("UDP napt-hit -> %d sp=%u dp=%u\n",(int)b,(unsigned)d.sp,(unsigned)d.dp); }
  { uint8_t p[12]={0}; p[4]=0;p[5]=12;   // ports 0 -> napt OFF -> raw ports 0 -> cc:481 EV 447
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(0);
    bool b=uc->decode(r,c,d); printf("UDP naptmiss-portzero -> %d sp=%u dp=%u\n",(int)b,(unsigned)d.sp,(unsigned)d.dp); }
  { z[0]=0; z[1]=1; z[2]=15; z[3]=196; z[4]=0x0F; z[5]=0xB4;  // uh_len 4020 == raw -> pay 4012 > 4000 cc:478 EV 445
    RawData r(nullptr,z,4020); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    bool b=uc->decode(r,c,d); printf("UDP large4020 -> %d\n",(int)b);
    for (int i=0;i<18;++i) z[i]=0; }
  { uint8_t p[12]={0}; p[0]=0x22;p[1]=0x23;p[2]=0x0D;p[3]=0xD8;p[4]=0;p[5]=12;  // dst BE 3544 (0x0DD8) -> TEREDO next
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::UDP); DecodeData d; set_ip4(d,b4);
    bool b=uc->decode(r,c,d); printf("UDP teredo3544 -> %d next=%u\n",(int)b,(unsigned)c.next_prot_id); }
  { std::vector<ProtocolId> v; uc->get_protocol_ids(v); printf("UDPPID %u n=%u\n",(unsigned)v[0],(unsigned)v.size()); }
  { const BaseApi* nb=cd_udp[0]; Module* m=nb->mod_ctor(); const RuleMap* rm=m->get_rules(); int n=0; while(rm[n].sid) n++;
    printf("UDPRULES %d sid0=%u name=%s\n", n, rm[0].sid, m->get_name()); nb->mod_dtor(m); }

  // ---- ICMP4: 19 arms cover ALL 18 unique event names (arm-dense face) ----
  Codec* ic=ia->ctor(nullptr);
  { RawData r(nullptr,z,3); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(0);   // all-zero dgram: cksum_add fold = ~0 = 0 -> gate passes
    bool b=ic->decode(r,c,d); printf("ICMP4 short3 -> %d\n",(int)b); }
  { uint8_t p[8]={3,4,0,0};  // type3 code4 group, raw.len 4 < 8 -> cc:212 EV 105
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(1);
    bool b=ic->decode(r,c,d); printf("ICMP4 type3-grp4 -> %d\n",(int)b); }
  { uint8_t p[8]={8,0,0xFF,0xFF};   // daq-OFF fold-invalid -> flag 8 face (cc:165-:167)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(0);
    bool b=ic->decode(r,c,d); printf("ICMP4 cksumbad-daqoff -> %d dflags=%u\n",(int)b,(unsigned)d.decode_flags); }
  { uint8_t p[8]={8,0,0xFF,0xFF};   // SAME packet daq-valid -> skips -> EV 434 (cc:282)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    probe_daq_enable(1);
    bool b=ic->decode(r,c,d); printf("ICMP4 cksumbad-daqvalid -> %d dflags=%u\n",(int)b,(unsigned)d.decode_flags); }
  probe_daq_enable(1);   // gate-skipped faces from here on (arm-dense sweep, cksum field irrelevant)
  { uint8_t p[8]={8,0,0,0,0,0,0x9A,0x02};   // seq 666 dsize 0 -> EV 434 + 435 (cc:282/:295)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 enum666 -> %d\n",(int)b); }
  { uint8_t p[12]={8,0,0,0,0xAA,0xBB,0,0};  // dsize 4 seq0 code0 -> EV 440 (cc:317)
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; uint8_t w[20]; set_ip4(d,w);
    bool b=ic->decode(r,c,d); printf("ICMP4 smurf -> %d\n",(int)b); }
  { uint8_t p[12]={8,0,0,0,0xAA,0xBB,0,0};  // dst 255.255.255.255 -> EV 416 (cc:251)
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; uint8_t w[20]={0};
    w[0]=0x45; w[9]=17; w[12]=10; w[16]=w[17]=w[18]=w[19]=0xFF; d.ip_api.set(w);
    bool b=ic->decode(r,c,d); printf("ICMP4 bcast -> %d\n",(int)b); }
  { uint8_t p[12]={8,0,0,0,0xAA,0xBB,0,0};  // dst ms-nibble 0xE -> EV 415 (cc:266)
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; uint8_t w[20]={0};
    w[0]=0x45; w[9]=17; w[16]=0xE0; d.ip_api.set(w);
    bool b=ic->decode(r,c,d); printf("ICMP4 mcast -> %d\n",(int)b); }
  { uint8_t p[8]={13,0,0,0};   // type13 len 8 < 20 -> EV 106 (cc:197)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 tstamp8 -> %d\n",(int)b); }
  { uint8_t p[8]={17,0,0,0};   // type17 len 8 < 12 -> EV 107 (cc:206)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 addr8 -> %d\n",(int)b); }
  { uint8_t p[8]={99,0,0,0};   // type99 default -> EV 418 (cc:212)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 type99 -> %d\n",(int)b); }
  { uint8_t p[8]={4,0,0,0};    // source-quench ok -> len+4 next 259 + EV 439 (cc:325)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 sq8 -> %d next=%u\n",(int)b,(unsigned)c.next_prot_id); }
  { uint8_t p[8]={5,1,0,0};    // redirect host -> EV 436 (cc:299)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 redirhost -> %d\n",(int)b); }
  { uint8_t p[8]={5,0,0,0};    // redirect net -> EV 437 (cc:303)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 redirnet -> %d\n",(int)b); }
  { uint8_t p[8]={0,0,0,0};    // echoreply + CODEC_IPOPT_RR_SEEN -> EV 438 (cc:307)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    c.codec_flags |= 0x0010;   // CODEC_IPOPT_RR_SEEN face codec.h :88
    bool b=ic->decode(r,c,d); printf("ICMP4 rr-echo -> %d\n",(int)b); }
  { uint8_t p[8]={3,13,0,0};   // unreach code13 -> EV 441 (cc:321)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 unreach13 -> %d\n",(int)b); }
  { uint8_t p[8]={3,10,0,0};   // -> EV 442 (cc:325)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 unreach10 -> %d\n",(int)b); }
  { uint8_t p[8]={3,9,0,0};    // -> EV 443 (cc:329)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 unreach9 -> %d\n",(int)b); }
  { uint8_t p[8]={3,4,0,0,0,0,2,0};   // FRAG_NEEDED mtu 512 < 576 -> EV 451 (cc:235)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV4); DecodeData d; set_ip4(d,b4);
    bool b=ic->decode(r,c,d); printf("ICMP4 pmtu512 -> %d next=%u\n",(int)b,(unsigned)c.next_prot_id); }
  { std::vector<ProtocolId> v; ic->get_protocol_ids(v); printf("ICMP4PID %u n=%u\n",(unsigned)v[0],(unsigned)v.size()); }
  { const BaseApi* nb=cd_icmp4[0]; Module* m=nb->mod_ctor(); const RuleMap* rm=m->get_rules(); int n=0; while(rm[n].sid) n++;
    printf("ICMP4RULES %d sid0=%u name=%s\n", n, rm[0].sid, m->get_name()); nb->mod_dtor(m); }

  // ---- ICMP6: daq face + 14 unique names (gate :197, switch :218-:407,
  // NDP walk :141-:176; the ipv6_api :488 struct name DOES NOT APPEAR in
  // any printout -- table cd_icmp6 NAME icmp6 face, the drift rider ride) ----
  Codec* sc=sa->ctor(nullptr);
  { uint8_t b6[40]={0}; RawData r(nullptr,z,3); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    probe_daq_enable(0);
    bool b=sc->decode(r,c,d); printf("ICMP6 short3 -> %d\n",(int)b); }
  { RawData r(nullptr,z,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d;   // NO ip6 -> EV 474 (cc:191)
    probe_daq_enable(0);
    bool b=sc->decode(r,c,d); printf("ICMP6 noip6 -> %d\n",(int)b); }
  { uint8_t p[8]={128,0,0xFF,0xFF}; uint8_t b6[40]={0};   // daq-OFF fold-invalid -> flag 8 (cc:209-:212)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    probe_daq_enable(0);
    bool b=sc->decode(r,c,d); printf("ICMP6 cksumbad-daqoff -> %d dflags=%u\n",(int)b,(unsigned)d.decode_flags); }
  { uint8_t p[8]={128,0,0xFF,0xFF}; uint8_t b6[40]={0};   // SAME packet daq-valid -> decode proceeds
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    probe_daq_enable(1);
    bool b=sc->decode(r,c,d); printf("ICMP6 cksumbad-daqvalid -> %d dflags=%u lyr=%u\n",(int)b,(unsigned)d.decode_flags,(unsigned)c.lyr_len); }
  { uint8_t p[8]={128,0,0,0,0xAA,0xBB,0,0}; uint8_t b6[40]={0};   // ip6 mcast dst -> EV 432 (cc:225)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    b6[24]=0xFF;   // IP6_MULTICAST first dst octet (ipv6.h :33/:111) -- AFTER the zeroing helper
    probe_daq_enable(1);
    bool b=sc->decode(r,c,d); printf("ICMP6 mcast -> %d\n",(int)b); }
  probe_daq_enable(1);   // gate-skipped faces for the type/NDP sweep
  { uint8_t p[12]={2,0,0,0}; uint8_t b6[40]={0};   // too-big: dsize 8 >= sizeof(ICMP6TooBig)=8 (icmp6.h struct)
    p[4]=0; p[5]=0; p[6]=4; p[7]=0;   // mtu BE 0x00000400 = 1024 < 1280 -> EV 285 (cc:232)
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 toobig1024 -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); }
  { uint8_t p[8]={1,2,0,0}; uint8_t b6[40]={0};   // unreach code2 UNREACH_INVALID -> EV 286 (cc:259)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 unreach2 -> %d\n",(int)b); }
  { uint8_t p[8]={1,7,0,0}; uint8_t b6[40]={0};   // code7 > 6 -> EV 457 (cc:262)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 unreach7 -> %d\n",(int)b); }
  { uint8_t p[8]={133,1,0,0,0,0,0,1}; uint8_t b6[40]={0}; // RS: code1 -> 287 (cc:284) + reserved -> 289 (cc:287)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 rs-bad -> %d\n",(int)b); }
  { uint8_t p[20]={134,1,0,0}; p[8]=0xFF; p[9]=0xFF; p[10]=0xFF; p[11]=0xFF; uint8_t b6[40]={0};  // RA: code1 -> 288 (cc:300) + reachable>3600000 -> 290 (cc:303)
    RawData r(nullptr,p,20); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 ra-bad -> %d\n",(int)b); }
  { uint8_t p[24]={134,0,0,0}; p[16]=1; p[17]=0;  // RA opt type1 length0 -> EV 478 cc:166 (walk cc:146-:172)
    uint8_t b6[40]={0};
    RawData r(nullptr,p,24); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 ra-zerolen -> %d\n",(int)b); }
  { uint8_t p[20]={139,3,0,0}; uint8_t b6[40]={0};  // NODE_INFO code3 > 2 -> EV 460 (cc:371)
    RawData r(nullptr,p,20); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 nodeinfo3 -> %d\n",(int)b); }
  { uint8_t p[6]={2,0,0,0}; uint8_t b6[40]={0};   // too-big dsize 2 < 4 -> EV 105 (cc:252)
    RawData r(nullptr,p,6); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 toobig6 -> %d\n",(int)b); }
  { uint8_t p[8]={200,0,0,0}; uint8_t b6[40]={0};  // type200 default -> EV 431 (cc:407)
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ICMPV6); DecodeData d; set_ip6(d,b6);
    bool b=sc->decode(r,c,d); printf("ICMP6 type200 -> %d\n",(int)b); }
  { std::vector<ProtocolId> v; sc->get_protocol_ids(v); printf("ICMP6PID %u n=%u\n",(unsigned)v[0],(unsigned)v.size()); }
  { const BaseApi* nb=cd_icmp6[0]; Module* m=nb->mod_ctor(); const RuleMap* rm=m->get_rules(); int n=0; while(rm[n].sid) n++;
    printf("ICMP6RULES %d sid0=%u name=%s\n", n, rm[0].sid, m->get_name()); nb->mod_dtor(m); }
  return 0;
}

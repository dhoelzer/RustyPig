// 20h DEC probe -- the trio decode ladder (PLAN sec-6 DEC: cite-never-guess,
// EVERY arm cc-cited). Witness seams: stubs_18d EV printer (EV 116 <sid> --
// the GID_DECODE face) + carried daq3 meta witness (probe_fake_pdd/napt/
// enable -- the pdd NAPT/CKSUM-BYPASS arms) + witness_18f tun mask pair
// (TUNNEL_4IN4 0x10 / 4IN6 0x08 / 6IN4 0x04, snort_config.h :120-:123) +
// witness_ipvars (sfvar trio FALSE face -- the anomaly-check discriminator:
// conf.address_anomaly_check_enabled TRUE + witness sfvar_ip_in FALSE = the
// closed-but-false vector, the 411/412/403 arms NEVER fire -> the witness is
// LIVE in the binary, never dead weight) + witness_opts (IpOptionIterator
// arms -- the IPMiscTests walk is REAL header-inline next(); our witness
// bodies = ground ipv4_options.cc near-verbatim).
// sid bands THIS row (PLAN sec-4, python re-verifies per file):
//   ipv4 {1-6,404-448 family} ipv6 {270-477} tcp {45-59,400-446} -- ALL
//   OUTSIDE the 170-176 EV-34 mpls face (0 overlap; own-row band vectors).
// NEVER-vectorized honest cites (witness/legality, logged in build.sh echo):
//  - IPV4OPT_TRUNCATED via options ladder: the uint8_t-valid-len iterator
//    ctor (cd_ipv4.cc :449) + header-inline next() walk runs PAST end for a
//    TRUNCATED length (ground ctor comment :439 "You MUST validate all
//    ip_options within len" -- the decode-time-truncated chain is ground-
//    unsafe territory; the BADLEN + OPTION_SET arms ride chain-safe ladders)
//  - DECODE_ZERO_LENGTH_FRAG 459 rides I4E (MF-path + ip_len -= hlen :316 ->
//    :358 `!ip_len` REACHABLE at payload-0); I4F/I4G/I4H (payload>=1) pin the
//    NEVER side of the same gate -- the pair-census face
//  - #if 0 DEAD BLOCK cd_ipv4.cc :210-:217 (ip_len<len alert) -- cite-never-
//    land (grep tripwire in build.sh: the block NEVER vectorizes an EV)
//  - DECODE_IPV6_ISATAP arms ride the OUTER-IP-V6-proto41 face :232-:243
//  - ipv4 UNASSIGNED 449 + PROTO ladder face :352-:356
// WORDS_BIGENDIAN faces (cd_ipv4.cc :379-:385 loopback msb / cd_tcp.cc :45-:51
// naptha consts): the HOST-LE arms are MEASURED live (msb = ip_src & 0xff;
// naptha_seq = 0x2a7b5c00 / naptha_id = 0x9d01 -- the seed-drift tripwire:
// IC21 fires 402 ONLY on the LE consts; IC22 with the BYTE-SWAPPED BE consts
// (0x005c7b2a) NEVER fires 402 -- the pair pins the arm THIS host took).
// R6 rule: every decode through a bool VAR before any printf; all-decimal.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include <daq.h>
#include <cstdio>
#include <cstdint>
extern const snort::BaseApi* cd_ipv4[];
extern const snort::BaseApi* cd_ipv6[];
extern const snort::BaseApi* cd_tcp[];
extern "C" void tun_witness_set_mask(unsigned short);
DAQ_PktDecodeData_t* probe_fake_pdd();
DAQ_NAPTInfo_t*      probe_fake_napt();
void                 probe_daq_enable(int);
using namespace snort;
int main(){
  SnortConfig conf("");
  SnortConfig conf_ml(""); conf_ml.max_ip_layers = 1;          // public field face :279
  SnortConfig conf_an(""); conf_an.address_anomaly_check_enabled = true;  // :282 flipped face
  DAQ_PktDecodeData_t* pdd = probe_fake_pdd();
  DAQ_NAPTInfo_t* napt = probe_fake_napt();
  pdd->flags.bits.l3_checksum=1; pdd->flags.bits.l3=1; pdd->flags.bits.ipv4=1;
  pdd->flags.bits.ipv6=1; pdd->flags.bits.tcp=1; pdd->flags.bits.l4_checksum=1; pdd->flags.bits.l4=1;
  pdd->l3_offset = DAQ_PKT_DECODE_OFFSET_INVALID; pdd->l4_offset = DAQ_PKT_DECODE_OFFSET_INVALID;
  napt->ip_layer = 255;                                        // NO napt match in DEC (FACE-A rides 1/0)
  const CodecApi* a4=(const CodecApi*)cd_ipv4[0];
  const CodecApi* a6=(const CodecApi*)cd_ipv6[0];
  const CodecApi* ac=(const CodecApi*)cd_tcp[0];
  Codec* c4=a4->ctor(nullptr); Codec* c6=a6->ctor(nullptr); Codec* ct=ac->ctor(nullptr);
  uint8_t z[8192]={0};
  // the TCP-header face helper (ports 25001/25002 + offx2/flags)
  #define TCPH(p,o2,f) do{ for(unsigned i_=0;i_<sizeof(p);i_++)p[i_]=0; p[12]=(o2); p[13]=(f); ((uint16_t*)p)[0]=htons(25001); ((uint16_t*)p)[1]=htons(25002);}while(0)

  // ---- IPv4 (I4x): cd_ipv4.cc decode gates ----
  // I41 short -> EV 425 :166-:170 (UNSURE_ENCAP unset) + false
  { uint8_t p[19]={0}; RawData r(nullptr,p,19); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I41 trunc19 -> %d lyr=%u next=%u\n",(int)b,(unsigned)cd.lyr_len,(unsigned)cd.next_prot_id); }
  // I42 ver!=4 -> EV 1 :186-:191
  { uint8_t p[20]={0x54}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I42 ver5 -> %d\n",(int)b); }
  // I43 hlen<20 (4<<2=16) -> EV 2 :196-:200
  { uint8_t p[20]={0x44,0,0,20, 0,0, 0,0, 64,6, 0,0, 1,1,1,1, 2,2,2,2}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I43 hlen16 -> %d\n",(int)b); }
  // I44 ip_len>raw.len -> EV 6 :202-:206
  { uint8_t p[20]={0x45,0,0,30, 0,0, 0,0, 64,6, 0,0, 1,1,1,1, 2,2,2,2}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I44 len30gt20 -> %d\n",(int)b); }
  // I45 ip_len<hlen -> EV 3 :219-:223 (the :210-:217 ip_len<len #if 0 DEAD face between them -- cite-never-land)
  { uint8_t p[20]={0x45,0,0,10, 0,0, 0,0, 64,6, 0,0, 1,1,1,1, 2,2,2,2}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I45 len10lt20 -> %d\n",(int)b); }
  // I46 checksum face: meta OFF -> ip_cksum!=0 -> false (:265-:280, cooked NOT
  // set); meta ON -> valid_checksum_from_daq TRUE (the ext#4 l3_checksum+l3+
  // ipv4 bits CD_CONSUMED = the E4 daq.h-drop INVERSION driver) -> continues
  { uint8_t p[20]={0x45,0,0,20, 0x9d,1, 0,0, 64,6, 0,0, 10,1,1,1, 10,255,255,1}; RawData r(nullptr,p,20);
    probe_daq_enable(0); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I46 cksum-off -> %d\n",(int)b);
    probe_daq_enable(1); CodecData cd2(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d2;
    bool b2=c4->decode(r,cd2,d2); printf("I47 cksum-bypass -> %d lyr=%u next=%u pb=%u\n",(int)b2,(unsigned)cd2.lyr_len,(unsigned)cd2.next_prot_id,(unsigned)cd2.proto_bits); }
  // I48 loopback msb (host-LE arm :379-:385, msb=ip_src&0xff==0x7F) -> EV 150
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 127,1,1,1, 10,1,1,1}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I48 lb127 -> %d\n",(int)b); }
  // I49 src==dst -> EV 151 :386-:390
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 10,1,1,1, 10,1,1,1}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I49 srcdst -> %d\n",(int)b); }
  // I4A src broadcast 255.255.255.255 -> EV 413 :391-:394 (dst plain)
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 255,255,255,255, 10,1,1,1}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4A bcast -> %d\n",(int)b); }
  // I4B this_net msb==0 -> EV 408 :400-:402
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 0,0,0,0, 10,1,1,1}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4B thisnet -> %d\n",(int)b); }
  // I4C msn 0xE multicast -> EV 410 :411-:416
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 239,1,1,1, 10,1,1,1}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4C mc239 -> %d\n",(int)b); }
  // I4D ANOMALY-ON(witness discriminator) + witness sfvar_ip_in FALSE + msb
  // !=0xF -> ZERO 411/412: the witness discriminator face (REAL world would
  // consult MulticastReservedIp; our witness FALSE = closed-but-silent,
  // honestly pinned -- the sfvar arms LIVE in the binary)
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2}; RawData r(nullptr,p,20); CodecData cd(&conf_an,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4D anom-wfalse -> %d\n",(int)b); }
  // I4E RB 0x8000|MF 0x2000 -> EV 448 :303-:306; MF -> DECODE_MF + frag-
  // branch :359 (!ip_len: ip_len 20 - hlen 20 = 0 REACHABLE here -- the
  // ZERO_LENGTH_FRAG 459 SINGLE face, my earlier NEVER-claim WRONG, disk
  // won) -> EV 459; masked offset 0 -> 407/430 NEVER
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0xA0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4E rbmf -> %d lyr=%u next=%u\n",(int)b,(unsigned)cd.lyr_len,(unsigned)cd.next_prot_id); }
  // I4F DF|MF both, ip_len 40 (payload 20 -> :358 !ip_len FALSE -> 459
  // NEVER here) -> EV 405 SINGLE :331-:332 (masked offset 0 -> 430/407 NEVER)
  { uint8_t p[40]={0x45,0,0,40, 0,0, 0x60,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2}; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4F dfmf -> %d\n",(int)b); }
  // I4G DF + offset 1 (ip_len 40 -> payload 20 -> :359 !ip_len FALSE -> 459
  // NEVER) -> EV 430 SINGLE :346-349 (no MF -> 405 NEVER)
  { uint8_t p[40]={0x45,0,0,40, 0,0, 0x40,1, 64,6, 0,0, 10,1,1,1, 10,2,2,2}; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4G dfoff -> %d\n",(int)b); }
  // I4H frag raw 0x7FFF (DF|MF|offset 8191; RB 0x8000 CLEARED -> 448 NEVER)
  // + ip_len 65247 (payload 65227 -> 459 NEVER): 151 (src/dst 10.0.0.0 EQUAL
  // -- the land face co-ride) + 405 (:331) + 430 (:346-:349) + (8191<<3)+
  // 65227 = 131555 > 65535 -> 407 (:352-355) -- THE 4-sid compound;
  // DECODE_FRAG -> the :374-:381 block SKIPPED -> next stays ctor 2048 (the
  // next_prot-suppression face shared with I4E/I4G)
  { uint8_t p[65280]; for(int i=0;i<65280;i++)p[i]=0; p[0]=0x45; p[2]=0xFE; p[3]=0xDF; p[6]=0x7F; p[7]=0xFF; p[8]=64; p[9]=6; p[12]=10; p[16]=10; RawData r(nullptr,p,65280); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4H lenoff -> %d lyr=%u next=%u\n",(int)b,(unsigned)cd.lyr_len,(unsigned)cd.next_prot_id); }
  // I4I BADLEN [7,1,0,0] hlen 24: opt len 1 < 2 -> OPT_BADLEN :524 -> EV 4;
  // DecodeIPOptions CLAMPS: invalid_bytes 4 + o_len REF -> ip_opt_len = 0
  // (:290) -> IPMiscTests valid_hdr_len = 20+0 -> iterator begin == end ->
  // ZERO walk -> 444 NEVER (the CLAMP face: the bad option is NEVER visited);
  // lyr = 24 - 4 = 20 PIN
  { uint8_t p[24]={0x46,0,0,24, 0,0, 0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2, 7,1,0,0}; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4I optbadlen -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // I4J decoder-SILENT [9,4,0,0]: RTRALT flag (no event), tot 4 == o_len
  // loop-ends ZERO decoder events; iterator visits 9(+1), next() += 4 lands
  // ON end -> cnt 1 -> EV 444 SINGLE (decoder-silent OPTION_SET pin)
  { uint8_t p[24]={0x46,0,0,24, 0,0, 0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2, 9,4,0,0}; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4J optset -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // I4K unassigned proto 143 -> EV 449 :353-354 + next=143
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,143, 0,0, 10,1,1,1, 10,2,2,2}; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    bool b=c4->decode(r,cd,d); printf("I4K unass143 -> %d next=%u\n",(int)b,(unsigned)cd.next_prot_id); }
  // I4L multi-encap cfg max_ip_layers=1: 1st ok, 2nd -> EV 293 :172-:176
  { uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2};
    CodecData cd(&conf_ml,ProtocolId::ETHERTYPE_IPV4); DecodeData d;
    RawData r1(nullptr,p,20); bool b1=c4->decode(r1,cd,d);
    RawData r2(nullptr,p,20); bool b2=c4->decode(r2,cd,d);
    printf("I4L menc -> %d,%d\n",(int)b1,(int)b2); }
  // I4M/I4N tunnel pair 4in4 :225-:236 (ip_api pre-set to V4; TUNNEL_4IN4
  // 0x10; witness mask 0 -> TRUE bypass; mask 0x10 -> FALSE) -- THE bypass
  // hook vectors (mpls 18o lineage face, trio-flavored)
  { uint8_t outer[20]={0x45,0,0,20, 0,0, 0,0, 64,4, 0,0, 1,1,1,1, 2,2,2,2};  // outer v4 proto 4
    uint8_t p[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2};
    tun_witness_set_mask(0);
    CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d; d.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r(nullptr,p,20); bool b=c4->decode(r,cd,d);
    printf("I4M byp4-0 -> %d bypass=%d\n",(int)b,(int)cd.tunnel_bypass);
    tun_witness_set_mask(0x10);
    CodecData cd2(&conf,ProtocolId::ETHERTYPE_IPV4); DecodeData d2; d2.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r2(nullptr,p,20); bool b2=c4->decode(r2,cd2,d2);
    printf("I4N byp4-10 -> %d bypass=%d\n",(int)b2,(int)cd2.tunnel_bypass);
    tun_witness_set_mask(0); }

  // ---- IPv6 (I6x): cd_ipv6.cc ----
  // I61 short 39 -> EV 273 (:139-:142) + EV 291 UNCONDITIONAL (:144) + false
  { uint8_t p[39]={0}; RawData r(nullptr,p,39); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I61 trunc39 -> %d lyr=%u next=%u\n",(int)b,(unsigned)cd.lyr_len,(unsigned)cd.next_prot_id); }
  // I62 ver!=6 -> EV 271 :149-:155
  { uint8_t p[40]={0x50}; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I62 ver5 -> %d\n",(int)b); }
  // I63 payload_len+40 > raw.len -> EV 275 :161-:169
  { uint8_t p[40]={0x60,0,0,0, 0,10}; p[6]=6; p[7]=64; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I63 gt-cap -> %d\n",(int)b); }
  // I64 TEREDO_SEEN + no 2001::/fe80:: prefix -> SILENT return false :201-:202
  { uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0x20; p[9]=0x02; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d; cd.codec_flags |= CODEC_TEREDO_SEEN;
    bool b=c6->decode(r,cd,d); printf("I64 teredo -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // I65 bad next header 255 -> EV 281 :229-:230 (CONTINUES, rc 1, next=255)
  { uint8_t p[40]={0x60,0,0,0, 0,0, 255,64}; p[8]=0x21; p[24]=0x20; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I65 badnext -> %d next=%u lyr=%u\n",(int)b,(unsigned)cd.next_prot_id,(unsigned)cd.lyr_len); }
  // I66-I6A ride napt MISMATCH (ip_layer 255): the SfIp observables stay
  // the header-set values -- otherwise :219 update rewrites them (I67's
  // whole 276-zero-dst face is INVISIBLE under a napt match, honest record;
  // FACE-A pins the match arm)
  // I66 src multicast ff.. -> EV 277 :300-:303 (dst fe.. nonzero -> no 276)
  { napt->ip_layer = 255; uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0xff; p[24]=0xfe; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I66 srcmc -> %d\n",(int)b); napt->ip_layer = 1; }
  // I67 dst :: zero -> EV 276 SINGLE (is_set false -- IPMiscTests dst-zero
  // arm; src 20.. nonzero)
  { napt->ip_layer = 255; uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0x21; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I67 dstzero -> %d\n",(int)b); napt->ip_layer = 1; }
  // I68 ::1/::1 -> fast_eq6 151 + is_loopback6 150 (the v6 loopback face
  // of the SAME IPMiscTests pair as I48/I49)
  { napt->ip_layer = 255; uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[23]=1; p[39]=1; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I68 lb6 -> %d\n",(int)b); napt->ip_layer = 1; }
  // I69 dst ff0e::0100 (u16[1] nonzero) -> EV 278 :334-:341 (scope GLOBAL
  // PASSes the switch -- the :326 switch/278 ORDER pin: bad scope would 280
  // and RETURN first; GLOBAL scope falls THROUGH to the 278 face)
  { napt->ip_layer = 255; uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0x21; p[24]=0xff; p[25]=0x0e; p[26]=0x01; p[39]=1; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I69 dstmc16 -> %d\n",(int)b); napt->ip_layer = 1; }
  // I6A dst ff03::5 (scope 3 undefined -> default arm -> EV 280 :314-:325;
  // the u16 word face: bytes[2..9]==0 -> 278 NEVER; scope 3 NOT reserved/LINK/
  // SITE/GLOBAL -> the chain ends: the 280-single arm)
  { napt->ip_layer = 255; uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0x21; p[24]=0xff; p[25]=3; p[39]=5; RawData r(nullptr,p,40); CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d;
    bool b=c6->decode(r,cd,d); printf("I6A scope3 -> %d\n",(int)b); napt->ip_layer = 1; }
  // I6B ISATAP spoof: OUTER v4 pre-set + proto 41=IPV6 (:232 get_ip4h()->
  // proto()); v6 src addr32[2] iface (addr BYTES 8-11 = p[16..19]) masked
  // 0xFCFFFFFF == 0x00005EFE (:234-:236) + addr32[3] (p[20..23]) 3.3.3.3 !=
  // outer ip_src raw 2.2.2.2 -> EV 453 :237-:240
  { napt->ip_layer = 255; uint8_t outer[20]={0x45,0,0,20, 0,0, 0,0, 64,41, 0,0, 1,1,1,1, 10,2,2,2};
    uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0xfe; p[9]=0x80; p[16]=0; p[17]=0; p[18]=0x5e; p[19]=0xfe; p[20]=2; p[21]=2; p[22]=2; p[23]=2; p[24]=0x21;
    CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d; d.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r(nullptr,p,40); bool b=c6->decode(r,cd,d); printf("I6B isatap -> %d\n",(int)b); napt->ip_layer = 1; }
  // I6C ISATAP clean: embedded v4 word == outer ip_src raw -> SILENT (the
  // negative pin; iface match alone NEVER alerts)
  { napt->ip_layer = 255; uint8_t outer[20]={0x45,0,0,20, 0,0, 0,0, 64,41, 0,0, 1,1,1,1, 10,2,2,2};
    uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0xfe; p[9]=0x80; p[16]=0; p[17]=0; p[18]=0x5e; p[19]=0xfe; p[20]=1; p[21]=1; p[22]=1; p[23]=1; p[24]=0x21;
    CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d; d.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r(nullptr,p,40); bool b=c6->decode(r,cd,d); printf("I6C isatap-ok -> %d\n",(int)b); napt->ip_layer = 1; }
  // I6D/I6E tunnel 6in4 PAIR :182-:186 (outer v4 proto 41 + inner v6):
  // I6D tunnel_mask = 0x04 (TUNNEL_6IN4 BYPASSED -> tunnel_bypass_enabled
  // TRUE -> codec.tunnel_bypass true); I6E mask 0 -> bypass FALSE (the
  // witness_18f observable-mask face; NOT the v4 arms -- v6 decode). napt
  // MISMATCH (255) so the update face NEVER pollutes the MiscTests observables)
  napt->ip_layer = 255;
  { uint8_t outer[20]={0x45,0,0,20, 0,0, 0,0, 64,4, 0,0, 1,1,1,1, 2,2,2,2};
    uint8_t p[40]={0x60,0,0,0, 0,0, 6,64}; p[8]=0x20; p[24]=0xfe;
    tun_witness_set_mask(0x04);
    CodecData cd(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d; d.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r(nullptr,p,40); bool b=c6->decode(r,cd,d);
    printf("I6D byp64-04 -> %d bypass=%d\n",(int)b,(int)cd.tunnel_bypass);
    tun_witness_set_mask(0);
    CodecData cd2(&conf,ProtocolId::ETHERTYPE_IPV6); DecodeData d2; d2.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r2(nullptr,p,40); bool b2=c6->decode(r2,cd2,d2);
    printf("I6E byp64-0 -> %d bypass=%d\n",(int)b2,(int)cd2.tunnel_bypass); }
  napt->ip_layer = 1;

  // ---- TCP (ICx): cd_tcp.cc (meta ON = pdd cksum bypass past the length
  // gates -- the tcp csum-fail path returns FALSE ALWAYS :243-:249, so the
  // DAQ-bypass arm is the ONLY ladder reaching flag_tests; honest DAQ face,
  // the same pdd consumption the E4 daq.h-drop inversion drives). TCP hdr
  // fields: th_offx2 @12 th_flags @13 (protocols/tcp.h); ports @0-3 ->
  // 25001/25002 unless an arm zeroes them (the TCPH helper). ----
  probe_daq_enable(1);
  // IC1 <20 -> EV 45 :204-:207
  { uint8_t p[19]={0}; RawData r(nullptr,p,19); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC1 trunc19 -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // IC2 offset 4 (0x40>>2=16<20) -> EV 46 SINGLE :212-:216
  { uint8_t p[20]; TCPH(p,0x40,0x10); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC2 off4 -> %d\n",(int)b); }
  // IC3 hlen 24 > raw 20 -> EV 47 SINGLE :218-:222
  { uint8_t p[20]; TCPH(p,0x60,0x10); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC3 hlen24gt -> %d\n",(int)b); }
  // IC4 XMAS + 24B form (payload 4 / urp 4 -> the :266 URG gate CLOSED):
  // FIN|PUSH|URG + SYN|ACK|RST -> 400 (are_flags_set BOTH :520-:523), SYN&RST
  // 421, SYN&FIN 420 -- the 3-sid flag_tests compound
  { uint8_t p[24]; TCPH(p,0x50,0x3F); p[22]=0; p[23]=4; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC4 xmas -> %d\n",(int)b); }
  // IC5 Nmap XMAS: flags EXACTLY FIN|PUSH|URG 0x29 (are_flags_set needs ALL
  // THREE -- the all-set gate face; NOT 0x0D) no SYN/ACK/RST -> 401 else-arm
  // + 423 + 422 (MUST_ACK) -- 3 sids
  { uint8_t p[24]; TCPH(p,0x50,0x29); p[22]=0; p[23]=4; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC5 nmapxmas -> %d\n",(int)b); }
  // IC6 clean ACK -> ZERO events (the baseline; lyr 20 pb 2 sp/dp header-path)
  { uint8_t p[20]; TCPH(p,0x50,0x10); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC6 ack -> %d lyr=%u pb=%u sp=%u dp=%u\n",(int)b,(unsigned)cd.lyr_len,(unsigned)cd.proto_bits,(unsigned)d.sp,(unsigned)d.dp); }
  // IC7 zero flags -> 423 SINGLE :551-:553
  { uint8_t p[20]; TCPH(p,0x50,0x00); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC7 noflags -> %d\n",(int)b); }
  // IC8 SYN|FIN -> 420 + 422
  { uint8_t p[20]; TCPH(p,0x50,0x03); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC8 synfin -> %d\n",(int)b); }
  // IC9 SYN|RST -> 421 SINGLE
  { uint8_t p[20]; TCPH(p,0x50,0x06); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC9 synrst -> %d\n",(int)b); }
  // IC10 FIN only -> 423 (:551 ACK|RST absent) + 422 MUST_ACK
  { uint8_t p[20]; TCPH(p,0x50,0x01); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC10 fin22 -> %d\n",(int)b); }
  // IC11 clean SYN seq 1 -> ZERO single (naptha/SHAFT/synmc negatives)
  { uint8_t p[20]; TCPH(p,0x50,0x02); ((uint32_t*)(p+4))[0]=htonl(1); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC11 syn -> %d\n",(int)b); }
  // IC12 SYN + v4 dst 239 + ANOM-ON: witness sfvar_ip_in FALSE -> NO 403
  // (the tcp anomaly WIRE face :539-:542 -- arms LIVE, verdict false)
  { uint8_t outer[20]={0x45,0,0,20, 0,0, 0,0, 64,6, 0,0, 10,1,1,1, 239,1,1,1};
    uint8_t p[20]; TCPH(p,0x50,0x02); ((uint32_t*)(p+4))[0]=htonl(1);
    CodecData cd(&conf_an,ProtocolId::TCP); DecodeData d; d.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r(nullptr,p,20); bool b=ct->decode(r,cd,d); printf("IC12 synmc -> %d\n",(int)b); }
  // IC13 SHAFT: SYN-only + seq()==674711609 -> 433 :549-:550 (host-LE face,
  // seq()==ntohl field compare -- the :557 TH_NORESERVED gate)
  { uint8_t p[20]; TCPH(p,0x50,0x02); ((uint32_t*)(p+4))[0]=htonl(674711609); RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC13 shaft -> %d\n",(int)b); }
  // IC14 NAPTHA THE LIVE ARM: the :533-:534 face compares the RAW FIELDS
  // (tcph->th_seq == naptha_seq / ip4h->ip_id == naptha_id), NOT seq()/id()
  // -- th_seq FIELD == the LE const 0x2a7b5c00 (:49) needs WIRE bytes 00 5c
  // 7b 2a (LE read of 0x005c7b2a-wire = 0x2a7b5c00 FIELD); ip_id FIELD ==
  // 0x9d01 (:50) wire 01 9d; th_flags == TH_SYN only (:532) + ip_api v4 ->
  // EV 402 -- pins the WORDS_BIGENDIAN arm THIS host took
  { uint8_t outer[20]={0x45,0,0,20, 0x01,0x9d, 0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2};
    uint8_t p[20]; TCPH(p,0x50,0x02); p[4]=0x00; p[5]=0x5c; p[6]=0x7b; p[7]=0x2a;
    CodecData cd(&conf,ProtocolId::TCP); DecodeData d; d.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r(nullptr,p,20); bool b=ct->decode(r,cd,d); printf("IC14 naptha-LE -> %d\n",(int)b); }
  // IC15 NAPTHA negative tripwire twin: wire 2a 7b 5c 00 (LE FIELD 0x005c
  // 7b2a != the LE const; the BE-era FACE) -> NEVER 402. THE 402 total over
  // IC14+IC15 EXACTLY-1 = the LE-arm seed-drift pin (:45-:51 pair)
  { uint8_t outer[20]={0x45,0,0,20, 0x01,0x9d, 0,0, 64,6, 0,0, 10,1,1,1, 10,2,2,2};
    uint8_t p[20]; TCPH(p,0x50,0x02); p[4]=0x2a; p[5]=0x7b; p[6]=0x5c; p[7]=0x00;
    CodecData cd(&conf,ProtocolId::TCP); DecodeData d; d.ip_api.set((const ip::IP4Hdr*)outer);
    RawData r(nullptr,p,20); bool b=ct->decode(r,cd,d); printf("IC15 naptha-faceBE -> %d\n",(int)b); }
  // IC16 URPGATE NEGATIVE: hlen20 + payload 4 + urp 100 > dsize 4 -> the
  // :266 gate (dsize and urp != dsize) SKIPS the URG block -> ZERO (the
  // urp-event lives in the option/URG parser -- cite-never-land honest)
  { uint8_t p[24]; TCPH(p,0x50,0x30); p[22]=0; p[23]=100; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC16 urp -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // IC17 PORT ZERO (both ports 0 raw; napt layer 255 MISMATCH -> the header-
  // port path :286-:287) -> 446 :290-:291
  { uint8_t p[20]; TCPH(p,0x50,0x10); ((uint16_t*)p)[0]=0; ((uint16_t*)p)[1]=0; RawData r(nullptr,p,20); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC17 portzero -> %d sp=%u dp=%u\n",(int)b,(unsigned)d.sp,(unsigned)d.dp); }
  // IC18 DAQ PORT OVERRIDE: napt ip_layer == codec.ip_layer_cnt (the tcp
  // decode NEVER increments it -- stays 0) -> snort.sp/dp = ntohs(napti->
  // src_addr? NO: src_port/dst_port) :281-:284 -> 7/9 vs header 25001/25002
  // (the ext#4 NAPTInfo_t member face INSIDE decode; tcp consumes the PORT
  // members ONLY -- addr members ride v4/v6 :250/:216)
  { uint8_t p[20]; TCPH(p,0x50,0x10);
    napt->ip_layer = 0; napt->src_port=htons(7); napt->dst_port=htons(9);
    CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    RawData r(nullptr,p,20); bool b=ct->decode(r,cd,d);
    printf("IC18 nanpt -> %d sp=%u dp=%u\n",(int)b,(unsigned)d.sp,(unsigned)d.dp);
    napt->ip_layer = 1; }
  // IC19 WSCALE data 15 > 14 -> 59 :375-:379 (validate ok len==3)
  { uint8_t p[24]; TCPH(p,0x60,0x10); p[20]=3; p[21]=3; p[22]=15; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC19 wscale -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // IC20 WSCALE clean data 4 -> ZERO (DECODE_TCP_WS peg cite :384)
  { uint8_t p[24]; TCPH(p,0x60,0x10); p[20]=3; p[21]=3; p[22]=4; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC20 wsok -> %d\n",(int)b); }
  // IC21 ECHO [6,6] hlen 28 (offx2 0x70): validate expected TCPOLEN_ECHO 6
  // OK -> obsolete flag; tot 6 < 8 -> next @26 = EOL -> done + invalid 2;
  // tail else-if obsolete -> 57 SINGLE (:481-:483 -- experimental FALSE pin:
  // the pair arms are MUTUALLY EXCLUSIVE) + lyr 28-2 = 26
  { uint8_t p[28]; TCPH(p,0x70,0x10); p[20]=6; p[21]=6; p[26]=0; RawData r(nullptr,p,28); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC21 echo57 -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // IC22 TRAILER_CSUM [18,4] hlen 24: the TRAILER face -- default case ->
  // experimental flag + validate_option WITHOUT expected (measured: with
  // TCPOLEN_TRAILER_CSUM 3 the FIXED-LEN list arms 58 -- [18,3] NEVER reaches
  // the tail: code 0 + tot==o_len -> ZERO face); [18,4]: opt+4 == end OK,
  // len 4 != o_len -> TRUNC gate (opt+opt->len > end? 20+... == end NO) ->
  // MEASURED EV 54 BADLEN -- the code-18 default-case + validate face
  { uint8_t p[24]; TCPH(p,0x60,0x10); p[20]=18; p[21]=4; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC22 trailer58 -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // IC23 CC.ECHO [13,6] hlen 28: 56 IMMEDIATE on ENTRY :454-:455 (BEFORE
  // validate) + fall-through validate CC 6 OK; next @26 EOL -> invalid 2 ->
  // tail ZERO (flags unset) -> 56 SINGLE + lyr 26
  { uint8_t p[28]; TCPH(p,0x70,0x10); p[20]=13; p[21]=6; p[26]=0; RawData r(nullptr,p,28); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC23 ttcp56 -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // IC24 OPTION BADLEN: WSCALE [3,len 1]: expected-3 validate: len!=3 ->
  // OPT_BADLEN -> 54 SINGLE :470-:472 (WSCALE rides NO obsolete/exp list --
  // the 99-code twin ALSO arms 57, honest cite) + invalid 4 -> lyr 20 PIN
  { uint8_t p[24]; TCPH(p,0x60,0x10); p[20]=3; p[21]=1; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC24 optbadlen54 -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }
  // IC25 OPTION TRUNC: TIMESTAMP [10,len 10] but o_len 4: opt+10 > end ->
  // OPT_TRUNC -> 55 SINGLE :473-:474 + invalid 4 PIN
  { uint8_t p[24]; TCPH(p,0x60,0x10); p[20]=10; p[21]=10; RawData r(nullptr,p,24); CodecData cd(&conf,ProtocolId::TCP); DecodeData d;
    bool b=ct->decode(r,cd,d); printf("IC25 opttrunc55 -> %d lyr=%u\n",(int)b,(unsigned)cd.lyr_len); }

  a4->dtor(c4); a6->dtor(c6); ac->dtor(ct);
  probe_daq_enable(0);
  return 0;
}

// 18l DEC probe -- arms drawn ONLY from the ground call-site census (PLAN §8:
// cite-never-guess; NEVER re-walked in-harness). cd_erspan2: len <
// sizeof(ERSpanType2Hdr)==8 gate cc :79 -> DECODE_ERSPAN2_DGRAM_LT_HDR 463;
// version-gate cc :87 (version() = ntohs(ver_vlan) >> 12, cc :65-:66) != 0x01
// -> the SHARED sid DECODE_ERSPAN_HDR_VERSION_MISMATCH 462 (the (a1) version-
// check story: 462 rides BOTH siblings, erspan2 cc :89 evt, erspan3 cc :91
// evt -- the 450-L sub-trio's one shared-sid pin); happy arm cc :93-:95
// lyr_len 8 + next ETHERTYPE_TRANS_ETHER_BRIDGING (0x6558 derived, NOT typed).
// cd_erspan3: len < sizeof(ERSpanType3Hdr)==20 cc :82 -> DECODE_ERSPAN3_
// DGRAM_LT_HDR 464 (DISK-measured face: seed-pass PLAN cite ":58-:70, 16B"
// was wrong-on-disk -- fields 2+2+4+2+4+4+2 pad face sums 20; the vectors
// CAUGHT the misfire 464-x3, fixed, §9 honesty receipt); != 0x02 -> 462 again cc :89/:91; happy arm cc :95-:96 --
// the EVAL-ORDER site-list face: erspan3 sets next_prot_id BEFORE lyr_len
// (next :95 THEN lyr :96) vs erspan2 lyr BEFORE next (:93/:94) -- a cite line
// through the cite, both arms return true so both fields land; the 20-B
// header + version accessor inline face cc :68-:69. Session-id face: ver_
// vlan low-12 vlan bits + flags_spanId (cc :61-:62 / :60-:61) are NEVER
// ported to vectors beyond the >>12 version mask -- the ONLY extracted field
// is version() (PLAN §8 honesty rule; cite lines below, NO fake prints).
// cd_trans_bridge: len < eth::ETH_HEADER_LEN 14 cc :54 -> DECODE_GRE_TRANS_
// DGRAM_LT_TRANSHDR 165 (ground sid-name face: the GRE token rides only the
// SID, §1/§12 -- NOT a gre-codec coupling, cd_gre.rs CITE-NEVER-LAND per §3);
// happy cc :66-:69: PROTO_BIT__ETH 0x000800 derived, lyr_len 14, next_prot_id
// = eh->ethertype() (eth.h :46-:47 ntohs face -- our own packet bytes),
// codec_flags CODEC_ETHER_NEXT 0x1000 derived (the eth-row face REUSED as a
// ground token, already-landed). log face cc :83-:86 (<= ETHERTYPE_MINIMUM
// -> "len:0x%04X" else "type:0x%04X") CITE-NEVER-VECTORIZE (log text NEVER
// vectorized, the 18k line-39 rule; the LogEthAddrs/TextLog_Print U-faces
// stay frozen-witness stand-ins, stubs ride witness_conf.cc :370 face -- eth
// build.sh :454 + tun :179 precedents, NEVER a new backbone pin). encode face
// cc :92 allocate / :98 ethertype_set htons-vs-copy / :100-:109 forward keep-
// vs-swap / :111-:112 NOT_SET resets: CITE-NEVER-CALL (EncState ctor pulls
// ip::IpApi -- eth_harness NEVER called encode either; zero encode arms).
// GID_DECODE 116 (codec_module.h :38 ground constexpr) drives the EV prefix.
// R6 eval-order rule: decode stored to bool VAR before any printf. NO
// dport/4789 face, NO tunnel prints (tunnel census 0x3 on this trio, §2).
// sids 165/462/463/464 ALREADY resident codec_module.rs :112/:220-:222 --
// NEVER re-walked, ZERO new consts.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include "protocols/eth.h"
#include <cstdio>
#include <cstdint>
extern const snort::BaseApi* cd_erspan2[];
extern const snort::BaseApi* cd_erspan3[];
extern const snort::BaseApi* cd_transbridge[];
using namespace snort;

int main(){
  SnortConfig conf("");
  const CodecApi* a2=(const CodecApi*)cd_erspan2[0];
  const CodecApi* a3=(const CodecApi*)cd_erspan3[0];
  const CodecApi* ab=(const CodecApi*)cd_transbridge[0];
  uint8_t z[4096]={0};

  // ---- cd_erspan2: the two-event ladder (463 outer gate + shared 462) ----
  Codec* c2=a2->ctor(nullptr);
  { RawData r(nullptr,z,7); CodecData c(&conf,ProtocolId::ETHERTYPE_ERSPAN_TYPE2); DecodeData d;
    bool b=c2->decode(r,c,d); printf("E2 len7 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); }   // cc :79/:81 EV 463; lyr NEVER set on the fail path (return :82)
  { uint8_t p[8]={0x20,0,0,0, 0,0,0,0};                                                       // version nibble 0x2 != 0x01
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_ERSPAN_TYPE2); DecodeData d;
    bool b=c2->decode(r,c,d); printf("E2 v2-mismatch -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // cc :87/:89 SHARED EV 462 (0x01 face = Version() cc :65-:66 >>12)
  { uint8_t p[12]={0x12,0x34, 0xAB,0xCD, 0,0,0,0, 0x08,0x00,0x11,0x22};                       // Type-2 version 0x01 head, 12 B payload behind
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::ETHERTYPE_ERSPAN_TYPE2); DecodeData d;
    bool b=c2->decode(r,c,d); printf("E2 happy -> %d lyr=%u next=%u flags=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.codec_flags); } // cc :93-:95 lyr 8 next TRANS_BRIDGING; lyr-before-next order face
  // session-id cite (cc :61-:62 ver_vlan vlan-bits + flags_spanId): NEVER ported
  // beyond the >>12 version mask -- p[0]=0x12 low nibble 2 / p[1]=0x34 ride ONLY
  // the wire, prints above extract version exclusively (PLAN §8).
  printf("E2 session-id cc:61-:62 ver_vlan+flags_spanId cited-never-ported face\n");

  // ---- cd_erspan3: 464 outer + shared 462 + the :95-before-:96 order face
  // NOTE (disk-wins correction vs PLAN :29 ":58-:70, 16B"): the ground struct
  // fields ver_vlan(2)+flags_spanId(2)+timestamp(4)+pad0(2)+pad1(2)+pad2(4)+
  // pad3(4) = 20B sizeof MEASURED (the seed-pass 16B arms misfired 464 x3 --
  // caught BY the vectors, fixed here; PLAN §9 preserves the receipt face).
  Codec* c3=a3->ctor(nullptr);
  { RawData r(nullptr,z,19); CodecData c(&conf,ProtocolId::ETHERTYPE_ERSPAN_TYPE3); DecodeData d;
    bool b=c3->decode(r,c,d); printf("E3 len19 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); }  // cc :82/:84 EV 464 (sizeof ERSpanType3Hdr 20 DISK-measured, cc :58-:70)
  { uint8_t p[20]={0x10,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};                           // version nibble 0x1 != 0x02
    RawData r(nullptr,p,20); CodecData c(&conf,ProtocolId::ETHERTYPE_ERSPAN_TYPE3); DecodeData d;
    bool b=c3->decode(r,c,d); printf("E3 v1-mismatch -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // cc :89/:91 SHARED 462 (inline version() :68-:69)
  { uint8_t p[20]={0x2E,0x02, 0x00,0x03, 0,0,0,1, 0,0, 0,0, 0,0,0,2, 0,0,0,3};                // Type-3 version 0x02 (0x2E>>4 nibble)
    RawData r(nullptr,p,20); CodecData c(&conf,ProtocolId::ETHERTYPE_ERSPAN_TYPE3); DecodeData d;
    bool b=c3->decode(r,c,d); printf("E3 happy -> %d lyr=%u next=%u flags=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.codec_flags); } // :95 next FIRST then :96 lyr (order face vs erspan2 :93/:94)
  printf("E3 session-id cc:60-:61 same-fields face cited-never-ported\n");
  printf("E3 order-site next:95-before-lyr:96 vs E2 lyr:93-before-next:94 cite\n");

  // ---- cd_trans_bridge: the 165 arm + the eth-mirror happy arm ----
  Codec* cb=ab->ctor(nullptr);
  { RawData r(nullptr,z,13); CodecData c(&conf,ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING); DecodeData d;
    bool b=cb->decode(r,c,d); printf("TB len13 -> %d\n",(int)b); }                             // cc :54/:56 EV 165 (the GRE-token SID name ONLY, §12; ETH_HEADER_LEN eth.h :37)
  { uint8_t p[14]={0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x11,0x22,0x33,0x44,0x55,0x66, 0x88,0xBE};  // dmac/smac + ethertype 0x88BE (erspan2-type2 INSIDE a trans-bridge frame -- the pair story, decimal-only print)
    RawData r(nullptr,p,14); CodecData c(&conf,ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING); DecodeData d;
    bool b=cb->decode(r,c,d); printf("TB happy -> %d pb=%u lyr=%u next=%u flags=%u\n",(int)b,(unsigned)c.proto_bits,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.codec_flags); } // :66 pb, :67 lyr, :68 next=eh->ethertype(), :69 flags
  printf("TB log cc:83-:86 len-vs-type face cited-never-vectorized\n");
  printf("TB encode cc:92/:98/:100-:109/:111-:112 cited-never-called EncState-IpApi face\n");
  return 0;
}

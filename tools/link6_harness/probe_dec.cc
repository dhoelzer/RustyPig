// 18m DEC probe -- arms drawn ONLY from the ground call-site census (PLAN §8:
// cite-never-guess; NEVER re-walked in-harness; dec_ground_cites.txt receipt).
// pppoe_disc: soft gate raw.len < PPPOE_HEADER_LEN 6 (:86) -> DECODE_BAD_
// PPPOE_DISC sid 120 (codec_module.rs RESIDENT :95, NEVER re-walked)
// cc :130-:132 evt, return :133 (lyr NEVER set on the fail path). HAPPY arm
// cc :136 return true with ZERO lyr/next EVER set -- the disc decode's zero-
// lyr face iff ground (PD len6 next stays the CodecData INIT prot :148 face,
// an honest unchanged-field print, cite-never-invent). pppoe_sess: len<6 ->
// DECODE_BAD_PPPOE_SESS 479 cc :154-:156; HAPPY cc :160 lyr = PPPOE_HEADER_
// LEN BEFORE :161 next = ETHERTYPE_PPP -- THE PAIR-LINK PIN (ppp_encap
// get_protocol_ids ETHERTYPE_PPP cc :52 -- the ground decode-chain family,
// PLAN §1). PADT: grep-0 CD ground NEVER-pull (the SESSION token TRUE x3
// :41/:140-name/:145-name face; build.sh re-asserts PADT 0 EVERY build).
// ppp_encap: raw.len<2 -> false :58-:59 (ZERO codec_event EVER on this TU --
// DECODE_ token census grep-0, §22 face; the EV sides of the pair are pppoe
// ONLY); protocol-compression odd-first-octet face :61-:67 lyr=1 (measured
// face: the compressed half-octet 0x21 NUMERICALLY matches PPP_IP 0x0021 :44
// so :82 fires next=IPV4 :103 -- the compression-vs-full-protocol collision
// rides ground, NOT our invention; 0x2d likewise rides VJ_COMP :82 return
// false with lyr=1 STAYS); 2-octet face :71-:73 lyr=2; VJ_COMP 0x002d -> :83
// false; VJ_UCOMP 0x002f len-gate :88-:91 (raw.len < lyr+ip::IP4_HEADER_LEN
// 20 -- protocols/ipv4.h :38 IP4_HEADER_LEN == 20 ground sed-cited) + the
// FIXIT-M :95-:98 const_cast set_proto(TCP) face (proto byte 9 flips to 6,
// PRINTED honest) + fall-through :100 -> :103 next IPV4; PPP_IPV6 0x0057 ->
// :107; PPP_IPX 0x002b -> :111 (ETHERTYPE_IPX 0x8137 :150 derived); default
// :114-:115 true, next UNSET. consts :44-:48 sed-pinned build-side.
// EVAL-ORDER cites: pppoe sess lyr:160-before-next:161; ppp_encap
// lyr:73-before-switch:80 (the R6 clone); encode faces pppoe cc :92-:105 +
// ppp_encap cc :120-:132 CITE-NEVER-CALL (EncState ctor pulls ip::IpApi --
// eth/tun/erspan ZERO-encode-arms precedent); session field PPPoEHdr cc :41
// cited-never-ported. GID_DECODE 116 (codec_module.h :38) drives the EV
// prefix. R6 eval-order rule: decode stored to bool VAR before any printf.
// EXACTLY 14 decode arms. All-decimal hygiene. sids 120/479 ALREADY resident
// codec_module.rs :95/:237 -- NEVER re-walked, ZERO new consts (PLAN §4).
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include <cstdio>
#include <cstdint>
extern const snort::BaseApi* cd_pppoepkt[];
extern const snort::BaseApi* cd_pppencap[];
using namespace snort;

int main(){
  SnortConfig conf("");
  const CodecApi* ad=(const CodecApi*)cd_pppoepkt[0];
  const CodecApi* as=(const CodecApi*)cd_pppoepkt[1];
  const CodecApi* ap=(const CodecApi*)cd_pppencap[0];
  uint8_t z[4096]={0};

  // ---- pppoe_disc: the 120 soft gate + the ZERO-lyr happy face ----
  Codec* cd_=ad->ctor(nullptr);
  { RawData r(nullptr,z,5); CodecData c(&conf,ProtocolId::ETHERTYPE_PPPOE_DISC); DecodeData d;
    bool b=cd_->decode(r,c,d); printf("PD len5 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // cc :130-:132 EV 120; return :133 lyr NEVER set
  { RawData r(nullptr,z,6); CodecData c(&conf,ProtocolId::ETHERTYPE_PPPOE_DISC); DecodeData d;
    bool b=cd_->decode(r,c,d); printf("PD len6 -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // cc :136: NO lyr/next EVER set (next rides the CodecData init ctor face codec.h :148 -- cited, never invented)
  printf("PD encode cc:92-:105 cited-never-called EncState-IpApi face\n");

  // ---- pppoe_sess: the 479 arm + THE PAIR-LINK happy face ----
  Codec* cs=as->ctor(nullptr);
  { RawData r(nullptr,z,5); CodecData c(&conf,ProtocolId::ETHERTYPE_PPPOE_SESS); DecodeData d;
    bool b=cs->decode(r,c,d); printf("PS len5 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); }  // cc :154-:156 EV 479
  { RawData r(nullptr,z,6); CodecData c(&conf,ProtocolId::ETHERTYPE_PPPOE_SESS); DecodeData d;
    bool b=cs->decode(r,c,d); printf("PS len6 -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :160 lyr BEFORE :161 next=ETHERTYPE_PPP -- the ppoe->ppp_encap decode-chain link pin (ppp_encap GETIDS same id cc :52)
  printf("PS order-site lyr:160-before-next:161 cite\n");
  printf("PS session-hdr cc:41 session field cited-never-ported (PADT grep-0 ground NEVER-pull face)\n");

  // ---- ppp_encap: the switch ladder, ZERO events on EVERY arm (:124 census) ----
  Codec* cp=ap->ctor(nullptr);
  { RawData r(nullptr,z,1); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE len1 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); }   // :58-:59 return false, NO event (the ZERO-codec_event TU face)
  { uint8_t p[2]={0x21,0x00};
    RawData r(nullptr,p,2); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE comp21 -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :61-:67 lyr=1; compressed half-octet 0x21 == PPP_IP 0x0021 :44 NUMERICALLY -> :82 fires :103 next IPV4 (the rfc1661 compression-collision face rides ground)
  { uint8_t p[2]={0x2d,0x00};
    RawData r(nullptr,p,2); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE comp2d -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // lyr=1 then 0x2d == PPP_VJ_COMP :82 return false -- lyr STAYS (lyr-before-switch :80 order face)
  { uint8_t p[2]={0x00,0x21};
    RawData r(nullptr,p,2); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE ip -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :71-:73 2-octet lyr=2; :82->:103 next IPV4
  { uint8_t p[2]={0x00,0x2d};
    RawData r(nullptr,p,2); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE vjcomp -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :83 return false; lyr 2 STAYS set
  { uint8_t p[21]={0x00,0x2f,0x45};  // 21 < lyr 2 + IP4_HEADER_LEN 20 (ipv4.h :38)
    RawData r(nullptr,p,21); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE vjucomp21 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // :88-:91 return false
  { uint8_t p[22]={0x00,0x2f,0x45,0,0,0,0,0,0, 0,0,0,0, 1,1,2,2, 3,3,4,4}; // 20-B IP4 head behind lyr 2; proto byte p[11]
    RawData r(nullptr,p,22); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE vjucomp22 -> %d lyr=%u next=%u proto9=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)p[11]); } // :97-:98 const_cast set_proto(TCP) FIXIT-M face (proto byte -> 6 PRINTED honest) + fall-through :100 -> :103 next IPV4
  { uint8_t p[2]={0x00,0x57};
    RawData r(nullptr,p,2); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE ipv6 -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :106-:107 ETHERTYPE_IPV6 0x86DD :151
  { uint8_t p[2]={0x00,0x2b};
    RawData r(nullptr,p,2); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE ipx -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :110-:111 ETHERTYPE_IPX 0x8137 :150
  { uint8_t p[2]={0x00,0x00};
    RawData r(nullptr,p,2); CodecData c(&conf,ProtocolId::ETHERTYPE_PPP); DecodeData d;
    bool b=cp->decode(r,c,d); printf("PE default -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :114-:115 true; next UNSET (init face)
  printf("PE order-site lyr:73-before-switch:80 cite; PE encode cc:120-:132 cited-never-called\n");
  return 0;
}

// 18n DEC probe -- arms drawn ONLY from the ground call-site census (PLAN §8:
// cite-never-guess; NEVER re-walked in-harness). sids 130/467/468-471 ALREADY
// resident codec_module.rs :96/:225/:226-:229 -- NEVER re-walked, ZERO new
// consts (PLAN §1 6/6 resident face; the sids_tokens.txt 3/8/2-token census).
// GRAFT-V3 eval-order headline (THE extension face, cd_vlan.cc): lyr_len :139
// SET BEFORE the pkthdr short-circuit daq_msg_get_pkthdr :141 -> flags &
// DAQ_PKT_FLAG_IGNORE_VLAN :142 -> return true :143 BEFORE the vid 0/4095 ->
// DECODE_BAD_VLAN :145-:148 check, then PROTO_BIT__VLAN :150 -- the IGNORE_VLAN
// arm SKIPS the BAD_VLAN event AND the :150 proto_bits set: V5 (vid 0, flag ON)
// prints pb=0 with NO EV line; V6 (vid 0, flag OFF) prints pb=1024 WITH EV 130.
// The pb 0-vs-1024 + EV-absence pair pins the order or the ext is decorative
// (PLAN §8). The witness pkthdr flags ride the witness_pkthdr.cc observable
// (witness_18f set-mask / witness_daq meta_enabled precedent -- ground code
// NEVER patched). vlan GETIDS is the unordered SET face (id_set :103) -- the
// face-A side pins the SET (python), never the iteration order.
// vlan soft gates: len < sizeof(vlan::VlanTagHdr) 4 (COPY-tree protocols/vlan.h
// fresh cp face, md5-pinned build-side) -> EV 130 cc :120-:123 lyr NEVER set
// on the fail path (:123 return); LLC branch proto <= ETHERNET_MAX_LEN_ENCAP
// 1518 (:98) -> next ETHERNET_LLC 263 (protocol_ids.h :134 0x0107) cc :134-
// :135; else next = (ProtocolId)proto :137 (QinQ 0x88A8 = 34984 arm); tpid
// ctor default "0x9100 0x9200" cc :49 (ctor(nullptr) -> default_tpids face,
// mod ? guard :200). V log cc :154-:171 + V encode cc :173-:185 cited-never-
// called (EncState ctor pulls ip::IpApi -- eth/tun/erspan ZERO-encode precedent).
// fabricpath: len < FABRICPATH_HEADER_LEN 16 (cc :70 sed-pinned) -> EV 467
// cc :78-:81; HAPPY cc :84 next = ETHERNET_802_3 261 (0x0105 :132) BEFORE
// :85 lyr = 16 -- the R6 bool-decode order clone MEASURED both lines; encode
// cc :89-:125 + format cc :127-:137 cited-never-called (Buffer/enc.flags face).
// ciscometadata const ladder cc :93-:98 (VALID_HDR_VER 1 / VALID_HDR_LEN 1 /
// VALID_OPT_LEN 0 / OPT_LEN_SHIFT 13 / OPT_TYPE_SGT 1 / MASK 0x1FFF sed-pinned
// build-side) + sizeof(cisco_meta_data::CiscoMetaDataHdr) == 8 (COPY-tree
// protocols/cisco_meta_data.h fresh cp, DISK arms len 7/8): len<8 -> stats++
// cc :108 + EV 468 :109 return false; ver != 1 -> stats INVALID-VER cc :118
// return false NO EVENT (the stats-only silent-fail face -- the ladder prints
// 0/0 with NO EV); len != 1 -> :124 return false NO EVENT; opt_len>0 (0x2001
// >> 13) -> EV 469 :137; type != 1 (0x0002) -> EV 470 :144; sgt == 0xFFFF
// SOFT event: stats++ + EV 471 :152 then CONTINUES :155 lyr = 8, :157 next =
// ntohs(ether_type) = 2048, :159 CODEC_ETHER_NEXT 4096, :160 PROTO_BIT__
// CISCO_META_DATA 131072 (decode_data.h :104) -- printed, the framing-error-
// but-decoded face; clean sgt arm NO event. eval-order cite ver:116-len:122-
// opt:130-type:141-sgt:149-lyr:155. pegs cc :49-:59 CountType::END :53 face
// (18m §P3's only-per-codec-stats cite) cited-not-vectorized; C encode cc
// :175-:187 + C log cc :165-:173 cited-never-called.
// GID_DECODE 116 (codec_module.h :38) drives the EV prefix (stubs_18d carried
// seam -- queue_event prints, NEVER re-walked). R6 eval-order rule: decode
// stored to bool VAR before any printf -- EXACTLY 16 arms (7 vlan + 2 fpath +
// 7 cisco). All-decimal hygiene. mpls NEVER-pull (the deferred q4 row law):
// the mpls TU rides its OWN future row -- ZERO mpls-table/EV 170-176 face
// ANYWHERE here.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include <cstdio>
#include <cstdint>
extern const snort::BaseApi* cd_vlan[];
extern const snort::BaseApi* cd_ciscometadata[];
extern const snort::BaseApi* cd_fabricpath[];
// witness_pkthdr.cc control surface (the graft-v3 flags observable):
extern "C" void pkthdr_witness_set_flags(unsigned long long f);
using namespace snort;

int main(){
  SnortConfig conf("");
  const CodecApi* av=(const CodecApi*)cd_vlan[0];
  const CodecApi* ac=(const CodecApi*)cd_ciscometadata[0];
  const CodecApi* af=(const CodecApi*)cd_fabricpath[0];
  uint8_t z[4096]={0};

  // ---- vlan: gates, branches, THE graft-v3 eval-order pair V5/V6 ----
  Codec* cv=av->ctor(nullptr);   // ctor :197 -> mod ? guard :200 -> default_tpids :49
  { RawData r(nullptr,z,3); CodecData c(&conf,ProtocolId::ETHERTYPE_8021Q); DecodeData d;
    bool b=cv->decode(r,c,d); printf("V len3 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // cc :120-:123 EV 130; lyr NEVER set (:123)
  { uint8_t p[4]={0x00,0x0A, 0x08,0x00};   // vid 10, proto 0x0800
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ETHERTYPE_8021Q); DecodeData d;
    bool b=cv->decode(r,c,d); printf("V ok -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); } // :137 next 2048; :139 lyr 4; flag OFF -> :148 passes, :150 PROTO_BIT__VLAN 1024
  { uint8_t p[4]={0x00,0x0A, 0x00,0xC8};   // proto 200 <= 1518 (:98) -> LLC face
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ETHERTYPE_8021Q); DecodeData d;
    bool b=cv->decode(r,c,d); printf("V llc -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :134-:135 ETHERNET_LLC 263 (0x0107 :134)
  { uint8_t p[4]={0x00,0x0A, 0x88,0xA8};   // QinQ 0x88A8 pass-through face
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ETHERTYPE_8021Q); DecodeData d;
    bool b=cv->decode(r,c,d); printf("V qinq -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); } // :137 cast face 34984 (8021AD :158 kin but the CAST rides, never the enum)
  pkthdr_witness_set_flags(0x0000000000000040ULL);  // DAQ_PKT_FLAG_IGNORE_VLAN (graft-v3 row 2)
  { uint8_t p[4]={0x00,0x00, 0x08,0x00};   // vid 0 = reserved
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ETHERTYPE_8021Q); DecodeData d;
    bool b=cv->decode(r,c,d); printf("V vid0-ignore -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); } // THE ext arm: :142->:143 return TRUE BEFORE :145-:148 -> NO EV 130 AND pb STAYS 0 (:150 never reached)
  pkthdr_witness_set_flags(0ULL);
  { uint8_t p[4]={0x00,0x00, 0x08,0x00};   // SAME bytes, flag OFF
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ETHERTYPE_8021Q); DecodeData d;
    bool b=cv->decode(r,c,d); printf("V vid0 -> %d lyr=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.proto_bits); } // :147-:148 EV 130 fires; :150 pb 1024 -- the V5/V6 CONTRAST = the eval-order pin
  { uint8_t p[4]={0x0F,0xFF, 0x08,0x00};   // vid 4095 = reserved
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ETHERTYPE_8021Q); DecodeData d;
    bool b=cv->decode(r,c,d); printf("V vid4095 -> %d lyr=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.proto_bits); } // :147 upper reserved arm
  printf("V order-site ext:141->143-before-badvid:145->148 pb0-vs-1024 cite; V encode cc:173-:185 + V log cc:154-:171 cited-never-called\n");

  // ---- fabricpath: the 467 soft gate + the :84-before-:85 order clone ----
  Codec* cf=af->ctor(nullptr);
  { RawData r(nullptr,z,15); CodecData c(&conf,ProtocolId::ETHERTYPE_FPATH); DecodeData d;
    bool b=cf->decode(r,c,d); printf("F len15 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // cc :78-:81 EV 467 (FABRICPATH_HEADER_LEN 16 cc :70)
  { RawData r(nullptr,z,16); CodecData c(&conf,ProtocolId::ETHERTYPE_FPATH); DecodeData d;
    bool b=cf->decode(r,c,d); printf("F len16 -> %d next=%u lyr=%u\n",(int)b,(unsigned)c.next_prot_id,(unsigned)c.lyr_len); } // :84 next=ETHERNET_802_3 261 BEFORE :85 lyr=16 (R6 clone MEASURED)
  printf("F order-site next:84-before-lyr:85 cite; F encode cc:89-:125 + F format cc:127-:137 cited-never-called\n");

  // ---- ciscometadata: the 468-471 ladder + the stats-only silent arms ----
  Codec* cc2=ac->ctor(nullptr);
  { RawData r(nullptr,z,7); CodecData c(&conf,ProtocolId::ETHERTYPE_CISCO_META); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("C len7 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // cc :106-:110 stats cc :108 + EV 468 (sizeof CiscoMetaDataHdr 8, copy-tree hdr face)
  { uint8_t p[8]={0x00,1, 0x00,0x01, 0x00,0x2A, 0x08,0x00};   // version 0 != 1
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_CISCO_META); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("C ver0 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // :116-:120 stats-only return false -- NO EVENT face (no EV line rides -- the silent-fail census)
  { uint8_t p[8]={0x01,0, 0x00,0x01, 0x00,0x2A, 0x08,0x00};   // length 0 != 1
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_CISCO_META); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("C lenf0 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // :122-:126 NO EVENT face
  { uint8_t p[8]={0x01,1, 0x20,0x01, 0x00,0x2A, 0x08,0x00};   // opt_len bits 0x2001>>13 = 1 > 0
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_CISCO_META); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("C optlen1 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // :130-:139 EV 469
  { uint8_t p[8]={0x01,1, 0x00,0x02, 0x00,0x2A, 0x08,0x00};   // type 2 != SGT 1
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_CISCO_META); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("C opttype2 -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // :141-:146 EV 470
  { uint8_t p[8]={0x01,1, 0x00,0x01, 0xFF,0xFF, 0x08,0x00};   // sgt 0xFFFF reserved
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_CISCO_META); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("C sgtffff -> %d lyr=%u next=%u flags=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.codec_flags,(unsigned)c.proto_bits); } // :148-:153 SOFT EV 471 then CONTINUES: :155 lyr 8 :157 next 2048 :159 CODEC_ETHER_NEXT 4096 :160 pb 131072
  { uint8_t p[8]={0x01,1, 0x00,0x01, 0x00,0x2A, 0x08,0x00};   // CLEAN arm sgt 42
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_CISCO_META); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("C clean -> %d lyr=%u next=%u flags=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.codec_flags,(unsigned)c.proto_bits); } // NO event; same tail face -- the ladder's happy end
  printf("C order-site ver:116-len:122-opt:130-type:141-sgt:149-lyr:155 cite; C pegs cc:49-:59 CountType-END:53 cited-not-vectorized\n");
  printf("C encode cc:175-:187 + C log cc:165-:173 cited-never-called\n");
  return 0;
}

// 18o DEC probe -- the label-stack ladder (PLAN §8 cite-never-guess; ground
// call-site census ONLY). sids 170-176 ALL resident codec_module.rs :113-:119
// (ZERO new consts); the sid band FIRES POSITIVE in its OWN vectors for the
// FIRST time (the 18n NEVER-land census flips AT the row; landed harnesses
// UNDISTURBED -- the python flip-census re-asserts their band grep-0). Bit
// layout decode_mpls_entry cc :137-:157 (ntohl; ttl low byte; bos = (w>>8)&1;
// tc = (w>>8)&0xE UNnormalized -- ground stores the RAW 3-bit field, the M2
// t=2 face; label = (w>>12)&0xFFFFF -- rfc5462 :139-:149): label 15 + S +
// tc1 + ttl 15 = 0x0000F30F (EVERY slice on ONE word). Word faces: label-N
// bos = (N<<12)|0x100|ttl; the 15-stack filler 0xF00F is NON-final (byte2
// S-bit 0 -- the layout trap rows usually eat).
// Walls/arms (EVERY line cc-cited): :169-:172 short -> EV 170 + false (M1;
// M15 DRAINS two non-final entries then the SAME wall re-fires -- the face a
// tail-counting rule MISSES); :181 validate PER-ENTRY INSIDE the walk (M8:
// label 3 at entry 8 -> 175 x7 THEN 174 + return false BEFORE any BoS
// capture -- mplsHdr NEVER filled, pb NEVER set, the :181-before-:186 eval-
// order receipt); label0 gate :286 `bos && plt && plt != IPV4` -- DEFAULT
// cfg plt AUTODETECT(0) SHORT-circuits (M3/M4/M16/M17 SILENT reserved face;
// EV 171 rides config arms ONLY: M13 eth + M14 ip6 -- the gate reads IPV4 so
// ip6 trips TOO); label1 :292-:296 bos -> 172 + FATAL return (M6; mid-stack
// bos FALSE continues SILENTLY -- M5 entry 1); label2 :302 `bos && plt &&
// plt != IPV6` -- auto SILENT (the 173 config census), :213 label2 rides
// FIRST -> 34525 (M7, payload nibble 0x41 = 2048 ELSE); label3 :308 uncon-
// ditional 174 + false; default 4-15 :313 SOFT 175 CONTINUES. BoS capture
// :186-:189 printed (bo/lab/t/ttl) + :191 set PROTO_BIT__MPLS 512 (ground
// 'proto_bits OR=' -- the clear is the DEPTH arm's ONLY proto_bits write,
// M10 pb=0 pins it): M2 bo=1 proves that set. :196/:200 depth gate `(cfg !=
// -1) && (++depth > cfg)` CONFIG-THREADED through ctor(m) :347-:354 (the
// MplsModule::set + get_data() binding -- the fmod V2_set precedent): M10 IS
// the ONLY 176 face (cfg 4; five non-final: the entry-5 gate ++depth 5 > 4
// fires AFTER 175 x5 INSIDE the walk, entry 6 the bos word NEVER read, pb
// 0, lyr NEVER set; default deflt "-1" CANNOT fire -- the config-threading
// pin); M11 4-stack cfg-4 PASSES (4 > 4 FALSE, the ladder boundary).
// :205-:206 bypass hook: witness_18f tun_mask observable (the tun_harness
// mask-pair precedent): 0 -> bypass TRUE (ground NSDMI tunnel_mask face);
// 0x80 = TUNNEL_MPLS (snort_config.h :126 sed-pinned) -> FALSE (the link4
// :139 hand-off face VECTORIZED -- the trio carried 0/0/0). :208 lyr_len.
// Next-prot ladder :210-:241 LABEL-FIRST eval order: :211 label0 -> 2048 in
// M3 (nibble 0x11 = 25944 ELSE), M4 (nibble 0x61 OVERRIDDEN -- pin), M13
// (forced eth NEVER rides), M14 (forced ip6 34525 NEVER rides -- label-first
// OVER BOTH :217 arms + 171 AGAIN since the gate reads IPV4); :213 label2 ->
// 34525 M7/M18; :215 forced ip4 M12 (2048 where auto nibble 0x11 says 25944
// -- forced-vs-auto pin); :219 forced eth M11 (25944 -- the honest recorded
// COINCIDENCE face: auto nibble 0x11 says the SAME 25944; only M12/M13/M14
// diverge, cited honestly); :226-:240 auto first-nibble (M2 0x41 -> 2048,
// M9 0x41; M5 payload 0xFF -> default 25944).
// encode :246-:272 VECTORIZED on the mirror face: pflow nullptr -> the
// nullptr Layer path (the mirror witness_flow.cc returns nullptr -- the
// ONLY Flow-U consumer; ground :255 `mpls_lyr && length` FALSE -> the
// raw_in/raw_len defaults :249-:250 ride); Buffer allocate gate :264 (zero-
// size Buffer -> allocate(4) FALSE -> false); ok-face = the memcpy_s :267
// copy THROUGH THE STOCK safec.h #else shim (config.h HAVE_SAFEC grep-0;
// the 42-L verbatim cp IS the minimal route -- C15 strip law, NO shim
// authoring, NO safe_*_lib graft) printing 4 label bytes + :268/:269
// next_ethertype ETHERTYPE_NOT_SET 0 / next_proto PROTO_NOT_SET 255 (proto-
// col_ids.h :91/:122). R6 rule: EVERY decode through a bool VAR (17 MEASURED
// M1..M17 + M18 = 18) before any printf; 2 encode bool VAR arms. log
// :320-:335 + TextLog_Print cited-NEVER-called (the U closes vs donor
// text_log.o -- the link4 REAL-list face). GID_DECODE 116 EV prefix rides
// the carried stubs_18d seam. All-decimal hygiene.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include <cstdio>
#include <cstdint>
extern const snort::BaseApi* cd_mpls[];
extern "C" void tun_witness_set_mask(unsigned short);
using namespace snort;
int main(){
  SnortConfig conf("");
  tun_witness_set_mask(0);                 // NSDMI tunnel_mask=0 face -> bypass TRUE
  const CodecApi* a=(const CodecApi*)cd_mpls[0];
  Codec* cc2=a->ctor(nullptr);             // DEFAULT cfg: depth -1, plt AUTO(0)
  uint8_t z[4096]={0};

  // ---- M1 short-pkt wall :169-:172 -> EV 170 + false; lyr NEVER set ----
  { RawData r(nullptr,z,3); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M1 len3 -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- M2 bit-layout ONE word 0x0000F30F (lab15 tc1 S ttl15) -> SOFT 175
  // (:313) + BoS print (:186-:189, t = the RAW 3-bit face 2) + :191 set +
  // auto nibble 0x41 -> 2048 (:231) ----
  { uint8_t p[8]={0x00,0x00,0xF3,0x0F, 0x41,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M2 one15 -> %d lyr=%u next=%u pb=%u bo=%u lab=%u t=%u ttl=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits,(unsigned)d.mplsHdr.bos,(unsigned)d.mplsHdr.label,(unsigned)d.mplsHdr.tc,(unsigned)d.mplsHdr.ttl); }

  // ---- M3 label0 AT BoS, DEFAULT plt: :286 gate SHORT-circuits (plt 0) ->
  // SILENT, NO 171; :211 label0 -> 2048 (payload nibble 0x11 = 25944 ELSE) ----
  { uint8_t p[8]={0x00,0x00,0x01,0xFF, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M3 lab0-auto -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- M4 label0 + payload nibble 0x61: :211 OVERRIDES nibble6 (34525
  // ELSE) -- the label-first pin #2 ----
  { uint8_t p[8]={0x00,0x00,0x01,0xFF, 0x61,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M4 lab0-n6 -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- M5 label1 MID-stack (S=0): :292 `if (bos)` FALSE -> NO event,
  // walk CONTINUES; entry2 15-bos SOFT 175; payload 0xFF -> :238 25944 ----
  { uint8_t p[12]={0x00,0x00,0x10,0xFF, 0x00,0x00,0xF3,0x0F, 0xFF,0x00,0x00,0x00};
    RawData r(nullptr,p,12); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M5 lab1-mid -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- M6 label1 AT BoS -> EV 172 + return false :292-:296 (NO BoS print) ----
  { uint8_t p[4]={0x00,0x00,0x11,0xFF};
    RawData r(nullptr,p,4); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M6 lab1-bos -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- M7 label2 AT BoS: :302 gate (plt AUTO 0) SILENT -- the 173 config
  // census face (NEVER fires on default cfg, cited-not-fabricated; M18
  // vectorizes the FORCED arm); :213 label2 -> 34525 (nibble 0x41 = 2048
  // ELSE -- label-first pin #3) ----
  { uint8_t p[8]={0x00,0x00,0x21,0xFF, 0x41,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M7 lab2-auto -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- M8 label3 at ENTRY 8 (15 x7 precede): 175 x7 THEN 174 (:308) +
  // return false -- the :181-per-entry-before-:186-capture eval-order
  // receipt: entry 8 NEVER captured, pb STAYS 0, :191 NEVER ran ----
  { uint8_t p[32]={0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F,
                   0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0x30,0xFF};
    RawData r(nullptr,p,32); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M8 lab3-e8 -> %d lyr=%u next=%u pb=%u lab=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits,(unsigned)d.mplsHdr.label); }

  // ---- M9 five-entry 15-stack (4 non-final + bos) + payload nibble 0x41;
  // the -1 sentinel deflt NEVER trips :196; SOFT 175 x5; 191-set face via
  // the bo print rides M2 ----
  { uint8_t p[24]={0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF3,0x0F, 0x41,0x00,0x00,0x00};
    RawData r(nullptr,p,24); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M9 five -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- config-thread arm: REAL mod->set(max_stack_depth 4 / payload_type
  // eth idx 2) + ctor(m) :347-:354 (mod->get_data() INTO MplsCodec). The
  // DEFAULT cfg CANNOT fire :196 (deflt "-1" sentinel :50) -> the M10 176
  // face below IS the ctor(m) threading pin (the face-A CTOR_M census
  // printed the same bind without the behavior). ----
  Module* m=a->base.mod_ctor();
  { const Parameter* pms=m->get_parameters();
    Value vd((int64_t)4);  vd.set(pms);      // max_stack_depth
    m->set("max_stack_depth", vd, nullptr);
    Value vp((uint64_t)1); vp.set(pms+1);    // payload_type enum idx 1 (eth -- ground MplsPayloadType ETHERNET=1, auto=0/eth=1/ip4=2/ip6=3 the :41 alignment)
    m->set("payload_type", vp, nullptr); }
  Codec* cd2=a->ctor(m);

  // ---- M10 depth 4: FIVE non-final 15s THEN the entry-5 gate (++depth 5 >
  // 4) -> 176 AFTER 175 x5 INSIDE the walk (:196 rides AFTER :194); entry 6
  // (bos word) NEVER read -> pb 0 (:200 clear face + :191 NEVER ran for a
  // bos), lyr NEVER set (:208 unreached) ----
  { uint8_t p[24]={0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF3,0x0F, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,24); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cd2->decode(r,c,d); printf("M10 five-d4 -> %d lyr=%u next=%u pb=%u lab=%u bo=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits,(unsigned)d.mplsHdr.label,(unsigned)d.mplsHdr.bos); }

  // ---- M11 FOUR-entry bos-stack vs cfg 4: :196 `4 > 4` FALSE -> PASSES
  // (the ladder-boundary face); forced ETH (:219) -> 25944 with the auto
  // nibble 0x11 COINCIDING (the honest recorded face; the DIVERGENCE pins
  // ride M12/M13/M14) ----
  { uint8_t p[20]={0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF3,0x0F, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,20); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cd2->decode(r,c,d); printf("M11 four-d4-eth -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits); }

  // ---- M12 label15-bos + FORCED ip4 (idx 3): :215 -> 2048 where the auto
  // nibble 0x11 says 25944 -- forced-vs-auto pin #1 (SOFT 175 pre) ----
  { Module* m4=a->base.mod_ctor();
    const Parameter* pms=m4->get_parameters();
    Value vp((uint64_t)2); vp.set(pms+1);    // ip4 (ground enum IPV4=2 -- the :41 alignment face)
    m4->set("payload_type", vp, nullptr);
    Codec* ci=a->ctor(m4);
    uint8_t p[8]={0x00,0x00,0xF3,0x0F, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=ci->decode(r,c,d); printf("M12 lab15-ip4 -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits);
    a->base.mod_dtor(m4); a->dtor(ci); }

  // ---- M13 label0-bos + FORCED eth: :286 gate `plt && plt!=IPV4` TRUE ->
  // EV 171 THEN :211 label0 rides FIRST -> 2048 (the forced-eth 25944 NEVER
  // rides -- label-first pin #4) ----
  { Module* m5=a->base.mod_ctor();
    const Parameter* pms=m5->get_parameters();
    Value vp((uint64_t)1); vp.set(pms+1);    // eth idx 1 (ground enum: auto 0 eth 1 ip4 2 ip6 3 -- the :41 alignment)
    m5->set("payload_type", vp, nullptr);
    Codec* ce=a->ctor(m5);
    uint8_t p[8]={0x00,0x00,0x01,0xFF, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=ce->decode(r,c,d); printf("M13 lab0-eth -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits);
    a->base.mod_dtor(m5); a->dtor(ce); }

  // ---- M14 label0-bos + FORCED ip6: the gate reads IPV4 ONLY -> 171 AGAIN
  // (the ip6-trips-too face) + :211 -> 2048 OVER the forced :217 34525 --
  // label-first pin #5 ----
  { Module* m6=a->base.mod_ctor();
    const Parameter* pms=m6->get_parameters();
    Value vp((uint64_t)3); vp.set(pms+1);    // ip6 idx 3
    m6->set("payload_type", vp, nullptr);
    Codec* c6=a->ctor(m6);
    uint8_t p[8]={0x00,0x00,0x01,0xFF, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=c6->decode(r,c,d); printf("M14 lab0-ip6 -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits);
    a->base.mod_dtor(m6); a->dtor(c6); }

  // ---- M15 DRAINED walk (DEFAULT cc2): two non-final 15s consume ALL 8
  // bytes -> stack_len 0 -> while(!bos) RE-ENTERS -> :169 EV 170 + false
  // (173/176 NEVER; lyr 0; the :169-at-drain face) ----
  { uint8_t p[8]={0x00,0x00,0xF0,0x0F, 0x00,0x00,0xF0,0x0F};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M15 drain -> %d lyr=%u next=%u pb=%u lab=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits,(unsigned)d.mplsHdr.label); }

  // ---- M16/M17 bypass-hook mask pair :205-:206 (TUNNEL_MPLS = 0x80,
  // snort_config.h :126): mask 0x80 -> bypass FALSE; mask 0 -> TRUE (the
  // ground NSDMI face; M17 ALSO prints the bo=1 face -- ground :191 'OR='
  // set, the :200 depth arm the ONLY proto_bits CLEAR, M10 pb=0 pin) ----
  tun_witness_set_mask(0x80);
  { uint8_t p[8]={0x00,0x00,0x01,0xFF, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M16 mask80 -> %d lyr=%u next=%u bypass=%d\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(int)c.tunnel_bypass); }
  tun_witness_set_mask(0);
  { uint8_t p[8]={0x00,0x00,0x01,0xFF, 0x11,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=cc2->decode(r,c,d); printf("M17 mask00 -> %d lyr=%u next=%u pb=%u bypass=%d bo=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits,(int)c.tunnel_bypass,(unsigned)d.mplsHdr.bos); }

  // ---- M18 label2-bos + FORCED eth (eth != IPV6 -> the :302 gate TRUE) ->
  // EV 173 the ONLY arm (the config-forced census, cited-not-fabricated --
  // M7 rode the SAME structure SILENT on the default cfg) + :213 -> 34525
  // (the forced-eth 25944 NEVER rides -- label-first pin OVER BOTH reserved
  // gate arms) ----
  { Module* m7=a->base.mod_ctor();
    const Parameter* pms=m7->get_parameters();
    Value vp((uint64_t)1); vp.set(pms+1);    // eth idx 1
    m7->set("payload_type", vp, nullptr);
    Codec* c7=a->ctor(m7);
    uint8_t p[8]={0x00,0x00,0x21,0xFF, 0x41,0x00,0x00,0x00};
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::ETHERTYPE_MPLS_UNICAST); DecodeData d;
    bool b=c7->decode(r,c,d); printf("M18 lab2-eth -> %d lyr=%u next=%u pb=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.proto_bits);
    a->base.mod_dtor(m7); a->dtor(c7); }

  // ---- encode :246-:272 on the mirror face (pflow nullptr -> the nullptr-
  // Layer fall-through :255 -> the raw_in/raw_len path -- the mirror's
  // honest observable face; the ONLY Flow-U consumer, the T census rides
  // build.sh): zero-size Buffer -> allocate(4) FALSE :264 -> false; ok-face
  // = the memcpy_s :267 copy THROUGH THE STOCK #else shim printing the 4
  // label bytes + :268/:269 NOT_SET faces (protocol_ids.h :91/:122). ----
  ip::IpApi ip_api;
  EncState enc(ip_api, ENC_FLAG_FWD, IpProtocol::PROTO_NOT_SET, 0, 0);
  uint8_t lab[4]={0x00,0x00,0xF3,0x0F};
  uint8_t t=0; Buffer b0(&t,0);
  bool e0=cc2->encode(lab,4,enc,b0,nullptr); printf("ENC b0 -> %d\n",(int)e0);
  uint8_t back[64]={0}; uint8_t* q=back+32; Buffer b1(q,32);
  bool e1=cc2->encode(lab,4,enc,b1,nullptr);
  printf("ENC ok -> %d bytes 0 0 243 15 netype %u npro %u\n",(int)e1,
    (unsigned)enc.next_ethertype,(unsigned)enc.next_proto);
  a->base.mod_dtor(m); a->dtor(cd2); a->dtor(cc2);
  return 0;
}

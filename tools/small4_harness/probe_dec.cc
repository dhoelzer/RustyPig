// 18h decode-face probe -- measured arms ONLY, drawn from the ground
// call-site census (NEVER guessed, receipts row18h R6): esp cc:100 gate +
// :108/:131/:135, frag cc:54/:60/:69/:91/:102/:111 + flags cc:77-:91,
// pgm pgm_nak_detect cc:108-:147 (statics :61-:63) -> cc:156, auth
// cc:92/:102/:113/:117. R6 var-before-printf (tun rule). The frag path is
// the lineage's MOST arm-dense ordering face: four events + three flags
// across ONE decode -- vector order = ground call order, NEVER sorted.
// esp config-gate arms: SnortConfig::enable_esp (ground NSDMI "false"
// face cc:44 param + snort_config.h :281) via esp_decoding() cc:100.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include <cstdio>
extern const snort::BaseApi* cd_esp[];
extern const snort::BaseApi* cd_frag[];
extern const snort::BaseApi* cd_pgm[];
extern const snort::BaseApi* cd_ah[];
using namespace snort;

static void set_ip6(DecodeData& d, uint8_t* b)
{ for (int i = 0; i < 40; ++i) b[i] = 0; b[0] = 0x60; d.ip_api.set(b); }

int main(){
  SnortConfig conf("");
  const CodecApi* ea=(const CodecApi*)cd_esp[0];
  const CodecApi* fa=(const CodecApi*)cd_frag[0];
  const CodecApi* pa=(const CodecApi*)cd_pgm[0];
  const CodecApi* aa=(const CodecApi*)cd_ah[0];
  uint8_t z[96]={0};

  // ---- ESP: config-gate OFF arm (cc:100 !esp_decoding() -> false, no EV;
  // ground NSDMI enable_esp=false face snort_config.h :281) ----
  Codec* ec=ea->ctor(nullptr);
  { RawData r(nullptr,z,24); CodecData c(&conf,ProtocolId::ESP); DecodeData d;
    bool b=ec->decode(r,c,d); printf("ESP gate-off -> %d\n",(int)b); }
  conf.enable_esp = true;
  // short-dgram arm raw.len < 8+12+2 -> EV 294 (cc:108)
  { RawData r(nullptr,z,21); CodecData c(&conf,ProtocolId::ESP); DecodeData d;
    bool b=ec->decode(r,c,d); printf("ESP short21 -> %d\n",(int)b); }
  // ok face: len 24, pad byte@10=0, next proto byte@11=6 -> lyr 8,
  // next 6, CODEC_ENCAP_LAYER face (cc:142-:148/:174), ip6 NOT entered
  { uint8_t e[32]={0}; e[10]=0; e[11]=6;
    RawData r(nullptr,e,24); CodecData c(&conf,ProtocolId::ESP); DecodeData d;
    bool b=ec->decode(r,c,d); printf("ESP ok24 -> %d lyr=%u next=%u flags=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.codec_flags); }
  // pad-huge arm: pad_length 255 >= len-14 -> cc:150-:155 TRUST+FINISHED
  { uint8_t e[32]={0}; e[10]=255; e[11]=6;
    RawData r(nullptr,e,24); CodecData c(&conf,ProtocolId::ESP); DecodeData d;
    bool b=ec->decode(r,c,d); printf("ESP pad255 -> %d next=%u dflags=%u\n",(int)b,(unsigned)c.next_prot_id,(unsigned)d.decode_flags); }
  // ip6 maxopts arm (cc:131 -> EV 456): hit_ip6_maxopts(cc:451) w/
  // max=1 curr=1 (NSDMI max_ip6_extensions=0 face snort_config.h :278)
  { uint8_t e[32]={0}; e[10]=0; e[11]=6; uint8_t b6[40]={0};
    RawData r(nullptr,e,24); CodecData c(&conf,ProtocolId::ESP); DecodeData d;
    conf.max_ip6_extensions=1; c.ip6_extension_count=1; set_ip6(d,b6);
    bool b=ec->decode(r,c,d); printf("ESP maxopts -> %d\n",(int)b);
    conf.max_ip6_extensions=0; }
  // ip6 ORDER arm (cc:135 codec.cc:156 current_order 6 <= curr 6 -> EV 296)
  // interleave face: the order EV rides a SUCCESSFUL decode
  { uint8_t e[32]={0}; e[10]=0; e[11]=6; uint8_t b6[40]={0};
    RawData r(nullptr,e,24); CodecData c(&conf,ProtocolId::ESP); DecodeData d;
    conf.max_ip6_extensions=5; c.curr_ip6_extension=6; set_ip6(d,b6);
    bool b=ec->decode(r,c,d); printf("ESP order66 -> %d flags=%u\n",(int)b,(unsigned)c.codec_flags);
    conf.max_ip6_extensions=0; }
  { std::vector<ProtocolId> v; ec->get_protocol_ids(v); printf("ESPPID %u n=%u\n",(unsigned)v[0],(unsigned)v.size()); }
  { const BaseApi* nb=cd_esp[0]; Module* m=nb->mod_ctor(); const RuleMap* rm=m->get_rules(); int n=0; while(rm[n].sid) n++;
    printf("ESPRULES %d sid0=%u name=%s\n", n, rm[0].sid, m->get_name()); nb->mod_dtor(m); }

  // ---- FRAG: NO mod_ctor (api :166/:167 nullptr face) -- the honest
  // absent-rule arm (R2: a port that adds a params table drifts FROM
  // ground); NO RuleMap face, NO Parameter face ----
  Codec* fc=fa->ctor(nullptr);
  // short arm raw.len < MIN_EXT_LEN(ipv6.h :32 = 8) -> EV 272 -> false (cc:54)
  { RawData r(nullptr,z,7); CodecData c(&conf,ProtocolId::FRAGMENT); DecodeData d;
    bool b=fc->decode(r,c,d); printf("FRAG short7 -> %d\n",(int)b); }
  // maxopts arm (cc:60 -> EV 456) after the len guard passes
  { uint8_t f[16]={0}; RawData r(nullptr,f,8); CodecData c(&conf,ProtocolId::FRAGMENT); DecodeData d;
    conf.max_ip6_extensions=1; c.ip6_extension_count=1;
    bool b=fc->decode(r,c,d); printf("FRAG maxopts -> %d\n",(int)b);
    conf.max_ip6_extensions=0; }
  // ZERO-LEN interleave head (order = ground call cc:69 -> :91): len 8,
  // off=0 MF=0 -> EV 459 (no return, cc:69) THEN EV 458 (cc:91); order
  // checks cc:102 (FRAGMENT 4, sets curr) + cc:111 (nxt UDP -> 7 > 4 set)
  { uint8_t f[16]={0}; f[0]=17; RawData r(nullptr,f,8); CodecData c(&conf,ProtocolId::FRAGMENT); DecodeData d;
    bool b=fc->decode(r,c,d); printf("FRAG zero8 -> %d lyr=%u next=%u dflags=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)d.decode_flags); }
  // MF flag arm: ip6f_offlg (ipv6.h :203, bytes 2-3) BE 0x0001 ->
  // DECODE_MF(:77) + DECODE_FRAG(:89); no 458 (cc:88 offset||MF holds);
  // next = FINISHED_DECODE (cc:124)
  { uint8_t f[16]={0}; f[0]=6; f[2]=0x00; f[3]=0x01;
    RawData r(nullptr,f,16); CodecData c(&conf,ProtocolId::FRAGMENT); DecodeData d;
    bool b=fc->decode(r,c,d); printf("FRAG mf -> %d next=%u dflags=%u\n",(int)b,(unsigned)c.next_prot_id,(unsigned)d.decode_flags); }
  // order2 EV arm: off=0 MF=0 + ip6f_nxt HOPOPTS(0) -> cc:111 order
  // IPV6IdExtensionOrder(HOPOPTS)=1 <= curr 4 -> EV 296 second order call
  { uint8_t f[16]={0}; f[0]=0; RawData r(nullptr,f,8); CodecData c(&conf,ProtocolId::FRAGMENT); DecodeData d;
    bool b=fc->decode(r,c,d); printf("FRAG ooo2 -> %d next=%u\n",(int)b,(unsigned)c.next_prot_id); }
  // offset arm offlg 0x0008 -> DECODE_FRAG, FINISHED_DECODE, no flags EV
  { uint8_t f[16]={0}; f[0]=6; f[3]=0x08;
    RawData r(nullptr,f,16); CodecData c(&conf,ProtocolId::FRAGMENT); DecodeData d;
    bool b=fc->decode(r,c,d); printf("FRAG off8 -> %d next=%u dflags=%u\n",(int)b,(unsigned)c.next_prot_id,(unsigned)d.decode_flags); }
  { std::vector<ProtocolId> v; fc->get_protocol_ids(v); printf("FRAGPID %u n=%u\n",(unsigned)v[0],(unsigned)v.size()); }
  printf("FRAG api mod_ctor=%d mod_dtor=%d\n", fa->base.mod_ctor?1:0, fa->base.mod_dtor?1:0);
  fa->dtor(fc);

  // ---- PGM: pgm_nak_detect statics cc:61-:63 feed cc:155/:156 (the ONLY
  // event site); decode ALWAYS returns true -> print-face arms on EV ----
  Codec* pc=pa->ctor(nullptr);
  // ERR arms: len <= sizeof(PgmHeader)=44 (cc:112) -- 44 + odd 45
  { RawData r(nullptr,z,44); CodecData c(&conf,ProtocolId::PGM); DecodeData d;
    bool b=pc->decode(r,c,d); printf("PGM len44 -> %d\n",(int)b); }
  { RawData r(nullptr,z,45); CodecData c(&conf,ProtocolId::PGM); DecodeData d;
    bool b=pc->decode(r,c,d); printf("PGM len45 -> %d\n",(int)b); }
  { uint8_t p[48]={0}; p[4]=9;   // type != 8 -> cc:120 ERR
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::PGM); DecodeData d;
    bool b=pc->decode(r,c,d); printf("PGM type9 -> %d\n",(int)b); }
  // VULN face: type@4=8 opt.type@36=2 len=48 data_left 12 > opt.len 8;
  // checksum field 0 -> skip the expensive cksum (cc:135) -> EV 454
  { uint8_t p[48]={0}; p[4]=8; p[36]=2; p[37]=8;
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::PGM); DecodeData d;
    bool b=pc->decode(r,c,d); printf("PGM nak-vuln -> %d\n",(int)b); }
  // cksum-guard face: same but checksum field 0xFFFF + lead byte 0x01 +
  // type 8 -> fold sum != 0 -> ERR, NO EV (cc:139-:140 cheap guard)
  { uint8_t p[48]={0}; p[4]=8; p[6]=0xFF; p[7]=0xFF; p[0]=0x01; p[36]=2; p[37]=8;
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::PGM); DecodeData d;
    bool b=pc->decode(r,c,d); printf("PGM cksum-guard -> %d\n",(int)b); }
  // OK face: data_left 12 <= opt.len 200 -> PGM_NAK_OK, no EV
  { uint8_t p[48]={0}; p[4]=8; p[36]=2; p[37]=200;
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::PGM); DecodeData d;
    bool b=pc->decode(r,c,d); printf("PGM optlen-ok -> %d\n",(int)b); }
  { std::vector<ProtocolId> v; pc->get_protocol_ids(v); printf("PGMPID %u n=%u\n",(unsigned)v[0],(unsigned)v.size()); }
  { const BaseApi* nb=cd_pgm[0]; Module* m=nb->mod_ctor(); const RuleMap* rm=m->get_rules(); int n=0; while(rm[n].sid) n++;
    printf("PGMRULES %d sid0=%u name=%s\n", n, rm[0].sid, m->get_name()); nb->mod_dtor(m); }

  // ---- AUTH (table cd_ah, NAME auth -- the drift ride through decode) ----
  Codec* ac=aa->ctor(nullptr);
  // short arm len < MIN_AUTH_LEN(cc:79 = 16) -> EV 465 -> false (cc:92)
  { RawData r(nullptr,z,15); CodecData c(&conf,ProtocolId::AUTH); DecodeData d;
    bool b=ac->decode(r,c,d); printf("AH short15 -> %d\n",(int)b); }
  // bad-len arm len byte 8 -> lyr 8+(8<<2)=40 > 16 -> EV 466 -> false (cc:98/:102)
  { uint8_t a[16]={0}; a[1]=8;
    RawData r(nullptr,a,16); CodecData c(&conf,ProtocolId::AUTH); DecodeData d;
    bool b=ac->decode(r,c,d); printf("AH badlen -> %d\n",(int)b); }
  // ok face (ip4-side: is_ip6 false, cc:109 skips the ip6 block): len 24,
  // len byte 4 -> lyr 8+16=24, next = a[0] = 6 (cc:98/:106)
  { uint8_t a[24]={0}; a[0]=6; a[1]=4;
    RawData r(nullptr,a,24); CodecData c(&conf,ProtocolId::AUTH); DecodeData d;
    bool b=ac->decode(r,c,d); printf("AH ok24 -> %d lyr=%u next=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id); }
  // ip6 maxopts arm (cc:113 -> EV 456)
  { uint8_t a[24]={0}; a[0]=6; a[1]=4; uint8_t b6[40]={0};
    RawData r(nullptr,a,24); CodecData c(&conf,ProtocolId::AUTH); DecodeData d;
    conf.max_ip6_extensions=1; c.ip6_extension_count=1; set_ip6(d,b6);
    bool b=ac->decode(r,c,d); printf("AH maxopts -> %d\n",(int)b);
    conf.max_ip6_extensions=0; }
  // ORDER arm (cc:117 AUTH order 5 <= curr 5 -> EV 296) rides a
  // SUCCESSFUL decode (interleave face)
  { uint8_t a[24]={0}; a[0]=6; a[1]=4; uint8_t b6[40]={0};
    RawData r(nullptr,a,24); CodecData c(&conf,ProtocolId::AUTH); DecodeData d;
    conf.max_ip6_extensions=5; c.curr_ip6_extension=5; set_ip6(d,b6);
    bool b=ac->decode(r,c,d); printf("AH order55 -> %d next=%u\n",(int)b,(unsigned)c.next_prot_id);
    conf.max_ip6_extensions=0; }
  { std::vector<ProtocolId> v; ac->get_protocol_ids(v); printf("AHPID %u n=%u\n",(unsigned)v[0],(unsigned)v.size()); }
  { const BaseApi* nb=cd_ah[0]; Module* m=nb->mod_ctor(); const RuleMap* rm=m->get_rules(); int n=0; while(rm[n].sid) n++;
    printf("AHRULES %d sid0=%u name=%s\n", n, rm[0].sid, m->get_name()); nb->mod_dtor(m); }
  return 0;
}

// 18f decode-face skeleton -- measured arms, R6 var-before-printf, and the
// ONE new witness exercised across the THREE ground masks (witness_18f.cc;
// TUNNEL_GTP 0x01 / TUNNEL_TEREDO 0x02 / TUNNEL_GENEVE 0x200). NO value below
// is a forecast: build.sh greps arms only against GROUND anchors (17p).
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include <cstdio>
extern const snort::BaseApi* cd_geneve[]; extern const snort::BaseApi* cd_gtp[];
extern const snort::BaseApi* cd_teredo[];
extern "C" void tun_witness_set_mask(unsigned short);
using namespace snort;
static void api(const char* tag, const BaseApi** t){ const CodecApi* a=(const CodecApi*)t[0];
  printf("API %s type=%d size=%u ver=%u name=%s\n", tag,(int)a->base.type,a->base.size,a->base.api_version,a->base.name);
  printf("HELP %s %s\n", tag, a->base.help); }
int main(){
  SnortConfig conf("");
  api("geneve",cd_geneve); api("gtp",cd_gtp); api("teredo",cd_teredo);
  // ---- teredo arms (cd_teredo.cc:64 short / :67-:77 auth / :86-:95 origin /
  // :97-:98 ipv6 nibble / :106 bypass / :110-:113 ENCAP-LAYR + next + bits)
  const CodecApi* ta=(const CodecApi*)cd_teredo[0]; Codec* tt=ta->ctor(nullptr);
  uint8_t z[64]={0};
  RawData t0(nullptr,z,1); CodecData tc0(&conf,ProtocolId::TEREDO); DecodeData td0;
  bool x0=tt->decode(t0,tc0,td0); printf("TER short1 -> %d\n",(int)x0);
  uint8_t a[64]={0}; a[1]=1; // indicator==AUTH but len 3 < INDICATOR_AUTH_MIN_LEN 13
  RawData t1(nullptr,a,3); CodecData tc1(&conf,ProtocolId::TEREDO); DecodeData td1;
  bool x1=tt->decode(t1,tc1,td1); printf("TER auth-shord -> %d\n",(int)x1);
  uint8_t o[64]={0}; o[8]=0x60; // ORIGIN (indicator 0, 8 B consumed) + ipv6 nibble @9
  tun_witness_set_mask(0);      // ground NSDMI tunnel_mask=0 face -> bypass TRUE
  RawData t2(nullptr,o,10); CodecData tc2(&conf,ProtocolId::TEREDO); DecodeData td2;
  bool x2=tt->decode(t2,tc2,td2); printf("TER mask0000 -> %d bypass=%d\n",(int)x2,(int)tc2.tunnel_bypass);
  tun_witness_set_mask(2);      // TUNNEL_TEREDO bit -> bypass FALSE
  RawData t3(nullptr,o,10); CodecData tc3(&conf,ProtocolId::TEREDO); DecodeData td3;
  bool x3=tt->decode(t3,tc3,td3); printf("TER mask0002 -> %d bypass=%d lyr=%u next=%u bits=%u flags=%u\n",(int)x3,(int)tc3.tunnel_bypass,(unsigned)tc3.lyr_len,(unsigned)tc3.next_prot_id,(unsigned)tc3.proto_bits,(unsigned)tc3.codec_flags);
  tun_witness_set_mask(2);      // mask STILL the teredo bit: ports != 3544 -> ENCAP-LAYR arm
  uint8_t o3[64]={0}; o3[8]=0x60;
  RawData t4(nullptr,o3,10); CodecData tc4(&conf,ProtocolId::TEREDO); DecodeData td4;
  td3.sp=3544; // TEREDO_PORT face in the mask0002 arm; td4 stays ports-off
  bool x4=tt->decode(t4,tc4,td4); printf("TER ports-off -> %d flags=%u\n",(int)x4,(unsigned)tc4.codec_flags);
  std::vector<ProtocolId> tv; tt->get_protocol_ids(tv); printf("TERPID %u n=%u\n",(unsigned)tv[0],(unsigned)tv.size());
  // ---- gtp arms (cd_gtp.cc:82 short / :85 type!=255 / :88 GTP'-flag /
  // v0 :96-:105 BAD_LEN / v1 :168-:171 BAD_LEN / :177 bypass / :185-:187
  // MULTI-ENCAP / :189-:197 ENCAP ip_ver next arms)
  const CodecApi* ga=(const CodecApi*)cd_gtp[0]; Codec* gg=ga->ctor(nullptr);
  RawData g0(nullptr,z,7); CodecData gc0(&conf,ProtocolId::GTP); DecodeData gd0;
  bool g0b=gg->decode(g0,gc0,gd0); printf("GTP short7 -> %d\n",(int)g0b);
  uint8_t s[64]={0}; s[0]=0x10; s[1]=0x01; // PDU-bit v0, type != 255
  RawData g1(nullptr,s,8); CodecData gc1(&conf,ProtocolId::GTP); DecodeData gd1;
  bool g1b=gg->decode(g1,gc1,gd1); printf("GTP type1 -> %d\n",(int)g1b);
  uint8_t q6[64]={0}; q6[0]=0x20; q6[1]=0xff; // v0 no PDU bit -> GTP' exit
  RawData gq(nullptr,q6,8); CodecData gcq(&conf,ProtocolId::GTP); DecodeData gdq;
  bool gqb=gg->decode(gq,gcq,gdq); printf("GTP gtpprime -> %d\n",(int)gqb);
  uint8_t v[64]={0}; v[0]=0x10; v[1]=0xff; // v0 PDU, raw 8 < V0_HEADER_LEN 20
  RawData g2(nullptr,v,8); CodecData gc2(&conf,ProtocolId::GTP); DecodeData gd2;
  bool g2b=gg->decode(g2,gc2,gd2); printf("GTP v0-shord -> %d\n",(int)g2b);
  uint8_t w[64]={0}; w[0]=0x30; w[1]=0xff; // v1, no optional bits, length=0
  tun_witness_set_mask(1);      // TUNNEL_GTP bit -> bypass FALSE
  RawData g3(nullptr,w,8); CodecData gc3(&conf,ProtocolId::GTP); DecodeData gd3;
  bool g3b=gg->decode(g3,gc3,gd3); printf("GTP v1-ok mask0001 -> %d bypass=%d lyr=%u bits=%u\n",(int)g3b,(int)gc3.tunnel_bypass,(unsigned)gc3.lyr_len,(unsigned)gc3.proto_bits);
  RawData g4(nullptr,w,8); CodecData gc4(&conf,ProtocolId::GTP); DecodeData gdd=gd3; gdd.decode_flags|=0x1000; // DECODE_GTP face -> EV
  bool g4b=gg->decode(g4,gc4,gdd); printf("GTP v1-twice -> %d\n",(int)g4b);
  tun_witness_set_mask(0);
  uint8_t x2b[64]={0}; x2b[0]=0x30; x2b[1]=0xff; x2b[2]=0x00; x2b[3]=0x05; // v1 length-field 5: 8 != 5+8 -> BAD_LEN
  RawData g5(nullptr,x2b,8); CodecData gc5(&conf,ProtocolId::GTP); DecodeData gd5;
  bool g5b=gg->decode(g5,gc5,gd5); printf("GTP v1-badlen -> %d\n",(int)g5b);
  uint8_t e4[64]={0}; e4[0]=0x30; e4[1]=0xff; e4[3]=0x08; // v1 length-field 8: raw 16 == 8+8 ok
  e4[8]=0x45; // inner at raw.data+len(8): ip_ver nibble 0x40 -> next=IPIP
  RawData g6(nullptr,e4,16); CodecData gc6(&conf,ProtocolId::GTP); DecodeData gd6;
  bool g6b=gg->decode(g6,gc6,gd6); printf("GTP v1-encap -> %d next=%u lyr=%u flags=%u\n",(int)g6b,(unsigned)gc6.next_prot_id,(unsigned)gc6.lyr_len,(unsigned)gc6.codec_flags);
  std::vector<ProtocolId> gv; gg->get_protocol_ids(gv); printf("GTPPID %u n=%u\n",(unsigned)gv[0],(unsigned)gv.size());
  // ---- geneve arms (cd_geneve.cc:132 LT / :139 VERSION / :148 INVALID-HDR /
  // :156-:159 C-flag / :161 validate -> :117 INVALID-OPTIONS face via long
  // opt / :166 bypass / :169-:175 next + bits)
  const CodecApi* na=(const CodecApi*)cd_geneve[0]; Codec* nq=na->ctor(nullptr);
  RawData n0(nullptr,z,7); CodecData nc0(&conf,ProtocolId::GENEVE); DecodeData nd0;
  bool n0b=nq->decode(n0,nc0,nd0); printf("GEN short7 -> %d\n",(int)n0b);
  uint8_t q1[64]={0}; q1[0]=0x40; // version bits = 1 != RFC_8926_GENEVE_VERSION 0
  RawData n1(nullptr,q1,8); CodecData nc1(&conf,ProtocolId::GENEVE); DecodeData nd1;
  bool n1b=nq->decode(n1,nc1,nd1); printf("GEN ver1 -> %d\n",(int)n1b);
  uint8_t h2[64]={0}; h2[0]=0x3f; // opts_len 0x3f*4=252 -> hdrlen 260 > 8
  RawData n2(nullptr,h2,8); CodecData nc2(&conf,ProtocolId::GENEVE); DecodeData nd2;
  bool n2b=nq->decode(n2,nc2,nd2); printf("GEN hdr-long -> %d\n",(int)n2b);
  uint8_t c[64]={0}; c[0]=0x01; c[1]=0x40; // opts_len 4, C flag set, option not critical -> EV INVALID_FLAGS face skipped; opts ok -> falls through; keep as measured face
  c[4]=0x00; c[5]=0x00; c[6]=0x65; c[7]=0x58;
  RawData n3(nullptr,c,12); CodecData nc3(&conf,ProtocolId::GENEVE); DecodeData nd3;
  bool n3b=nq->decode(n3,nc3,nd3); printf("GEN C-no-copt -> %d\n",(int)n3b);
  uint8_t h[64]={0}; h[4]=0x65; h[5]=0x58; // opts_len 0, proto 0x6558 -> ETHERNET_802_3
  tun_witness_set_mask(0x200);  // TUNNEL_GENEVE bit -> bypass FALSE
  RawData n4(nullptr,h,8); CodecData nc4(&conf,ProtocolId::GENEVE); DecodeData nd4;
  bool n4b=nq->decode(n4,nc4,nd4); printf("GEN mask0200 -> %d bypass=%d lyr=%u next=%u bits=%u\n",(int)n4b,(int)nc4.tunnel_bypass,(unsigned)nc4.lyr_len,(unsigned)nc4.next_prot_id,(unsigned)nc4.proto_bits);
  tun_witness_set_mask(0);      // ground default face -> bypass TRUE
  RawData n5(nullptr,h,8); CodecData nc5(&conf,ProtocolId::GENEVE); DecodeData nd5;
  bool n5b=nq->decode(n5,nc5,nd5); printf("GEN mask0000 -> %d bypass=%d\n",(int)n5b,(int)nc5.tunnel_bypass);
  uint8_t o2[64]={0}; o2[0]=0x01; o2[4]=0x65; o2[5]=0x58; o2[11]=0x07; // opt olen = 4 + (0x07&0x1f)*4 = 32 > 4 -> INVALID_OPTIONS
  RawData n6(nullptr,o2,12); CodecData nc6(&conf,ProtocolId::GENEVE); DecodeData nd6;
  bool n6b=nq->decode(n6,nc6,nd6); printf("GEN badopt -> %d\n",(int)n6b);
  std::vector<ProtocolId> nv; nq->get_protocol_ids(nv); printf("GENPID %u n=%u\n",(unsigned)nv[0],(unsigned)nv.size());
  // ---- module/RuleMap faces (geneve 5 rows, gtp 2 rows; teredo NO module)
  const BaseApi* nb=cd_geneve[0]; Module* nm=nb->mod_ctor(); const RuleMap* nr=nm->get_rules(); int ncc=0; while(nr[ncc].sid) ncc++;
  printf("GEN rules=%d sid0=%u name=%s\n",ncc,nr[0].sid,nm->get_name()); nb->mod_dtor(nm);
  const BaseApi* gb=cd_gtp[0]; Module* gm=gb->mod_ctor(); const RuleMap* gr=gm->get_rules(); int gc7=0; while(gr[gc7].sid) gc7++;
  printf("GTP rules=%d sid0=%u name=%s\n",gc7,gr[0].sid,gm->get_name()); gb->mod_dtor(gm);
  printf("TER mod_ctor=%d mod_dtor=%d\n", ta->base.mod_ctor?1:0, ta->base.mod_dtor?1:0);
  return 0;
}

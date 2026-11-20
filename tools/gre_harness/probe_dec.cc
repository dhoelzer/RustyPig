// 18g decode-face probe -- measured arms ONLY (event sites ground cd_gre.cc
// :171/:189/:241/:248/:255/:270/:276), R6 var-before-printf (tun rule), the
// witness_18f carry exercised across the TWO TUNNEL_GRE mask faces (0x40 set
// -> bypass FALSE / ground tunnel_mask=0 default -> bypass TRUE). NO value
// below is a forecast: build.sh greps arms only against GROUND anchors (17p).
// The encode face IS the ground embedded TEST_CASE's own subject (:352-:365:
// Buffer over 1 byte, raw_len 5 -> allocate gate), probe-side arm per PLAN 8.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include <cstdio>
extern const snort::BaseApi* cd_gre[];
extern "C" void tun_witness_set_mask(unsigned short);
using namespace snort;
int main(){
  SnortConfig conf("");
  const CodecApi* a=(const CodecApi*)cd_gre[0];
  printf("API gre type=%d size=%u ver=%u name=%s\n",(int)a->base.type,(unsigned)a->base.size,(unsigned)a->base.api_version,a->base.name);
  printf("HELP gre %s\n", a->base.help);
  Codec* gg=a->ctor(nullptr);
  uint8_t z[64]={0};
  // short face: raw.len < GRE_HEADER_LEN (cc:171) -> EV 160
  RawData r0(nullptr,z,3); CodecData c0(&conf,ProtocolId::GRE); DecodeData d0;
  bool b0=gg->decode(r0,c0,d0); printf("GRE short3 -> %d\n",(int)b0);
  // v0 bad flags: version&0xF8 set (cc:189) -> EV 163
  uint8_t f[16]={0}; f[1]=0x08;
  RawData r1(nullptr,f,8); CodecData c1(&conf,ProtocolId::GRE); DecodeData d1;
  bool b1=gg->decode(r1,c1,d1); printf("GRE v0-badflags -> %d\n",(int)b1);
  // v0 chksum walk (cc:192-:193 len+=CHKSUM+OFFSET) then the SECOND guard
  // len>raw.len (cc:276 -> 160): flags 0x80, raw 4 -> len 8 > 4
  uint8_t k[16]={0}; k[0]=0x80;
  RawData r2(nullptr,k,4); CodecData c2(&conf,ProtocolId::GRE); DecodeData d2;
  bool b2=gg->decode(r2,c2,d2); printf("GRE chksum-long -> %d\n",(int)b2);
  // v0 seq walk -> second guard face: flags 0x10, raw 4 -> len 8 > 4
  uint8_t q[16]={0}; q[0]=0x10;
  RawData r3(nullptr,q,4); CodecData c3(&conf,ProtocolId::GRE); DecodeData d3;
  bool b3=gg->decode(r3,c3,d3); printf("GRE seq-long -> %d\n",(int)b3);
  // v1 flags-present arm (cc:238-:241) -> EV 164: version 0x01|0x08 (V1_FLAGS)
  uint8_t v1[16]={0}; v1[1]=0x09;
  RawData r4(nullptr,v1,8); CodecData c4(&conf,ProtocolId::GRE); DecodeData d4;
  bool b4=gg->decode(r4,c4,d4); printf("GRE v1-flags -> %d\n",(int)b4);
  // v1 wrong ethertype arm (cc:246-:248) -> EV 164: etype 0 != ETHERTYPE_PPP
  uint8_t v2[16]={0}; v2[1]=0x01;
  RawData r5(nullptr,v2,8); CodecData c5(&conf,ProtocolId::GRE); DecodeData d5;
  bool b5=gg->decode(r5,c5,d5); printf("GRE v1-badetype -> %d\n",(int)b5);
  // v1 no-KEY arm (cc:253-:255) -> EV 164: etype 0x880B, flags 0
  uint8_t v3[16]={0}; v3[1]=0x01; v3[2]=0x88; v3[3]=0x0B;
  RawData r6(nullptr,v3,8); CodecData c6(&conf,ProtocolId::GRE); DecodeData d6;
  bool b6=gg->decode(r6,c6,d6); printf("GRE v1-nokey -> %d\n",(int)b6);
  // bad version face (default arm cc:270) -> EV 162
  uint8_t bv[16]={0}; bv[1]=0x02;
  RawData r7(nullptr,bv,8); CodecData c7(&conf,ProtocolId::GRE); DecodeData d7;
  bool b7=gg->decode(r7,c7,d7); printf("GRE badver2 -> %d\n",(int)b7);
  // v1-ok decode + the ONE witness mask faces (cc:280-:281 TUNNEL_GRE 0x40):
  // flags KEY 0x20, etype 0x880B, version 0x01 -> len 4+KEY 4 = 8, raw 10
  uint8_t ok[16]={0}; ok[0]=0x20; ok[1]=0x01; ok[2]=0x88; ok[3]=0x0B;
  tun_witness_set_mask(0x40);   // GRE bit -> bypass FALSE -> decodes on
  RawData r8(nullptr,ok,10); CodecData c8(&conf,ProtocolId::GRE); DecodeData d8;
  bool b8=gg->decode(r8,c8,d8); printf("GRE mask0040 -> %d bypass=%d lyr=%u next=%u bits=%u flags=%u\n",(int)b8,(int)c8.tunnel_bypass,(unsigned)c8.lyr_len,(unsigned)c8.next_prot_id,(unsigned)c8.proto_bits,(unsigned)c8.codec_flags);
  tun_witness_set_mask(0);      // ground NSDMI tunnel_mask=0 face -> bypass TRUE
  RawData r9(nullptr,ok,10); CodecData c9(&conf,ProtocolId::GRE); DecodeData d9;
  bool b9=gg->decode(r9,c9,d9); printf("GRE mask0000 -> %d bypass=%d\n",(int)b9,(int)c9.tunnel_bypass);
  tun_witness_set_mask(0);
  std::vector<ProtocolId> gv; gg->get_protocol_ids(gv); printf("GREPID %u n=%u\n",(unsigned)gv[0],(unsigned)gv.size());
  // module/RuleMap face (gre_rules cc:45, mod_ctor cc:303):
  const BaseApi* nb=cd_gre[0]; Module* nm=nb->mod_ctor(); const RuleMap* nr=nm->get_rules(); int ncc=0; while(nr[ncc].sid) ncc++;
  printf("GRE rules=%d sid0=%u name=%s\n",ncc,nr[0].sid,nm->get_name()); nb->mod_dtor(nm);
  printf("GRE api mod_ctor=%d mod_dtor=%d\n", nb->mod_ctor?1:0, nb->mod_dtor?1:0);
  // encode face = the ground TEST_CASE subject: 1-byte Buffer, raw_len
  // GRE_HEADER_LEN+1 (cc:127 allocate gate) -- ground block's own CHECK arm:
  ip::IpApi ip_api;
  EncState enc(ip_api, ENC_FLAG_VAL, IpProtocol::GRE, 0, 0);
  const uint8_t raw_in = 0; uint8_t t = 0; uint16_t size = 1;
  Buffer buf(&t, size);
  bool ef=gg->encode(&raw_in,(uint16_t)5,enc,buf,nullptr); printf("ENC lt-grehdr -> %d\n",(int)ef);
  // encode ok-face: flags CHKSUM|SEQ (0x90), etype 0x0800; BACKING base+32
  // with base = back+32 so allocate can move base back (Buffer base-=len face,
  // codec.h :215-:223)
  uint8_t back[64]={0}; uint8_t* p=back+32;
  p[0]=0x90; p[1]=0x00; p[2]=0x08; p[3]=0x00;
  Buffer buf2(p,32);
  uint8_t cin[8]={0}; cin[0]=0x90; cin[1]=0x00; cin[2]=0x08; cin[3]=0x00;
  EncState enc2(ip_api, ENC_FLAG_VAL, IpProtocol::GRE, 0, 0);
  bool eg=gg->encode(cin,8,enc2,buf2,nullptr); uint8_t cb0=*(buf2.data()+4), cb1=*(buf2.data()+5);
  printf("ENC ok -> %d cksum-bytes %u %u nproto=%u netype=%u\n",(int)eg,(unsigned)cb0,(unsigned)cb1,(unsigned)enc2.next_proto,(unsigned)enc2.next_ethertype);
  // update() chksum face (cc:112-:118 -- checksum::cksum_add, the FIRST C-side
  // consumer of the copied checksum.h; the csum row 18b was Rust-inline):
  uint8_t up[16]={0}; up[0]=0x80; uint32_t ul=0;
  gg->update(ip_api, ENC_FLAG_VAL, up, 8, ul);   // update() UNUSED(api/flags)
  printf("UPD chksum-bytes %u %u ul=%u\n",(unsigned)up[4],(unsigned)up[5],(unsigned)ul);
  return 0;
}

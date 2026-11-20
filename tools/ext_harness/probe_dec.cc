// 18e decode-face skeleton — measured arms, R6 var-before-printf.
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include <cstdio>
extern const snort::BaseApi* cd_hopopts[]; extern const snort::BaseApi* cd_dstopts[];
extern const snort::BaseApi* cd_routing[]; extern const snort::BaseApi* cd_mobility[];
extern const snort::BaseApi* cd_igmp[];
using namespace snort;
static void api(const char* tag, const BaseApi** t){ const CodecApi* a=(const CodecApi*)t[0];
  printf("API %s type=%d size=%u ver=%u name=%s\n", tag,(int)a->base.type,a->base.size,a->base.api_version,a->base.name);
  printf("HELP %s %s\n", tag, a->base.help); }
int main(){
  SnortConfig conf("");
  api("hopopts",cd_hopopts); api("dstopts",cd_dstopts); api("routing",cd_routing); api("mobility",cd_mobility); api("igmp",cd_igmp);
  uint8_t p[64]={0};
  // hopopts: short -> TRUNC event 272; then ok8: nxt=0(len0) -> next=0 csum=0 extcnt=1 bits=65536
  const CodecApi* ha=(const CodecApi*)cd_hopopts[0]; Codec* h=ha->ctor(nullptr);
  RawData r0(nullptr,p,7); CodecData c0(&conf,ProtocolId::HOPOPTS); DecodeData d0;
  bool a0=h->decode(r0,c0,d0); printf("HOP short7 -> %d\n",(int)a0);
  p[0]=0x3a; // nxt=TCP? 0x3a=58 NONEXT; use 6 tcp
  p[0]=0x06; RawData r1(nullptr,p,8); CodecData c1(&conf,ProtocolId::HOPOPTS); DecodeData d1;
  bool a1=h->decode(r1,c1,d1); printf("HOP ok8 -> %d next=%u lyr=%u bits=%llu cnt=%u csumproto=%u\n",(int)a1,(unsigned)c1.next_prot_id,(unsigned)c1.lyr_len,(unsigned long long)c1.proto_bits,(unsigned)c1.ip6_extension_count,(unsigned)c1.ip6_csum_proto);
  p[1]=1; RawData r2(nullptr,p,8); CodecData c2(&conf,ProtocolId::HOPOPTS); DecodeData d2;
  bool a2=h->decode(r2,c2,d2); printf("HOP lyr>len -> %d\n",(int)a2);
  std::vector<ProtocolId> pv; h->get_protocol_ids(pv); printf("HOPPID %u n=%u\n",(unsigned)pv[0],(unsigned)pv.size());
  const CodecApi* da=(const CodecApi*)cd_dstopts[0]; Codec* dd=da->ctor(nullptr);
  std::vector<ProtocolId> dv; dd->get_protocol_ids(dv); printf("DSTPID %u n=%u\n",(unsigned)dv[0],(unsigned)dv.size());
  const CodecApi* ra=(const CodecApi*)cd_routing[0]; Codec* rr=ra->ctor(nullptr);
  uint8_t q[64]={0}; q[2]=0; // type0 -> ROUTE_ZERO 461; nxt=8 ROUTING -> TWO_ROUTE 283 after type events
  q[0]=0x2b; q[2]=0; q[3]=0;
  RawData q0(nullptr,q,8); CodecData qc(&conf,ProtocolId::ROUTING); DecodeData qd;
  bool b0=rr->decode(q0,qc,qd); printf("ROUTE t0 -> %d next=%u bits=%llu\n",(int)b0,(unsigned)qc.next_prot_id,(unsigned long long)qc.proto_bits);
  std::vector<ProtocolId> rv; rr->get_protocol_ids(rv); printf("ROUTE_PID %u n=%u\n",(unsigned)rv[0],(unsigned)rv.size());
  const CodecApi* ma=(const CodecApi*)cd_mobility[0]; Codec* mm=ma->ctor(nullptr);
  uint8_t m[64]={0}; m[0]=60; RawData m0(nullptr,m,16); CodecData mc(&conf,ProtocolId::MOBILITY_IPV6); DecodeData md;
  bool c0b=mm->decode(m0,mc,md); printf("MOB badpayl -> %d next=%u\n",(int)c0b,(unsigned)mc.next_prot_id);
  std::vector<ProtocolId> mv; mm->get_protocol_ids(mv); printf("MOB_PID %u n=%u\n",(unsigned)mv[0],(unsigned)mv.size());
  const CodecApi* ia=(const CodecApi*)cd_igmp[0]; Codec* ic=ia->ctor(nullptr);
  std::vector<ProtocolId> iv; ic->get_protocol_ids(iv); printf("IGMP_PID %u n=%u\n",(unsigned)iv[0],(unsigned)iv.size());
  const BaseApi* ib=cd_igmp[0]; printf("IGMP mod_ctor=%d mod_dtor=%d\n", ib->mod_ctor?1:0, ib->mod_dtor?1:0);
  Module* im = ib->mod_ctor();
  const RuleMap* rmap = im->get_rules();
  int n=0; while (rmap[n].sid) n++;
  printf("IGMP rules=%d sid0=%u name=%s\n", n, rmap[0].sid, im->get_name());
  ib->mod_dtor(im);
  return 0;
}

// 18j DEC probe -- arms drawn ONLY from the ground call-site census (cite-
// never-guess; receipts row18j W/X/Z + evnames_pair.txt): cd_icmp4_ip SIX
// event arms (TRUNCATED :58 via :56; VER_MISMATCH :71 via :69 WITH the R5
// is_ip6 rider PAIR -- ver!=4 + IAt4 api DIES vs ver!=4 + IAt6 api CONTINUES;
// DGRAM_LT_ORIG_IP :79 via hlen :75/:77; PAYLOAD_LT_64 :91; PAYLOAD_GT_576
// :99 via dgram_len :97 (rides the ip_api SET header, ip.cc:247 face, NOT the
// embedded one -- the U arm); IP_WITH_FRAGOFFSET :105 via off() :102 (the
// RFC "only first frag" comment :104)); the embed switch :109 four arms ->
// PROTO_BIT__TCP/UDP/ICMP_EMBED_ICMP/ICMP_EMBED_OTHER (decode_data.h :99-:102
// sed-pinned, printed DECIMAL). cd_icmp6_ip THREE-name census: :61 TRUNCATED
// + :71 VER + :78/:80 DGRAM_LT -- the SECOND gate is ground-dead (the
// cppcheck-suppress knownConditionNextHeader / knownConditionTrueFalse face
// :77: first gate raw.len>=40 => second raw.len<40 can NEVER fire): the 252
// arm is UNARMED, recorded honestly (cite-never-guess = print a cite line,
// NEVER a fake EV); the next() switch :97 four arms + lyr_len :118.
// NO log() call ANYWHERE (the get_proto_name witness body exists so the
// staged LINK closes; the log arms' TEXT is cite-never-vectorize, PLAN 7 /
// small4 pgm precedent). R6 eval-order rule: decode stored to bool VAR
// before any printf. BaseApi* -> CodecApi* cast face inherited from daq3
// probe_dec.cc:39-:41 (the tables are BaseApi**, the ctor lives on CodecApi).
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include <cstdio>
extern const snort::BaseApi* cd_icmp4_ip[];
extern const snort::BaseApi* cd_icmp6_ip[];
using namespace snort;

static void set_ip4(DecodeData& d, uint8_t* b)
{ for (int i=0;i<20;++i) b[i]=0; b[0]=0x45; b[12]=10; b[16]=20; b[9]=17; d.ip_api.set(b); }
static void set_ip6(DecodeData& d, uint8_t* b)
{ for (int i=0;i<40;++i) b[i]=0; b[0]=0x60; d.ip_api.set(b); }

int main(){
  SnortConfig conf("");
  const CodecApi* a4=(const CodecApi*)cd_icmp4_ip[0];
  const CodecApi* a6=(const CodecApi*)cd_icmp6_ip[0];
  uint8_t b4[20]; (void)b4;
  uint8_t z[4096]={0};

  // ---- cd_icmp4_ip: the six-event decode ladder ----
  Codec* c4=a4->ctor(nullptr);
  { RawData r(nullptr,z,19); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 short19 -> %d\n",(int)b); }          // :56 TRUNCATED 250
  { uint8_t p[40]={0}; p[0]=0x65;                                             // ver nibble 6
    RawData r(nullptr,p,40); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 ver6-ip4api -> %d\n",(int)b); }      // :69 dies, VER 251 (is_ip6 FALSE)
  { uint8_t p[48]={0}; p[0]=0x65; p[9]=1;                                     // ver 6 rides ON, proto ICMPV4
    uint8_t b6[40]={0};
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip6(d,b6);
    bool b=c4->decode(r,c,d); printf("IP4 ver6-ip6rider -> %d pb=%u lyr=%u\n",(int)b,(unsigned)c.proto_bits,(unsigned)c.lyr_len); } // R5 rider: survives -> ICMP_EMBED_ICMP
  { uint8_t p[22]={0}; p[0]=0x46;                                             // IHL 6 -> hlen 24 > raw.len 22
    RawData r(nullptr,p,22); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 hlen24-22 -> %d\n",(int)b); }        // :77/:79 DGRAM_LT 252
  { uint8_t p[27]={0}; p[0]=0x45;                                             // ip_len 27-20 = 7 < 8
    RawData r(nullptr,p,27); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 pay7 -> %d\n",(int)b); }             // :89/:91 PAYLOAD_LT_64 253
  { uint8_t p[40]={0}; p[0]=0x45; p[9]=17;                                    // proto UDP, off 0
    RawData r(nullptr,p,40); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    b4[2]=0xEA; b4[3]=0x60;                                                   // ip_api len 60000 > 576 (ip.cc:247 IAT_4 face)
    bool b=c4->decode(r,c,d); printf("IP4 gt576 -> %d pb=%u lyr=%u\n",(int)b,(unsigned)c.proto_bits,(unsigned)c.lyr_len); } // :97/:99 GT_576 254 EVENT-THEN-CONTINUE
  { uint8_t p[40]={0}; p[0]=0x45; p[6]=0x01;                                  // frag off 256 != 0
    RawData r(nullptr,p,40); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 fragoff -> %d\n",(int)b); }          // :102/:105 FRAGOFFSET 255
  // embed-switch faces (the gt576 arm above already rode the UDP arm = 8192):
  { uint8_t p[48]={0}; p[0]=0x45; p[9]=6;
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 embed-tcp -> %d pb=%u\n",(int)b,(unsigned)c.proto_bits); }    // :109/:112
  { uint8_t p[48]={0}; p[0]=0x45; p[9]=1;
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 embed-icmp -> %d pb=%u\n",(int)b,(unsigned)c.proto_bits); }   // :119
  { uint8_t p[48]={0}; p[0]=0x45; p[9]=47;
    RawData r(nullptr,p,48); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP4); DecodeData d; set_ip4(d,b4);
    bool b=c4->decode(r,c,d); printf("IP4 embed-other -> %d pb=%u\n",(int)b,(unsigned)c.proto_bits); }  // :122 default

  // ---- cd_icmp6_ip: three-name census (252 GROUND-DEAD, cite line) ----
  Codec* c6=a6->ctor(nullptr);
  { RawData r(nullptr,z,39); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP6); DecodeData d;
    bool b=c6->decode(r,c,d); printf("IP6 short39 -> %d\n",(int)b); }          // :61/:63 TRUNCATED 250
  { uint8_t q[40]={0}; q[0]=0x45;                                             // ver nibble 4
    RawData r(nullptr,q,40); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP6); DecodeData d;
    bool b=c6->decode(r,c,d); printf("IP6 ver4 -> %d\n",(int)b); }             // :71/:73 VER 251
  printf("IP6 252-unarmed cc:78-fixed-true\n");                               // :77 cppcheck face: DEAD CODE, NEVER vector-armed
  { uint8_t q[40]={0}; q[0]=0x60; q[6]=6;                                     // next = TCP
    RawData r(nullptr,q,40); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP6); DecodeData d;
    bool b=c6->decode(r,c,d); printf("IP6 next-tcp -> %d pb=%u lyr=%u\n",(int)b,(unsigned)c.proto_bits,(unsigned)c.lyr_len); } // :97/:100 + lyr :118
  { uint8_t q[40]={0}; q[0]=0x60; q[6]=47;
    RawData r(nullptr,q,40); CodecData c(&conf,ProtocolId::IP_EMBEDDED_IN_ICMP6); DecodeData d;
    bool b=c6->decode(r,c,d); printf("IP6 next-default -> %d pb=%u lyr=%u\n",(int)b,(unsigned)c.proto_bits,(unsigned)c.lyr_len); } // :111 default
  return 0;
}

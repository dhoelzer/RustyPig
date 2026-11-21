// 18k DEC probe -- arms drawn ONLY from the ground call-site census (cite-
// never-guess): cd_llc TWO event arms (DECODE_BAD_LLC_HEADER 131 cc :96/:99
// via raw.len < sizeof(EthLlc)==3; DECODE_BAD_LLC_OTHER 132 cc :108/:110 via
// the SNAP inner len gate; sids 131/132 ALREADY landed codec_module.rs :97-
// :98, NEVER re-walked) + the AND-pair FIRST-operand cite line (cc :105/:106
// dsap&&ssap evaluated first: an aa/00 pair with len<8 hits NEITHER event --
// a cite line, NOT a fake EV) + the inner-len 2nd gate cite line (len 7 +
// aa/aa reaches :108 NOT :110? NO -- 7 < 8 fires 132; the NON-firing 6..7
// face is the gate, arms ride 3/6/8 exactly); llc SNAP-0-org happy arm cc
// :117-:123 -> lyr 8 + next=proto() + CODEC_ETHER_NEXT (0x1000 = 4096). The
// SIX dead defines (ETH_DSAP_SNA/SSAP_SNA/DSAP_STP/SSAP_STP cc :80-:83 +
// ETH_ORG_CODE_ETHR/CDP :87/:88) are grep-count-1 (#define ONLY, ZERO use
// sites; the SNAP arms ride literal 0 :117-:119 + ETH_DSAP_IP/SSAP_IP :84/
// :85 USED :105/:106/:139/:140) -- cite-NEVER-land (cd_gre dead-init
// discipline). cd_vxlan: len<8 false (cc :65) + flags!=0x08 false (cc :70) +
// the tunnel_bypass HOOK dual face (cc :73-:74: the 18f witness_18f body
// ride -- tun_witness_set_mask(0x100=TUNNEL_VXLAN snort_config.h :127) ->
// bypass FALSE; set_mask(0) -> TRUE; EXACTLY zero NEW bypass witness, the
// ea1f79f3 CARRIED face; eval-order pin: the HOOK :73 runs BEFORE the lyr/
// proto_bits sets :76-:79 -- the FALSE arm proves it: lyr still 0 at return)
// + vxlan happy arm lyr 8 + PROTO_BIT__VXLAN 0x040000=262144 (row-scoped,
// ZERO Rust face, grep src = 0) + next 0x0105=261 ETHERNET_802_3 +
// CODEC_NON_IP_TUNNEL 0x0200=512 (already-landed codec.rs :51 import).
// cd_user (the witness-channel face, channel = q->msg on the ground ioctl's
// OWN arg): NO-instance arm = witness get_local_instance -> nullptr while
// ground cc :103 chain-calls ->ioctl() withOUT a null check (ground SEGV
// face, cite line; survives ONLY because the synthetic witness ioctl NEVER
// derefs `this` -- the 17d synthetic-precedent honesty line, cc:103-not-
// fixed cite) + the !=DAQ_SUCCESS return-false arm CITED never-armed (witness
// ALWAYS DAQ_SUCCESS) + the !pci arm cc :108 cited (witness ALWAYS fills
// pci) + set_ip ip_proto TCP (6)/UDP (17) pair cc :62-:65 -> PROTO_BIT__TCP
// 2 / PROTO_BIT__UDP 4 + sp/dp ride the hdr channel (printable sp_cc face) +
// PktType::USER cc :114 = 5 vs FILE cc :119 = 6 (decode_data.h :47 enum);
// set_key hardcoded face cc :70-:76: FIXIT-L make configurable + 192.168.2.2
// + 54321 = THREE cite lines, observable prints = sp 12345 (cc :75) + dp
// 54321 (cc :76) + PROTO_BIT__TCP + FILE; set_flags trio cc :84-:96
// (TO_SERVER->DECODE_C2S 512 / START_FLOW->DECODE_SOF 1024 / END_FLOW->
// DECODE_EOF 2048 + lyr=raw.len, else lyr 0, decode_data.h :146-:148).
// dport 4789 NEVER here (cd_udp face, PLAN 2). NO log() call ANYWHERE (log
// text is cite-never-vectorize). R6 eval-order rule: decode stored to bool
// VAR before any printf. BaseApi* -> CodecApi* cast inherited (tables are
// BaseApi**; the ctor lives on CodecApi).
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"
#include <cstdio>
#include <cstdint>
extern const snort::BaseApi* cd_llc[];
extern const snort::BaseApi* cd_vxlan[];
extern const snort::BaseApi* cd_user[];
extern "C" void tun_witness_set_mask(unsigned short);   // witness_18f CARRIED face (gre probe_dec.cc:14 precedent)
using namespace snort;

// the daq_msg channel is an OPAQUE pointer (framework/codec.h:38 fwd decl);
// the witnesses' ioctl memcpy channel rides DAQ_UsrHdr_t layout (C header
// daqs/daq_user.h :36-:43): u32 src_addr @0, u32 dst_addr @4, u16 src_port
// @8, u16 dst_port @10, u8 ip_proto @12, u8 flags @13 (sizeof 14).
int main(){
  SnortConfig conf("");
  const CodecApi* al=(const CodecApi*)cd_llc[0];
  const CodecApi* av=(const CodecApi*)cd_vxlan[0];
  const CodecApi* au=(const CodecApi*)cd_user[0];
  uint8_t z[4096]={0};

  // ---- cd_llc: the two-event ladder + SNAP arms ----
  Codec* cl=al->ctor(nullptr);
  { RawData r(nullptr,z,2); CodecData c(&conf,ProtocolId::ETHERNET_LLC); DecodeData d;
    bool b=cl->decode(r,c,d); printf("LLC short2 -> %d\n",(int)b); }              // :96/:99 EV 131
  { uint8_t p[3]={0xaa,0x00,0x03};                                               // 3 = sizeof(EthLlc): outer gate PASSES, AND-pair operand 1 FAILS
    RawData r(nullptr,p,3); CodecData c(&conf,ProtocolId::ETHERNET_LLC); DecodeData d;
    bool b=cl->decode(r,c,d); printf("LLC dsap-aa-ssap-00 -> %d\n",(int)b); }     // :105 && FIRST-operand FALSE: NO event, NO SNAP (eval order cc:105/:106)
  { uint8_t p[7]={0xaa,0xaa,0x03};                                               // SNAP pair yes, 7 < 8 inner gate
    RawData r(nullptr,p,7); CodecData c(&conf,ProtocolId::ETHERNET_LLC); DecodeData d;
    bool b=cl->decode(r,c,d); printf("LLC snap7 -> %d\n",(int)b); }              // :108/:110 EV 132
  { uint8_t p[10]={0xaa,0xaa,0x03, 0,0,0, 0x08,0x00, 0x11,0x22};                 // org 0/0/0, proto 0x0800
    RawData r(nullptr,p,10); CodecData c(&conf,ProtocolId::ETHERNET_LLC); DecodeData d;
    bool b=cl->decode(r,c,d); printf("LLC snap0-org -> %d lyr=%u next=%u flags=%u\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.next_prot_id,(unsigned)c.codec_flags); } // :117-:123 lyr 8 next 2048 ETHER_NEXT 4096
  { uint8_t p[10]={0xaa,0xaa,0x03, 0,0,0x0c, 0x20,0x00, 0x11,0x22};              // org_code[2]==0x0c (CDP face): org gate FALSE
    RawData r(nullptr,p,10); CodecData c(&conf,ProtocolId::ETHERNET_LLC); DecodeData d;
    bool b=cl->decode(r,c,d); printf("LLC snap-org-nonzero -> %d lyr=%u\n",(int)b,(unsigned)c.lyr_len); } // :117-:119 fail: TRUE, lyr 0

  // ---- cd_vxlan: the hook + gates ----
  Codec* cv=av->ctor(nullptr);
  { RawData r(nullptr,z,7); CodecData c(&conf,ProtocolId::VXLAN); DecodeData d;
    bool b=cv->decode(r,c,d); printf("VX len7 -> %d\n",(int)b); }                // :65
  { uint8_t p[8]={0x00};                                                        // flags 0 != 0x08
    RawData r(nullptr,p,8); CodecData c(&conf,ProtocolId::VXLAN); DecodeData d;
    bool b=cv->decode(r,c,d); printf("VX flags-neq8 -> %d\n",(int)b); }         // :70
  printf("VX hook-before-sets cc:73-vs-:76-:79\n");                              // eval-order cite: HOOK read rides BEFORE lyr/proto_bits/next/flag sets
  tun_witness_set_mask(0x100);                                                  // TUNNEL_VXLAN bit SET -> enabled FALSE -> bypass stays FALSE
  { uint8_t p[8]={0x08};
    RawData r(nullptr,p,88); CodecData c(&conf,ProtocolId::VXLAN); DecodeData d;
    bool b=cv->decode(r,c,d); printf("VX mask256 -> %d lyr=%u pb=%u next=%u flags=%u bypass=%d\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.proto_bits,(unsigned)c.next_prot_id,(unsigned)c.codec_flags,(int)c.tunnel_bypass); } // :73 false arm + :76-:79 sets
  tun_witness_set_mask(0);                                                      // mask 0 -> enabled TRUE -> tunnel_bypass = true
  { uint8_t p[8]={0x08};
    RawData r(nullptr,p,88); CodecData c(&conf,ProtocolId::VXLAN); DecodeData d;
    bool b=cv->decode(r,c,d); printf("VX mask0 -> %d lyr=%u pb=%u next=%u flags=%u bypass=%d\n",(int)b,(unsigned)c.lyr_len,(unsigned)c.proto_bits,(unsigned)c.next_prot_id,(unsigned)c.codec_flags,(int)c.tunnel_bypass); } // :73-:74 TRUE face
  tun_witness_set_mask(0);

  // ---- cd_user: the witness-channel face ----
  Codec* cu=au->ctor(nullptr);
  printf("US no-instance ground-SEGV cc:103 chain-call, witness-ioctl survives\n"); // honest cite: ground derefs get_local_instance()->ioctl UNCHECKED; synthetic witnesses only (PLAN 6)
  { uint8_t m[16]={0};                                                          // ip_proto 0 -> set_key + FILE
    CodecData c(&conf,ProtocolId::IP); DecodeData d;
    bool b=cu->decode(RawData((const struct _daq_msg*)m,nullptr,0),c,d); printf("US proto0-key -> %d pb=%u sp=%u dp=%u type=%d lyr=%u\n",(int)b,(unsigned)c.proto_bits,(unsigned)d.sp,(unsigned)d.dp,(int)d.get_pkt_type(),(unsigned)c.lyr_len); } // cc:118/:119 + sp 12345; FIXIT-L make configurable cite; hardcoded dip 192.168.2.2 + dp 54321 = ground LITERALS cc:72/:76, build.sh sed cite-never-land
  { uint8_t m[16]={0}; m[12]=6; m[13]=0x01; *(uint16_t*)(m+8)=12345;             // ip_proto TCP @12, TO_SERVER @13, src_port @8
    CodecData c(&conf,ProtocolId::IP); DecodeData d;
    bool b=cu->decode(RawData((const struct _daq_msg*)m,nullptr,0),c,d); printf("US tcp-c2s -> %d pb=%u sp=%u dp=%u type=%d df=%u lyr=%u\n",(int)b,(unsigned)c.proto_bits,(unsigned)d.sp,(unsigned)d.dp,(int)d.get_pkt_type(),(unsigned)d.decode_flags,(unsigned)c.lyr_len); } // cc:62-:63 TCP 2 + cc:84 C2S 512 + cc:114 USER 5
  { uint8_t m[16]={0}; m[12]=17; m[13]=0x07; *(uint16_t*)(m+8)=20000; *(uint16_t*)(m+10)=30000; // UDP + all three flags (cc:90-:94 END_FLOW -> lyr=raw.len)
    CodecData c(&conf,ProtocolId::IP); DecodeData d;
    bool b=cu->decode(RawData((const struct _daq_msg*)m,(const uint8_t*)"pay",4),c,d); printf("US udp-flags7 -> %d pb=%u sp=%u dp=%u df=%u lyr=%u type=%d\n",(int)b,(unsigned)c.proto_bits,(unsigned)d.sp,(unsigned)d.dp,(unsigned)d.decode_flags,(unsigned)c.lyr_len,(int)d.get_pkt_type()); } // UDP 4 + C2S|SOF|EOF 3584 + lyr=raw.len 4 (cc:93)
  printf("US arms-cc:95-:96-else-lyr0-face\n");                                   // ELSE lyr 0 rides the tcp-c2s arm above (flags 0x01, no END_FLOW)
  printf("US ioctl-fail cc:103 + !pci cc:108 cited-never-armed witness-always-success/fills\n");
  return 0;
}

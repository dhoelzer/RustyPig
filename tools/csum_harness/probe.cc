#include "codecs/ip/checksum.h"
#include <cstdio>
#include <cstdint>
int main()
{
    static const uint8_t short_buf[16] =
    { 0x22,0x11,0x44,0x33,0x66,0x55,0x88,0x77,0xaa,0x99,0xcc,0xbb,0xee,0xdd,0x00,0xff };
    // detail guard arms (the 10-TEST suite's spine)
    { const uint8_t* d=short_buf; std::size_t len=4; uint32_t c=0; checksum::detail::add_tcp_header(d,len,c); printf("G_tcp len4->len=%zu cks=0x%04x ptr_moved=%d\n", len, c, d!=short_buf); }
    { const uint8_t* d=short_buf; std::size_t len=4; uint32_t c=0; checksum::detail::add_udp_header(d,len,c); printf("G_udp len4->len=%zu cks=0x%04x\n", len, c); }
    { const uint8_t* d=short_buf; std::size_t len=4; uint32_t c=0; checksum::detail::add_ip_header(d,len,c); printf("G_ip  len4->len=%zu cks=0x%04x\n", len, c); }
    { const uint8_t* d=short_buf; std::size_t len=0; uint32_t c=0; checksum::detail::add_tcp_header(d,len,c); printf("G_tcp len0->len=%zu\n", len); }
    // public short-len arms (guard -> pseudoheader-only complement)
    checksum::Pseudoheader ph; ph.hdr.sip=0; ph.hdr.dip=0; ph.hdr.zero=0; ph.hdr.protocol=IpProtocol::TCP; ph.hdr.len=0;
    printf("P_tcp4_len4=0x%04x\n", checksum::tcp_cksum(short_buf,4,ph));
    checksum::Pseudoheader6 ph6{};
    printf("P_tcp6_len4=0x%04x\n", checksum::tcp_cksum(short_buf,4,ph6));
    checksum::Pseudoheader phu; phu.hdr.sip=0; phu.hdr.dip=0; phu.hdr.zero=0; phu.hdr.protocol=IpProtocol::UDP; phu.hdr.len=0;
    printf("P_udp4_len4=0x%04x\n", checksum::udp_cksum(short_buf,4,phu));
    printf("P_ip_len4=0x%04x\n", checksum::ip_cksum(short_buf,4));
    // valid-input verify pair (the tests' self-verification property)
    { uint16_t tcph[10]={0x0050,0xd431,0x0000,0x0001,0x0000,0x0000,0x5002,0x2000,0x0000,0x0000};
      checksum::Pseudoheader p; p.hdr.sip=0x0100007f; p.hdr.dip=0x0100007f; p.hdr.zero=0; p.hdr.protocol=IpProtocol::TCP; p.hdr.len=0x1400; /* htons(20) LE */
      uint16_t s=checksum::tcp_cksum(tcph,20,p); tcph[8]=s;
      printf("K_tcp4 sum=0x%04x reverify=%d\n", s, checksum::tcp_cksum(tcph,20,p)==0); }
    { uint16_t iph[10]={0x4500,0x0028,0x1c46,0x4000,0x4006,0x0000,0x007f,0x0000,0x0100,0x0000};
      uint16_t s=checksum::ip_cksum(iph,20); iph[5]=s;
      printf("K_ip4 sum=0x%04x reverify=%d\n", s, checksum::ip_cksum(iph,20)==0); }
    // odd tail + len==1 + bare cksum_add over the fixture
    printf("K_cksum16=0x%04x\n", checksum::cksum_add(short_buf,16));
    printf("K_cksum15=0x%04x\n", checksum::cksum_add(short_buf,15));
    printf("K_cksum1=0x%04x\n", checksum::cksum_add(short_buf,1));
    printf("K_cksum0=0x%04x\n", checksum::cksum_add(short_buf,0));
    // pseudoheader word dumps (union punning pins)
    checksum::Pseudoheader q; q.hdr.sip=0x0100007f; q.hdr.dip=0x0100007f; q.hdr.zero=0; q.hdr.protocol=IpProtocol::TCP; q.hdr.len=0x1400;
    printf("PH4 arr=%04x %04x %04x %04x %04x %04x sizeof=%zu\n", q.arr[0],q.arr[1],q.arr[2],q.arr[3],q.arr[4],q.arr[5], sizeof(q));
    checksum::Pseudoheader6 r{}; r.hdr.protocol=IpProtocol::TCP; r.hdr.len=0x1400;
    printf("PH6 sizeof=%zu arr17=0x%04x\n", sizeof(r), r.arr[17]);
    return 0;
}

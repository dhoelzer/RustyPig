// Ground-truth probe for framework/codec.{h,cc}. Prints labeled vectors:
//   * Buffer init/alloc/clear geometry (mirrors the 4 upstream [buffer]
//     Catch cases as plain vectors too, so the replay sees both channels),
//   * EncState::get_ttl table (forward/reverse x ENC_FLAG_TTL x clamp),
//   * CodecData ctor defaults + is_cooked,
//   * CheckIPV6HopOptions / CheckIPv6ExtensionOrder through a ProbeCodec
//     subclass (the members are protected in upstream; every real codec
//     reaches them the same way). queue_event witness prints 'EV 116 sid'.
// All raw buffers are built here; nothing random, no pointers printed.
#include <cstdio>
#include <cstring>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "framework/decode_data.h"
#include "protocols/ipv6.h"
#include "sfip/sf_ip.h"

using namespace snort;

struct ProbeCodec : public Codec
{
    ProbeCodec() : Codec("probe") { }
    bool decode(const RawData&, CodecData&, DecodeData&) override { return true; }
    using Codec::CheckIPV6HopOptions;
    using Codec::CheckIPv6ExtensionOrder;
    using Codec::codec_event;
};

static void dump_buf(const char* tag, const Buffer& b, const uint8_t* base_lo)
{
    // print data offset relative to the raw array base + size; never the
    // address itself (ASLR).
    printf("%s off=%ld size=%u\n", tag,
        (long)(b.data() - base_lo), (unsigned)b.size());
}

int main()
{
    ProbeCodec pc;

    // ---- Buffer geometry (upstream 'init'/'alloc'/'multi alloc'/'clear')
    {
        uint8_t raw[2];
        Buffer b(raw, 1);
        dump_buf("B init", b, raw);
    }
    {
        uint8_t raw[1];
        Buffer b(raw, 1);
        bool ok = b.allocate(1);
        printf("B alloc ok=%d\n", (int)ok);
        dump_buf("B alloc", b, raw);
    }
    {
        uint8_t raw[3];
        Buffer b(raw, 3);
        bool a1 = b.allocate(1);
        printf("B a1 ok=%d\n", (int)a1);
        dump_buf("B a1", b, raw);
        bool a2 = b.allocate(2);
        printf("B a2 ok=%d\n", (int)a2);
        dump_buf("B a2", b, raw);
    }
    {
        uint8_t raw[2];
        Buffer b(raw, 1);
        bool a1 = b.allocate(1);
        printf("B pre ok=%d\n", (int)a1);
        dump_buf("B pre", b, raw);
        b.clear();
        dump_buf("B clear", b, raw);
    }
    // over-allocate: allocate returns false and does NOT move base
    {
        uint8_t raw[2];
        Buffer b(raw, 2);
        bool a1 = b.allocate(1);
        bool a2 = b.allocate(2);      // end(1)+2 > max(2) -> false
        printf("B over a1=%d a2=%d\n", (int)a1, (int)a2);
        dump_buf("B over", b, raw);
        b.allocate(1);                // exactly fits
        dump_buf("B fit", b, raw);
        b.allocate(0);                // zero-len allocate
        dump_buf("B zero", b, raw);
        b.clear();
        dump_buf("B cleared", b, raw);
        bool ok0 = b.allocate(3);     // fresh but over
        printf("B fresh-over ok=%d\n", (int)ok0);
        dump_buf("B fresh-over", b, raw);
    }
    // off member: public, reset by clear, NOT touched by allocate
    {
        uint8_t raw[4];
        Buffer b(raw, 4);
        b.allocate(4);
        b.off = 2;
        printf("B off off=%u size=%u\n", b.off, (unsigned)b.size());
        b.clear();
        printf("B off-clr off=%u size=%u\n", b.off, (unsigned)b.size());
        dump_buf("B off-geo", b, raw);
    }

    // ---- EncState::get_ttl table (MIN_TTL=64 MAX_TTL=255)
    {
        ip::IpApi api;                 // default-constructed (no packet)
        struct Row { EncodeFlags f; uint8_t ttl; uint8_t lyr; };
        Row rows[] = {
            { ENC_FLAG_FWD,                   7, 200 },  // fwd passthrough
            { ENC_FLAG_FWD | ENC_FLAG_TTL,    7, 200 },  // fwd override
            { 0,                              0, 200 },  // rev 255-200=55 -> clamp 64
            { 0,                              0, 128 },  // rev 255-128=127 -> stays
            { ENC_FLAG_TTL,                   3, 128 },  // rev override 3 -> clamp 64
            { ENC_FLAG_TTL,                 200, 128 },  // rev override stays
            { ENC_FLAG_FWD,                   0, 0   },  // fwd 0 passthrough
            { 0,                              0, 255 },  // rev 255-255=0 -> clamp 64
        };
        for (unsigned i = 0; i < sizeof rows / sizeof rows[0]; ++i)
        {
            EncState es(api, rows[i].f, IpProtocol::TCP, rows[i].ttl, 0);
            printf("T r%u f=%016llX t=%u lyr=%u -> %u fwd=%d\n", i,
                (unsigned long long)rows[i].f, rows[i].ttl, rows[i].lyr,
                es.get_ttl(rows[i].lyr), (int)es.forward());
        }
        EncState es(api, 0, IpProtocol::TCP, 0, 0);
        printf("T next-set=%d eth-set=%d\n", (int)es.next_proto_set(),
            (int)es.ethertype_set());
        // next_proto_set() TRUE only via ctor arg != PROTO_NOT_SET:
        EncState es2(api, ENC_FLAG_FWD, IpProtocol::TCP, 0, 9);
        printf("T2 next-set=%d eth-set=%d dsize=%u\n",
            (int)es2.next_proto_set(), (int)es2.ethertype_set(),
            (unsigned)es2.dsize);
    }
    // ---- CheckIPV6HopOptions (via ProbeCodec; protected in upstream)
    {
        // each case: fresh CodecData, fixed hdr bytes.
        // H1: [nxt=0,len=0] pad1,pad1 -> total=8 len=8 loop exits, true, no EV
        {
            uint8_t h[] = { 0, 0, 0x00, 0x00, 0, 0, 0, 0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H1 r=%d cdo=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
        // H2: [len=0,total=8] padn(len=2) truncated (hdr_end-pkt=4 < 4? no:
        // (hdr_end-pkt)=4, op+2=4 -> fits) padn(len=6) over -> BAD_OPT_LEN
        {
            uint8_t h[] = { 0, 0, 0x01, 0x02, 0,0, 0x01, 0x06 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H2 r=%d\n", (int)r);
        }
        // H3: bad type 0x02 (not in HopByHopOptions): falls through to TLV
        // check; type bits 0x02 & 0xC0 == 0 -> skips after BAD_OPT_LEN path
        // when op over; here op=0 fits: consume; then 0x00 pad1; end true
        {
            uint8_t h[] = { 0, 0, 0x02, 0x00, 0x00, 0, 0, 0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H3 r=%d cdbad=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
        // H4: bad type 0x03 op=10 OVER -> EV BAD_OPT_LEN; default label
        // fell through so BAD_OPT already latched -> only BAD_OPT_LEN EV;
        // return ip6_opt_receiver_skips(0x03): 0x03 & 0xC0 == 0 -> true
        {
            uint8_t h[] = { 0, 0, 0x03, 0x0A, 0, 0, 0, 0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H4 r=%d cdbad=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
        // H4b: action-bits type 0xC1 not in enum -> default: latch BAD_OPT
        // + EV BAD_OPT_TYPE, then TLV check; op=0 fits; skip (0xC1&0xC0!=0 ->
        // returns false only on LEN path, not here) -> loop continues
        {
            uint8_t h[] = { 0, 0, 0xC1, 0x00, 0x00, 0, 0, 0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H4b r=%d cdbad=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
        // H5: type 0x04 (JUMBO) op over -> return false
        {
            uint8_t h[] = { 0, 0, 0x04, 0x0A, 0, 0, 0, 0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H5 r=%d cdbad=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
        // H6: raw len 4 < total 8 -> TRUNCATED EV (UNgated), then the
        // padn TLV check: hdr_end-pkt = 6 < 6+2 -> BAD_OPT_LEN EV, return
        // skips(0x01) = true. ip6e_len MUST be 0 here (len field drives
        // total_octets; a nonzero hdr len would put hdr_end past this
        // array -- OOB -- which is why the first draft mis-emitted).
        {
            uint8_t h[] = { 0, 0, 0x01, 0x06, 0, 0, 0, 0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, 4);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H6 r=%d cdbad=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
        // H7: 16-octet header padn chains
        {
            uint8_t h[] = { 0, 1, 0x01, 0x00, 0x01, 0x01, 0,0, 0x01, 0x00,
                            0x01, 0x06, 0,0,0,0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H7 r=%d cdbad=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
        // H8: type 0xC9 HOME_ADDRESS op=0 then pad1 at the very end
        {
            uint8_t h[] = { 0, 0, 0xC9, 0x00, 0x00, 0, 0, 0 };
            CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
            RawData rd(nullptr, h, sizeof h);
            bool r = pc.CheckIPV6HopOptions(rd, cd);
            printf("H8 r=%d cdbad=%d\n", (int)r,
                (int)!!(cd.codec_flags & CODEC_IP6_BAD_OPT));
        }
    }

    // ---- CheckIPv6ExtensionOrder
    {
        // O1: fresh (curr=0); HOPOPTS(1)>0 accept curr=1
        {
            CodecData cd(nullptr, ProtocolId::HOPOPTS);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::HOPOPTS);
            printf("O1 curr=%u flags=%04X\n", cd.curr_ip6_extension,
                cd.codec_flags);
        }
        // O2: fresh; ROUTING curr=3, ROUTING_SEEN
        {
            CodecData cd(nullptr, ProtocolId::ROUTING);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::ROUTING);
            printf("O2 curr=%u flags=%04X\n", cd.curr_ip6_extension,
                cd.codec_flags);
        }
        // O3: curr=3; DSTOPTS(2)<=3, next FRAGMENT(4)!=MAX -> not exception
        // -> EV UNORDERED + OOO; curr stays 3
        {
            CodecData cd(nullptr, ProtocolId::FRAGMENT);
            cd.curr_ip6_extension = 3;
            cd.codec_flags |= CODEC_ROUTING_SEEN;
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::DSTOPTS);
            printf("O3 curr=%u flags=%04X\n", cd.curr_ip6_extension,
                cd.codec_flags);
        }
        // O4 chain: next_prot_id = DSTOPTS -> next_order 2 != ORDER_MAX, so
        // the second-DSTOPTS exception does NOT apply: iter0 accepts
        // (curr 0<2), iter1 fires UNORDERED + latches OOO, iter2 silenced.
        {
            CodecData cd(nullptr, ProtocolId::DSTOPTS); // next_order MAX
            cd.codec_flags |= CODEC_ROUTING_SEEN;
            for (int i = 0; i < 3; ++i)
            {
                pc.CheckIPv6ExtensionOrder(cd, IpProtocol::DSTOPTS);
                printf("O4 iter%d curr=%u flags=%04X\n", i,
                    cd.curr_ip6_extension, cd.codec_flags);
            }
        }
        // O7: curr=6; AUTH(5) <=6 but no exception -> OOO (already set, no EV)
        {
            CodecData cd(nullptr, ProtocolId::ESP);
            cd.curr_ip6_extension = 6;
            cd.codec_flags |= CODEC_IP6_EXT_OOO;
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::AUTH);
            printf("O7 curr=%u flags=%04X\n", cd.curr_ip6_extension,
                cd.codec_flags);
        }
        // O8: fresh curr=0; HOPOPTS twice
        {
            CodecData cd(nullptr, ProtocolId::HOPOPTS);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::HOPOPTS);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::HOPOPTS);
            printf("O8 curr=%u flags=%04X\n", cd.curr_ip6_extension,
                cd.codec_flags);
        }
        // O9: HOPOPTS(1) < FRAGMENT(4); curr=1 -> accept -> FRAGMENT
        {
            CodecData cd(nullptr, ProtocolId::FRAGMENT);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::HOPOPTS);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::FRAGMENT);
            printf("O9 curr=%u flags=%04X\n", cd.curr_ip6_extension,
                cd.codec_flags);
        }
        // O10: ESP(6) then HOPOPTS(1) unordered (fresh)
        {
            CodecData cd(nullptr, ProtocolId::HOPOPTS);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::ESP);
            pc.CheckIPv6ExtensionOrder(cd, IpProtocol::HOPOPTS);
            printf("O10 curr=%u flags=%04X\n", cd.curr_ip6_extension,
                cd.codec_flags);
        }
    }

    // O11: next_prot_id=IPV6(41) -> next_order MAX; routing seen; the
    // second DSTOPTS is the ALLOWED exception -> no event at all, no
    // OOO latch (pins the negative side of the exception branch).
    {
        CodecData cd(nullptr, ProtocolId::IPV6);
        cd.curr_ip6_extension = 2;
        cd.codec_flags |= CODEC_ROUTING_SEEN;
        pc.CheckIPv6ExtensionOrder(cd, IpProtocol::DSTOPTS);
        pc.CheckIPv6ExtensionOrder(cd, IpProtocol::DSTOPTS);
        printf("O11 curr=%u flags=%04X\n", cd.curr_ip6_extension,
            cd.codec_flags);
    }

    // ---- CodecData ctor defaults + is_cooked
    {
        CodecData cd(nullptr, ProtocolId::ETHERTYPE_NOT_SET);
        printf("CD next_id=%u lyr=%u inv=%u bits=%u flags=%u ipl=%u ext=%u cur=%u csum=%d tun=%d cook=%d\n",
            (unsigned)cd.next_prot_id, cd.lyr_len, cd.invalid_bytes,
            cd.proto_bits, cd.codec_flags, cd.ip_layer_cnt,
            cd.ip6_extension_count, cd.curr_ip6_extension,
            (int)(cd.ip6_csum_proto == IpProtocol::IP), (int)cd.tunnel_bypass,
            (int)cd.is_cooked());
        cd.codec_flags |= CODEC_STREAM_REBUILT;
        printf("CD cook2=%d\n", (int)cd.is_cooked());
    }
    printf("DONE\n");
    return 0;
}

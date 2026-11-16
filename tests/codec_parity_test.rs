// Whole-transcript replay of tools/codec_harness/vectors.txt (row 4
// milestone): drives the Rust framework::codec port through the identical
// probe sequence (probe.cc mirrored 1:1: Buffer geometry, EncState::get_ttl
// table, CheckIPV6HopOptions H1-H8, CheckIPv6ExtensionOrder O1-O11,
// CodecData ctor defaults) and compares the merged line stream (print +
// queued-event witness lines interleave in call order, exactly as stdout
// does in the C probe) against the locked transcript.
#![allow(clippy::type_complexity, dead_code, unused_variables)]

use snort3::framework::codec::ip_protocol as ipp;
use snort3::framework::codec::protocol_id as pi;
use snort3::framework::codec::*;

struct Out {
    lines: Vec<String>,
}

impl Out {
    fn p(&mut self, s: &str) {
        self.lines.push(s.to_string());
    }
    // queue_event witness: print 'EV gid sid' (the C harness witness does
    // exactly this on stdout). Built per call so the borrow ends with it.
    fn ev(&mut self, gid: u32, sid: u32) {
        self.p(&format!("EV {} {}", gid, sid));
    }
}

// probe dump_buf: printf("%s off=%ld size=%u\n", tag, data()-base, size)
fn dump_buf(out: &mut Out, tag: &str, b: &Buffer<'_>) {
    out.p(&format!("{tag} off={} size={}", b.data_off(), b.size()));
}

fn hex16(v: u16) -> String {
    format!("{:04X}", v)
}

#[test]
fn replay_codec_transcript() {
    let out = &mut Out { lines: Vec::new() };

    // ---- Buffer (upstream 'init'/'alloc'/'multi alloc'/'clear' + extras)
    {
        let raw = &mut [0u8; 2];
        let b = Buffer::new(raw, 1);
        dump_buf(out, "B init", &b);
    }
    {
        let raw = &mut [0u8; 1];
        let mut b = Buffer::new(raw, 1);
        let ok = b.allocate(1);
        out.p(&format!("B alloc ok={}", ok as i32));
        dump_buf(out, "B alloc", &b);
    }
    {
        let raw = &mut [0u8; 3];
        let mut b = Buffer::new(raw, 3);
        let a1 = b.allocate(1);
        out.p(&format!("B a1 ok={}", a1 as i32));
        dump_buf(out, "B a1", &b);
        let a2 = b.allocate(2);
        out.p(&format!("B a2 ok={}", a2 as i32));
        dump_buf(out, "B a2", &b);
    }
    {
        let raw = &mut [0u8; 2];
        let mut b = Buffer::new(raw, 1);
        let a1 = b.allocate(1);
        out.p(&format!("B pre ok={}", a1 as i32));
        dump_buf(out, "B pre", &b);
        b.clear();
        dump_buf(out, "B clear", &b);
    }
    {
        let raw = &mut [0u8; 2];
        let mut b = Buffer::new(raw, 2);
        let a1 = b.allocate(1);
        let a2 = b.allocate(2);
        out.p(&format!("B over a1={} a2={}", a1 as i32, a2 as i32));
        dump_buf(out, "B over", &b);
        b.allocate(1);
        dump_buf(out, "B fit", &b);
        b.allocate(0);
        dump_buf(out, "B zero", &b);
        b.clear();
        dump_buf(out, "B cleared", &b);
        let ok0 = b.allocate(3);
        out.p(&format!("B fresh-over ok={}", ok0 as i32));
        dump_buf(out, "B fresh-over", &b);
    }
    {
        let raw = &mut [0u8; 4];
        let mut b = Buffer::new(raw, 4);
        b.allocate(4);
        b.off = 2;
        out.p(&format!("B off off={} size={}", b.off, b.size()));
        b.clear();
        out.p(&format!("B off-clr off={} size={}", b.off, b.size()));
        dump_buf(out, "B off-geo", &b);
    }

    // ---- EncState::get_ttl table
    {
        struct Row {
            f: EncodeFlags,
            ttl: u8,
            lyr: u8,
        }
        let rows = [
            Row { f: ENC_FLAG_FWD, ttl: 7, lyr: 200 },
            Row { f: ENC_FLAG_FWD | ENC_FLAG_TTL, ttl: 7, lyr: 200 },
            Row { f: 0, ttl: 0, lyr: 200 },
            Row { f: 0, ttl: 0, lyr: 128 },
            Row { f: ENC_FLAG_TTL, ttl: 3, lyr: 128 },
            Row { f: ENC_FLAG_TTL, ttl: 200, lyr: 128 },
            Row { f: ENC_FLAG_FWD, ttl: 0, lyr: 0 },
            Row { f: 0, ttl: 0, lyr: 255 },
        ];
        for (i, row) in rows.iter().enumerate() {
            let es = EncState::new(row.f, ipp::TCP, row.ttl, 0);
            out.p(&format!(
                "T r{} f={:016X} t={} lyr={} -> {} fwd={}",
                i,
                row.f,
                row.ttl,
                row.lyr,
                es.get_ttl(row.lyr),
                es.forward() as i32
            ));
        }
        let es = EncState::new(0, ipp::TCP, 0, 0);
        out.p(&format!(
            "T next-set={} eth-set={}",
            es.next_proto_set() as i32,
            es.ethertype_set() as i32
        ));
        let es2 = EncState::new(ENC_FLAG_FWD, ipp::TCP, 0, 9);
        out.p(&format!(
            "T2 next-set={} eth-set={} dsize={}",
            es2.next_proto_set() as i32,
            es2.ethertype_set() as i32,
            es2.dsize
        ));
    }

    // ---- CheckIPV6HopOptions (H1..H8; identical byte inputs to probe.cc)
    // out.p after each check: events for THAT call stream before the label
    // line (evaluation-order-safe C probe pins this [events][label] order).
    macro_rules! hcase {
        ($out:expr, $tag:literal, $h:expr, $rawlen:expr, $lbl:literal) => {{
            let h = $h;
            let mut cd = CodecData::new(None, pi::ETHERTYPE_NOT_SET);
            let rd = RawData { data: &h, len: $rawlen };
            {
                let r = check_ipv6_hop_options(&rd, &mut cd, &mut |g, s| $out.ev(g, s));
                if $lbl == "cdbad" {
                    $out.p(&format!(
                        "{} r={} cdbad={}",
                        $tag,
                        r as i32,
                        ((cd.codec_flags & CODEC_IP6_BAD_OPT) != 0) as i32
                    ));
                } else if $lbl == "cdo" {
                    $out.p(&format!(
                        "{} r={} cdo={}",
                        $tag,
                        r as i32,
                        ((cd.codec_flags & CODEC_IP6_BAD_OPT) != 0) as i32
                    ));
                } else {
                    $out.p(&format!("{} r={}", $tag, r as i32));
                }
            }
        }};
    }
    // H1: [nxt=0,len=0] pad1,pad1 -> loop exits exactly, true, no EV
    hcase!(
        out,
        "H1",
        [0u8, 0, 0x00, 0x00, 0, 0, 0, 0],
        8,
        "cdo"
    );
    // H2: [len=0,total=8] padn op=2 fits, padn op=6 over -> BAD_OPT_LEN,
    // skips(0x01)=true. (probe comment labelled this 'r=1' plain)
    hcase!(
        out,
        "H2",
        [0u8, 0, 0x01, 0x02, 0, 0, 0x01, 0x06],
        8,
        "r"
    );
    // H3: type 0x02 not in enum -> latch BAD_OPT + EV 279 (default fall
    // thru), TLV op=0 fits -> consume; pad1 at 4,6 exit; true
    hcase!(
        out,
        "H3",
        [0u8, 0, 0x02, 0x00, 0x00, 0, 0, 0],
        8,
        "cdbad"
    );
    // H4: type 0x03 op=10 OVER -> latch 279 then EV 295 -> skips(3)=true
    hcase!(
        out,
        "H4",
        [0u8, 0, 0x03, 0x0A, 0, 0, 0, 0],
        8,
        "cdbad"
    );
    // H4b: action-bit type 0xC1 (not an enumerator): default -> latch 279,
    // TLV op=0 fits -> continues; pad1 exits; BAD_OPT latched=1, r=true
    hcase!(
        out,
        "H4b",
        [0u8, 0, 0xC1, 0x00, 0x00, 0, 0, 0],
        8,
        "cdbad"
    );
    // H5: JUMBO op=10 OVER -> EV 272?? no: EV 295 first? the transcript
    // shows 'EV 116 272' BEFORE 295 on H5 (raw len 8 == total 8, no 272)...
    // probe feeds total=(0*8)+8=8; the 272 belongs to H6 below. H5 emits
    // 295 then skips(0x04)=true.
    hcase!(
        out,
        "H5",
        [0u8, 0, 0x04, 0x0A, 0, 0, 0, 0],
        8,
        "cdbad"
    );
    // H6: raw len 4 < total 8 -> EV 272 WITHOUT return (walk continues),
    // padn op=6: hdr_end-pkt=6 < 8 -> EV 295, skips(1)=1 -> r=1
    hcase!(
        out,
        "H6",
        [0u8, 0, 0x01, 0x06, 0, 0, 0, 0],
        4,
        "cdbad"
    );
    // H7: 16-octet header (ip6e_len=1), padn chains clean
    hcase!(
        out,
        "H7",
        [0u8, 1, 0x01, 0x00, 0x01, 0x01, 0, 0, 0x01, 0x00, 0x01, 0x06, 0, 0, 0, 0],
        16,
        "cdbad"
    );
    // H8: HOME_ADDRESS op=0 then pad1 exit
    hcase!(
        out,
        "H8",
        [0u8, 0, 0xC9, 0x00, 0x00, 0, 0, 0],
        8,
        "cdbad"
    );

    // ---- CheckIPv6ExtensionOrder (O1..O11)
    macro_rules! ocall {
        ($out:expr, $cd:expr, $prot:expr) => {
            check_ipv6_extension_order(&mut $cd, $prot, &mut |g, s| $out.ev(g, s))
        };
    }
    {
        let mut cd = CodecData::new(None, pi::HOPOPTS);
        ocall!(out, cd, ipp::HOPOPTS);
        out.p(&format!("O1 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }
    {
        let mut cd = CodecData::new(None, pi::ROUTING);
        ocall!(out, cd, ipp::ROUTING);
        out.p(&format!("O2 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }
    {
        let mut cd = CodecData::new(None, pi::FRAGMENT);
        cd.curr_ip6_extension = 3;
        cd.codec_flags |= CODEC_ROUTING_SEEN;
        ocall!(out, cd, ipp::DSTOPTS);
        out.p(&format!("O3 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }
    {
        let mut cd = CodecData::new(None, pi::DSTOPTS);
        cd.codec_flags |= CODEC_ROUTING_SEEN;
        for i in 0..3 {
            ocall!(out, cd, ipp::DSTOPTS);
            out.p(&format!(
                "O4 iter{} curr={} flags={}",
                i,
                cd.curr_ip6_extension,
                hex16(cd.codec_flags)
            ));
        }
    }
    {
        let mut cd = CodecData::new(None, pi::ESP);
        cd.curr_ip6_extension = 6;
        cd.codec_flags |= CODEC_IP6_EXT_OOO;
        ocall!(out, cd, ipp::AUTH);
        out.p(&format!("O7 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }
    {
        let mut cd = CodecData::new(None, pi::HOPOPTS);
        ocall!(out, cd, ipp::HOPOPTS);
        ocall!(out, cd, ipp::HOPOPTS);
        out.p(&format!("O8 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }
    {
        let mut cd = CodecData::new(None, pi::FRAGMENT);
        ocall!(out, cd, ipp::HOPOPTS);
        ocall!(out, cd, ipp::FRAGMENT);
        out.p(&format!("O9 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }
    {
        let mut cd = CodecData::new(None, pi::HOPOPTS);
        ocall!(out, cd, ipp::ESP);
        ocall!(out, cd, ipp::HOPOPTS);
        out.p(&format!("O10 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }
    {
        let mut cd = CodecData::new(None, pi::IPV6);
        cd.curr_ip6_extension = 2;
        cd.codec_flags |= CODEC_ROUTING_SEEN;
        ocall!(out, cd, ipp::DSTOPTS);
        ocall!(out, cd, ipp::DSTOPTS);
        out.p(&format!("O11 curr={} flags={}", cd.curr_ip6_extension, hex16(cd.codec_flags)));
    }

    // ---- CodecData ctor defaults + is_cooked
    {
        let mut cd = CodecData::new(None, pi::ETHERTYPE_NOT_SET);
        out.p(&format!(
            "CD next_id={} lyr={} inv={} bits={} flags={} ipl={} ext={} cur={} csum={} tun={} cook={}",
            cd.next_prot_id,
            cd.lyr_len,
            cd.invalid_bytes,
            cd.proto_bits,
            cd.codec_flags,
            cd.ip_layer_cnt,
            cd.ip6_extension_count,
            cd.curr_ip6_extension,
            (cd.ip6_csum_proto == ipp::IP) as i32,
            cd.tunnel_bypass as i32,
            cd.is_cooked() as i32
        ));
        cd.codec_flags |= CODEC_STREAM_REBUILT;
        out.p(&format!("CD cook2={}", cd.is_cooked() as i32));
    }
    out.p("DONE");

    let got = std::mem::take(&mut out.lines);
    let want: Vec<&str> = include_str!("../tools/codec_harness/vectors.txt").lines().collect();
    let mut diffs = Vec::new();
    for i in 0..got.len().max(want.len()) {
        let g = got.get(i).map(String::as_str).unwrap_or("<missing>");
        let w = want.get(i).copied().unwrap_or("<missing>");
        if g != w {
            diffs.push(format!("line {}: got {:?} want {:?}", i + 1, g, w));
        }
    }
    assert!(diffs.is_empty(), "codec transcript replay:\n{}", diffs.join("\n"));
}

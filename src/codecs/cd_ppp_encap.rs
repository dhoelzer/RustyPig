//! Port of `src/codecs/link/cd_ppp_encap.cc` (174 L) — row 18m, the
//! codecs/link PPP DRIFT PAIR half two (`tools/link6_harness`, ZERO-gate
//! probe-only, 20th straight honest zero-gate face). Ground: snort3-src @
//! fe29cbe, md5 `3a254d9eeb93298d8fc548f84ad6cad0` wc 174 (the 243+174 =
//! 417 SUM re-measured and asserted EVERY build by build.sh). DIR FACT:
//! `codecs/link/`. DRIFT-PAIR half two of two: the mate is cd_pppoe.rs
//! (243 L, md5 65109bbd2bd8837140568f35bdf98eb5).
//!
//! THE NAME/HELP ENCLOSURE CONTRAST (build.sh sed enclosure pins):
//! `CD_PPPENCAP_NAME "ppp_encap"` :29 + `CD_PPPENCAP_HELP` :30 ride
//! OUTSIDE the anon namespace (ns-open :32, ns-close :49) — the inverse
//! of the pppoe mate's INSIDE-ns :115/:139 double-NAME face. The const
//! ladder PPP_IP..PPP_IPX :44-:48 rides INSIDE the ns. The tail's
//! leanest include face: NO codec_module.h (:22 config.h + :25 framework/
//! codec.h ONLY — the E4 nocm strip kills ONLY the pppoe mate, this TU
//! SURVIVES rc0, every build).
//!
//! THE TRUE-NAME DRIFT face #2 (PLAN §1/:17): the FILE base is
//! `cd_ppp_encap` but the static table symbol is `const BaseApi*
//! cd_pppencap[]` :169 feeding `&pppencap_api.base` :172 — the Rust
//! landing file keeps the FILE base (this file) and the hidden-table
//! const rides the TABLE spelling `CD_PPPENCAP` (the 18l cd_trans_bridge
//! precedent; nm: cd_pppencap D EXACTLY-1, `cd_ppp_encap$` EXACTLY-0,
//! the build.sh drift refusal). Ladder entry "cd_pppencap" RESIDENT
//! codec_api.rs:122 (ground extern codec_api.cc :64, load :109) NEVER
//! re-walked; THIS row TURNS it loaded.
//!
//! THE nullptr MOD-PAIR face (the §5 face, MEASURED, NEVER carried from
//! any prior row): the BaseApi slots :155/:156 after NAME :153/HELP :154
//! carry the EXPLICIT `nullptr,` / `nullptr` pair — `ppp_encap mod_ctor=0
//! mod_dtor=0` (the tail's ONLY nullptr mod pair; NO Module type lands,
//! the honest-absence posture like 18l's trans_bridge); CodecApi ctor
//! :138-:139 / dtor :141-:142 real -> slots :162/:163 SET (faceA
//! `ctor=1 dtor=1`).
//!
//! THE GROUND FAMILY LINK (PLAN §1, the pair story's ppp side):
//! get_protocol_ids :51-:52 pushes ETHERTYPE_PPP (0x880B = 34827,
//! protocol_ids.h :152) — the SAME id the pppoe mate's sess decode sets
//! as next_prot_id at cc:161: pppoe_sess -> ppp_encap is a REAL decode-
//! chain family; this file is the id's ROW HOME (the sess-side twin cites
//! HERE), parity-pinned EQUAL cross-file + the family assert in the row's
//! parity test (34827 FACE-A GETIDS == PD/PS next face).
//!
//! THE rfc1661 compression-collision face (grounds, NEVER our invention):
//! the odd-first-octet branch :61-:68 masks NOTHING — the compressed
//! half-octet 0x21 NUMERICALLY equals PPP_IP 0x0021 (:44) so the
//! switch :80 fires case PPP_IP -> next IPV4 :103 with lyr 1; 0x2d
//! likewise equals PPP_VJ_COMP -> :83 return false with lyr 1 STAYING
//! (the order-site pin `PE order-site lyr:73-before-switch:80` — the R6
//! clone). Vector faces `PE comp21 -> 1 lyr=1 next=2048` / `PE comp2d ->
//! 0 lyr=1 next=34827`.
//!
//! THE FIXIT-M face (honest cite, KNOWN DEVIATIONS row 18m): :94-:99
//! `// FIXIT-M X This is broken - it should not modify the packet data
//! (which should be const)` + `const_cast<ip::IP4Hdr*>(iph)->set_proto
//! (IpProtocol::TCP)` — the VJ_UCOMP arm MUTATES proto byte 9 of the
//! behind-lyr IP4 header to 6 (the ground's own admitted wart). Rust
//! RawData ships an immutable window; the write FOLDS to the documented
//! face below (the cd_no_next.rs:14-:19 / cd_esp.rs:229 const_cast-fold
//! precedent). The vectors ride it printed HONEST: `PE vjucomp22 -> 1
//! lyr=2 next=2048 proto9=6` — the probe mutated its OWN fixture
//! (probe_dec.cc prints p[11] post-decode), the parity replay mirrors
//! the cited write to the fixture (cc:97-:98 cite) — NEVER invented.
//! The :88 IP4_HEADER_LEN==20 boundary (protocols/ipv4.h :38, ground sed)
//! lands 21-vs-22 arms: `PE vjucomp21 -> 0 lyr=2` / vjucomp22 passes.
//! VJ_COMP :82-:83 false, fall-through :100 into PPP_IP, IPV6 :106-:107,
//! IPX :110-:111 (0x8137 = 33079 protocol_ids.h :150), default :114-:115
//! true. ZERO codec_event EVER on this TU (:124-adjacent census; build.sh
//! greps codec_event 0 in the .cc every build — the DECODE_ token census
//! 0, the pair's EV sides are pppoe ONLY {120,479}).
//!
//! PADT NEVER-PULL: grep-0 BOTH files (the ruling rides the pair; this TU
//! carries ZERO session/PADT token at all). encode :120-:132 cited-NEVER-
//! called (EncState-IpApi seam, ZERO-encode-arms precedent), ported-by-
//! reading below. sids: this TU fires NONE (ZERO new consts, PLAN §4).

use crate::framework::codec::{
    API_OPTIONS, Buffer, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData,
    CodecTable, EncState, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;

/// :29 `#define CD_PPPENCAP_NAME "ppp_encap"` — OUTSIDE the anon
/// namespace (:32/:49 enclosure contrast, module doc).
pub const CD_PPPENCAP_NAME: &str = "ppp_encap";
/// :30 `#define CD_PPPENCAP_HELP "support for point-to-point
/// encapsulation"` (vectors_faceA HELP line verbatim).
pub const CD_PPPENCAP_HELP: &str = "support for point-to-point encapsulation";

/// :44 `static const uint16_t PPP_IP = 0x0021` — Internet Protocol (the
/// compression-collision face: the ODD branch's unmasked 0x21 lands HERE
/// NUMERICALLY, module doc).
pub const PPP_IP: u16 = 0x0021;
/// :45 `static const uint16_t PPP_IPV6 = 0x0057` — Internet Protocol v6.
pub const PPP_IPV6: u16 = 0x0057;
/// :46 `static const uint16_t PPP_VJ_COMP = 0x002d` — VJ compressed
/// TCP/IP (unhandled: :82-:83 return false).
pub const PPP_VJ_COMP: u16 = 0x002d;
/// :47 `static const uint16_t PPP_VJ_UCOMP = 0x002f` — VJ uncompressed
/// TCP/IP (the FIXIT-M arm :85-:100).
pub const PPP_VJ_UCOMP: u16 = 0x002f;
/// :48 `static const uint16_t PPP_IPX = 0x002b` — Novell IPX Protocol.
pub const PPP_IPX: u16 = 0x002b;

/// protocol_ids.h:152 `ETHERTYPE_PPP = 0x880B` (= 34827, the FACE-A
/// GETIDS pin) — the :52 push + the pppoe mate cc:161 next_prot_id: THE
/// ground decode-chain link (module doc). ROW HOME of the id (the
/// cd_pppoe.rs twin cites HERE, the landed dup-not-import family,
/// parity-pinned EQUAL).
pub const ETHERTYPE_PPP: ProtocolId = 0x880B;
/// protocol_ids.h:150 `ETHERTYPE_IPX = 0x8137` (= 33079, the vectors'
/// `next=33079` face) — the :111 write. Row-scoped home (MEASURED ZERO
/// prior landed Rust face for the IPX id; the dup-not-import family).
/// The IPV4 (:144 `0x0800` = 2048, the :103 write) + IPV6 (:151
/// `0x86DD` = 34525, the :107 write) ids are framework-OWNED landed
/// values — IMPORT face (`protocol_id::ETHERTYPE_IPV4` / `_IPV6` in the
/// arms below), NEVER re-authored.
pub const ETHERTYPE_IPX: ProtocolId = 0x8137;

/// protocols/ipv4.h:38 `constexpr uint8_t IP4_HEADER_LEN = 20;` — the
/// :88 VJ_UCOMP len gate (`raw.len < lyr_len + 20`, the 21-vs-22 vector
/// arms). Ground sed-pinned by build.sh every build. Row-scoped twin
/// (ZERO prior landed Rust face; the dup-not-import family).
pub const IP4_HEADER_LEN: u16 = 20;

/// :34-:42 `class PppEncap : public Codec` — THREE overrides
/// (get_protocol_ids :39 / decode :40 / encode :41) + the
/// `Codec(CD_PPPENCAP_NAME)` ctor face :37 (rides the api record). decode's
/// third C param UNNAMED (:40) = never-read (the pgm precedent). NO
/// Module subclass exists (the nullptr mod pair headline). NO log, NO
/// get_data_link_type (the GETDLT ZERO census face).
#[derive(Default)]
pub struct PppEncap;

impl PppEncap {
    /// :37 the base-ctor name face.
    pub fn new() -> PppEncap {
        PppEncap
    }

    /// :51-:52 `v.emplace_back(ProtocolId::ETHERTYPE_PPP)` — vectors_faceA
    /// `GETIDS ppp_encap 34827` DECIMAL == the pppoe sess next (the
    /// family assert, the decode-chain link).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_PPP); // :52
    }

    /// :54-:118 out-of-line decode — the protocol switch ladder, ZERO
    /// codec_event on EVERY arm. Statement order VERBATIM; EVAL ORDER the
    /// row's rule: `protocol` is a VAR (:56) fed by the :61-:74 branches
    /// BEFORE the switch :80 (the order-site cite `lyr:73-before-
    /// switch:80` — branch-internal lyr writes land before the switch).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, _sink: QueueSink<'_>) -> bool {
        // :58-:59 `if (raw.len < 2) return false;` — NO event (the ZERO-
        // codec_event TU face; vectors `PE len1 -> 0 lyr=0`).
        if raw.len < 2 {
            return false;
        }

        // :56 `uint16_t protocol;` + the :61-:74 branch pair feeding it
        // (var-first, verbatim order).
        let protocol: u16;
        if raw.data[0] & 0x01 != 0 {
            // :61 `if (raw.data[0] & 0x01)` — :63-:65 the ground comment
            // `/* Check for protocol compression rfc1661 section 5 */`
            // rides. :66-:67 the compressed half-octet face: lyr_len = 1
            // and protocol = the OCTET VALUE unmasked -- the compression-
            // collision face (0x21 == PPP_IP NUMERICALLY, module doc).
            codec.lyr_len = 1; // :66
            protocol = u16::from(raw.data[0]); // :67
        } else {
            // :71-:73 the 2-octet face: `protocol = (data[0] << 8) |
            // data[1]` THEN `codec.lyr_len = 2` — VERBATIM order (the
            // write rides after the var, the order-site cite).
            protocol = u16::from_be_bytes([raw.data[0], raw.data[1]]); // :71-:72
            codec.lyr_len = 2; // :73
        }

        // :76-:79 the ground comment block `/* We only handle uncompressed
        // packets. Handling VJ compression would mean to implement a PPP
        // state machine. */` rides.
        // :80-:116 the switch. C fall-through :100 `/* fall through */`
        // from VJ_UCOMP into PPP_IP is EXACT (kept via the Rust
        // fall-through-shaped control flow below).
        match protocol {
            // :82-:83 case PPP_VJ_COMP: return false (lyr_len STAYS set —
            // vectors `PE vjcomp -> 0 lyr=2 next=34827-init` / `PE comp2d
            // -> 0 lyr=1`, the lyr-before-switch:80 face).
            PPP_VJ_COMP => {
                return false; // :83
            }

            PPP_VJ_UCOMP => {
                // :86-:87 the ground comment `/* VJ compression modifies
                // the protocol field. It must be set to tcp (only TCP
                // packets can be VJ compressed) */` rides.
                // :88-:92 `raw.len < (uint32_t)(codec.lyr_len + ip::
                // IP4_HEADER_LEN)` -> return false (the 21-vs-22 boundary,
                // ipv4.h :38 == 20; vectors `PE vjucomp21 -> 0 lyr=2`,
                // the `// PPP VJ min packet length > captured len` :90
                // comment rides).
                let min_len = u32::from(codec.lyr_len) + u32::from(IP4_HEADER_LEN); // :88
                if raw.len < min_len {
                    return false; // :91
                }

                // :94-:99 the FIXIT-M block + the `const_cast<ip::IP4Hdr
                // *>(raw.data + codec.lyr_len)->set_proto(IpProtocol::
                // TCP)` mutation of the behind-lyr IP4 header's proto byte
                // (:97-:98). Rust fold (KNOWN DEVIATIONS row 18m; the
                // cd_no_next.rs:14-:19 / cd_esp.rs:229 precedent): the
                // immutable window carries NO aliasing write — the face
                // lands documented, and the vectors' `proto9=6` print
                // rides the probe's OWN mutated fixture (probe_dec.cc
                // :87-:89), mirrored by cite in the parity replay. The
                // ground `// FIXIT-M X This is broken - it should not
                // modify the packet data (which should be const).` :95-:96
                // comment rides VERBATIM in this cite. The :97 overlay
                // window (proto slot @ lyr+9 of the behind-lyr IP4 head;
                // the len gate above bounds it) is READ-side only here —
                // the set_proto write's observable face rides the probe's
                // OWN mutated fixture + the parity replay's cited mirror.
                let _ = raw.data.get(usize::from(codec.lyr_len) + 9); // :97 iph overlay window

                // :100 `/* fall through */` -> falls into case PPP_IP:
                // :102-:103 (the Rust match arms are separate, so the
                // fall-through lands HERE explicitly, cited):
                codec.next_prot_id = protocol_id::ETHERTYPE_IPV4; // :103
            }

            // :102-:104 case PPP_IP:
            PPP_IP => {
                codec.next_prot_id = protocol_id::ETHERTYPE_IPV4; // :103
            }

            // :106-:108 case PPP_IPV6:
            PPP_IPV6 => {
                codec.next_prot_id = protocol_id::ETHERTYPE_IPV6; // :107
            }

            // :110-:112 case PPP_IPX:
            PPP_IPX => {
                codec.next_prot_id = ETHERTYPE_IPX; // :111 (0x8137, row home)
            }

            // :114-:115 default: break — true, next STAYS the init face
            // (vectors `PE default -> 1 lyr=2 next=34827`).
            _ => {}
        }
        true // :117
    }

    /// :120-:132 out-of-line encode — cited-NEVER-called (vectors cite
    /// line; EncState pulls ip::IpApi — ZERO-encode-arms precedent),
    /// ported-by-reading, statement order VERBATIM: allocate :123-:124 ->
    /// memcpy :126 (NO length rewrite — the contrast vs the pppoe mate's
    /// htons length face) -> NOT_SET resets :128-:129 -> true :131. The
    /// `Flow*` and `raw_len`'s non-read nuance: `raw_len` IS read (:123
    /// allocate + :126 memcpy extent).
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // :123-:124 `if (!buf.allocate(raw_len)) return false;`
        if !buf.allocate(u32::from(raw_len)) {
            return false;
        }

        // :126 `memcpy(buf.data(), raw_in, raw_len)` — the landed Buffer
        // posture copies the window explicitly.
        let n = usize::from(raw_len);
        let head = buf.data_mut().expect("allocate(raw_len) just made size != 0");
        head[..n].copy_from_slice(&raw_in[..n]); // :126

        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET; // :128
        enc.next_proto = ip_protocol::PROTO_NOT_SET;         // :129

        true // :131
    }
}

// :134-:136 the "api" separator banner rides. :138-:139 `static Codec*
// ctor(Module*)` + :141-:142 `static void dtor(Codec*)` ride behavior-
// only cites (record SET flags; the Rust codec face is PppEncap::new; the
// dtor folds onto the stack-owned drop, 18d posture).

/// :144-:164 `static const CodecApi pppencap_api` — name/help slots :153/
/// :154 land the :29/:30 OUTSIDE-ns macro faces; THE tail's ONLY explicit
/// `nullptr, nullptr` MOD pair :155/:156 (module doc headline — faceA
/// `mod_ctor=0 mod_dtor=0`); pinit :158 / pterm :159 / tinit :160 / tterm
/// :161 nullptr WITH the ground `// pinit`-style slot comments; ctor :162
/// (`// ctor`) + dtor :163 (`// dtor`) SET.
pub const PPPENCAP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // :147
    size: CDAPI_SIZEOF_CODEC_API, // :148 sizeof(CodecApi)=112 (faceA size pin)
    api_version: CDAPI_VERSION,   // :149 1900547
    version: 0,                   // :150
    features: PLUGIN_SO_RELOAD,   // :151
    options: API_OPTIONS,         // :152
    name: CD_PPPENCAP_NAME,       // :153 -> "ppp_encap"
    help: CD_PPPENCAP_HELP,       // :154
    mod_ctor: false,              // :155 nullptr (the tail's ONLY pair)
    mod_dtor: false,              // :156 nullptr
    pinit: false,                 // :158 nullptr // pinit
    pterm: false,                 // :159 nullptr // pterm
    tinit: false,                 // :160 nullptr // tinit
    tterm: false,                 // :161 nullptr // tterm
    ctor: true,                   // :162 SET  // ctor
    dtor: true,                   // :163 SET  // dtor
};

/// :166-:174 the hidden export with THE drift name: `#ifdef BUILDING_SO`
/// :166 / SO arm :167 / the static-build `const BaseApi* cd_pppencap[] =`
/// :169 feeding `&pppencap_api.base` :172 + nullptr :173 (ONE feed —
/// faceA `LOAD ppp_encap` + `LOADS 1`). nm: cd_pppencap D EXACTLY-1,
/// `cd_ppp_encap$` EXACTLY-0 (the build.sh drift-refusal tripwire clone,
/// §5). Rust const rides the TABLE spelling; the FILE base stays
/// cd_ppp_encap.rs. Ladder entry "cd_pppencap" RESIDENT codec_api.rs:122
/// NEVER re-touched (ground extern codec_api.cc :64, load :109) — THIS
/// row TURNS it loaded.
pub const CD_PPPENCAP: CodecTable = &[&PPPENCAP_API];

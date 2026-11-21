//! Port of `src/codecs/misc/cd_user.cc` (167 L) — row 18k, the codecs/misc
//! LEFTOVER TRIO half three (`tools/misc3_harness`, ZERO-gate probe-only) —
//! THE DAQ seam row of the misc tail. Ground: snort3-src @ fe29cbe, md5
//! `01e41407b300562c840b4f66a4da4e45` wc 167 (the 498 SUM pinned every
//! build). DIR FACT: `codecs/misc/` — this half drags the row's whole
//! fresh-cp budget: EXACTLY 3 fresh header cps — daqs/daq_user.h 54
//! (md5 1d2e2b9c), packet_io/sfdaq.h 72 (2e272d2d) and packet_io/
//! sfdaq_instance.h 105 (9497f394) — E4 walls flipped EVERY build: strip
//! EACH alone -> ONLY cd_user DIES (fatal first-line greps cc:26/:28/:29);
//! llc + vxlan SURVIVE
//! (ZERO fresh cps between them, the residency split). The trio-header
//! landmine stays ZERO (llc.h/vxlan.h/user.h find-0, the docs "vxlan.h
//! 82L" face FALSE). daq.h NEVER rides HERE: cc:24 is `<daq_common.h>` NOT
//! `<daq.h>` — the fresh-cp-vs-graft split the E4 daq-removal wall proves
//! IN-TREE (ip trio x3 DIE, misc trio x3 SURVIVE).

use crate::framework::codec::{
    API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData, CodecTable,
    PLUGIN_SO_RELOAD, PT_CODEC, RawData, ip_protocol,
};

/// THE name-macro family cc:33-:35 (contrast the llc/vxlan twins' single
/// NAME/HELP pair): `#define CD_NAME "user"` cc:33 TRUE-NAME + `CD_HELP_STR`
/// cc:34 + `CD_HELP ADD_DLT(CD_HELP_STR, DLT_USER)` cc:35 — the codec.h:52
/// compile-time splice evaluated at DLT_USER 230 (vectors_faceA:16
/// `HELP user support for user sessions (DLT 230)`); the cd_raw.rs add_dlt
/// recipe pin family (the literal below IS the splice face).
pub const CD_NAME: &str = "user";
/// cc:34 `#define CD_HELP_STR "support for user sessions"`.
pub const CD_HELP_STR: &str = "support for user sessions";
/// cc:35 ADD_DLT splice at 230 (module doc; the cd_raw.rs:48 add_dlt
/// recipe asserts the composition — help + " (DLT " + 230 + ")" — NEVER
/// a runtime concat inside decode).
pub const CD_HELP: &str = "support for user sessions (DLT 230)";

/// daqs/daq_user.h:29 `#define DLT_USER 230` (`/* for raw payload only */`
/// comment :28 rides) — the get_data_link_type emplace cc:48, the HELP
/// splice, and vectors_faceA:19 `GETDLT user 230` (the trio's ONLY
/// data-link registrant).
pub const DLT_USER: i32 = 230;

// ---- THE DAQ user-hdr seam (daqs/daq_user.h :32-:51, fresh cp; the
// graft-v2 daq_common.h face — `typedef const void* DAQ_Msg_h` etc — is a
// HARNESS C-side face, NEVER a Rust type; the field mirrors are row-scoped
// and SYNTHETIC, NEVER ABI, per the 18i DaqFace ruling) ----
/// daqs/daq_user.h:32 `#define DAQ_USR_FLAG_TO_SERVER  0x01` — read cc:84.
pub const DAQ_USR_FLAG_TO_SERVER: u8 = 0x01;
/// daqs/daq_user.h:33 `#define DAQ_USR_FLAG_START_FLOW 0x02` — read cc:87.
pub const DAQ_USR_FLAG_START_FLOW: u8 = 0x02;
/// daqs/daq_user.h:34 `#define DAQ_USR_FLAG_END_FLOW   0x04` — read cc:90.
pub const DAQ_USR_FLAG_END_FLOW: u8 = 0x04;
/// daqs/daq_user.h:46 `#define DIOCTL_QUERY_USR_PCI    (DAQ_IoctlCmd) 2048`
/// — the cc:103 ioctl argument (the cast is a C-side face; the value rides).
pub const DIOCTL_QUERY_USR_PCI: u32 = 2048;
/// daqs/daq_user.h:36-:44 `DAQ_UsrHdr_t` layout mirror (sizeof 14):
/// src_addr u32 @0, dst_addr u32 @4, src_port u16 @8, dst_port u16 @10,
/// ip_proto u8 @12, flags u8 @13 — the witness ioctl memcpy channel
/// (witness_trio.cc:30-:31 statichdr fills from q->msg == the ground
/// call's OWN arg, raw.daq_msg). The probe fixture face writes fields in
/// HOST order (probe_dec.cc `*(uint16_t*)(m+8)=12345`) — NOT wire-BE; the
/// Rust window reads mirror that host-order face (x86 -> LE; the same
/// LE assumption discipline every probe build carries, WORDS_BIGENDIAN
/// cite-only).
pub const DAQ_USR_HDR_SIZE: usize = 14;

/// decode_data.h:146-:148 (the "using decode flags in lieu of creating
/// user layer for now" block :145) — `DECODE_C2S = 0x200` (// user -
/// client to server), `DECODE_SOF = 0x400`, `DECODE_EOF = 0x800`: the
/// cc:85/:88/:92 writes; vectors:15 df=512, vectors:16 df=3584 (the trio
/// sum 512+1024+2048, PYPIN'd ground-side every build). Row-scoped homes
/// (the small4 DECODE_PKT_TRUST h:140-:142 family, ZERO landed face for
/// THIS trio).
pub const DECODE_C2S: u64 = 0x0000_0200;
pub const DECODE_SOF: u64 = 0x0000_0400;
pub const DECODE_EOF: u64 = 0x0000_0800;

/// decode_data.h:88 `#define PROTO_BIT__TCP 0x000002` — the cc:63 (set_ip
/// TCP arm) and cc:78 (set_key) ORs; vectors pb=2. ROW-SCOPED DUPLICATE
/// per the cd_icmp6.rs:179-:183 ruling (the cd_udp.rs:155 PROTO_BIT__UDP
/// sibling module-scope family — detection/parse_rule.rs:78 and
/// rtn_checks.rs:26 carry THEIR OWN unrelated-module values of the same
/// name; cite posture, no import across the codec boundary).
pub const PROTO_BIT__TCP: u32 = 0x0000_0002;
/// decode_data.h:89 `#define PROTO_BIT__UDP 0x000004` — the cc:65 else
/// arm; vectors:16 pb=4. The cd_udp.rs :155 twin precedent (same value
/// same cite, different module scope, zero collision).
pub const PROTO_BIT__UDP: u32 = 0x0000_0004;

/// decode_data.h:45-:48 `enum class PktType : uint8_t { NONE, IP, TCP,
/// UDP, ICMP, USER, FILE, PDU, MAX }`: USER = the 5th enumerator (0-based
/// -> 5, cc:114), FILE = the 6th (-> 6, cc:119); the PYPIN re-derives both
/// indices ground-side every build; vectors type=5/type=6. Row-scoped
/// homes per the landed cd_icmp4.rs:141 / cd_icmp6.rs:198 PKT_TYPE__ICMP
/// precedent (no landed PktType home).
pub const PKT_TYPE__USER: u8 = 5;
pub const PKT_TYPE__FILE: u8 = 6;

/// The row-scoped DecodeData seam (the 18h/18i lineage precedent; NOT a
/// DecodeData port): the cc:59-:60 sp/dp writes, the cc:85/:88/:92
/// decode_flags ORs (fresh 0 = the probe `DecodeData d` fixture posture),
/// the cc:114/:119 set_pkt_type face (pkt_type slot, the landed
/// cd_icmp4.rs:194 family), and the ip_api writes CITED-NOT-LANDED: the
/// cc:57 set_ip / cc:73 set_key `snort.ip_api.set(sip, dip)` writes touch
/// NO landed Snort-side home (the 18i UdpApiLite LEFT-OPEN face — the
/// PROVIDER queued) and are NEVER observable in either vectors face
/// (only sp/dp/pb/type/df/lyr print). `sfip::sf_ip::SfIp` (the landed
/// row-9 port) carries the SAME set/set_raw/pton shapes the C calls —
/// cited, NEVER fed here (the set_key literals stay cite-never-land, see
/// set_key).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UserDecodeData {
    pub decode_flags: u64, // cc:85/:88/:92 |= face
    pub sp: u16,           // cc:59/:75
    pub dp: u16,           // cc:60/:76
    pub pkt_type: u8,      // cc:114/:119 set_pkt_type face
}

/// cc:37-:44 `class UserCodec : public Codec` — TWO overrides only
/// (get_data_link_type + decode): NO get_protocol_ids override, the base
/// answers the empty vector (vectors_faceA:15-:19: the user block prints
/// NO GETIDS line — the trio's data-link asymmetry). Stack-owned Rust
/// posture (18d); the `Codec(CD_NAME)` ctor name face cc:40 rides the
/// record.
#[derive(Default)]
pub struct UserCodec;

impl UserCodec {
    /// cc:40 `UserCodec() : Codec(CD_NAME) { }`
    pub fn new() -> UserCodec {
        UserCodec
    }

    /// cc:46-:49 `v.emplace_back(DLT_USER)` — vectors_faceA:19 `GETDLT
    /// user 230` (the cd_raw.rs:92 shape).
    pub fn get_data_link_type(&self, v: &mut Vec<i32>) {
        v.push(DLT_USER); // cc:48
    }

    /// cc:99-:124 out-of-line decode, statement order VERBATIM.
    /// `daq_msg` models the cc:100 `raw.daq_msg` operand (the landed
    /// RawData DROPS daq_msg — the 17d seam closure rides row 20; the
    /// 18i DaqFace per-TU bundle precedent: the channel = Option window,
    /// some == the witness `if (q->msg) memcpy` face, NONE == the
    /// witness's memset-zeroed hdr face — harness fixture posture).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut UserDecodeData,
        daq_msg: Option<&[u8]>,
    ) -> bool {
        // cc:101 `DIOCTL_QueryUsrPCI qup = { raw.daq_msg, nullptr };` —
        // the aggregate-init face (pci STARTS null: the cc:108 read of a
        // witness-FILLED slot). graft-v2's const-DAQ_Msg_h flip is the
        // C-side compile face this line demanded (R1 landmine, receipts
        // E4_cd_user_v1.txt re-run every build) — NEVER a Rust type.

        // cc:103 `if ( SFDAQ::get_local_instance()->ioctl(DIOCTL_QUERY_
        // USR_PCI, &qup, sizeof(qup)) != DAQ_SUCCESS ) return false;` —
        // the ioctl call LIVES INSIDE the if (PLAN §8 eval cite). THE
        // WITNESS-MIRROR FACING (module doc headline; the get_proto_name
        // precedent cd_icmp4_ip.rs:464-:473): the SFDAQ::get_local_
        // instance / SFDAQInstance::ioctl PROVIDERS are NEVER invented
        // Rust-side (sfdaq.cc + sfdaq_instance.cc = 856 L class face,
        // find-tools-0 in EVERY donor, the 18j-scoped REJECT census; the
        // harness carries the SYNTHETIC witness bodies instead — the
        // TRacked 18k witness, PLAN §7: get_local_instance -> nullptr +
        // ioctl memcpy + ALWAYS DAQ_SUCCESS). THE TWO CITED NEVER-ARMED
        // GROUND FACES: (a) get_local_instance -> nullptr then the ground
        // chain-CALLS ->ioctl withOUT a null check (cc:103 = the ground
        // SEGV-if-no-instance honesty face; the synthetic witness ioctl
        // NEVER derefs `this` so the chain survives where ground dies —
        // cite-never-fix, vectors:13's cite line; the provider face stays
        // LEFT-OPEN to row 20); (b) the != DAQ_SUCCESS return-false leg
        // (the witness ALWAYS DAQ_SUCCESS, vectors:18 cite line). The
        // cc:108 `if ( !pci ) return false;` leg is the THIRD cite-never-
        // armed face (the witness ALWAYS fills qup.pci).
        let hdr = sfdaq_query_usr_pci(daq_msg); // cc:101-:103 seam face

        // cc:111-:120 the ip_proto discriminator: the hdr channel read.
        if hdr[12] != 0 {
            Self::set_ip(&hdr, codec, snort); // cc:113
            snort.pkt_type = PKT_TYPE__USER; // cc:114 set_pkt_type face
        } else {
            Self::set_key(codec, snort); // cc:118
            snort.pkt_type = PKT_TYPE__FILE; // cc:119
        }

        Self::set_flags(&hdr, raw, codec, snort); // cc:122
        true // cc:123
    }

    /// cc:51-:66 `set_ip` (file-static behavior face, landed as an
    /// inherent fn — the landed static-fn shape): the cc:54-:57 SfIp
    /// pair build `sip.set(&pci->src_addr, AF_INET)` / `dip.set(&pci->
    /// dst_addr, AF_INET)` + `snort.ip_api.set(sip, dip)` ride CITED-
    /// NOT-LANDED (the landed sfip::SfIp set_raw shape at the AF_INET
    /// constant is the cite home — framework/ip layer provider queued,
    /// 18i UdpApiLite face; ZERO vectors face prints the IPs); the
    /// cc:59-:60 sp/dp writes land (the hdr channel @8/@10 host-order);
    /// the cc:62-:65 `ip_proto == IPPROTO_TCP` pair arms land (the landed
    /// ip_protocol::TCP 6 IMPORT, vectors m[12]=6 -> PROTO_BIT__TCP; the
    /// else arm UNCONDITIONAL UDP m[12]=17).
    fn set_ip(hdr: &[u8; DAQ_USR_HDR_SIZE], codec: &mut CodecData<'_>, snort: &mut UserDecodeData) {
        // cc:54-:57 the SfIp set pair — cite-only (module doc; the
        // ip_api.set target has NO landed Snort home, provider queued).
        snort.sp = u16::from_le_bytes([hdr[8], hdr[9]]);  // cc:59 (host-order fixture face)
        snort.dp = u16::from_le_bytes([hdr[10], hdr[11]]); // cc:60

        if hdr[12] == ip_protocol::TCP {
            // cc:62-:63 `IPPROTO_TCP` == the landed ip_protocol::TCP 6
            codec.proto_bits |= PROTO_BIT__TCP;
        } else {
            // cc:64-:65 the unconditional else arm
            codec.proto_bits |= PROTO_BIT__UDP;
        }
    }

    /// cc:68-:79 `set_key` — THE hardcoded KEY face (the row's honest
    /// pin, PLAN §3): cc:70 `// FIXIT-L make configurable` rides as the
    /// ground's OWN debt comment (harness sed-pin :70 every build); the
    /// cc:71-:73 SfIp set pair carries the GROUND HARDCODED dotted-quad
    /// ADDRESS-LITERAL pair — CITE-NEVER-LAND (the build.sh grep-arms the
    /// ground file holds them; the address tokens NEVER appear in Rust
    /// src/tests, only in build.sh sed cites of cc:72; the snort.ip_api.set
    /// write is NEVER observable in either vectors face). THE LANDABLE
    /// OBSERVABLES (the probe prints EXACTLY these ground literals —
    /// cc:75/:76 ARE the observable face, per the PLAN landing receipt):
    /// sp 12345 + dp 54321; cc:78 `codec.proto_bits |= PROTO_BIT__TCP`
    /// unconditional TCP (vectors:14 pb=2 sp=12345 dp=54321 type=6).
    fn set_key(codec: &mut CodecData<'_>, snort: &mut UserDecodeData) {
        // cc:71-:73 the dotted-quad SfIp pair: cite-NEVER-land (doc
        // headline) — the cc:72 `... == SFIP_SUCCESS and ... ==
        // SFIP_SUCCESS` guard face (C++20 `and`) rides the cite only;
        // the landed sfip::sf_returns::SfIpRet::Success IS the SFIP_
        // SUCCESS face (row-9 port) — named as the compare-shape cite,
        // NEVER fed (no landed ip_api home).

        snort.sp = 12345; // cc:75 GROUND literal == observable (landing ruled by the PLAN)
        snort.dp = 54321; // cc:76 ditto

        codec.proto_bits |= PROTO_BIT__TCP; // cc:78
    }

    /// cc:81-:97 `set_flags` — the trio leg census, THREE `pci->flags &`
    /// tests: cc:84 TO_SERVER -> DECODE_C2S; cc:87 START_FLOW ->
    /// DECODE_SOF; cc:90 END_FLOW -> { DECODE_EOF + lyr_len = raw.len
    /// cc:92-:93 }; the cc:95-:96 ELSE arm `codec.lyr_len = 0` (the
    /// vectors:17 cite line names the arms; the tcp-c2s arm rides the
    /// ELSE face live — flags 0x01, no END_FLOW). Host-order hdr channel
    /// read @13 (the fixture face).
    fn set_flags(
        hdr: &[u8; DAQ_USR_HDR_SIZE],
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut UserDecodeData,
    ) {
        if hdr[13] & DAQ_USR_FLAG_TO_SERVER != 0 {
            snort.decode_flags |= DECODE_C2S; // cc:84-:85
        }
        if hdr[13] & DAQ_USR_FLAG_START_FLOW != 0 {
            snort.decode_flags |= DECODE_SOF; // cc:87-:88
        }
        if hdr[13] & DAQ_USR_FLAG_END_FLOW != 0 {
            snort.decode_flags |= DECODE_EOF; // cc:90-:92
            codec.lyr_len = raw.len as u16; // cc:93 (vectors:16 lyr=4)
        } else {
            codec.lyr_len = 0; // cc:95-:96 the ELSE face
        }
    }
}

/// THE sfdaq witness-mirror seam fn (module doc headline; NEVER the real
/// SFDAQ provider — the get_proto_name precedent family): models the
/// TRacked harness witness's OBSERVABLE body face (the row's +2 witness,
/// PLAN §6/§7: SFDAQ::get_local_instance -> nullptr + SFDAQInstance::
/// ioctl fills a STATIC DAQ_UsrHdr_t from q->msg with ALWAYS-DAQ_SUCCESS
/// return). The ground cc:101-:103 qup pair (msg == raw.daq_msg, pci
/// out-param) folds onto: Some(window) -> the memcpy-copied hdr; NONE ->
/// the witness memset-zeroed hdr (the probe nullptr-fixture face driving
/// the cc:116-:120 set_key/FILE arm). The DAQ_SUCCESS / !pci arms are
/// CITED never-armed (vectors:18) — the fn ALWAYS succeeds + ALWAYS
/// yields a pci-equivalent, mirroring the witness census (own-new T
/// symbols EXACTLY-2, L1 undefined-EXACTLY-2, re-measured every build).
#[inline]
pub fn sfdaq_query_usr_pci(msg: Option<&[u8]>) -> [u8; DAQ_USR_HDR_SIZE] {
    let mut hdr = [0u8; DAQ_USR_HDR_SIZE]; // the cc:101 `nullptr` pci-slot + witness memset face
    if let Some(m) = msg {
        // the witness `if (q->msg) memcpy(&hdr, q->msg, sizeof(hdr))` face
        hdr.copy_from_slice(&m[..DAQ_USR_HDR_SIZE]);
    }
    hdr // qup.pci always FILLED -> the cc:108 !pci leg cite-never-armed
}

// cc:126-:128 the "api" separator banner rides. cc:130-:134 `static
// Codec* ctor(Module*) { return new UserCodec; }` / `static void
// dtor(Codec*)` ride behavior-only cites (record flags SET; the Rust
// codec face is UserCodec::new).

/// cc:136-:156 `static const CodecApi user_api` — the mod-pair ZERO face
/// WITH the ground's own EXPLICIT inline comments cc:147/:148 `nullptr,
/// // mod_ctor` / `nullptr,  // mod_dtor` (the trio asymmetry's loudest
/// transcript, sed-pinned both lines every build; vectors_faceA:17
/// `user mod_ctor=0 mod_dtor=0`); the g/t slots cc:150-:153 carry the
/// `// pinit`-family comments; ctor/dtor SET cc:154-:155. HELP slot
/// cc:146 rides the ADD_DLT splice face.
pub const USER_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,             // cc:139
    size: CDAPI_SIZEOF_CODEC_API, // cc:140 sizeof(CodecApi)=112 (faceA:15)
    api_version: CDAPI_VERSION,  // cc:141 1900547
    version: 0,                  // cc:142
    features: PLUGIN_SO_RELOAD,  // cc:143
    options: API_OPTIONS,        // cc:144
    name: CD_NAME,               // cc:145 -> "user"
    help: CD_HELP,               // cc:146 ADD_DLT splice (faceA:16)
    mod_ctor: false,             // cc:147 nullptr,  // mod_ctor (EXPLICIT comment face)
    mod_dtor: false,             // cc:148 nullptr,  // mod_dtor (EXPLICIT comment face)
    pinit: false,                // cc:150 nullptr  // pinit
    pterm: false,                // cc:151 nullptr  // pterm
    tinit: false,                // cc:152 nullptr  // tinit
    tterm: false,                // cc:153 nullptr  // tterm
    ctor: true,                  // cc:154 SET
    dtor: true,                  // cc:155 SET
};

/// cc:158-:167 the hidden export (trio BUILDING_SO census): `#ifdef
/// BUILDING_SO` cc:158 / SO arm cc:159 / the static-build `const BaseApi*
/// cd_user[] =` cc:161 feeding `&user_api.base` cc:164 + nullptr cc:165;
/// nm table symbol EXACTLY-1 (the STATIC arm IS the harness face). Table
/// name == file base == NAME (TRUE x3, no drift face). Ladder entry
/// "cd_user" RESIDENT codec_api.rs :129 NEVER re-touched (extern
/// codec_api.cc :71, load :116).
pub const CD_USER: CodecTable = &[&USER_API];

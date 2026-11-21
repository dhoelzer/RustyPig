//! Port of `src/codecs/link/cd_vlan.cc` (236 L) — row 18n, the codecs/link
//! chapter-tail vlan TRIO half one (`tools/link4_harness`, ZERO-gate probe-
//! only, 21st straight honest zero-gate face: find src/codecs/link -type d
//! -name test = 0 + add_cpputest census 0). Ground: snort3-src @ fe29cbe,
//! md5 `fe9747e87a7383eeacf43ce381b5ab7c` wc 236 (the 236+235+187 = 658 SUM
//! asserted build-side; THIS landing file is cd_vlan.rs per the FLAT call) —
//! re-measured and asserted EVERY build by tools/link4_harness/build.sh).
//! DIR FACT: `codecs/link/`. Trio mates: cd_ciscometadata.rs (235 L, md5
//! 8cd594aa...) + cd_fabricpath.rs (187 L, md5 f3fee8d9...).
//!
//! THE GRAFT-V3 FIRST-EXTENSION HEADLINE (the row's name-pin story, PLAN
//! §5 + §9): this is the FIRST row in the port that EXTENDS the graft — the
//! frozen daq3 masters (daq.h **73fdbc39** 33 L / daq_common.h **f683749c**)
//! are NEVER edited and NEVER cp'd (md5-asserted ladder-head AND ladder-tail
//! every build); the link4 build.sh heredoc RE-RIDES the 33 L master face
//! byte-EXACT (daq3 :202-:236 EOFDAQ face, misc3 :220-:249 per-link
//! isolation law) and the ladder's arm #3 appends the EXACTLY-2 DECL rows —
//! `daq_msg_get_pkthdr` decl (graft copy daq.h **:37**) +
//! `DAQ_PKT_FLAG_IGNORE_VLAN` define (**:38**, 0x40) — the ONLY 2 missing
//! face-sites (cd_vlan.cc :141:32 + :142:23 EXACTLY-2 error ladder receipt
//! E4_vlan_extface.txt). DAQ_PktHdr_t ALREADY rides the INHERITED graft-v2
//! daq_common.h :4 (`uint64_t flags = 0`, fead0027 NEVER re-authored) => the
//! extension is DECL-only, type face FREE. Landing face 39 L md5 **0f7016a6**
//! copy-LOCAL (Option-B pin; scratch daq.h.masterface parked). enum #2
//! (MAX_DAQ_VERDICT, 9b603f8f) NEVER landed HERE — the deferred q4
//! owns it (§5 graft-ext#1+hook same-row rule).
//!
//! THE WITNESS +1 FACE (the §9 honest flip of the zero-witness expectation):
//! the graft DECL puts `daq_msg_get_pkthdr(_daq_msg const*)` on the vlan .o
//! UNDEF face (nm_U vlan EXACTLY-1; cisco/fab 0). The L1 trial census dies
//! at EXACTLY-1 undefined => **witness_pkthdr.cc 21 L md5 3777a894 TRACKED**
//! (the 18i witness_daq precedent at a fraction of the size; the 1/4-size
//! pkthdr_witness_set_flags observable = tun_witness_set_mask/meta_enabled
//! law). STAGEABLES = 7 (the daq3 law, not the small4/erspan/link6 6-face);
//! the BACKBONE STAYS EXACTLY 10 (a backbone SYMBOL face, NEVER an ARRAY
//! face; wc-10 assert every build; the trio tunnel-U 0/0/0 NEVER force the
//! bypass witness — the 27+1 census stays the q4 banked receipt).
//!
//! THE EXT EVAL-ORDER HEADLINE (the vectors' non-decorative pin, PLAN §8):
//! `codec.lyr_len = sizeof(vlan::VlanTagHdr)` :139 SETS BEFORE the pkthdr
//! short-circuit `daq_msg_get_pkthdr(raw.daq_msg)` :141 -> `pkth->flags &
//! DAQ_PKT_FLAG_IGNORE_VLAN` :142 -> `return true` :143 — the early return
//! lands BEFORE the vid 0/4095 reserved check :145-:148 AND BEFORE the
//! `codec.proto_bits |= PROTO_BIT__VLAN` :150. The V5/V6 CONTRAST pins it:
//! `V vid0-ignore -> 1 lyr=4 next=2048 pb=0` NO EV line (flag ON) vs
//! `EV 116 130` + `V vid0 -> 1 lyr=4 pb=1024` (same bytes, flag OFF). The
//! pb 0-vs-1024 + EV-absence pair is THE order-site (`V order-site
//! ext:141->143-before-badvid:145->148 pb0-vs-1024 cite`).
//!
//! THE get_pkthdr SEAM — LEFT-OPEN (row 18i R1 cheat sheet, the daq3 SFDAQ
//! witness-mirror precedent): ground :141 reaches `daq_msg_get_pkthdr`
//! through the C fwd-declared `_daq_msg` (framework/codec.h :38 face ONLY
//! — the graft daq.h :37 decl rides the harness copy face). The Rust decode
//! takes the flags WORD as a seam parameter (`pkthdr_flags: u64`): the
//! witness-mirror face — harness `pkthdr_witness_set_flags` toggles the
//! INHERITED DAQ_PktHdr_t flags word (daq_common.h :4-:5) and the probe's
//! V5 arm feeds 0x40, every other arm 0. The REAL provider home stays
//! QUEUED for row 20 (real DAQ) which MUST re-cite the SDK header — NEVER
//! an invented cite; the flags value 0x40 rides the graft-v3 copy daq.h :38
//! define face (SYNTHETIC graft, NEVER ABI truth — the 18i law).
//!
//! TRUE-NAME face: the table symbol `const BaseApi* cd_vlan[]` :231 == the
//! FILE base (BUILDING_SO arm :228, feed &vlan_api.base :234) — the 18m
//! drift-pair contrast: NO drift discipline needed, the nm D-face EQUALITY
//! pin rides build.sh. Ladder entry "cd_vlan" RESIDENT codec_api.rs:130
//! (ground extern codec_api.cc :72, load :117) NEVER re-walked; THIS row
//! TURNS it loaded. mod arms ALL REAL (PLAN §8 nullptr-free tail face):
//! mod_ctor :191 / mod_dtor :194 -> api arms :217/:218 => faceA `vlan
//! mod_ctor=1 mod_dtor=1` (contrast 18m's pppencap nullptr pair, NEVER
//! carried); CodecApi ctor :197 / dtor :203 SET (faceA `ctor=1 dtor=1`).
//!
//! GETIDS is the unordered-SET face: `std::unordered_set<ProtocolId> id_set`
//! :103, insert ETHERTYPE_8021Q :104 (protocol_ids.h :149 0x8100 = 33024 —
//! ROW HOME const) + ETHERTYPE_8021AD :105 (:158 0x88A8 = 34984), then the
//! tpids stringstream loop :107-:112 (`ss >> std::setbase(0)` — "0x9100
//! 0x9200" default_tpids :49 = 37120/37376) casts each val `(ProtocolId)val`
//! :112. FACE-A pins the SET {33024, 34984, 37120, 37376} — the
//! unordered_set :103 iteration order is the libstdc++ bucket face, NEVER
//! pinned (PLAN §8 caution; the probe's print order is the harness RUNNER
//! face, not a port fact). sids: DECODE_BAD_VLAN = 130 RESIDENT
//! codec_module.rs :96 (h:79) — NEVER re-walked, ZERO new consts (PLAN §1
//! 6/6 resident census; the sids_tokens face vlan 3 rows/1 distinct token).
//!
//! vlan soft gates (probe_dec.cc census, all DEC vectors): len <
//! sizeof(vlan::VlanTagHdr) 4 (COPY-tree protocols/vlan.h :31-:32 two u16
//! fields, 50 L e68dcca9 fresh cp, arpa/inet-only :23) -> EV 130 :120-:123,
//! lyr NEVER set on the fail path (:123 return); the LLC branch `proto <=
//! ETHERNET_MAX_LEN_ENCAP` 1518 (:98 constexpr) -> next ETHERNET_LLC 263
//! (:134-:135, framework IMPORT protocol_id::ETHERNET_LLC); else `next =
//! (ProtocolId)proto` :137 CAST face (QinQ 0x88A8 = 34984 arm — the CAST
//! rides, never the enum); tpid ctor default :49 via `mod ? mod->get_tpids()
//! : default_tpids` :200 (the probe's ctor(nullptr) face). V log cc
//! :154-:171 + V encode cc :173-:185 cited-NEVER-called (EncState pulls
//! ip::IpApi — the eth/tun/erspan/ppp ZERO-encode-arms precedent), ported-
//! by-reading with cc cites, unit-mirrored in the row's parity test.

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData,
    CodecTable, EncState, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;

/// :38 `#define CD_VLAN_NAME "vlan"` (vectors_faceA LOAD/API/HELP name).
pub const CD_VLAN_NAME: &str = "vlan";
/// :39 `#define CD_VLAN_HELP "support for local area network"` (faceA HELP
/// line verbatim).
pub const CD_VLAN_HELP: &str = "support for local area network";

/// protocol_ids.h:149 `ETHERTYPE_8021Q = 0x8100` (= 33024, the SET member)
/// — the :104 insert. ROW HOME (MEASURED ZERO prior landed Rust face for
/// the 8021Q id; the landed dup-not-import family).
pub const ETHERTYPE_8021Q: ProtocolId = 0x8100;
/// protocol_ids.h:158 `ETHERTYPE_8021AD = 0x88A8` (= 34984) — the :105
/// insert AND the cast-landing value of the `V qinq` arm (the CAST at :137
/// rides, the enum value equals it — vectors pin the decimal, never a name).
pub const ETHERTYPE_8021AD: ProtocolId = 0x88A8;

/// :98 `constexpr unsigned int ETHERNET_MAX_LEN_ENCAP = 1518;` — the :134
/// LLC gate (`proto <= 1518`, ground comment :131-:133 "encapsulated LLC
/// layer" rides).
pub const ETHERNET_MAX_LEN_ENCAP: u16 = 1518;

/// decode_data.h:97 `#define PROTO_BIT__VLAN 0x000400` (= 1024, the
/// vectors' `pb=1024` face) — the :150 write. Row-scope home (MEASURED
/// ZERO prior landed Rust face for this bit — the landed dup-not-import
/// family; the framework census at codec.rs:478-:484 carries ONLY
/// IP6_EXT/ETH/ARP — this row NEVER re-touches framework/codec.rs).
pub const PROTO_BIT__VLAN: u32 = 0x000400;

/// protocols/vlan.h:29-:44 `struct VlanTagHdr` — TWO u16 fields
/// (`vth_pri_cfi_vlan` :31, `vth_proto` :32) => `sizeof` == **4**
/// (the :120 len gate; DISK arm `V len3` dies, 4-byte arms pass). Wire
/// accessors mirror the header's inline pair: priority = ntohs >> 13
/// (h:34-:35), cfi = (ntohs & 0x1000) >> 12 (h:36-:37), vid = ntohs &
/// 0x0FFF (h:38-:39), proto = ntohs(vth_proto) (h:40-:41). The header's
/// ONLY include is <arpa/inet.h> (h:23 — the header-symmetric arpa-only
/// duo with cisco_meta_data.h, PLAN §1); fresh cp 50 L md5 e68dcca9
/// (build.sh copy-tree md5 pin: the CP face, NEVER ABI law).
pub const VLAN_TAG_HDR_SIZE: u16 = 4;

#[inline]
fn vh_priority(pri_cfi_vlan: u16) -> u16 {
    pri_cfi_vlan >> 13 // vlan.h:34-35 ntohs(...) >> 13 (BE-read face below)
}
#[inline]
fn vh_cfi(pri_cfi_vlan: u16) -> u16 {
    (pri_cfi_vlan & 0x1000) >> 12 // vlan.h:36-37
}
#[inline]
fn vh_vid(pri_cfi_vlan: u16) -> u16 {
    pri_cfi_vlan & 0x0FFF // vlan.h:38-39 (the :146 vid operand)
}

/// graft-v3 copy daq.h :37 + :38 (the EXACTLY-2 DECL rows; landing face 39 L
/// md5 0f7016a6, copy-LOCAL — masters 73fdbc39/f683749c UNDISTURBED):
/// `#define DAQ_PKT_FLAG_IGNORE_VLAN 0x0000000000000040` — the :142 gate
/// value. SYNTHETIC graft face, NEVER ABI truth (row 20 re-cites the real
/// SDK header, the 18i law).
pub const DAQ_PKT_FLAG_IGNORE_VLAN: u64 = 0x0000_0000_0000_0040;

/// :49 `static const char* default_tpids = "0x9100 0x9200";` — the ctor
/// default face (:200 `mod ? mod->get_tpids() : default_tpids`; the probe's
/// ctor(nullptr) always lands HERE -> faceA GETIDS carries 37120/37376).
pub const DEFAULT_TPIDS: &str = "0x9100 0x9200";

/// :51-:57 `static const Parameter vlan_params[]` — ONE data row + the PT_MAX
/// terminator. The landed Parameter keeps name/ptype/deflt (range + help
/// slots omitted — the carried cd_esp.rs:89-:103 / codec_module.rs:350-:358
/// deviation): the :53 row name "extra_tpid_ether_types", PT_INT_LIST
/// (:53 — framework/parameter.rs Type::PtIntList), deflt == default_tpids
/// (:53 4th field); :56 the terminator row. The 3-arg module ctor :62 feeds
/// this table (BaseCodecModule::new_with_params).
pub const VLAN_PARAMS: [crate::framework::parameter::Parameter; 2] = [
    crate::framework::parameter::Parameter {
        name: Some("extra_tpid_ether_types"), // :53 1st field
        ptype: crate::framework::parameter::Type::PtIntList, // :53 PT_INT_LIST
        deflt: Some(DEFAULT_TPIDS), // :53 4th field (default_tpids)
    },
    crate::framework::parameter::Parameter {
        name: None, // :56 1st field nullptr
        ptype: crate::framework::parameter::Type::PtMax, // :56 PT_MAX
        deflt: None, // :56
    },
];

/// :43-:47 `static const RuleMap vlan_rules[]` — ONE data row + terminator;
/// sid RESIDENT DECODE_BAD_VLAN = 130 (codec_module.rs :96, h:79, NEVER
/// re-walked), msg byte-exact.
pub const VLAN_RULES: [RuleMap; 2] = [
    RuleMap { sid: CodecSid::DECODE_BAD_VLAN as u32, msg: Some("bad VLAN frame") }, // :45
    RuleMap { sid: 0, msg: None }, // :46 `{ 0, nullptr }`
];

/// :59-:74 `class VlanModule : public BaseCodecModule` — the :62 3-arg ctor
/// face (name/help + `vlan_params`); :64 `bool set(const char*, Value&,
/// SnortConfig*)` + :66-:67 get_rules + :69-:70 `get_tpids()` + the private
/// `tpids` string :73. The C std::string ownership folds onto a
/// caller-supplied string (the params are all static literals; the option-
/// parsing provider that FEEDS set() stays queued with the config layer —
/// the landed cd_esp.rs:133 `set` queued-provider precedent, NOT invented).
#[derive(Debug)]
pub struct VlanModule {
    pub base: BaseCodecModule,
    pub tpids: String,
}

impl VlanModule {
    /// :62 the ctor face + the :200 default face: with NO module the codec
    /// ctor falls back to `default_tpids` (the probe's ctor(nullptr) — faceA
    /// GETIDS rides this window).
    pub fn new() -> VlanModule {
        VlanModule {
            base: BaseCodecModule::new(CD_VLAN_NAME, CD_VLAN_HELP),
            tpids: DEFAULT_TPIDS.to_string(), // :49/:200 the nullptr-mod fallback face
        }
    }

    /// :76-:81 out-of-line set — `assert(v.is("extra_tpid_ether_types"))`
    /// :78 then `tpids = v.get_string()` :79, return true :80. The Value
    /// read-back lands as the name-match + string store (the esp queued-
    /// provider precedent — the option-parsing layer NEVER re-invented).
    pub fn set(&mut self, name: &str, value: &str) -> bool {
        if name != "extra_tpid_ether_types" {
            return false; // :78 the assert face — mismatch NEVER writes
        }
        self.tpids = value.to_string(); // :79
        true // :80
    }

    /// :66-:67 the get_rules override -> the stored table.
    pub fn get_rules(&self) -> &'static [RuleMap] {
        &VLAN_RULES
    }

    /// :69-:70 `const char* get_tpids() const { return tpids.c_str(); }`.
    pub fn get_tpids(&self) -> &str {
        &self.tpids
    }
}

impl Default for VlanModule {
    fn default() -> Self {
        Self::new()
    }
}

/// :83-:96 `class VlanCodec : public Codec` — get_protocol_ids :89 /
/// decode :90 / log :91 / encode :92 overrides + the `Codec(CD_VLAN_NAME)`
/// ctor name face :86 + stored `tpids` :95. Stack-owned Rust posture (18d).
#[derive(Debug)]
pub struct VlanCodec {
    pub tpids: String,
}

impl VlanCodec {
    /// :86 `VlanCodec(const char* s) : Codec(CD_VLAN_NAME), tpids(s)` —
    /// reached through the api ctor :197-:201 (`mod ? mod->get_tpids() :
    /// default_tpids`, the probe always passes nullptr).
    pub fn new(tpids: String) -> VlanCodec {
        VlanCodec { tpids }
    }

    /// :101-:116 out-of-line get_protocol_ids — THE unordered-SET face
    /// (module doc): id_set :103, insert 8021Q/8021AD :104-:105, then the
    /// `ss >> std::setbase(0)` loop :107-:112 casting `(ProtocolId)val`.
    /// The Rust face models the SET as an insert-if-absent Vec in C
    /// INSERTION order (dedup face kept); the libstdc++ bucket ITERATION
    /// order is NEVER ported (the probe's print order is the runner face —
    /// the parity test asserts the SET, PLAN §8). `std::setbase(0)` token
    /// grammar: 0x-prefixed hex, leading-0 octal, else decimal.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        let mut push_set = |id: ProtocolId| {
            if !v.contains(&id) {
                v.push(id); // :114-:115 `for (auto id : id_set) v.emplace_back(id)`
            }
        };
        push_set(ETHERTYPE_8021Q); // :104
        push_set(ETHERTYPE_8021AD); // :105

        for token in self.tpids.split_whitespace() {
            // :111 `while (ss >> val)` — the stream-exhaustion face; a
            // token that the C stream would REJECT stops the loop (setbase
            // semantics), never mid-list skips: honest stop-on-reject.
            let Some(val) = parse_setbase0_i32(token) else { break };
            push_set(val as ProtocolId); // :112 `(ProtocolId)val` u16 fold
        }
    }

    /// :118-:152 out-of-line decode — the soft gate, the LLC branch, THE
    /// graft-v3 ext short-circuit, the reserved-vid pair, the proto_bits
    /// tail. Statement order VERBATIM; the ext block's position relative
    /// to :145-:148 and :150 is the vectors' order-site pin. The third C
    /// param UNNAMED (:118 `DecodeData&`) = never-read (the pgm precedent).
    /// The `pkthdr_flags` seam: the witness-mirror face of
    /// `daq_msg_get_pkthdr(raw.daq_msg)->flags` :141 (module doc — the
    /// provider LEFT-OPEN, harness witness_pkthdr.cc feeds it).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: QueueSink<'_>,
        pkthdr_flags: u64,
    ) -> bool {
        // :120-:124 `raw.len < sizeof(vlan::VlanTagHdr)` (4, vlan.h) ->
        // codec_event DECODE_BAD_VLAN (:122 — sid 130 RESIDENT) + return
        // false :123 — the fail path NEVER touches lyr / next.
        if raw.len < u32::from(VLAN_TAG_HDR_SIZE) {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_BAD_VLAN as u32,
                &mut *sink,
            );
            return false; // :123
        }

        // :126-:127 the VlanTagHdr overlay + :129 `const uint16_t proto =
        // vh->proto();` — the VAR lands FIRST (the R6 eval-order rule:
        // every compound reads its vars before comparing).
        let proto = u16::from_be_bytes([raw.data[2], raw.data[3]]); // vlan.h:40-41

        // :131-:133 the ground comment (`encapsulated LLC layer` + the
        // geocities URL) rides. :134-:137 `proto <= ETHERNET_MAX_LEN_ENCAP`
        // -> ETHERNET_LLC (framework import, NEVER re-authored) else the
        // CAST face `(ProtocolId)proto`.
        if proto <= ETHERNET_MAX_LEN_ENCAP {
            codec.next_prot_id = protocol_id::ETHERNET_LLC; // :135
        } else {
            codec.next_prot_id = proto; // :137 the cast face (34984 qinq arm)
        }

        // :139 `codec.lyr_len = sizeof(vlan::VlanTagHdr);` — SETS BEFORE
        // the ext arm (the head of the order-site chain).
        codec.lyr_len = VLAN_TAG_HDR_SIZE; // :139

        // :141-:143 THE graft-v3 EXT block: `const DAQ_PktHdr_t* pkth =
        // daq_msg_get_pkthdr(raw.daq_msg);` (graft daq.h :37 DECL; the
        // witness-mirror seam feeds the flags word — module doc) `if
        // (pkth->flags & DAQ_PKT_FLAG_IGNORE_VLAN) return true;` — the var
        // first, then the bitwise test (eval-order rule; graft daq.h :38
        // 0x40 value). THE return :143 lands BEFORE the reserved-vid check
        // AND before the :150 proto_bits set (the V5/V6 pb 0-vs-1024 pin).
        let ignore_vlan = (pkthdr_flags & DAQ_PKT_FLAG_IGNORE_VLAN) != 0; // :142
        if ignore_vlan {
            return true; // :143
        }

        // :145 the ground comment (`Vlan IDs 0 and 4095 are reserved.`)
        // rides. :146-:148 `const uint16_t vid = vh->vid();` VAR first,
        // then `if (vid == 0 || vid == 4095) codec_event(codec,
        // DECODE_BAD_VLAN);` — SOFT: NO return (:148 falls through to the
        // tail; vectors `V vid0 -> 1 lyr=4 pb=1024` WITH EV 130).
        let vid = vh_vid(u16::from_be_bytes([raw.data[0], raw.data[1]])); // :146
        if vid == 0 || vid == 4095 {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_BAD_VLAN as u32,
                &mut *sink,
            ); // :148 (no return — the tail still lands)
        }

        // :150-:151 `codec.proto_bits |= PROTO_BIT__VLAN; return true;`
        // (PROTO_BIT__VLAN 0x000400 — framework const, decode_data.h :97).
        codec.proto_bits |= PROTO_BIT__VLAN; // :150
        true // :151
    }

    /// :154-:171 out-of-line log — cited-NEVER-called (the vectors' `V
    /// encode cc:173-:185 + V log cc:154-:171 cited-never-called` line),
    /// ported-by-reading with EVERY move cc-cited (the cd_udp.rs:964 /
    /// cd_vxlan.rs:176 TextLog-print seam precedent; the :155 lyr_len param
    /// UNNAMED — never-read posture): the :158 ntohs(vth_proto) + :159
    /// vid() + :160 priority() reads, the format :162-:165
    /// `"Priority:%d(0x%X) CFI:%d Vlan_ID:%d(0x%04X)"` (decimal %d /
    /// uppercase %X pair — the C #printf dialect kept), then the :167-:170
    /// Len-vs-Next branch on the SAME 1518 gate (the log's private clone of
    /// :134), `"  Len:0x%04X"` / `"  Next:0x%04X"`.
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        // :157 the VlanTagHdr overlay over raw_pkt.
        let pri_cfi_vlan = u16::from_be_bytes([raw_pkt[0], raw_pkt[1]]);
        let proto = u16::from_be_bytes([raw_pkt[2], raw_pkt[3]]); // :158
        let vid = vh_vid(pri_cfi_vlan);   // :159
        let priority = vh_priority(pri_cfi_vlan); // :160

        sink(format!(
            "Priority:{}(0x{:X}) CFI:{} Vlan_ID:{}(0x{:04X})", // :162-:163
            priority,
            priority,
            vh_cfi(pri_cfi_vlan), // :164 vh->cfi() arg
            vid,
            vid,
        ));

        if proto <= ETHERNET_MAX_LEN_ENCAP {
            sink(format!("  Len:0x{:04X}", proto)); // :168
        } else {
            sink(format!("  Next:0x{:04X}", proto)); // :170
        }
    }

    /// :173-:185 out-of-line encode — cited-NEVER-called (unit-mirrored in
    /// the parity test like 18l's TB / 18m's ppp encodes), statement order
    /// VERBATIM: allocate :176-:177 -> memcpy :179 -> NOT_SET x2 :181-:182
    /// -> true :184. The `Flow*` operand UNNAMED (:174) = dropped like
    /// every landed never-read pointer; NO header rewrite (the pppoe htons
    /// contrast — the honest copy-only face).
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // :176-:177 `if (!buf.allocate(raw_len)) return false;`
        if !buf.allocate(u32::from(raw_len)) {
            return false;
        }

        // :179 `memcpy(buf.data(), raw_in, raw_len)` — the landed Buffer
        // posture copies the window explicitly.
        let n = usize::from(raw_len);
        let head = buf.data_mut().expect("allocate(raw_len) just made size != 0");
        head[..n].copy_from_slice(&raw_in[..n]); // :179

        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET; // :181
        enc.next_proto = ip_protocol::PROTO_NOT_SET; // :182

        true // :184
    }
}

/// :107-:112 helper face — the C `stringstream >> std::setbase(0) >> int`
/// token semantics mirrored (0x hex / leading-0 octal / decimal; signed
/// int parse, the :112 cast truncates to ProtocolId). A malformed token
/// stops the C stream loop — mirrored via the decode-side stop-on-reject.
fn parse_setbase0_i32(token: &str) -> Option<i32> {
    let t = token.trim();
    if t.is_empty() {
        return None;
    }
    let (digits, radix) = if t.starts_with("0x") || t.starts_with("0X") {
        (&t[2..], 16)
    } else if t.starts_with('0') && t.len() > 1 {
        (&t[1..], 8)
    } else {
        (t, 10)
    };
    i32::from_str_radix(digits, radix).ok()
}

// :187-:189 the "api" separator banner rides. :191-:192 `static Module*
// mod_ctor() { return new VlanModule; }` + :194-:195 `mod_dtor` ride
// behavior-only cites (record mod slots SET — faceA `vlan mod_ctor=1
// mod_dtor=1`; the Rust mod face is VlanModule::new; the dtor folds onto
// the stack-owned drop, 18d posture). :197-:201 `static Codec*
// ctor(Module* m)` — the `mod ? mod->get_tpids() : default_tpids` :200
// fallback lands above (VlanModule::new / VlanCodec::new); :203-:204
// `static void dtor(Codec* cd)` SET.

/// :206-:226 `static const CodecApi vlan_api` — NAME/HELP slots :215/:216
/// land the :38/:39 macro faces; mod arms :217/:218 REAL (the mod_ctor
/// :191/mod_dtor :194 pair — the trio's nullptr-FREE mod face, PLAN §8,
/// contrast 18m pppencap NEVER carried); pinit :220 / pterm :221 / tinit
/// :222 / tterm :223 nullptr WITH the ground `// pinit`-style slot
/// comments; ctor :224 (`// ctor`) + dtor :225 (`// dtor`) SET.
pub const VLAN_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // :209
    size: CDAPI_SIZEOF_CODEC_API, // :210 sizeof(CodecApi)=112 (faceA size pin)
    api_version: CDAPI_VERSION,   // :211 1900547
    version: 0,                   // :212
    features: PLUGIN_SO_RELOAD,   // :213
    options: API_OPTIONS,         // :214
    name: CD_VLAN_NAME,           // :215 -> "vlan"
    help: CD_VLAN_HELP,           // :216
    mod_ctor: true,               // :217 SET (mod_ctor :191 REAL)
    mod_dtor: true,               // :218 SET (mod_dtor :194 REAL)
    pinit: false,                 // :220 nullptr // pinit
    pterm: false,                 // :221 nullptr // pterm
    tinit: false,                 // :222 nullptr // tinit
    tterm: false,                 // :223 nullptr // tterm
    ctor: true,                   // :224 SET  // ctor
    dtor: true,                   // :225 SET  // dtor
};

/// :228-:236 the hidden export, TRUE-NAME: `#ifdef BUILDING_SO` :228 / SO
/// arm :229 / the static-build `const BaseApi* cd_vlan[] =` :231 feeding
/// `&vlan_api.base` :234 + nullptr :235 (ONE feed — faceA `LOAD vlan` +
/// `LOADS 1`). nm: cd_vlan D EXACTLY-1 == FILE base (the TRUE-NAME EQUALITY
/// pin, build.sh — the 18m drift CONTRAST face). Ladder entry "cd_vlan"
/// RESIDENT codec_api.rs:130 (ground extern codec_api.cc :72, load :117)
/// NEVER re-touched — THIS row TURNS it loaded.
pub const CD_VLAN: CodecTable = &[&VLAN_API];

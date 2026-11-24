// Port of snort3 src/packet_io/packet_constraints.h 76 L (md5
// 447e814a551709a99ffa165e60bb7a41) + src/packet_io/packet_constraints.cc
// 331 L (md5 cb7b3584d08a22e01ae70d7b0b748124) @ fe29cbe (row 23e — THE
// SECOND REAL GATE ROW). "PacketConstraints filters packets/flows by
// ip_proto / ports / ips / tenants" — h :34 struct with a SetBits mask
// (h :36-:43) selecting which members the comparison gates on.
//
// THE GATE FACE (host-green @ the harness): the cc carries its OWN
// in-TU Catch block :143-:330 (#ifdef UNIT_TEST) = EXACTLY-3 TEST_CASE
// "[framework]" faces (:149 comparison / :205 matching / :297 flow
// matching — the [framework] tag face, cite-pinned EVERY build by the
// harness). The runner's tail is RUNNER-MEASURED (never typed here):
// the parity twin's GATE window carries the self-measured assert census
// that maps the runner face through translation.
//
// THE C++ -> Rust law banks on this row (each cited at KNOWN DEVIATIONS
// row 23e):
// - h :45-:51 the NSDMI ctor + the cc :61/:67 copy-ctor/operator= full
//   member copies: Rust lands Clone (the member-wise copy face) +
//   Default (the NSDMI cold defaults: ip_proto PROTO_NOT_SET :60,
//   set_bits 0 :66, match true :68, tenants empty :70) — the harness
//   FACE-A pins the default face; C's user copy-ctor NEVER deep-copies
//   beyond the members (no owning raw pointers here), so Clone IS the
//   byte face.
// - operator== (cc :84-:93): the MASKED comparison — set_bits first,
//   then per-bit gated members. Lands as a hand-written PartialEq (the
//   C != derive law; the derived derive would IGNORE the mask — wrong).
// - cc :32-:55 the anonymous-namespace match_constraints helper: file-
//   static scope -> a private fn on the value (the statics->fields
//   family law, here statics->methods; zero shared state, so NO
//   thread-unsafety question arises). std::find_if over tenants ->
//   iter().any (the C equality predicate, same first-match semantics
//   with an bool early-out — the ONLY observable is found/not-found,
//   pinned by the P-legs).
// - the Packet/Flow OWNER seam (row 20 open): cc :111-:115 reads
//   p.ptrs.ip_api.get_src()/get_dst(), p.ptrs.sp/dp, p.pkth->tenant_id;
//   cc :129 f.ip_proto ? f.ip_proto : f.key->ip_protocol + f.client_ip
//   /server_ip/client_port/server_port + f.key->tenant_id. The 22b
//   tracer Packet-MIRROR precedent re-rides: the full snort::Packet /
//   snort::Flow owners NEVER land before row 20 — the port carries
//   row-scoped READ faces (ConstraintPacketFace / ConstraintFlowFace)
//   citing the exact C member faces; the harness mirrors the C scaffol-
//   ding (Packet ctor/dtor + the Flow ctor + the two flow-data member
//   lives) to keep the C side REAL at the gate/DEC link.
// - has_ip (cc :100 via packet.h :193 -> ip.h :83 is_ip4() or is_ip6():
//   IAT_4|IAT_6 TRUE, IAT_NONE/IAT_DATA FALSE — the iat gate lands on
//   the landed IpApiLite from detection/rtn_checks.rs (one-home REUSE,
//   NEVER forked): the has_ip test is iat==IAT_4||iat==IAT_6 cited
//   verbatim (the DATA type has no IP header — the C face).
// - #ifndef DISABLE_TENANT_ID (cc :136-:140): NEVER defined anywhere in
//   this repo/host build (the harness greps the ground definition face
//   find-0): the f.key->tenant_id arm is LIVE, the 0-arm dead; the
//   port rides the tenant_id arm unconditionally — cited, the ifdef
//   face pinned by the harness ground grep.
// - IpProtocol: the landed codec ip_protocol home (PROTO_NOT_SET==255,
//   TCP==6, UDP==17, ICMPV4==1) — REUSE, NEVER re-forked.

use crate::detection::rtn_checks::{IpApiLite, IAT_4, IAT_6};
use crate::framework::codec::ip_protocol::{IpProtocol, PROTO_NOT_SET};
use crate::sfip::sf_ip::SfIp;

/// h :36-:43 `enum SetBits : uint8_t` — the comparison mask. Values are
/// the C enumerators VERBATIM (IP_PROTO=1, SRC_IP=1<<1, DST_IP=1<<2,
/// SRC_PORT=1<<3, DST_PORT=1<<4, TENANT=1<<5). Rust mask arithmetic
/// rides u8 (the C :uint8_t width face; (uint8_t)~(SetBits::DST_IP) and
/// (uint8_t)-1 in the gate cases exercise the width face — the harness
/// FACE-A pins the six decimals).
pub mod set_bits {
    pub const IP_PROTO: u8 = 1;      // h :37
    pub const SRC_IP: u8 = 1 << 1;   // h :38
    pub const DST_IP: u8 = 1 << 2;   // h :39
    pub const SRC_PORT: u8 = 1 << 3; // h :40
    pub const DST_PORT: u8 = 1 << 4; // h :41
    pub const TENANT: u8 = 1 << 5;   // h :42
}

/// The row-scoped packet READ face (the packet_match arm, cc :100-:115):
/// ptrs.ip_api (decode_data.h:176, the landed IpApiLite — iat gate =
/// ip.h is_ip :83), ip_proto_next (packet.h :144 via getter :278),
/// ptrs.sp/dp (decode_data.h:170-:171), and pkth->tenant_id
/// (packet.h:160 pkth -> the REAL SDK DAQ_PktHdr_t tenant_id u32; the
/// 23a-23c re-cite law: pkthdr 56B, tenant_id @48 on the real face —
/// row 20 owns the carrier; here the plain field the read touches).
/// cite-never-carry: the full snort::Packet (ctor/dtor, has_ip via the
/// Layer world, the ip_api union) NEVER lands (the 22b mirror law).
#[derive(Debug)]
pub struct ConstraintPacketFace<'a> {
    pub ip_api: &'a IpApiLite, // cc :111-:112 get_src/get_dst + :100 has_ip
    pub ip_proto_next: IpProtocol, // cc :108 p.get_ip_proto_next()
    pub sp: u16,               // cc :113 p.ptrs.sp
    pub dp: u16,               // cc :114 p.ptrs.dp
    pub tenant_id: u32,        // cc :115 p.pkth->tenant_id (REAL u32 face)
}

/// The row-scoped flow READ face (the flow_match arms, cc :129/:134-:137):
/// f.ip_proto (flow.h :592 uint8_t — session-side, 0 = NOT set, the
/// tri-state the :129 fallback reads), f.key->ip_protocol (flow_key.h
/// :66 uint8_t) + f.key->tenant_id (flow_key.h :58 uint32_t, the LIVE
/// #ifndef DISABLE_TENANT_ID arm), f.client_ip/server_ip (flow.h
/// :523-:524 SfIp), f.client_port/server_port (flow.h :586-:587).
/// The full snort::Flow owner (virtual dtor + session machinery, h
/// :181-:184) NEVER lands; the harness mirrors its ctor face so the C
/// side stays REAL (the 22b scaffolding law extends to the flow side).
#[derive(Debug, Default)]
pub struct ConstraintFlowFace {
    pub ip_proto: u8,           // flow.h :592 (0 = session NEVER set it)
    pub key_ip_protocol: u8,    // flow_key.h :66 (the fallback source)
    pub key_tenant_id: u32,     // flow_key.h :58 (LIVE ifdef arm)
    pub client_ip: SfIp,        // flow.h :523
    pub server_ip: SfIp,        // flow.h :524
    pub client_port: u16,       // flow.h :586
    pub server_port: u16,       // flow.h :587
}

/// h :34-:71 struct PacketConstraints — the public value. Members
/// verbatim (h :60-:70): ip_proto/src_port/dst_port/src_ip/dst_ip/
/// set_bits/match/tenants. C's explicit copy-ctor (cc :61-:65) and
/// copy-assign (cc :67-:82, the self-assign guard :69-:70 are no-ops
/// for member-wise copy) land as #[derive(Clone)]: identical member-wise
/// copy semantics, the self-guard observable-free (cited deviation: the
/// guard NEVER changes the result face).
#[derive(Debug, Clone)]
pub struct PacketConstraints {
    pub ip_proto: IpProtocol, // :60 NSDMI PROTO_NOT_SET
    pub src_port: u16,        // :61
    pub dst_port: u16,        // :62
    pub src_ip: SfIp,         // :63
    pub dst_ip: SfIp,         // :64
    pub set_bits: u8,         // :66 NSDMI 0
    pub r#match: bool,        // :68 NSDMI true (`match` Rust keyword -> r#match, the jsnorm law)
    pub tenants: Vec<u32>,    // :70 std::vector<uint32_t>
}

impl Default for PacketConstraints {
    /// h :45 `PacketConstraints() = default` — the NSDMI cold face:
    /// ip_proto PROTO_NOT_SET(255), ports/ip addrs zeroed, set_bits 0,
    /// match TRUE (:68 default true — the gate "matching" case :207
    /// relies on it), tenants empty. FACE-A pins every decimal.
    fn default() -> Self {
        PacketConstraints {
            ip_proto: PROTO_NOT_SET, // h :60 (codec home REUSE, NEVER re-forked)
            src_port: 0,             // h :61
            dst_port: 0,             // h :62
            src_ip: SfIp::new(),     // h :63 SfIp() zero face
            dst_ip: SfIp::new(),     // h :64
            set_bits: 0,             // h :66
            r#match: true,           // h :68
            tenants: Vec::new(),     // h :70
        }
    }
}

/// the no-tenants ctor arm (h :48 default arg `tenants = {}`): the C
/// default-arg call shape lands as this 7-arg fn (the clippy
/// too_many_arguments threshold law: the 8th param rides the builder
/// leg `with_tenants` — SAME member face, C's init-list order pinned;
/// the h :46-:51 one-ctor face is cited, the arg-split is a Rust-shape
/// ONLY deviation, never semantic: members are value-assigned).
pub fn new(
    ip_proto: IpProtocol,
    src_port: u16,
    dst_port: u16,
    src_ip: SfIp,
    dst_ip: SfIp,
    set_bits: u8,
    r#match: bool,
) -> PacketConstraints {
    PacketConstraints {
        ip_proto, src_port, dst_port, src_ip, dst_ip, set_bits, r#match,
        tenants: Vec::new(), // h :48 default arg face
    }
}

/// the tenants arm (the h :48 8th arg + the gate's tenants1/tenants2
/// legs cc :187-:200): the full ctor member face with the explicit
/// tenants vector (h :70 + init-list :50).
impl PacketConstraints {
    pub fn with_tenants(mut self, tenants: Vec<u32>) -> Self {
        self.tenants = tenants; // cc :64/:79 the tenants copy face (Clone)
        self
    }

    /// cc :84-:93 operator== — the MASKED equality. C order VERBATIM:
    /// set_bits compared FIRST (:86), then each gated member armed ONLY
    /// when its bit rides (:87-:92). The SfIp legs use C's `sip == cs
    /// .src_ip` — sf_ip.h :91/:458 `operator==` -> fast_equals_raw :434
    /// (the family-fold face: AF_INET needs AF_INET + the 4-byte v4
    /// fold; AF_INET6 the 16-byte fold; ELSE FALSE — the two-unsolved +
    /// cross-family legs are FALSE, NEVER a raw-blob compare). The
    /// landed SfIp derive is STRUCTURAL (ip8+family) which OVER-matches
    /// a v4-mapped-payload drift: the landed FAST home's
    /// fast_equals_raw is the C-exact operator== face and rides HERE
    /// directly (one-home REUSE cited; NEVER a forked compare). The
    /// tenants leg (:92) is the vector ==. NO derived PartialEq/Eq on
    /// PacketConstraints (the mask law: a derive would IGNORE set_bits).
    pub fn eq_masked(&self, other: &PacketConstraints) -> bool {
        self.set_bits == other.set_bits                                        // :86
            && (self.set_bits & set_bits::IP_PROTO == 0                        // :87
                || self.ip_proto == other.ip_proto)
            && (self.set_bits & set_bits::SRC_PORT == 0                        // :88
                || self.src_port == other.src_port)
            && (self.set_bits & set_bits::DST_PORT == 0                        // :89
                || self.dst_port == other.dst_port)
            && (self.set_bits & set_bits::SRC_IP == 0                          // :90
                || self.src_ip.fast_equals_raw(&other.src_ip))
            && (self.set_bits & set_bits::DST_IP == 0                          // :91
                || self.dst_ip.fast_equals_raw(&other.dst_ip))
            && (self.set_bits & set_bits::TENANT == 0                          // :92
                || self.tenants == other.tenants)
    }

    /// cc :34-:55 the anon-namespace match_constraints (the file-static
    /// scope -> private assoc fn law; ZERO shared state). Arms VERBATIM:
    /// :40-:43 the four masked gates (port/port/ip/ip — AND chain),
    /// :45 the TENANT gate NECESSITATES all four being TRUE first (the
    /// `res and` short-circuit face — a failed masked gate NEVER reaches
    /// the tenant list scan; observable-identical but the shape rides),
    /// then: TENANT bit AND tenant_id != 0 AND non-empty tenants ->
    /// scan (std::find_if :47-:48), MISS -> false (:50-:51). A zero
    /// tenant_id SKIPS the scan (:45 `and tenant_id`) — the anonymous
    /// tenant face. tenents-empty SKIPS (:45 `!cs.tenants.empty()`).
    fn match_constraints(
        &self,
        sip: &SfIp,
        dip: &SfIp,
        sport: u16,
        dport: u16,
        tenant_id: u32,
    ) -> bool {
        let res = (self.set_bits & set_bits::SRC_PORT == 0 || sport == self.src_port)   // :40
            && (self.set_bits & set_bits::DST_PORT == 0 || dport == self.dst_port)      // :41
            // :42/:43 the C `sip == cs.src_ip` leg rides fast_equals_raw
            // (the operator== body, sf_ip.h :458): an UNSET family on
            // the constraint side with the gate bit armed is FALSE on
            // the C face (fast_equals_raw else-arm) — the structural
            // derive would OVER-match two zero-byte unset SfIp: NEVER.
            && (self.set_bits & set_bits::SRC_IP == 0 || sip.fast_equals_raw(&self.src_ip))
            && (self.set_bits & set_bits::DST_IP == 0 || dip.fast_equals_raw(&self.dst_ip));

        if res
            && (self.set_bits & set_bits::TENANT != 0)   // :45
            && tenant_id != 0
            && !self.tenants.is_empty()
        {
            // :47-:51 std::find_if equality lambda -> find (the first-
            // match scan; only the found/miss face is observable)
            if !self.tenants.contains(&tenant_id) { // find_if :49-:51 == the slice-contains face (clippy-clean, same semantics)
                return false;
            }
        }

        res // :54
    }

    /// cc :95-:119 packet_match: :97 `!match` -> false (the h :68 gate —
    /// the SAME named member, r#match); :100-:106 no-IP packet: ANY of
    /// the five IP-class bits armed -> false, else TRUE (the TENANT bit
    /// ALONE passes the no-IP face — the bit-set is
    /// IP_PROTO|SRC_PORT|DST_PORT|SRC_IP|DST_IP, TENANT ABSENT :102,
    /// cited the exact face); :108 IP_PROTO vs ip_proto_next; then
    /// :117-:118 the TWO-ORDER match_constraints (forward OR swapped —
    /// the bidirectional face a DIRECT swapped call NEVER satisfies,
    /// pinned by the gate's backwards SECTION cc :240-:255 which calls
    /// the helper with swapped args and expects false at the helper
    /// level vs the packet_match OR).
    pub fn packet_match(&self, p: &ConstraintPacketFace) -> bool {
        if !self.r#match {                                        // :97
            return false;
        }

        // :100 has_ip = ip.h :83 is_ip4() or is_ip6() (IAT_4|IAT_6;
        // IAT_NONE + IAT_DATA FALSE — landed IpApiLite.iat gate)
        let has_ip = p.ip_api.iat == IAT_4 || p.ip_api.iat == IAT_6;
        if !has_ip {                                              // :100
            // :102 the five-bit set (TENANT NEVER in this mask — the C
            // face: a TENANT-only constraint on a non-IP packet PASSES)
            let ip_class = set_bits::IP_PROTO
                | set_bits::SRC_PORT
                | set_bits::DST_PORT
                | set_bits::SRC_IP
                | set_bits::DST_IP;
            if self.set_bits & ip_class != 0 {
                return false; // :103
            } else {
                return true; // :105
            }
        }

        if (self.set_bits & set_bits::IP_PROTO) != 0 && p.ip_proto_next != self.ip_proto {
            return false; // :108-:109
        }

        // :111-:115 the reads: C's get_src()/get_dst() (ip.h :93/:96)
        // return &src/&dst when the union type is armed — has_ip rode
        // true above the same gate, so the landed IpApiLite fields are
        // the direct faces (the C nullptr face NEVER surfaces under
        // has_ip).
        let sip = &p.ip_api.src; // :111 *p.ptrs.ip_api.get_src()
        let dip = &p.ip_api.dst; // :112 *p.ptrs.ip_api.get_dst()
        let sp = p.sp;           // :113 p.ptrs.sp
        let dp = p.dp;           // :114 p.ptrs.dp

        // :117-:118 the TWO-ORDER face: forward (`or`) swapped. The C
        // swapped call NEVER re-checks the IP_PROTO arm (:108 already
        // ran once); the swap re-runs ONLY match_constraints — the byte
        // shape below is EXACTLY that (helper-level swap, same tenant).
        self.match_constraints(sip, dip, sp, dp, p.tenant_id)         // :117
            || self.match_constraints(dip, sip, dp, sp, p.tenant_id)  // :118
    }

    /// cc :121-:141 flow_match: :123 `!match` -> false; :129 the
    /// ip_proto FALLBACK law (session value wins if non-zero: icmp/ip
    /// sessions NEVER set it, per the :126-:128 comment); :131 the
    /// IP_PROTO bit vs IpProtocol(proto) != ip_proto; :134-:137 the
    /// match_constraints leg on client/server (NO swapped order here —
    /// the flow face is DIRECTIONAL, unlike packet_match, cited by the
    /// gate's flow case riding a single order) + the LIVE key->tenant_id
    /// arm (cc :136-:140 #ifndef DISABLE_TENANT_ID — NEVER defined on
    /// this ground; the 0-arm dead, cited).
    pub fn flow_match(&self, f: &ConstraintFlowFace) -> bool {
        if !self.r#match {                                          // :123
            return false;
        }

        // :129 const uint8_t proto = f.ip_proto ? f.ip_proto : f.key->ip_protocol
        let proto = if f.ip_proto != 0 { f.ip_proto } else { f.key_ip_protocol };

        if (self.set_bits & set_bits::IP_PROTO) != 0 && (proto as IpProtocol) != self.ip_proto {
            return false; // :131-:132
        }

        // :134-:137 single-order match_constraints (client->server)
        self.match_constraints(
            &f.client_ip,
            &f.server_ip,
            f.client_port,
            f.server_port,
            f.key_tenant_id, // :137 the LIVE key tenant arm
        )
    }
}

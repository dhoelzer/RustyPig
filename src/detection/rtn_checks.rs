// Literal port of detection/rtn_checks.cc (rule-header check function arms).
//
// The C functions take (Packet*, RuleTreeNode*, RuleFpList*, int). Packet
// itself is NOT ported yet (its real ctor drags DAQ + flow; framework/
// decode_data + the decode layer land with the codecs rows), so the checks
// run against PacketLite below, which mirrors EXACTLY the fields rtn_checks
// reads: p->proto_bits, p->ptrs.sp, p->ptrs.dp, p->ptrs.ip_api.get_src()/
// get_dst() (IpApi subset: IAT_NONE gate + stored src/dst per REAL
// IpApi::set(const SfIp&, const SfIp&), ip.cc lines 58-64).
//
// The C linked-list RuleFpList chain is a Vec<RuleFpList> in treenodes.rs;
// call_head() is the C "fp_list->RuleHeadFunc(...)" dispatch, and each arm
// recursing to "fp_list->next->RuleHeadFunc(...)" is call_head(i + 1).
// Production entry mirrors fp_detect.cc:355:
//   rtn->rule_func->RuleHeadFunc(p, rtn, rtn->rule_func, check_ports)

use crate::detection::treenodes::{RuleFpList, RuleFuncId, RuleTreeNode};
use crate::ports::port_var_table::PoHandle;
use crate::sfip::sf_ip::SfIp;
use crate::sfip::sf_ipvar::{sfvar_ip_in, SfIpVar};
use crate::target_based::snort_protocols::SNORT_PROTO_MAX;

// framework/decode_data.h PROTO_BIT__* (lines 84-96)
pub const PROTO_BIT__NONE: u32 = 0x000000;
pub const PROTO_BIT__IP: u32 = 0x000001;
pub const PROTO_BIT__TCP: u32 = 0x000002;
pub const PROTO_BIT__UDP: u32 = 0x000004;
pub const PROTO_BIT__ICMP: u32 = 0x000008;
pub const PROTO_BIT__USER: u32 = 0x000010;
pub const PROTO_BIT__FILE: u32 = 0x000020;
pub const PROTO_BIT__PDU: u32 = 0x000040;
pub const PROTO_BIT__TEREDO: u32 = 0x000080;
pub const PROTO_BIT__GTP: u32 = 0x000100;
pub const PROTO_BIT__MPLS: u32 = 0x000200;

// IpApi subset (protocols/ip.h class; only the type gate + src/dst that the
// checks reach). IAT ordering kept verbatim: { IAT_NONE, IAT_4, IAT_6, IAT_DATA }.
pub const IAT_NONE: u8 = 0;
pub const IAT_4: u8 = 1;
pub const IAT_6: u8 = 2;
pub const IAT_DATA: u8 = 3;

#[derive(Debug, Default)]
pub struct IpApiLite {
    pub iat: u8,
    pub src: SfIp,
    pub dst: SfIp,
}

impl IpApiLite {
    /// void IpApi::set(const SfIp& sip, const SfIp& dip) (ip.cc:58):
    /// type = IAT_DATA; src = sip; dst = dip; iph = nullptr.
    pub fn set(&mut self, sip: SfIp, dip: SfIp) {
        self.iat = IAT_DATA;
        self.src = sip;
        self.dst = dip;
    }
    /// inline const SfIp* get_src() const
    /// { return (type != IAT_NONE) ? &src : nullptr; }
    pub fn get_src(&self) -> Option<&SfIp> {
        if self.iat != IAT_NONE {
            Some(&self.src)
        } else {
            None
        }
    }
    pub fn get_dst(&self) -> Option<&SfIp> {
        if self.iat != IAT_NONE {
            Some(&self.dst)
        } else {
            None
        }
    }
}

/// Mock-packet stand-in: only the fields rtn_checks.cc touches.
#[derive(Debug, Default)]
pub struct PacketLite {
    pub proto_bits: u32,
    pub sp: u16,
    pub dp: u16,
    pub ip_api: IpApiLite,
}

// rtn_checks.cc:43-47
const CHECK_SRC_IP: i32 = 0x01;
const CHECK_DST_IP: i32 = 0x02;
const INVERSE: i32 = 0x04;
const CHECK_SRC_PORT: i32 = 0x08;
const CHECK_DST_PORT: i32 = 0x10;

/// static int CheckAddrPort(sfip_var_t* rule_addr, const PortObject* po,
///     Packet* p, uint32_t flags, int mode)
fn check_addr_port(
    rule_addr: &Option<SfIpVar>,
    po: &Option<PoHandle>,
    p: &PacketLite,
    flags: u8,
    mode: i32,
) -> i32 {
    let pkt_addr: Option<&SfIp>;
    let pkt_port: u16;
    let any_port_flag: u8;

    /* set up the packet particulars */
    if mode & CHECK_SRC_IP != 0 {
        pkt_addr = p.ip_api.get_src();
        pkt_port = p.sp;

        if mode & INVERSE != 0 {
            any_port_flag = flags & RuleTreeNode::ANY_DST_PORT;
        } else {
            any_port_flag = flags & RuleTreeNode::ANY_SRC_PORT;
        }
    } else {
        pkt_addr = p.ip_api.get_dst();
        pkt_port = p.dp;

        if mode & INVERSE != 0 {
            any_port_flag = flags & RuleTreeNode::ANY_SRC_PORT;
        } else {
            any_port_flag = flags & RuleTreeNode::ANY_DST_PORT;
        }
    }

    let mut ip_match = false;
    if let Some(var) = rule_addr {
        // C: sfvar_ip_in(rule_addr, pkt_addr); false on null pkt_addr too
        // (upstream sfvar_ip_in: if (!var || !ip) return false).
        if let Some(ip) = pkt_addr {
            ip_match = sfvar_ip_in(var, ip);
        }
    }
    // bail:
    if !ip_match {
        return 0;
    }

    /* if the any port flag is up, we're all done (success) */
    if any_port_flag != 0 {
        return 1;
    }

    if mode & (CHECK_SRC_PORT | CHECK_DST_PORT) == 0 {
        return 1;
    }

    /* check the packet port against the rule port */
    /* if the exception flag isn't up, fail */
    match po {
        Some(h) => h.borrow().has_port(pkt_port as i32),
        None => 0, // C PortObjectHasPort: if ( !po ) return 0;
    }
}

// #define CHECK_ADDR_SRC_ARGS(x) (x)->src_portobject
// #define CHECK_ADDR_DST_ARGS(x) (x)->dst_portobject

/// int CheckBidirectional(Packet* p, RuleTreeNode* rtn_idx, RuleFpList*, int)
pub fn check_bidirectional(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    _chain: &[RuleFpList],
    _i: usize,
    check_ports: i32,
) -> i32 {
    if check_addr_port(
        &rtn_idx.sip,
        &rtn_idx.src_portobject,
        p,
        rtn_idx.flags,
        CHECK_SRC_IP | (if check_ports != 0 { CHECK_SRC_PORT } else { 0 }),
    ) != 0
    {
        if check_addr_port(
            &rtn_idx.dip,
            &rtn_idx.dst_portobject,
            p,
            rtn_idx.flags,
            CHECK_DST_IP | (if check_ports != 0 { CHECK_DST_PORT } else { 0 }),
        ) == 0
        {
            if check_addr_port(
                &rtn_idx.dip,
                &rtn_idx.dst_portobject,
                p,
                rtn_idx.flags,
                CHECK_SRC_IP | INVERSE | (if check_ports != 0 { CHECK_SRC_PORT } else { 0 }),
            ) != 0
            {
                if check_addr_port(
                    &rtn_idx.sip,
                    &rtn_idx.src_portobject,
                    p,
                    rtn_idx.flags,
                    CHECK_DST_IP | INVERSE | (if check_ports != 0 { CHECK_DST_PORT } else { 0 }),
                ) == 0
                {
                    return 0;
                }
            } else {
                return 0;
            }
        }
    } else if check_addr_port(
        &rtn_idx.dip,
        &rtn_idx.dst_portobject,
        p,
        rtn_idx.flags,
        CHECK_SRC_IP | INVERSE | (if check_ports != 0 { CHECK_SRC_PORT } else { 0 }),
    ) != 0
    {
        if check_addr_port(
            &rtn_idx.sip,
            &rtn_idx.src_portobject,
            p,
            rtn_idx.flags,
            CHECK_DST_IP | INVERSE | (if check_ports != 0 { CHECK_DST_PORT } else { 0 }),
        ) == 0
        {
            return 0;
        }
    } else {
        return 0;
    }

    // C quirk pinned by RC922 icmp (tcp rule, icmp packet -> cp1=1): this
    // function's RuleFpList* param is unnamed/unused, so on full match the
    // body ends `return 1;` (rtn_checks.cc:149) and the Proto/End nodes
    // linked AFTER the bidirectional node NEVER run (had Proto run, the
    // mask AND would have returned 0 for the icmp packet).
    1
}

/// int CheckSrcIP(...) -- match -> next arm; else 0.
pub fn check_src_ip(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    chain: &[RuleFpList],
    i: usize,
    check_ports: i32,
) -> i32 {
    // C: sfvar_ip_in(rtn_idx->sip, p->ptrs.ip_api.get_src())
    let hit = match (&rtn_idx.sip, p.ip_api.get_src()) {
        (Some(var), Some(ip)) => sfvar_ip_in(var, ip),
        _ => false,
    };
    if hit {
        /* the packet matches this test, proceed to the next test */
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    /* return 0 on a failed test */
    0
}

pub fn check_dst_ip(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    chain: &[RuleFpList],
    i: usize,
    check_ports: i32,
) -> i32 {
    let hit = match (&rtn_idx.dip, p.ip_api.get_dst()) {
        (Some(var), Some(ip)) => sfvar_ip_in(var, ip),
        _ => false,
    };
    if hit {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    0
}

pub fn check_src_port_equal(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    chain: &[RuleFpList],
    i: usize,
    check_ports: i32,
) -> i32 {
    /* Check if attributes provided match earlier */
    if check_ports == 0 {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    let hit = match &rtn_idx.src_portobject {
        Some(h) => h.borrow().has_port(p.sp as i32) != 0,
        None => false, // C PortObjectHasPort null -> 0
    };
    if hit {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    0
}

pub fn check_src_port_not_eq(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    chain: &[RuleFpList],
    i: usize,
    check_ports: i32,
) -> i32 {
    /* Check if attributes provided match earlier */
    if check_ports == 0 {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    let hit = match &rtn_idx.src_portobject {
        Some(h) => h.borrow().has_port(p.sp as i32) != 0,
        None => false,
    };
    if !hit {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    0
}

pub fn check_dst_port_equal(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    chain: &[RuleFpList],
    i: usize,
    check_ports: i32,
) -> i32 {
    /* Check if attributes provided match earlier */
    if check_ports == 0 {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    let hit = match &rtn_idx.dst_portobject {
        Some(h) => h.borrow().has_port(p.dp as i32) != 0,
        None => false,
    };
    if hit {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    0
}

pub fn check_dst_port_not_eq(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    chain: &[RuleFpList],
    i: usize,
    check_ports: i32,
) -> i32 {
    /* Check if attributes provided match earlier */
    if check_ports == 0 {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    let hit = match &rtn_idx.dst_portobject {
        Some(h) => h.borrow().has_port(p.dp as i32) != 0,
        None => false,
    };
    if !hit {
        return call_head(p, rtn_idx, chain, i + 1, check_ports);
    }
    0
}

// cppcheck-suppress constParameterPointer ; preserve the public declaration and ABI
pub fn check_proto(
    p: &PacketLite,
    rtn_idx: &RuleTreeNode,
    _chain: &[RuleFpList],
    _i: usize,
    check_ports: i32,
) -> i32 {
    if check_ports == 0 {
        return 1; // ignore proto when ignoring ports
    }

    assert!((rtn_idx.snort_protocol_id as usize) < SNORT_PROTO_MAX as usize);

    const PROTO_BITS: [u32; 6] = [
        /* n/a */ PROTO_BIT__NONE,
        /* ip */ PROTO_BIT__IP | PROTO_BIT__TCP | PROTO_BIT__UDP, /* legacy */
        /* icmp */ PROTO_BIT__ICMP,
        /* tcp */ PROTO_BIT__TCP | PROTO_BIT__PDU,
        /* udp */ PROTO_BIT__UDP,
        /* file */ PROTO_BIT__FILE | PROTO_BIT__PDU,
    ];
    // SNORT_PROTO_ to PROTO_BIT__* -- C returns the raw AND (not
    // normalized to 1); pinned: tcp-rule/tcp-pkt eval cp1=2, ip-legacy=4,
    // file=32, tcp-rule/pdu-pkt=64.
    (PROTO_BITS[rtn_idx.snort_protocol_id as usize] & p.proto_bits) as i32
}

/// int RuleListEnd(Packet*, RuleTreeNode*, RuleFpList*, int)
pub fn rule_list_end(
    _p: &PacketLite,
    _rtn: &RuleTreeNode,
    _chain: &[RuleFpList],
    _i: usize,
    _check_ports: i32,
) -> i32 {
    1
}

/// C: fp_list->RuleHeadFunc(p, rtn_idx, fp_list, check_ports) -- dispatch
/// one chain node. C's hand-linked RuleFpList chain is our Vec slice.
pub fn call_head(
    p: &PacketLite,
    rtn: &RuleTreeNode,
    chain: &[RuleFpList],
    i: usize,
    check_ports: i32,
) -> i32 {
    match chain[i].rule_head_func {
        RuleFuncId::ListEnd => rule_list_end(p, rtn, chain, i, check_ports),
        RuleFuncId::Bidirectional => check_bidirectional(p, rtn, chain, i, check_ports),
        RuleFuncId::Proto => check_proto(p, rtn, chain, i, check_ports),
        RuleFuncId::SrcIp => check_src_ip(p, rtn, chain, i, check_ports),
        RuleFuncId::DstIp => check_dst_ip(p, rtn, chain, i, check_ports),
        RuleFuncId::SrcPortEqual => check_src_port_equal(p, rtn, chain, i, check_ports),
        RuleFuncId::DstPortEqual => check_dst_port_equal(p, rtn, chain, i, check_ports),
        RuleFuncId::SrcPortNotEq => check_src_port_not_eq(p, rtn, chain, i, check_ports),
        RuleFuncId::DstPortNotEq => check_dst_port_not_eq(p, rtn, chain, i, check_ports),
    }
}

/// Production entry (fp_detect.cc:355). C asserts nothing here: an RTN
/// that reached an OTN always went through SetupRTNFuncList (chain never
/// empty); slicing chain[0] in Rust panics where C would deref null.
pub fn eval_rule(p: &PacketLite, rtn: &RuleTreeNode, check_ports: i32) -> i32 {
    call_head(p, rtn, rtn.rule_func.as_slice(), 0, check_ports)
}

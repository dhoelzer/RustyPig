// Port of snort3 src/detection/treenodes.{h,cc}: the RuleTreeNode /
// OptTreeNode structs, RuleHeader (signature.h), SigInfo /
// SignatureServiceInfo, ListHead / RuleListNode, RuleFpList / OptFpList
// and AddOptFuncToList. Literal transcription (field order, flag bit
// values, inline accessors; C member names spelled exactly as upstream,
// including its camel/snake mix: otnRefCount, evalCount, ruleIndex,
// num_detection_opts, sigInfo). C raw pointers become Rc<RefCell<T>>
// handles; otnRefCount stays an explicit field because the C lifecycle is
// refcount-gated (DestroyRuleTreeNode is a no-op while refcount != 0),
// not drop-gated.
// Ground truth: ORIGINAL treenodes compiled in tools/rules_harness; probe
// dump lines pin flags/refc/ndo/ri/body verbatim.
#![allow(dead_code)]
#![allow(non_snake_case)] // literal C member names (otnRefCount, sigInfo, ...)

use std::cell::RefCell;
use std::rc::Rc;

use crate::framework::ips_action::ActionType;
use crate::framework::ips_option::OptionType;
use crate::framework::pdu_section::{section_to_flag, PduSection};
use crate::main::policy::{ActionSelector, Enable};
use crate::ports::port_var_table::PoHandle;
use crate::sfip::sf_ipvar::SfIpVar;
use crate::target_based::snort_protocols::SnortProtocolId;

pub const GID_DEFAULT: u32 = 1;
pub const GID_BUILTIN_MIN: u32 = 40;
pub const GID_BUILTIN_MAX: u32 = 999;

/// signature.h SignatureServiceInfo
#[derive(Clone, Debug, Default)]
pub struct SignatureServiceInfo {
    pub service: String,
    pub snort_protocol_id: SnortProtocolId,
}

/// signature.h SigInfo (ctor initializer: gid = GID_DEFAULT)
#[derive(Clone, Debug)]
pub struct SigInfo {
    pub message: String,
    pub body: Option<String>, // C std::string* (null until dump_rule_meta)

    pub refs: Vec<()>, // ReferenceNode* (classification layer, deferred)
    pub services: Vec<SignatureServiceInfo>,

    pub class_type: Option<()>, // ClassType*

    pub gid: u32,
    pub sid: u32,
    pub rev: u32,

    pub class_id: u32,
    pub priority: u32,

    pub builtin: bool,
    pub target: u8, // Target TARGET_NONE = 0
    pub file_id: u64,
}

impl Default for SigInfo {
    fn default() -> Self {
        SigInfo {
            message: String::new(),
            body: None,
            refs: Vec::new(),
            services: Vec::new(),
            class_type: None,
            gid: GID_DEFAULT,
            sid: 0,
            rev: 0,
            class_id: 0,
            priority: 0,
            builtin: false,
            target: 0,
            file_id: 0,
        }
    }
}

/// signature.h RuleHeader (fields assigned only when dump_rule_meta)
#[derive(Clone, Debug, Default)]
pub struct RuleHeader {
    pub action: String,
    pub proto: String,
    pub src_nets: String,
    pub src_ports: String,
    pub dir: String,
    pub dst_nets: String,
    pub dst_ports: String,
}

impl RuleHeader {
    pub fn with_action(action: &str) -> RuleHeader {
        RuleHeader {
            action: action.to_string(),
            ..RuleHeader::default()
        }
    }
}

/// parser.h ListHead. Identity matters: same_headers and update_rtn
/// compare listhead POINTERS.
#[derive(Debug)]
pub struct ListHead {
    pub rule_list_node: RefCell<Option<Rc<RefCell<RuleListNode>>>>,
}

/// treenodes.h RuleListNode (parser.cc RuleList; one per rule type).
#[derive(Debug)]
pub struct RuleListNode {
    pub rule_list: Option<Rc<RefCell<ListHead>>>,
    pub mode: ActionType,
    pub eval_index: u32,
    pub name: String,
    pub next: Option<Rc<RefCell<RuleListNode>>>,
}

pub type RuleListNodeHandle = Rc<RefCell<RuleListNode>>;
pub type ListHeadHandle = Rc<RefCell<ListHead>>;

/// RuleFpList function-pointer identity. Every harness witness for a
/// Check*/RuleListEnd abort()s if the chain is ever EXECUTED (it never is
/// under the probe), so only presence + order + which function id landed
/// are observable; ported as an enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleFuncId {
    ListEnd,
    Bidirectional,
    Proto,
    SrcIp,
    DstIp,
    SrcPortEqual,
    DstPortEqual,
    SrcPortNotEq,
    DstPortNotEq,
}

/// treenodes.h RuleFpList (a Vec stands in for the C singly-linked list;
/// add-rule-func appends at the tail, verbatim walk semantics).
#[derive(Clone, Copy, Debug)]
pub struct RuleFpList {
    pub rule_head_func: RuleFuncId,
}

/// treenodes.h OptFpList
#[derive(Debug)]
pub struct OptFpList {
    pub option_func: Option<()>, // RuleOptEval* (never invoked in replay)
    pub opt_flags: u32,          // OptTreeFlagBits (ROF_*)
    pub opt_type: OptionType,    // RULE_OPTION_TYPE_*
    pub ips_opt: Option<Rc<RefCell<crate::framework::ips_option::IpsOption>>>,
    pub next: Option<Rc<RefCell<OptFpList>>>,
}

/// treenodes.cc AddOptFuncToList: append a fresh node at the tail; fresh
/// nodes start opt_type = RULE_OPTION_TYPE_CONTENT. Returns the node so
/// parse_rule_close pins fpl->type = LEAF_NODE.
pub fn add_opt_func_to_list(
    option_func: Option<()>,
    otn: &mut OptTreeNode,
) -> Rc<RefCell<OptFpList>> {
    let ofl = Rc::new(RefCell::new(OptFpList {
        option_func,
        opt_flags: 0,
        opt_type: OptionType::Content,
        ips_opt: None,
        next: None,
    }));
    match otn.opt_func_tail.clone() {
        None => {
            otn.opt_func = Some(Rc::clone(&ofl));
        }
        Some(tail) => {
            tail.borrow_mut().next = Some(Rc::clone(&ofl));
        }
    }
    otn.opt_func_tail = Some(Rc::clone(&ofl));
    ofl
}

/// treenodes.h RuleTreeNode — C member names verbatim.
#[derive(Debug)]
pub struct RuleTreeNode {
    pub rule_func: Vec<RuleFpList>, // match functions (C linked list)
    pub flags: u8,
    pub action: ActionType,
    pub snort_protocol_id: SnortProtocolId,

    pub listhead: Option<ListHeadHandle>,
    pub header: Option<Box<RuleHeader>>,

    pub sip: Option<SfIpVar>,
    pub dip: Option<SfIpVar>,

    pub src_portobject: Option<PoHandle>,
    pub dst_portobject: Option<PoHandle>,

    /// reference count from otn: multiple OTNs can share this RTN
    pub otnRefCount: u32,

    pub action_selector: ActionSelector,
}

impl RuleTreeNode {
    pub const ENABLED: u8 = 0x01;
    pub const ANY_SRC_PORT: u8 = 0x02;
    pub const ANY_DST_PORT: u8 = 0x04;
    pub const ANY_FLAGS: u8 = 0x08;
    pub const BIDIRECTIONAL: u8 = 0x10;
    pub const ANY_SRC_IP: u8 = 0x20;
    pub const ANY_DST_IP: u8 = 0x40;
    pub const USER_MODE: u8 = 0x80;

    pub fn new() -> RuleTreeNode {
        RuleTreeNode {
            rule_func: Vec::new(),
            flags: 0,
            action: 0,
            snort_protocol_id: 0,
            listhead: None,
            header: None,
            sip: None,
            dip: None,
            src_portobject: None,
            dst_portobject: None,
            otnRefCount: 0,
            action_selector: 0,
        }
    }

    pub fn set_enabled(&mut self) {
        self.flags |= Self::ENABLED;
    }
    pub fn clear_enabled(&mut self) {
        self.flags &= !Self::ENABLED;
    }
    pub fn enabled(&self) -> bool {
        (self.flags & Self::ENABLED) != 0
    }
    pub fn set_user_mode(&mut self) {
        self.flags |= Self::USER_MODE;
    }
    pub fn user_mode(&self) -> bool {
        (self.flags & Self::USER_MODE) != 0
    }
    pub fn any_src_port(&self) -> bool {
        (self.flags & Self::ANY_SRC_PORT) != 0
    }
    pub fn any_dst_port(&self) -> bool {
        (self.flags & Self::ANY_DST_PORT) != 0
    }
    pub fn any_any_port(&self) -> bool {
        self.any_src_port() && self.any_dst_port()
    }
}

impl Default for RuleTreeNode {
    fn default() -> Self {
        RuleTreeNode::new()
    }
}

pub type RtnHandle = Rc<RefCell<RuleTreeNode>>;

/// treenodes.h OptTreeNode. Deviation (pinned): the per-instance
/// `OtnState state[instance_max]` packet-runtime array is never touched
/// by the harness nor read by the replay; not modeled. `buffer_setters`
/// is a C const char** array (null-terminated) copied from the file
/// static; Vec<String> (null sentinel implicit).
#[derive(Debug)]
pub struct OptTreeNode {
    pub sigInfo: SigInfo,
    pub soid: Option<String>,

    pub opt_func: Option<Rc<RefCell<OptFpList>>>,
    pub opt_func_tail: Option<Rc<RefCell<OptFpList>>>,

    pub output_funcs: Option<()>, // OutputSet* (output layer, deferred)
    pub agent: Option<()>,        // IpsOption*

    pub buffer_setters: Vec<String>,

    pub normal_fp_only: Vec<()>, // OptFpList* lists (FP layer, deferred)
    pub offload_fp_only: Vec<()>,

    pub detection_filter: Option<()>, // THD_NODE*
    pub tag: Option<()>,              // TagData*

    /// ptr to list of ptrs to RTNs (head part; head policyId's RTN)
    pub proto_nodes: Vec<Option<RtnHandle>>,

    pub evalCount: u32,
    pub evalIndex: u32,
    pub ruleIndex: u32,
    pub num_detection_opts: u32,
    pub snort_protocol_id: SnortProtocolId,
    pub proto_node_num: u32,
    pub longest_pattern_len: u16,
    pub enable: Enable,
    pub flags: u8,

    // SectionDir { SECT_TO_SRV, SECT_TO_CLIENT, SECT_DIR__MAX }
    // init: section_to_flag(PS_NONE)
    pub sections: [u16; OptTreeNode::SECT_DIR__MAX],
}

impl OptTreeNode {
    pub const WARNED_FP: u8 = 0x01;
    pub const STATELESS: u8 = 0x02;
    pub const RULE_STATE: u8 = 0x04;
    pub const META_MATCH: u8 = 0x08;
    pub const TO_CLIENT: u8 = 0x10;
    pub const TO_SERVER: u8 = 0x20;
    pub const BIT_CHECK: u8 = 0x40;
    pub const SVC_ONLY: u8 = 0x80;

    pub const SECT_TO_SRV: usize = 0;
    pub const SECT_TO_CLIENT: usize = 1;
    pub const SECT_DIR__MAX: usize = 2;

    pub fn new() -> OptTreeNode {
        OptTreeNode {
            sigInfo: SigInfo::default(),
            soid: None,
            opt_func: None,
            opt_func_tail: None,
            output_funcs: None,
            agent: None,
            buffer_setters: Vec::new(),
            normal_fp_only: Vec::new(),
            offload_fp_only: Vec::new(),
            detection_filter: None,
            tag: None,
            proto_nodes: Vec::new(),
            evalCount: 0,
            evalIndex: 0,
            ruleIndex: 0,
            num_detection_opts: 0,
            snort_protocol_id: 0,
            proto_node_num: 0,
            longest_pattern_len: 0,
            enable: Enable::Disabled,
            flags: 0,
            sections: [section_to_flag(PduSection::PsNone); Self::SECT_DIR__MAX],
        }
    }

    pub fn set_warned_fp(&mut self) {
        self.flags |= Self::WARNED_FP;
    }
    pub fn warned_fp(&self) -> bool {
        (self.flags & Self::WARNED_FP) != 0
    }
    pub fn set_stateless(&mut self) {
        self.flags |= Self::STATELESS;
    }
    pub fn stateless(&self) -> bool {
        (self.flags & Self::STATELESS) != 0
    }
    pub fn set_enabled(&mut self, e: Enable) {
        self.enable = e;
        self.flags |= Self::RULE_STATE;
    }
    pub fn is_rule_state_stub(&self) -> bool {
        (self.flags & Self::RULE_STATE) != 0
    }
    pub fn enabled_somewhere(&self) -> bool {
        for n in &self.proto_nodes {
            if let Some(r) = n
                && r.borrow().enabled() {
                    return true;
                }
        }
        false
    }
    pub fn set_metadata_match(&mut self) {
        self.flags |= Self::META_MATCH;
    }
    pub fn metadata_matched(&self) -> bool {
        (self.flags & Self::META_MATCH) != 0
    }
    pub fn set_to_client(&mut self) {
        self.flags |= Self::TO_CLIENT;
    }
    pub fn to_client(&self) -> bool {
        (self.flags & Self::TO_CLIENT) != 0
    }
    pub fn set_to_server(&mut self) {
        self.flags |= Self::TO_SERVER;
    }
    pub fn to_server(&self) -> bool {
        (self.flags & Self::TO_SERVER) != 0
    }
    pub fn set_flowbits_check(&mut self) {
        self.flags |= Self::BIT_CHECK;
    }
    pub fn checks_flowbits(&self) -> bool {
        (self.flags & Self::BIT_CHECK) != 0
    }
    pub fn set_service_only(&mut self) {
        self.flags |= Self::SVC_ONLY;
    }
    pub fn service_only(&self) -> bool {
        (self.flags & Self::SVC_ONLY) != 0
    }
    pub fn to_client_err(&self) -> bool {
        self.sections[Self::SECT_TO_CLIENT] == section_to_flag(PduSection::PsError)
    }
    pub fn to_server_err(&self) -> bool {
        self.sections[Self::SECT_TO_SRV] == section_to_flag(PduSection::PsError)
    }
}

impl Default for OptTreeNode {
    fn default() -> Self {
        OptTreeNode::new()
    }
}

pub type OtnHandle = Rc<RefCell<OptTreeNode>>;

/// getRtnFromOtn(otn, policyId) inline (parser.h): C guards
/// (proto_nodes && (proto_node_num >= (policyId+1))) then returns
/// proto_nodes[policyId] (may be null).
pub fn get_rtn_from_otn(otn: &OtnHandle, policy_id: u32) -> Option<RtnHandle> {
    let b = otn.borrow();
    if !b.proto_nodes.is_empty() && b.proto_node_num >= (policy_id + 1) {
        return b.proto_nodes.get(policy_id as usize).cloned().flatten();
    }
    None
}

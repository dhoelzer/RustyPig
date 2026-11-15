// Port of the IpsPolicy action-variable subset of snort3 main/policy.{h,cc}
// (the parts the embedded Catch suite tests plus get_action()). PolicyMap /
// NetworkPolicy / InspectionPolicy fields depend on Shell, CodecManager,
// DataBus and DAQ types and defer to the detection/packet_io layers.
//
// C resolves action names to IpsAction::Type through the global
// ActionManager statics; the Rust port threads an explicit
// framework::ips_action::ActionRegistry instead (see deviations).

use crate::framework::ips_action::{ActionRegistry, ActionType};

pub type PolicyId = u32;
pub type ActionSelector = u8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyMode {
    Passive,
    Inline,
    InlineTest,
    #[default]
    Max,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Enable {
    Disabled,
    Enabled,
    #[default]
    InheritEnable,
}

impl Enable {
    // C enum Enable : uint8_t { DISABLED, ENABLED, INHERIT_ENABLE }
    pub fn code(self) -> u8 {
        match self {
            Enable::Disabled => 0,
            Enable::Enabled => 1,
            Enable::InheritEnable => 2,
        }
    }
}

#[derive(Debug, Default)]
pub struct IpsPolicy {
    pub policy_id: PolicyId,
    pub user_policy_id: u64,

    pub policy_mode: PolicyMode,
    pub enable_builtin_rules: bool,
    pub rules_loaded: i32,
    pub rules_shared: i32,

    pub var_id: u32,

    pub default_rule_state: Enable,
    pub obfuscate_pii: bool,

    pub action_override: String,

    // name -> (action_name, action_type, selector); C std::map, ordered.
    pub action_vars: Vec<(String, (String, ActionType, ActionSelector))>,
    // Holds all plugin actions associated with this policy.
    pub action: Vec<Option<()>>, // IpsAction* placeholders; payloads later
    pub configured_action: Vec<Option<()>>,
}

impl IpsPolicy {
    pub fn new(policy_id: PolicyId) -> Self {
        IpsPolicy {
            policy_id,
            user_policy_id: 0,
            policy_mode: PolicyMode::Max,
            enable_builtin_rules: false,
            rules_loaded: 0,
            rules_shared: 0,
            var_id: 0,
            default_rule_state: Enable::InheritEnable,
            obfuscate_pii: false,
            action_override: String::new(),
            action_vars: Vec::new(),
            action: Vec::new(),
            configured_action: Vec::new(),
        }
    }

    pub fn update_user_policy_id(&mut self) {
        if self.user_policy_id == 0 {
            self.user_policy_id = 1;
        }
    }

    pub fn has_action_variable_capacity(&self) -> bool {
        self.configured_action.len() <= u8::MAX as usize
    }

    pub fn has_action_variable(&self, name: &str) -> bool {
        self.action_vars.iter().any(|(n, _)| n == name)
    }

    pub fn commit_action_variable(
        &mut self,
        name: &str,
        action_name: &str,
        act: Option<()>,
        reg: &ActionRegistry,
    ) {
        let selector = self.configured_action.len() as ActionSelector;
        let action_type: ActionType = reg.get_action_type(action_name);

        // std::map::emplace: first insert wins on duplicate key
        if !self.action_vars.iter().any(|(n, _)| n == name) {
            self.action_vars
                .push((name.to_string(), (action_name.to_string(), action_type, selector)));
            self.action_vars.sort_by(|a, b| a.0.cmp(&b.0));
        }
        self.configured_action.push(act);
    }

    pub fn get_action_variable(
        &self,
        name: &str,
    ) -> Option<(&String, ActionType, ActionSelector)> {
        self.action_vars
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, (an, at, sel))| (an, *at, *sel))
    }

    /// C get_action(type, selector) inline in policy.h
    pub fn get_action(&self, action_type: ActionType, selector: ActionSelector) -> Option<()> {
        if selector == 0 {
            if (action_type as usize) < self.action.len() {
                self.action[action_type as usize]
            } else {
                None
            }
        } else if (selector as usize) < self.configured_action.len() {
            self.configured_action[selector as usize]
        } else {
            None
        }
    }
}

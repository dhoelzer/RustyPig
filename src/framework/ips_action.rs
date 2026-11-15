// Port of snort3 framework/ips_action.{h,cc} Type plumbing + the subset of
// managers/action_manager.cc's static registry (s_act_types / s_act_index /
// s_act_priorities) needed by IpsPolicy and future parse_rule. C keeps these
// as file-statics filled at plugin registration; the Rust port holds them in
// an explicit ActionRegistry so tests can register actions exactly like the
// built-in act_alert/act_pass/... ActionApis do.
//
// Quirks preserved:
//   * get_interface emplaces name -> s_act_index++ (registration order
//     assigns types) and emplaces priority -> name into a map ordered by
//     priority DESCENDING (std::greater); duplicate priorities keep the
//     FIRST registrant (map emplace semantics);
//   * get_action_string returns "ERROR" for out-of-range or unknown;
//   * get_action_type returns get_max_action_types() on miss;
//   * get_action_priorities joins descending-priority names with single
//     spaces; with alert_before_pass, "pass" entries are SKIPPED and
//     "alert" expands to "alert pass " inline (quirk: the expansion happens
//     before the ++iter != end space logic, so a trailing entry still gets
//     its separator suppressed).

pub type ActionType = u8;

pub const ACTAPI_VERSION: u32 = (29 << 16) | 3; // BASE_API_VERSION=29 (framework/base_api.h:41)

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpsActionPriority {
    Other = 1,
    Log = 10,
    Alert = 20,
    Rewrite = 30,
    Drop = 40,
    Block = 50,
    Reject = 60,
    Pass = 70,
}

pub const IAP_MAX: IpsActionPriority = IpsActionPriority::Pass;

#[derive(Debug, Default)]
pub struct ActionRegistry {
    // registration-ordered list; index in `types` mirrors unordered_map
    // contents and s_act_index
    names: Vec<String>,
    types: Vec<ActionType>,
    priorities: Vec<(IpsActionPriority, String)>, // kept sorted desc, first-wins on dup
    s_act_index: ActionType,
}

impl ActionRegistry {
    /// C ActionManager::get_interface
    pub fn get_interface(&mut self, name: &str, priority: IpsActionPriority) {
        // C: s_act_types.emplace(name, s_act_index++) — emplace does NOT
        // overwrite an existing key, but the index++ still happens even for a
        // duplicate name (wasted type index quirk).
        if !self.names.iter().any(|n| n == name) {
            self.names.push(name.to_string());
            self.types.push(self.s_act_index);
        }
        self.s_act_index = self.s_act_index.wrapping_add(1);
        // std::map::emplace: duplicate key keeps existing (C PlugInterface is
        // looked up by name first, but ActionApi priority list keyed by
        // priority: first registration wins)
        if !self.priorities.iter().any(|(p, _)| *p == priority) {
            let key = priority;
            let pos = self
                .priorities
                .iter()
                .position(|(p, _)| *p < key) // std::greater order: descending
                .unwrap_or(self.priorities.len());
            self.priorities.insert(pos, (key, name.to_string()));
        }
    }

    /// C ActionManager::get_action_string
    pub fn get_action_string(&self, action: ActionType) -> String {
        if action < self.s_act_index {
            // find_if over the map for first (name,type) with type == action;
            // types are unique so iteration order is irrelevant
            if let Some(i) = self
                .types
                .iter()
                .position(|&t| t == action)
            {
                return self.names[i].clone();
            }
        }
        "ERROR".to_string()
    }

    /// C ActionManager::get_action_type
    pub fn get_action_type(&self, s: &str) -> ActionType {
        match self.names.iter().position(|n| n == s) {
            Some(i) => self.types[i],
            None => self.get_max_action_types(),
        }
    }

    pub fn get_max_action_types(&self) -> ActionType {
        self.s_act_index
    }

    pub fn is_valid_action(&self, action: ActionType) -> bool {
        action < self.get_max_action_types()
    }

    /// C ActionManager::get_action_priorities(alert_before_pass)
    pub fn get_action_priorities(&self, alert_before_pass: bool) -> String {
        let mut priorities = String::new();
        let mut iter = 0usize;
        while iter < self.priorities.len() {
            if alert_before_pass {
                if self.priorities[iter].1 == "pass" {
                    iter += 1;
                    continue;
                } else if self.priorities[iter].1 == "alert" {
                    // C appends "alert pass " (trailing space included) and
                    // `continue`s, skipping the ++iter != end separator logic.
                    priorities += "alert pass ";
                    iter += 1;
                    continue;
                }
            }
            priorities += &self.priorities[iter].1;
            iter += 1;
            if iter < self.priorities.len() {
                priorities += " ";
            }
        }
        priorities
    }
}

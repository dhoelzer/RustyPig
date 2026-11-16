//! Ports of:
//!   * main/policy.cc embedded Catch cases ("IPS policy reports action
//!     variable capacity", "reports existing action variable", "reports
//!     missing action variable") — the C++ suite uses the global
//!     ActionManager's built-in registrations, but with an EMPTY registry
//!     get_action_type returns max (0 here); the C IpsPolicy behavior under
//!     test (selector/capacity/lookup) is registry-independent, and the
//!     REACT_DEFINED tuple stores the registry's mapping. We replay against
//!     a registry with "react" registered, matching real snort behavior.
//!   * Replay of tools/action_harness/vectors.txt: five actions registered,
//!     all lookups, priority-join both modes, duplicate-registration and
//!     duplicate-priority quirks.

use snort3::framework::ips_action::{ActionRegistry, IpsActionPriority};
use snort3::main::policy::IpsPolicy;

// ---------------------------------------------------------------------------
// main/policy.cc Catch cases
// ---------------------------------------------------------------------------

#[test]
fn policy_action_variable_capacity() {
    let mut policy = IpsPolicy::new(0);

    policy.configured_action.resize(u8::MAX as usize, None);
    assert!(policy.has_action_variable_capacity());

    policy.configured_action.resize(u8::MAX as usize + 1, None);
    assert!(!policy.has_action_variable_capacity());
}

#[test]
fn policy_existing_action_variable() {
    let mut reg = ActionRegistry::default();
    reg.get_interface("react", IpsActionPriority::Other);

    let mut policy = IpsPolicy::new(0);
    assert!(!policy.has_action_variable("REACT_DEFINED"));

    policy.commit_action_variable("REACT_DEFINED", "react", None, &reg);
    assert!(policy.has_action_variable("REACT_DEFINED"));

    // the C tuple stored (action_name, get_type(name), selector); the C
    // ctor seeds configured_action(1, nullptr), so the first commit gets
    // selector 1 (policy.cc: IpsPolicy(PolicyId id) : configured_action(1, nullptr)).
    let (an, at, sel) = policy.get_action_variable("REACT_DEFINED").unwrap();
    assert_eq!(an, "react");
    assert_eq!(at, reg.get_action_type("react"));
    assert_eq!(sel, 1);
}

#[test]
fn policy_missing_action_variable() {
    let policy = IpsPolicy::new(0);
    assert!(policy.get_action_variable("REACT_MISSING").is_none());
}

// ---------------------------------------------------------------------------
// tools/action_harness/vectors.txt replay (ActionRegistry C ground truth)
// ---------------------------------------------------------------------------

#[test]
fn action_registry_replay() {
    let body = include_str!("../tools/action_harness/vectors.txt");
    let mut reg = ActionRegistry::default();
    reg.get_interface("drop", IpsActionPriority::Drop);
    reg.get_interface("reject", IpsActionPriority::Reject);
    reg.get_interface("alert", IpsActionPriority::Alert);
    reg.get_interface("log", IpsActionPriority::Log);
    reg.get_interface("pass", IpsActionPriority::Pass);

    let mut as_rows = 0;
    let mut at_rows = 0;
    let mut pri_rows = 0;

    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("AS ") {
            as_rows += 1;
            let (i, s) = rest.split_once(' ').unwrap();
            let i: u8 = i.parse().unwrap();
            assert_eq!(reg.get_action_string(i), s, "{line}");
        } else if let Some(rest) = line.strip_prefix("AT ") {
            at_rows += 1;
            // "AT <name> <type>"; name may be empty ("AT  5")
            let (name, ty) = rest.rsplit_once(' ').unwrap();
            let ty: u8 = ty.parse().unwrap();
            assert_eq!(reg.get_action_type(name), ty, "{line}");
        } else if let Some(rest) = line.strip_prefix("PRI0 [") {
            pri_rows += 1;
            let want = rest.trim_end_matches(']');
            assert_eq!(reg.get_action_priorities(false), want, "{line}");
        } else if let Some(rest) = line.strip_prefix("PRI1 [") {
            pri_rows += 1;
            let want = rest.trim_end_matches(']');
            assert_eq!(reg.get_action_priorities(true), want, "{line}");
        } else if let Some(rest) = line.strip_prefix("MAX2 ") {
            // duplicate registration: emplace doesn't overwrite but index++
            // still fires; "drop" dup + "custom" each burned an index.
            reg.get_interface("drop", IpsActionPriority::Drop);
            reg.get_interface("custom", IpsActionPriority::Alert); // dup priority
            let want: u8 = rest.trim().parse().unwrap();
            assert_eq!(reg.get_max_action_types(), want, "{line}");
        } else if let Some(rest) = line.strip_prefix("PRI2 [") {
            pri_rows += 1;
            let want = rest.trim_end_matches(']');
            // duplicate priority key rejected by map::emplace: "custom" absent
            assert_eq!(reg.get_action_priorities(false), want, "{line}");
        } else if let Some(rest) = line.strip_prefix("AS2 0 ") {
            let want = rest;
            assert_eq!(reg.get_action_string(0), want, "{line}");
        } else {
            panic!("unknown vector line: {line}");
        }
    }
    assert!(as_rows == 6 && at_rows == 7 && pri_rows == 3);
}

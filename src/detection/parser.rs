// Port of the RTN-lifecycle + rule-index half of snort3 src/parser/parser.cc.
// The literal C transcriptions of addRtnToOtn / deleteRtnFromOtn / find_rtn /
// Destroy* / Free* / reduce_rtns / CreateRuleType / rule_index_map channels
// live in detection/parse_rule.rs (single source of truth; upstream splits
// them across parser.cc + parse_rule.cc but they are one tightly coupled
// unit — the C file statics rtn_hash_table + rule_index_map ride along).
// This module re-exports that machinery under the parser.cc names and
// documents the mapping. Ground truth: ORIGINAL parser.cc slice compiled in
// tools/rules_harness (DEL/RIM/SH vectors + STATE/reduce blocks).
#![allow(dead_code)]

pub use crate::detection::parse_rule::{
    add_rtn_to_otn, create_rule_type, delete_rtn_from_otn, destroy_rule_tree_node,
    find_rtn, free_rule_tree_node_impl, free_rule_tree_nodes, parser_append_rules,
    parser_append_rules_special, parser_get_rule_ids, parser_get_rule_index,
    parser_get_special_includer, reduce_rtns, RuleTreeCache,
};

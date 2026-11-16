// FastPatternConfig (detection/fp_config.h): the portlists knobs the rule
// tree reads. Literal transcription of the inline members; the ctor body
// (MPSE search-api resolution + method defaults) is the documented harness
// deviation — bleedover_port_limit keeps its in-class initializer (1024)
// exactly as the compiled harness pins it (vectors: finish_ports limits).
#![allow(dead_code)]

pub const PL_BLEEDOVER_WARNINGS_ENABLED: u32 = 0x01;
pub const PL_DEBUG_PRINT_NC_DETECT_RULES: u32 = 0x02;
pub const PL_DEBUG_PRINT_RULEGROUP_BUILD: u32 = 0x04;
pub const PL_DEBUG_PRINT_RULEGROUPS_UNCOMPILED: u32 = 0x08;
pub const PL_DEBUG_PRINT_RULEGROUPS_COMPILED: u32 = 0x10;
pub const PL_SINGLE_RULE_GROUP: u32 = 0x20;

#[derive(Debug, Clone)]
pub struct FastPatternConfig {
    portlists_flags: u32,
    bleedover_port_limit: u32,

    // debug/print flags (fp_config.h inline members; parse_rule paths
    // read them, the probe never sets them):
    pub debug: bool,
}

impl FastPatternConfig {
    pub fn new() -> FastPatternConfig {
        FastPatternConfig {
            portlists_flags: 0,
            bleedover_port_limit: 1024, // fp_config.h:159 in-class init
            debug: false,
        }
    }

    pub fn set_bleed_over_port_limit(&mut self, n: u32) {
        self.bleedover_port_limit = n;
    }
    pub fn get_bleed_over_port_limit(&self) -> u32 {
        self.bleedover_port_limit
    }
    pub fn get_single_rule_group(&self) -> bool {
        self.portlists_flags & PL_SINGLE_RULE_GROUP != 0
    }
    pub fn get_bleed_over_warnings(&self) -> bool {
        self.portlists_flags & PL_BLEEDOVER_WARNINGS_ENABLED != 0
    }
    pub fn set_single_rule_group(&mut self) {
        self.portlists_flags |= PL_SINGLE_RULE_GROUP;
    }
    pub fn set_bleed_over_warnings(&mut self) {
        self.portlists_flags |= PL_BLEEDOVER_WARNINGS_ENABLED;
    }
}

impl Default for FastPatternConfig {
    fn default() -> Self {
        FastPatternConfig::new()
    }
}

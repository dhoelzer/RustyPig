#pragma once
namespace snort {
struct SnortConfig {
    static SnortConfig* get_conf();
    bool dump_rule_info() const;
};
}

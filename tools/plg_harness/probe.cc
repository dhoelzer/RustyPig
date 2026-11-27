// probe (row 24h): the DEC ladder. The row TU rides the DIRECT-INCLUDE
// seat (the static THREAD_LOCAL nav ladder face cc :325-:328 + the
// nav-home family + the only_* pair ride there — the include-trick the
// task licenses); the witness supplies the NEVER-executed family legs
// and the 22 REAL ground legs carry the IpsPolicy boot/free semantics.
// The policy.h legacy family (IpsPolicy + the PolicyMode seats) rides
// GLOBAL scope (the header's own law); the snort:: side rides the Ips-
// Action + nav-home seats exactly as the row TU declares them.
// Deterministic: values + counts ONLY, ZERO pointers, ZERO clock faces.
#include "main/policy.cc"
#include <climits>
#include <cstdio>
#include <string>

int main()
{
    IpsPolicy p(3);
    printf("C1 policy_id=3 %u\n", p.policy_id);
    printf("C2 mode_is_max %d\n", (int)(p.policy_mode == POLICY_MODE__MAX));
    printf("C3 boot_ip_vartable %d\n", (int)(p.ip_vartable != nullptr));
    printf("C4 boot_portVarTable %d\n", (int)(p.portVarTable != nullptr));
    printf("C5 boot_nonameTable %d\n", (int)(p.nonamePortVarTable != nullptr));
    printf("C6 builtin_off pii_on inherit %d %d %d\n", (int)p.enable_builtin_rules,
        (int)p.obfuscate_pii, (int)(p.default_rule_state == IpsPolicy::INHERIT_ENABLE));

    // the THREE gate semantics walked as the DEC ladder (the REAL in-TU
    // bodies through the include seat, NEVER a mirror)
    printf("C7 av_absent %d\n", (int)!p.has_action_variable("REACT_DEFINED"));
    const std::string* nm = nullptr;
    snort::IpsAction::Type ty = 9;
    IpsPolicy::ActionSelector sel = 9;
    printf("C8 missing_found %d\n", (int)p.get_action_variable("REACT_MISSING", nm, ty, sel));
    p.commit_action_variable("REACT_DEFINED", "react", nullptr);
    printf("C9 committed_present %d\n", (int)p.has_action_variable("REACT_DEFINED"));
    // the lookup FIRST as its own statement, NEVER an in-arg call whose
    // out-param the sibling arg would deref before the call lands (the
    // unspecified-arg-order SEGV the first cold run exposed, fixed HONEST)
    const bool found2 = p.get_action_variable("REACT_DEFINED", nm, ty, sel);
    printf("C10 found name_react type0 sel1 %d %d %d %d\n",
        (int)found2, (int)(*nm == "react"),
        (int)(ty == 0), (int)(sel == 1));
    p.configured_action.resize(UINT8_MAX);
    printf("C11 cap_255 %d\n", (int)p.has_action_variable_capacity());
    p.configured_action.resize((size_t)UINT8_MAX + 2);
    printf("C12 cap_257_off %d\n", (int)!p.has_action_variable_capacity());
    p.configured_action.resize(2);
    p.commit_action_variable("REACT_BLOCK", "block", nullptr);
    nm = nullptr; ty = 9; sel = 9;
    p.get_action_variable("REACT_BLOCK", nm, ty, sel);
    printf("C13 second_sel name_block %d %d\n", (int)(sel == 2), (int)(*nm == "block"));
    printf("C14 get_action_sel0_null %d\n", (int)(p.get_action(snort::IpsAction::Type(0), 0) == nullptr));
    p.update_user_policy_id();
    unsigned long u1 = p.user_policy_id;
    p.update_user_policy_id();
    printf("C15 user_policy_idempotent %d\n", (int)(u1 == 1 && p.user_policy_id == 1));
    return 0;
}

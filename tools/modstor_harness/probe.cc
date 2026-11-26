// probe (row 24e): the DEC ladder. The row TU rides the DIRECT-INCLUDE
// seat (the file-statics face: get_var_name / is_action_var_placeholder —
// the include-trick the task licenses); the witness supplies the NAME
// capture + the mirror legs. Deterministic: names + counts ONLY.
#include "main/modules.cc"
#include <cstdio>
#include <string>
#include <vector>

extern std::vector<std::string> g_captured_names;
void capture_reset();

int main()
{
    capture_reset();
    add_independent_modules();
    printf("I1 independent=%zu\n", g_captured_names.size());
    for (size_t i = 0; i < g_captured_names.size(); ++i)
        printf("I2 n%02zu %s\n", i + 1, g_captured_names[i].c_str());

    capture_reset();
    add_dependent_modules();
    printf("D1 dependent=%zu", g_captured_names.size());
    for (auto& s : g_captured_names) printf(" %s", s.c_str());
    printf("\n");

    printf("P1 ph_self=%d\n",  (int)is_action_var_placeholder("ips.variables.actions.$var.react"));
    printf("P2 ph_named=%d\n", (int)is_action_var_placeholder("ips.variables.actions.REACT_CUSTOM.react"));
    printf("P3 ph_missing=%d\n", (int)is_action_var_placeholder("ips.variables.actions.$var"));
    printf("P4 ph_net=%d\n",   (int)is_action_var_placeholder("ips.variables.nets.$var.react"));
    printf("P5 ph_prefix=%d\n", (int)is_action_var_placeholder("ips.variables.actions.$var.react.page"));
    printf("P6 ph_none=%d\n",  (int)is_action_var_placeholder("ips.mode"));

    printf("V1 vn_react=%s\n", get_var_name("ips.variables.actions.REACT_CUSTOM.react"));
    printf("V2 vn_var=%s\n",   get_var_name("ips.variables.nets.$var"));
    printf("V3 vn_page=%s\n",  get_var_name("ips.variables.actions.REACT.page"));

    return 0;
}

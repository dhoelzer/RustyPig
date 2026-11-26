// probe_faceA (row 24e): the nested IPS variable parameter-table CHAIN
// WALK (the parameter tables are file-static seats -> the row TU rides
// the direct-include seat) + the CRASH_MITIGATOR-off dependent face +
// the Parameter size face. Names + counts ONLY (deterministic).
#include "main/modules.cc"
#include <cstdio>
#include <string>
#include <vector>

extern std::vector<std::string> g_captured_names;
void capture_reset();

static void walk(const char* tag, const Parameter* p)
{
    int n = 0;
    while (p[n].type != Parameter::PT_MAX) ++n;
    printf("%s n=%d:", tag, n);
    for (int i = 0; i < n; ++i) printf(" %s", p[i].name);
    printf("\n");
}

int main()
{
    walk("A1 ips", ips_params);
    walk("A2 variables", variable_params);
    walk("A3 action_vars", action_vars_params);
    walk("A4 action_var", action_var_params);
    walk("A5 action_var_react", action_var_react_params);

    int seat = -1;
    int uuids = 0;
    for (int i = 0; ips_params[i].type != Parameter::PT_MAX; ++i)
    {
        if (!strcmp(ips_params[i].name, "variables")) seat = i;
        if (!strcmp(ips_params[i].name, "uuid")) ++uuids;
    }
    const Parameter* child = (const Parameter*)ips_params[seat].range;
    printf("A6 seat=%d child_is_variables=%d\n", seat, (int)(child == variable_params));
    printf("A7 uuid_seat=%d (HAVE_UUID-off face)\n", uuids);

    capture_reset();
    add_dependent_modules();
    printf("A8 dependent=%zu", g_captured_names.size());
    for (auto& s : g_captured_names) printf(" %s", s.c_str());
    printf("\n");

    printf("A9 sizeof_Parameter=%zu\n", sizeof(Parameter));
    return 0;
}

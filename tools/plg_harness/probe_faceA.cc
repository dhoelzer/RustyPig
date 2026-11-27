// probe_faceA (row 24h): the policy NAV ladder FACE (the static
// THREAD_LOCAL seats cc :325-:328 + the nav-home family + the only_*
// pair + the PolicyMap ctor/dtor family ride the DIRECT-INCLUDE seat —
// the include-trick the task licenses; this is the ONLY face where the
// PolicyMap body EXECUTES for real). The legacy policy family rides
// GLOBAL scope (the header's own law); the nav-home family rides
// snort:: exactly as policy.cc :330-:384 declares it. Deterministic:
// values + counts ONLY, ZERO pointers printed, ZERO clock faces.
#include "main/policy.cc"
#include <cstdio>

int main()
{
    printf("A1 nav_fresh_4null %d\n", (int)(!snort::get_ips_policy() &&
        !snort::get_network_policy() && !snort::get_inspection_policy() &&
        !snort::get_network_parse_policy()));

    PolicyMap pm;
    printf("A2 pm_ips2_shells1_nets1 %d\n", (int)(pm.ips_policy_count() == 2 &&
        pm.shells_count() == 1 && pm.network_policy_count() == 1));
    printf("A3 empty_is_ips1 net0_insp1 %d %d\n",
        (int)(pm.get_empty_ips() == pm.get_ips_policy(1) && pm.get_empty_ips()->policy_id == 1),
        (int)(pm.get_network_policy(0)->inspection_policy_count() == 1));

    // ctor side-effects on the nav ladder (policy.cc :207-:210)
    printf("A4 nav_after_ctor %d\n", (int)(snort::get_ips_policy() == pm.get_ips_policy(0) &&
        snort::get_network_policy() == pm.get_network_policy(0) &&
        snort::get_inspection_policy() == pm.get_network_policy(0)->get_inspection_policy(0) &&
        snort::get_network_parse_policy() == pm.get_network_policy(0)));
    printf("A5 only_pair_off %d\n", (int)(!only_inspection_policy() && !only_ips_policy()));

    // the triple-null face + the lonely-ips face (all rides the REAL
    // nav bodies; the nav is RESET before the stack policy dies)
    snort::set_ips_policy(nullptr);
    snort::set_network_policy((NetworkPolicy*)nullptr);
    snort::set_inspection_policy((InspectionPolicy*)nullptr);
    printf("A6 triple_null_only_off %d\n", (int)(!only_inspection_policy() && !only_ips_policy()));
    {
        IpsPolicy q(7);
        snort::set_ips_policy(&q);
        IpsPolicy* g = snort::get_ips_policy();
        q.update_user_policy_id();
        q.update_user_policy_id();
        printf("A7 lonely_ips_only id7 uid1 %d %d %d\n", (int)only_ips_policy(),
            (int)(g && g->policy_id == 7), (int)(g->user_policy_id == 1));
        snort::set_ips_policy(nullptr);
    }

    // the default-policy re-seat through the boot-conf seat (the
    // static-local boot leg through the witness mirror — NEVER derefs
    // beyond policy_map)
    snort::SnortConfig* sc = const_cast<snort::SnortConfig*>(snort::SnortConfig::get_conf());
    sc->policy_map = &pm;
    set_default_policy(sc);
    printf("A8 default_reseat %d\n", (int)(snort::get_network_policy() == pm.get_network_policy(0) &&
        snort::get_inspection_policy() == pm.get_network_policy(0)->get_inspection_policy(0) &&
        snort::get_ips_policy() == pm.get_ips_policy(0)));
    sc->policy_map = nullptr;
    return 0;
}

// Probe driver for the rule-tree core. Drives ORIGINAL parse_rule.cc +
// parser.cc (RTN lifecycle) + rules.cc (RuleStateMap) + signature.cc
// (OtnLookup) + sfrim.cc (rule index map) over synthesized rules and
// emits deterministic vectors. The ips_options meta layer (sid/rev/msg/
// gid options) is out of scope: the probe assigns sigInfo fields after
// parse_rule_open, exactly what those modules do through the option seam.
#include "main/snort_config.h"
#include "main/policy.h"
#include "parser/parser.h"
#include "parser/parse_rule.h"
#include "parser/parse_conf.h"
#include "detection/rules.h"
#include "detection/signature.h"
#include "detection/treenodes.h"
#include "detection/sfrim.h"
#include "detection/fp_config.h"
#include "ports/rule_port_tables.h"
#include "sfip/sf_vartable.h"
#include "sfip/sf_ipvar.h"
#include "ports/port_var_table.h"
#include "log/messages.h"
#include <cstdio>
#include <cstring>
#include <memory>

using namespace snort;

extern SnortConfig* g_probe_sc;
unsigned probe_register_action(const char* n);
const char* probe_action_name(IpsAction::Type t);

static SnortConfig* sc = nullptr;

static void dump_rtn(const char* tag, const RuleTreeNode* rtn)
{
    if ( !rtn ) { printf("%s NIL\n", tag); return; }
    printf("%s act=%s(%u) sel=%u spid=%u flags=%02X en=%d refc=%u sip=%s dip=%s spo=%s dpo=%s\n",
        tag, probe_action_name(rtn->action), rtn->action, rtn->action_selector,
        rtn->snort_protocol_id, rtn->flags, rtn->enabled() ? 1 : 0,
        rtn->otnRefCount,
        rtn->sip ? (rtn->sip->name ? rtn->sip->name : "~") : "NIL",
        rtn->dip ? (rtn->dip->name ? rtn->dip->name : "~") : "NIL",
        rtn->src_portobject ? (rtn->src_portobject->name ? rtn->src_portobject->name : "~raw") : "NIL",
        rtn->dst_portobject ? (rtn->dst_portobject->name ? rtn->dst_portobject->name : "~raw") : "NIL");
}

static void dump_otn(const OptTreeNode* otn)
{
    if ( !otn ) { printf("OTN NIL\n"); return; }
    printf("OTN %u:%u:%u spid=%u nodes=%u ri=%u ndo=%u flags=%02X en=%d body=%s\n",
        otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev,
        otn->snort_protocol_id, otn->proto_node_num, otn->ruleIndex,
        otn->num_detection_opts, otn->flags, (int)otn->enable,
        otn->sigInfo.body ? otn->sigInfo.body->c_str() : "-");
    for ( unsigned i = 0; i < otn->proto_node_num; ++i )
        dump_rtn("  RTN", otn->proto_nodes[i]);
}

static void walk_rule_lists()
{
    for ( const RuleListNode* p = sc->rule_lists; p; p = p->next )
        printf("RLIST %s mode=%u eval=%u\n", p->name, p->mode, p->evalIndex);
}

// Build one rule the way parse_stream drives the API, assigning gid/sid/rev
// manually (meta-option stand-in). Returns the final OTN (or nullptr).
static OptTreeNode* make_rule(const char* action, const char* proto,
    const char* nets_s, const char* ports_s, const char* dir,
    const char* nets_d, const char* ports_d,
    uint32_t gid, uint32_t sid, uint32_t rev)
{
    RuleTreeNode rtn;
    parse_rule_type(sc, action, rtn);
    if ( get_parse_errors() ) { printf("PE=%u after type\n", get_parse_errors()); reset_parse_errors(); }
    parse_rule_proto(sc, proto, rtn, false);
    parse_rule_nets(sc, nets_s, true, rtn, false);
    parse_rule_ports(sc, ports_s, true, rtn, false);
    parse_rule_dir(sc, dir, rtn, false);
    parse_rule_nets(sc, nets_d, false, rtn, false);
    parse_rule_ports(sc, ports_d, false, rtn, false);
    OptTreeNode* otn = parse_rule_open(sc, rtn, false);
    if ( !otn ) { printf("OPEN null (ignore)\n"); return nullptr; }
    otn->sigInfo.gid = gid;
    otn->sigInfo.sid = sid;
    otn->sigInfo.rev = rev;
    parse_rule_close(sc, rtn, otn);
    return otn;
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    // fixed action registration order (pin; upstream = plugin init order)
    const char* acts[] = { "drop", "sdrop", "reject", "rejectboth", "rejectip",
        "dropflow", "rejectflow", "alert", "pass", "log", "file", "file_id",
        "proximity", "url", "react", "close" };
    for ( const char* a : acts ) probe_register_action(a);
    printf("ACTMAX %u alert=%u pass=%u file=%u bogus=%u\n",
        IpsAction::get_max_types(), IpsAction::get_type("alert"),
        IpsAction::get_type("pass"), IpsAction::get_type("file"),
        IpsAction::get_type("not_an_action"));
    printf("ACTSTR %s %s\n", probe_action_name(IpsAction::get_type("alert")),
        probe_action_name(IpsAction::get_max_types()));

    // ---- config + policy map (empty policy first, like PolicyMap) --------
    sc = new SnortConfig();
    g_probe_sc = sc;
    PolicyMap* pm = new PolicyMap();      // policy.cc-style wiring: empty
    IpsPolicy* p0 = pm->empty_ips_policy; // policy self-registered at id 0
    IpsPolicy* p1 = new IpsPolicy(1);
    IpsPolicy* p2 = new IpsPolicy(2);     // user_policy_id 0 -> bumps on use
    // reuse the network_policy[0] spine: its ips slot becomes p1/p2 in the
    // order reduce/addRtnToOtn observe (probe-local; real shell wiring is
    // out of scope -- documented deviation).
    pm->ips_policy.push_back(p1);
    pm->ips_policy.push_back(p2);
    pm->set_user_ips(p1);
    pm->set_user_ips(p2);
    sc->policy_map = pm;
    sc->otn_map = OtnLookupNew();
    sc->port_tables = PortTablesNew();
    sc->fast_pattern_config = new FastPatternConfig();
    sc->proto_ref = new ProtocolReference();
    sc->rule_states = new RuleStateMap();
    sc->dump_rule_meta_flag = true;   // exercise RuleHeader + s_body capture
    parser_init();

    // vartables per policy
    sfip_var_t* var = nullptr;
    printf("V %d\n", sfvt_add_str(p1->ip_vartable, "HOME_NET [10.0.0.0/8]", &var));
    printf("V %d\n", sfvt_add_str(p1->ip_vartable, "EXT_NET [192.168.0.0/16,!192.168.1.0/24]", &var));
    printf("V %d\n", sfvt_add_str(p0->ip_vartable, "HOME_NET [10.0.0.0/8]", &var));
    printf("V %d\n", sfvt_add_str(p0->ip_vartable, "EXT_NET [.16]", &var));
    // $ alias in policy1 only
    printf("V %d\n", sfvt_add_str(p1->ip_vartable, "MYNETS -> $HOME_NET", &var));

    set_ips_policy(p1);
    printf("POLICY now=%u user=%llu\n", get_ips_policy()->policy_id,
        (unsigned long long)get_ips_policy()->user_policy_id);

    // ---- R1: basic alert with real nets/ports ----------------------------
    OptTreeNode* o1 = make_rule("alert", "tcp", "$HOME_NET", "any", "->",
        "$EXT_NET", "[80,8080]", 1, 100, 2);
    printf("R1\n"); dump_otn(o1);
    walk_rule_lists();

    // ---- R2: dup same ids higher rev -> keeps new -------------------------
    OptTreeNode* o2 = make_rule("alert", "tcp", "$HOME_NET", "any", "->",
        "$EXT_NET", "[80,8080]", 1, 100, 3);
    printf("R2\n"); dump_otn(o2);
    dump_otn(OtnLookup(sc->otn_map, 1, 100));

    // ---- R3: dup lower rev -> keeps old, salvage rtn ----------------------
    OptTreeNode* o3 = make_rule("alert", "tcp", "$HOME_NET", "any", "->",
        "$EXT_NET", "[80,8080]", 1, 100, 1);
    printf("R3 after-lower-rev-dup\n");
    dump_otn(OtnLookup(sc->otn_map, 1, 100));

    // ---- R4: dup different protocol --------------------------------------
    make_rule("alert", "udp", "$HOME_NET", "any", "->", "$EXT_NET", "any", 1, 100, 5);
    printf("R4 after-proto-conflict\n"); dump_otn(OtnLookup(sc->otn_map, 1, 100));

    // ---- R5: dup different action ----------------------------------------
    make_rule("drop", "tcp", "$HOME_NET", "any", "->", "$EXT_NET", "[80,8080]", 1, 100, 6);
    printf("R5 after-action-conflict\n"); dump_otn(OtnLookup(sc->otn_map, 1, 100));

    // ---- R6: builtin gid range + pass, no options -------------------------
    make_rule("pass", "ip", "any", "any", "->", "any", "any", 50, 1, 1);
    printf("R6 builtin\n"); dump_otn(OtnLookup(sc->otn_map, 50, 1));

    // ---- R7: bidir + raw src ports ---------------------------------------
    make_rule("alert", "tcp", "[1.1.1.1,2.2.2.2]", "[10:20,!15]", "<>",
        "any", "any", 3000001, 7, 1);
    printf("R7 bidir\n"); dump_otn(OtnLookup(sc->otn_map, 3000001, 7));

    // ---- R8: error paths --------------------------------------------------
    reset_parse_errors();
    RuleTreeNode rtn8;
    parse_rule_type(sc, "$NOPE", rtn8);
    printf("R8 var-miss PE=%u\n", get_parse_errors()); reset_parse_errors();
    parse_rule_type(sc, "not_an_action", rtn8);
    printf("R8 bad-act PE=%u\n", get_parse_errors()); reset_parse_errors();
    parse_rule_type(sc, nullptr, rtn8);
    printf("R8 no-act PE=%u\n", get_parse_errors()); reset_parse_errors();
    OptTreeNode* nx = parse_rule_open(sc, rtn8, false);
    printf("R8 open-after-err=%d\n", nx ? 1 : 0);
    {
        RuleTreeNode rtn9;
        parse_rule_type(sc, "alert", rtn9);
        parse_rule_proto(sc, "boguproto", rtn9, false);
        printf("R9 badproto spid=%u PE=%u\n", rtn9.snort_protocol_id, get_parse_errors());
        reset_parse_errors();
    }
    {
        RuleTreeNode rtn9;
        parse_rule_type(sc, "alert", rtn9);
        parse_rule_proto(sc, "tcp", rtn9, false);
        parse_rule_nets(sc, "$UNDEFSRC", true, rtn9, false);
        printf("R9 undef-var PE=%u\n", get_parse_errors()); reset_parse_errors();
        parse_rule_proto(sc, "icmp", rtn9, false);
        parse_rule_ports(sc, "notaport", false, rtn9, false);
        printf("R9 abort-path? no: icmp bad dst PE=%u\n", get_parse_errors());
        reset_parse_errors();
    }

    // ---- counters (destructive policy counters!) --------------------------
    printf("COUNT r=%d lr=%d ls=%d\n", get_rule_count(),
        get_policy_loaded_rule_count(), get_policy_shared_rule_count());
    printf("COUNT2 r=%d lr=%d ls=%d\n", get_rule_count(),
        get_policy_loaded_rule_count(), get_policy_shared_rule_count());

    // ---- same_headers matrix ----------------------------------------------
    {
        RuleTreeNode a, b;
        parse_rule_type(sc, "alert", a);
        parse_rule_proto(sc, "tcp", a, false);
        parse_rule_nets(sc, "$HOME_NET", true, a, false);
        parse_rule_ports(sc, "any", true, a, false);
        parse_rule_proto(sc, "tcp", b, false);
        parse_rule_type(sc, "alert", b);
        parse_rule_nets(sc, "$HOME_NET", true, b, false);
        parse_rule_ports(sc, "any", true, b, false);
        printf("SH base=%d\n", same_headers(&a, &b) ? 1 : 0);
        b.action = IpsAction::get_type("drop");
        printf("SH act=%d\n", same_headers(&a, &b) ? 1 : 0);
        b.action = a.action; b.flags |= RuleTreeNode::BIDIRECTIONAL;
        printf("SH flags=%d\n", same_headers(&a, &b) ? 1 : 0);
        b.flags = a.flags; b.snort_protocol_id = 99;
        printf("SH spid=%d\n", same_headers(&a, &b) ? 1 : 0);
        b.snort_protocol_id = a.snort_protocol_id;
        b.src_portobject = a.src_portobject; b.dst_portobject = a.dst_portobject;
        printf("SH po-ptr-eq=%d (strict off)\n", same_headers(&a, &b) ? 1 : 0);
        PortVarTableAdd(p1->portVarTable, [&]{
            PortObject* po = PortObjectNew(); PortObjectAddPort(po, 80);
            po->name = snort_strdup("P80"); return po; }());
        PortObject* a80 = PortVarTableFind(p1->portVarTable, "P80", false);
        b.src_portobject = a80;
        printf("SH po-diff=%d strict-off\n", same_headers(&a, &b) ? 1 : 0);
        set_strict_rtn_reduction(true);
        printf("SH po-diff=%d strict-on (P80 vs any-content-equal? no)\n",
            same_headers(&a, &b) ? 1 : 0);
        RuleTreeNode c;
        parse_rule_type(sc, "alert", c);
        parse_rule_proto(sc, "tcp", c, false);
        parse_rule_nets(sc, "$HOME_NET", true, c, false);
        parse_rule_ports(sc, "$P80", true, c, false);
        printf("SH po-same-name strict-on=%d\n", same_headers(&a, &c) ? 1 : 0);
        set_strict_rtn_reduction(false);
        set_strict_rtn_reduction(true);
        printf("SH po-same-name strict-on re=%d\n", same_headers(&a, &c) ? 1 : 0);
        set_strict_rtn_reduction(false);
    }

    // ---- policy 2: rerun identical rules -> RTN sharing via reduce -------
    set_ips_policy(p2);
    OptTreeNode* q1 = make_rule("alert", "tcp", "$HOME_NET", "any", "->",
        "$EXT_NET", "[80,8080]", 1, 100, 3);
    printf("P2-R1 same-ids\n"); dump_otn(OtnLookup(sc->otn_map, 1, 100));

    reduce_rtns(sc);
    printf("P2 after-reduce p2user=%llu shared p1=%d p2=%d\n",
        (unsigned long long)p2->user_policy_id, p1->rules_shared, p2->rules_shared);
    dump_otn(OtnLookup(sc->otn_map, 1, 100));

    // ---- RuleStateMap ------------------------------------------------------
    p1->commit_action_variable("RA", "drop", nullptr);
    {
        RuleKey k1 { 1, 3000001, 7 };
        RuleKey k2 { 1, 999, 999 };   // unknown rule
        RuleState s1 { "$RA", 0, 0, IpsPolicy::DISABLED };
        RuleState s2 { "alert", IpsAction::get_type("alert"), 0, IpsPolicy::ENABLED };
        sc->rule_states->add(k1, s1);
        sc->rule_states->add(k2, s2);
        get_parse_errors(); // burn
        sc->rule_states->apply(sc);
        printf("STATE apply PE=%u PW=%u\n", get_parse_errors(), get_parse_warnings());
        dump_otn(OtnLookup(sc->otn_map, 3000001, 7));
    }
    {
        // global_rule_state fan-out
        sc->global_rule_state = true;
        RuleKey k3 { 0, 1, 100 };
        RuleState s3 { "drop", IpsAction::get_type("drop"), 0, IpsPolicy::ENABLED };
        sc->rule_states->add(k3, s3);
        sc->rule_states->apply(sc);
        printf("STATE global PE=%u\n", get_parse_errors());
        sc->global_rule_state = false;
        dump_otn(OtnLookup(sc->otn_map, 1, 100));
    }
    {
        // $-action var with unknown name -> fatal? no: ParseError false
        RuleKey k4 { 1, 3000001, 7 };
        RuleState s4 { "$GHOST", 0, 0, IpsPolicy::INHERIT_ENABLE };
        sc->rule_states->add(k4, s4);
        sc->rule_states->apply(sc);
        printf("STATE ghost-var PE=%u\n", get_parse_errors());
        dump_otn(OtnLookup(sc->otn_map, 3000001, 7));
    }

    // ---- delete/free lifecycle --------------------------------------------
    {
        OptTreeNode* otn = OtnLookup(sc->otn_map, 1, 100);
        RuleTreeNode* r0 = deleteRtnFromOtn(otn, 0, sc);
        printf("DEL p0 refc=%u destroy\n", r0 ? r0->otnRefCount : 0xDEAD);
        DestroyRuleTreeNode(r0);
        RuleTreeNode* r1 = deleteRtnFromOtn(otn, 1, sc);
        dump_rtn("DEL p1", r1);
        DestroyRuleTreeNode(r1);
        dump_otn(otn);
    }

    // ---- rule index map ----------------------------------------------------
    // ---- direct rule-index-map API (sfrim coverage) ------------------------
    rule_index_map_t* rim = RuleIndexMapCreate();
    printf("RIM add %d %d %d\n", RuleIndexMapAdd(rim, 5, 50),
        RuleIndexMapAdd(rim, 5, 50), RuleIndexMapAdd(rim, 6, 60));
    unsigned gg = 0, ss = 0;
    printf("RIM get %d %u:%u\n", RuleIndexMapGet(rim, 0, gg, ss) ? 1 : 0, gg, ss);
    printf("RIM get %d\n", RuleIndexMapGet(rim, 9, gg, ss) ? 1 : 0);
    RuleIndexMapFree(rim);

    // tear otn map (exercises ~OptTreeNode + FreeRuleTreeNodes path)
    delete sc->otn_map; sc->otn_map = nullptr;
    printf("DONE\n");
    return 0;
}

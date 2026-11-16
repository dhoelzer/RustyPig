// Probe driver for the rule-tree core. Drives ORIGINAL parse_rule.cc +
// parser.cc (RTN lifecycle) + rules.cc (RuleStateMap) + signature.cc
// (OtnLookup) + sfrim.cc (rule index map) over synthesized rules and
// emits deterministic vectors. The ips_options meta layer (sid/rev/msg/
// gid options) is out of scope: the probe assigns sigInfo fields after
// parse_rule_open, and options flow through parse_rule_opt_* into the
// IpsManager witness, which returns REAL base IpsOptions (framework/
// ips_option.cc compiled) for probe-registered keywords.
#include "main/snort_config.h"
#include "main/policy.h"
#include "main/thread.h"
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
#include "log/log_errors.h"
#include "utils/util_cstring.h"
#include "utils/util.h"
#include <cstdio>



#include <cstring>
#include <memory>

using namespace snort;

extern SnortConfig* g_probe_sc;
void reduce_rtns(SnortConfig* sc);  // static->global in the copy slice (build.sh)
unsigned probe_register_action(const char* n, int prio);
void probe_register_option(const char* n);
const char* probe_action_name(IpsAction::Type t);

static SnortConfig* sc = nullptr;

static void dump_rtn(const char* tag, const RuleTreeNode* rtn)
{
    if ( !rtn ) { printf("%s NIL\n", tag); return; }
    printf("%s act=%s(%u) sel=%u spid=%u flags=%02X en=%d refc=%u sip=%s dip=%s spo=%s dpo=%s nrf=%u\n",
        tag, probe_action_name(rtn->action), rtn->action, rtn->action_selector,
        rtn->snort_protocol_id, rtn->flags, rtn->enabled() ? 1 : 0,
        rtn->otnRefCount,
        rtn->sip ? (rtn->sip->name ? rtn->sip->name : "~") : "NIL",
        rtn->dip ? (rtn->dip->name ? rtn->dip->name : "~") : "NIL",
        rtn->src_portobject ? (rtn->src_portobject->name ? rtn->src_portobject->name : "~raw") : "NIL",
        rtn->dst_portobject ? (rtn->dst_portobject->name ? rtn->dst_portobject->name : "~raw") : "NIL",
        (unsigned)(rtn->rule_func ? 1 : 0));   // rule-func list installed? (transfer_rtn)
}

static void dump_otn(const OptTreeNode* otn)
{
    if ( !otn ) { printf("OTN NIL\n"); return; }
    printf("OTN %u:%u:%u spid=%u nodes=%u ri=%u ndo=%u flags=%02X en=%d body=%s svc_only=%d\n",
        otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev,
        otn->snort_protocol_id, otn->proto_node_num, otn->ruleIndex,
        otn->num_detection_opts, otn->flags, (int)otn->enable,
        otn->sigInfo.body ? otn->sigInfo.body->c_str() : "-",
        otn->service_only() ? 1 : 0);
    for ( const SignatureServiceInfo& si : otn->sigInfo.services )
        printf("  SVC %s:%u\n", si.service.c_str(), si.snort_protocol_id);
    for ( unsigned i = 0; i < otn->proto_node_num; ++i )
        dump_rtn("  RTN", otn->proto_nodes[i]);
}

static void walk_rule_lists()
{
    for ( const RuleListNode* p = sc->rule_lists; p; p = p->next )
        printf("RLIST %s mode=%u eval=%u\n", p->name, p->mode, p->evalIndex);
}

static void print_stats(const char* tag, unsigned fb1, unsigned fb2, unsigned fb3)
{
    printf("STATS %s\n", tag);
    parse_rule_print(fb1, fb2, fb3);
}

// Build one rule the way parse_stream drives the API, assigning gid/sid/rev
// manually (meta-option stand-in). Returns the final OTN (or nullptr).
static OptTreeNode* make_rule(const char* action, const char* proto,
    const char* nets_s, const char* ports_s, const char* dir,
    const char* nets_d, const char* ports_d,
    uint32_t gid, uint32_t sid, uint32_t rev,
    bool with_options = true)
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
    if ( !otn )
    {
        printf("OPEN null (ignore)\n");
        // the real stream always reaches ParseEndofRule; parse_rule_close
        // clears s_ignore in its guard before any otn deref (original code).
        parse_rule_close(sc, rtn, nullptr);
        return nullptr;
    }
    otn->sigInfo.gid = gid;
    otn->sigInfo.sid = sid;
    otn->sigInfo.rev = rev;
    // options arrive through the parse_rule_opt_* channel exactly as
    // parse_stream drives it; the IpsManager witness builds REAL base
    // IpsOptions (framework/ips_option.cc compiled), so opt_end bookkeeping
    // (num_detection_opts, sections, buffer_setters) is ORIGINAL code.
    if ( with_options )
    {
        parse_rule_opt_begin(sc, "content");
        parse_rule_opt_set(sc, "content", "content", "|abc|");
        parse_rule_opt_end(sc, "content", otn);
        parse_rule_opt_begin(sc, "sid");   // unregistered keyword -> option_begin false
        parse_rule_opt_set(sc, "sid", "sid", "x");
        parse_rule_opt_end(sc, "sid", otn);
    }
    parse_rule_close(sc, rtn, otn);
    return otn;
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    set_thread_type(STHREAD_TYPE_MAIN);

    // fixed action registration order (pin; upstream = plugin init order)
    // FATAL-DEMO: upstream, both undefined port vars and unparseable raw
    // port list literals go through ParseAbort -> FatalError, which always
    // terminates the process ("Fatal Error, Quitting.." when in main
    // thread). Pinned as a subprocess transcript: run with FATAL=n where
    // n=1 (undefined $VAR port) or n=2 (raw literal parse error).
    {
        const char* fd = getenv("FATAL_DEMO");
        if ( fd )
        {
            int mode = atoi(fd);
            sc = new SnortConfig();
            g_probe_sc = sc;
            PolicyMap* pm = new PolicyMap();
            IpsPolicy* p1 = new IpsPolicy(1);
            pm->ips_policy.push_back(p1);
            pm->set_user_ips(p1);
            sc->policy_map = pm;
            sc->otn_map = OtnLookupNew();
            sc->port_tables = PortTablesNew();
            sc->proto_ref = new ProtocolReference();
            parser_init();
            set_thread_type(STHREAD_TYPE_MAIN);
            probe_register_action("alert", 20);
            set_ips_policy(p1);
            RuleTreeNode rta;
            parse_rule_type(sc, "alert", rta);
            parse_rule_proto(sc, "tcp", rta, false);
            parse_rule_nets(sc, "any", true, rta, false);
            if ( mode == 1 )
                parse_rule_ports(sc, "$NOPE", true, rta, false);
            else if ( mode == 2 )
                parse_rule_ports(sc, "notaport", true, rta, false);
            else
                // mode 3: ParseAbort flows through the REAL parse_stream
                // FSM (header port var) and must terminate the process.
                parse_rules_string(sc,
                    "alert tcp any $NOPE -> any any (sid:9; rev:1;)\n", false);
            printf("unreachable\n");
            return 0;
        }
    }

    struct { const char* n; int prio; } acts[] = {
        { "drop", 40 }, { "sdrop", 40 }, { "reject", 60 }, { "rejectboth", 60 },
        { "rejectip", 60 }, { "dropflow", 40 }, { "rejectflow", 60 },
        { "alert", 20 }, { "pass", 70 }, { "log", 10 }, { "file", 10 },
        { "file_id", 10 }, { "proximity", 10 }, { "url", 10 },
        { "react", 30 }, { "close", 20 } };
    for ( auto& a : acts ) probe_register_action(a.n, a.prio);
    printf("ACTMAX %u alert=%u pass=%u file=%u bogus=%u\n",
        IpsAction::get_max_types(), IpsAction::get_type("alert"),
        IpsAction::get_type("pass"), IpsAction::get_type("file"),
        IpsAction::get_type("not_an_action"));
    printf("ACTSTR %s %s\n", probe_action_name(IpsAction::get_type("alert")),
        probe_action_name(IpsAction::get_max_types()));
    printf("PRIOS %s\n", IpsAction::get_default_priorities(false).c_str());
    printf("PRIOSABP %s\n", IpsAction::get_default_priorities(true).c_str());
    // option keywords for the IpsManager witness (meta layer stand-in:
    // content = buffer setter w/ cursor; flowbits-like off here)
    probe_register_option("content");

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

    // ---- R8: error paths. Upstream: ONLY parse_rule_type sets s_ignore
    // (action errors); net/port/proto errors ParseError but do NOT latch,
    // so the rule continues and still gets an OTN + close. parse_rule_close
    // derefs otn only after its s_ignore guard, so a null otn reaches the
    // deref iff not latched (real streams never pass null then).
    reset_parse_errors();
    {
        RuleTreeNode rta;
        parse_rule_type(sc, "$NOPE", rta);
        printf("R8 var-miss PE=%u\n", get_parse_errors()); reset_parse_errors();
        parse_rule_close(sc, rta, nullptr);       // latched -> guard, skip_count++
    }
    {
        RuleTreeNode rta;
        parse_rule_type(sc, "not_an_action", rta);
        printf("R8 bad-act PE=%u\n", get_parse_errors()); reset_parse_errors();
        OptTreeNode* nx = parse_rule_open(sc, rta, false);
        printf("R8 open-after-err=%d\n", nx ? 1 : 0);
        parse_rule_close(sc, rta, nx);
    }
    {
        RuleTreeNode rta;
        parse_rule_type(sc, nullptr, rta);
        printf("R8 no-act PE=%u\n", get_parse_errors()); reset_parse_errors();
        parse_rule_close(sc, rta, nullptr);
    }
    {
        // bad protocol NAME: ProtocolReference::add() allocates a new id
        // (no latch, no error); rule still flows through the full header.
        RuleTreeNode rta;
        parse_rule_type(sc, "alert", rta);
        parse_rule_proto(sc, "boguproto", rta, false);
        printf("R9 badproto spid=%u PE=%u\n", rta.snort_protocol_id, get_parse_errors());
        parse_rule_nets(sc, "any", true, rta, false);
        parse_rule_ports(sc, "any", true, rta, false);
        parse_rule_dir(sc, "->", rta, false);
        parse_rule_nets(sc, "any", false, rta, false);
        parse_rule_ports(sc, "any", false, rta, false);
        OptTreeNode* o9 = parse_rule_open(sc, rta, false);
        printf("R9 open=%d\n", o9 ? 1 : 0);
        if ( o9 ) { o9->sigInfo.gid = 1; o9->sigInfo.sid = 899; o9->sigInfo.rev = 1; }
        parse_rule_close(sc, rta, o9);
        printf("R9 added=%d PE=%u\n",
            OtnLookup(sc->otn_map, 1, 899) ? 1 : 0, get_parse_errors());
        reset_parse_errors();
    }
    {
        // undef src var: ProcessIP ParseErrors, returns -1, NO latch; rtn->sip
        // keeps the calloc'd empty var (head null); rule still added.
        RuleTreeNode rta;
        parse_rule_type(sc, "alert", rta);
        parse_rule_proto(sc, "tcp", rta, false);
        parse_rule_nets(sc, "$UNDEFSRC", true, rta, false);
        printf("R10 undef-var PE=%u\n", get_parse_errors()); reset_parse_errors();
        parse_rule_ports(sc, "any", true, rta, false);
        parse_rule_dir(sc, "->", rta, false);
        parse_rule_nets(sc, "any", false, rta, false);
        parse_rule_ports(sc, "any", false, rta, false);
        OptTreeNode* o10 = parse_rule_open(sc, rta, false);
        if ( o10 ) { o10->sigInfo.gid = 1; o10->sigInfo.sid = 898; o10->sigInfo.rev = 1; }
        parse_rule_close(sc, rta, o10);
        dump_otn(OtnLookup(sc->otn_map, 1, 898));
        printf("R10 PE=%u\n", get_parse_errors()); reset_parse_errors();
    }
    {
        // negated-only IP list: ProcessIP conflict error, no latch
        RuleTreeNode rta;
        parse_rule_type(sc, "alert", rta);
        parse_rule_proto(sc, "ip", rta, false);
        parse_rule_nets(sc, "![10.0.0.0/8]", true, rta, false);
        printf("R10b negated-conflict PE=%u\n", get_parse_errors()); reset_parse_errors();
        parse_rule_ports(sc, "any", true, rta, false);
        parse_rule_dir(sc, "->", rta, false);
        parse_rule_nets(sc, "any", false, rta, false);
        parse_rule_ports(sc, "any", false, rta, false);
        OptTreeNode* ob = parse_rule_open(sc, rta, false);
        if ( ob ) { ob->sigInfo.gid = 1; ob->sigInfo.sid = 895; ob->sigInfo.rev = 1; }
        parse_rule_close(sc, rta, ob);
        printf("R10b added=%d\n", OtnLookup(sc->otn_map, 1, 895) ? 1 : 0);
    }
    // in-process note: undefined $port vars and bad raw port literals are
    // ParseAbort (fatal) upstream -> FATAL_DEMO subprocess only (see below).
    {
        // pure-not ports ("![80:90]"): ParseError "Pure NOT ports are not
        // allowed.", no latch
        RuleTreeNode rta;
        parse_rule_type(sc, "alert", rta);
        parse_rule_proto(sc, "tcp", rta, false);
        parse_rule_nets(sc, "any", true, rta, false);
        parse_rule_ports(sc, "![80:90]", true, rta, false);
        printf("R11b pure-not PE=%u\n", get_parse_errors()); reset_parse_errors();
        parse_rule_dir(sc, "->", rta, false);
        parse_rule_nets(sc, "any", false, rta, false);
        parse_rule_ports(sc, "any", false, rta, false);
        OptTreeNode* o11b = parse_rule_open(sc, rta, false);
        if ( o11b ) { o11b->sigInfo.gid = 1; o11b->sigInfo.sid = 896; o11b->sigInfo.rev = 1; }
        parse_rule_close(sc, rta, o11b);
        printf("R11b added=%d\n", OtnLookup(sc->otn_map, 1, 896) ? 1 : 0);
    }

    // ---- service protocol rule + service_extension (add_service path)
    sc->service_extension["http"] = { "http2" };
    make_rule("alert", "http", "$HOME_NET", "any", "->", "$EXT_NET", "[80]", 1, 900, 1);
    printf("R12 svc\n"); dump_otn(OtnLookup(sc->otn_map, 1, 900));
    printf("R12 PE=%u\n", get_parse_errors()); reset_parse_errors();

    // ---- file_id action: close-time ParseErrors (no options) -------------
    make_rule("file_id", "tcp", "any", "any", "->", "any", "any", 1, 901, 1, false);
    printf("R13 file-id PE=%u added=%d\n", get_parse_errors(),
        OtnLookup(sc->otn_map, 1, 901) ? 1 : 0);
    reset_parse_errors();

    // ---- so-rule stub with missing rule (SoManager -> null) --------------
    {
        RuleTreeNode rtnS;
        parse_rule_type(sc, "alert", rtnS);
        parse_rule_proto(sc, "tcp", rtnS, false);
        parse_rule_nets(sc, "any", true, rtnS, false);
        parse_rule_ports(sc, "any", true, rtnS, false);
        parse_rule_dir(sc, "->", rtnS, false);
        parse_rule_nets(sc, "any", false, rtnS, false);
        parse_rule_ports(sc, "any", false, rtnS, false);
        OptTreeNode* otnS = parse_rule_open(sc, rtnS, false);
        otnS->sigInfo.gid = 1; otnS->sigInfo.sid = 902; otnS->sigInfo.rev = 1;
        otnS->soid = snort_strdup("SOMISSING");
        parse_rule_close(sc, rtnS, otnS);
        printf("R14 so-missing PE=%u lookup=%d\n", get_parse_errors(),
            OtnLookup(sc->otn_map, 1, 902) ? 1 : 0);
        reset_parse_errors();
        sc->allow_missing_so_rules = true;
        RuleTreeNode rtnT;
        parse_rule_type(sc, "alert", rtnT);
        parse_rule_proto(sc, "tcp", rtnT, false);
        parse_rule_nets(sc, "any", true, rtnT, false);
        parse_rule_ports(sc, "any", true, rtnT, false);
        parse_rule_dir(sc, "->", rtnT, false);
        parse_rule_nets(sc, "any", false, rtnT, false);
        parse_rule_ports(sc, "any", false, rtnT, false);
        OptTreeNode* otnT = parse_rule_open(sc, rtnT, false);
        otnT->sigInfo.gid = 1; otnT->sigInfo.sid = 904; otnT->sigInfo.rev = 1;
        otnT->soid = snort_strdup("SOMISSING2");
        parse_rule_close(sc, rtnT, otnT);
        printf("R14b so-missing-warn PE=%u PW=%u lookup=%d\n", get_parse_errors(),
            get_parse_warnings(), OtnLookup(sc->otn_map, 1, 904) ? 1 : 0);
        reset_parse_errors();
        sc->allow_missing_so_rules = false;
    }

    // ---- rule-state stub channel (otn RULE_STATE flag -> parse_rule_state)
    {
        RuleTreeNode rtnQ;
        parse_rule_type(sc, "drop", rtnQ);
        parse_rule_proto(sc, "tcp", rtnQ, false);
        parse_rule_nets(sc, "any", true, rtnQ, false);
        parse_rule_ports(sc, "any", true, rtnQ, false);
        parse_rule_dir(sc, "->", rtnQ, false);
        parse_rule_nets(sc, "any", false, rtnQ, false);
        parse_rule_ports(sc, "any", false, rtnQ, false);
        OptTreeNode* otnQ = parse_rule_open(sc, rtnQ, false);
        otnQ->sigInfo.gid = 1; otnQ->sigInfo.sid = 100; otnQ->sigInfo.rev = 9;
        otnQ->set_enabled(IpsPolicy::DISABLED);   // sets RULE_STATE flag
        parse_rule_opt_begin(sc, "content");
        parse_rule_opt_set(sc, "content", "content", "|q|");
        parse_rule_opt_end(sc, "content", otnQ);
        parse_rule_close(sc, rtnQ, otnQ);          // RULE_STATE -> parse_rule_state
        OptTreeNode* live = OtnLookup(sc->otn_map, 1, 100);
        printf("R15 state-stub PE=%u rev=%u\n", get_parse_errors(),
            live ? live->sigInfo.rev : 0);
        dump_otn(live);
        reset_parse_errors();
    }

    // ---- metadata filter skip (close deletes otn, skip_count++) ----------
    {
        sc->metadata_filter = "nope";
        make_rule("alert", "tcp", "any", "any", "->", "any", "any", 1, 903, 1);
        printf("R16 meta-skip lookup=%d PE=%u\n",
            OtnLookup(sc->otn_map, 1, 903) ? 1 : 0, get_parse_errors());
        sc->metadata_filter.clear();
        reset_parse_errors();
    }

    // ---- counters (destructive policy counters!) --------------------------
    print_stats("pre-counters", 0, 0, 0);
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
    q1 = make_rule("alert", "tcp", "any", "[80,8080]", "<>", "any", "[80,8080]", 1, 910, 1);
    printf("P2-R2 bidir-finish-ports\n"); dump_otn(OtnLookup(sc->otn_map, 1, 910));

    print_stats("pre-reduce", 0, 0, 0);
    reduce_rtns(sc);
    printf("P2 after-reduce p2user=%llu shared p1=%d p2=%d\n",
        (unsigned long long)p2->user_policy_id, p1->rules_shared, p2->rules_shared);
    dump_otn(OtnLookup(sc->otn_map, 1, 100));
    dump_otn(OtnLookup(sc->otn_map, 1, 910));

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
        RuleKey k3 { 0, 1, 910 };
        RuleState s3 { "drop", IpsAction::get_type("drop"), 0, IpsPolicy::ENABLED };
        sc->rule_states->add(k3, s3);
        sc->rule_states->apply(sc);
        printf("STATE global PE=%u\n", get_parse_errors());
        sc->global_rule_state = false;
        dump_otn(OtnLookup(sc->otn_map, 1, 910));
    }
    {
        // $-action var with unknown name -> ParseError (policy present)
        RuleKey k4 { 1, 3000001, 7 };
        RuleState s4 { "$GHOST", 0, 0, IpsPolicy::INHERIT_ENABLE };
        sc->rule_states->add(k4, s4);
        sc->rule_states->apply(sc);
        printf("STATE ghost-var PE=%u\n", get_parse_errors());
        dump_otn(OtnLookup(sc->otn_map, 3000001, 7));
    }
    {
        // state for the builtin pass rule via policy 0 (empty ips): the
        // empty policy id is skipped in the global fan-out path; direct-id
        // path applies to p0 slot of Otn 50:1.
        RuleKey k5 { 0, 50, 1 };
        RuleState s5 { "drop", IpsAction::get_type("drop"), 0, IpsPolicy::DISABLED };
        sc->rule_states->add(k5, s5);
        sc->rule_states->apply(sc);
        printf("STATE p0-slot PE=%u\n", get_parse_errors());
        dump_otn(OtnLookup(sc->otn_map, 50, 1));
    }

    // ---- delete/free lifecycle --------------------------------------------
    {
        OptTreeNode* otn = OtnLookup(sc->otn_map, 1, 100);
        RuleTreeNode* r0 = deleteRtnFromOtn(otn, 0, sc);
        printf("DEL p0 nil=%d refc=%u\n", r0 ? 0 : 1, r0 ? r0->otnRefCount : 0xDEAD);
        if ( r0 ) DestroyRuleTreeNode(r0);   // DestroyRuleTreeNode asserts non-null
        RuleTreeNode* r1 = deleteRtnFromOtn(otn, 1, sc);
        printf("DEL p1 refc=%u\n", r1 ? r1->otnRefCount : 0xDEAD);
        if ( r1 ) DestroyRuleTreeNode(r1);
        RuleTreeNode* r2 = deleteRtnFromOtn(otn, 2, sc);
        printf("DEL p2 refc=%u\n", r2 ? r2->otnRefCount : 0xDEAD);
        if ( r2 ) DestroyRuleTreeNode(r2);
        dump_otn(otn);
    }

    // ---- direct rule-index-map API (sfrim coverage) ------------------------
    rule_index_map_t* rim = RuleIndexMapCreate();
    printf("RIM add %d %d %d\n", RuleIndexMapAdd(rim, 5, 50),
        RuleIndexMapAdd(rim, 5, 50), RuleIndexMapAdd(rim, 6, 60));
    unsigned gg = 0, ss = 0;
    printf("RIM get %d %u:%u\n", RuleIndexMapGet(rim, 0, gg, ss) ? 1 : 0, gg, ss);
    printf("RIM get %d\n", RuleIndexMapGet(rim, 9, gg, ss) ? 1 : 0);
    RuleIndexMapFree(rim);
    {
        char buf[64] = "PRE>";
        int idx = parser_get_rule_index(77, 88);
        rule_index_map_print_index(idx, buf, sizeof(buf));
        printf("RIMPRINT idx=%d [%s]\n", idx, buf);
        unsigned g2 = 0, s2 = 0;
        parser_get_rule_ids(idx, g2, s2);
        printf("RIMIDS %u:%u\n", g2, s2);
    }

    // ---- stats print (real parse_rule_print -> LogLabel/LogCount via
    // real log_stats.cc + messages.cc; flowbits counters from witness) ----
    print_stats("final-fb0", 0, 0, 0);
    print_stats("final-fb3", 3, 1, 2);

    // ---- parser_append_* (real parse_conf.cc; stream now REAL:
    // parser/parse_stream.cc compiled verbatim) ----
    parser_append_rules("alert tcp any any -> any 80 (sid:1; rev:1;)");
    parser_append_rules_special("pass ip any any -> any any (sid:2; rev:1;)", "INC");
    printf("SPECIAL-INC %s\n", parser_get_special_includer());

    // ---- parse_stream end-to-end (real get_token FSM + get_state + exec)
    // sid band 10-16 untouched elsewhere. warning_flags stays 0 (upstream
    // default, snort_config.cc:110) so the FSM escape/string warnings bump
    // the counter but print nothing: PW= pins the latch. ----
    parse_rules_string(sc,
        "alert ip any any -> any any (msg:\"R10\"; sid:10; rev:1;)\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET [80,443] (msg:\"R11\"; sid:11; rev:1; content:\"abc\";)\n",
        false);
    printf("S1 PE=%u PW=%u\n", get_parse_errors(), get_parse_warnings());
    {
        // meta layer doubled: sid never reaches sigInfo -> the OTN lands
        // under key (1,0); R11 (tcp) hits the dup/protocol type error.
        OptTreeNode* o = OtnLookup(sc->otn_map, 1, 0);
        printf("S1 otn(1,0)=1 spid=%u ndo=%u ruleIdx=%d\n",
            o->snort_protocol_id, o->num_detection_opts, o->ruleIndex);
        printf("S1 miss(1,10)=%d miss(1,11)=%d\n",
            (int)!OtnLookup(sc->otn_map, 1, 10), (int)!OtnLookup(sc->otn_map, 1, 11));
    }
    // tokenizer escapes + errors
    reset_parse_errors();
    parse_rules_string(sc,
        "alert tcp any any -> any any (sid:12; rev:1; content:\"a\\x41b\";)  # tail comment\n"
        "alert tcp any any -> any any (sid:13; rev:1\\n"
        "alert tcp any any - any any (sid:14; rev:1;)\n"
        "alert tcp any any >> any any (sid:15; rev:1;)\n",
        false);
    printf("S2 PE=%u PW=%u\n", get_parse_errors(), get_parse_warnings());
    {
        OptTreeNode* o = OtnLookup(sc->otn_map, 1, 12);
        RuleTreeNode* r = (o && o->proto_node_num) ? o->proto_nodes[0] : nullptr;
        printf("S2 R12 dpo=%s ndo=%u\n",
            r && r->dst_portobject && r->dst_portobject->name
                ? r->dst_portobject->name : "-", o ? o->num_detection_opts : 0);
        printf("S2 R14=%d R15=%d\n", (int)!!OtnLookup(sc->otn_map, 1, 14),
            (int)!!OtnLookup(sc->otn_map, 1, 15));
    }
    // include channel (real parse_include: ExpandVars + get_config_file +
    // can't-open ParseError; depth stays 0 so no location is pushed)
    reset_parse_errors();
    parse_rules_string(sc, "include no_such_file.conf\n", false);
    printf("S3 PE=%u\n", get_parse_errors());

    // tear otn map (exercises ~OptTreeNode + FreeRuleTreeNodes path)
    delete sc->otn_map; sc->otn_map = nullptr;
    printf("DONE\n");
    return 0;
}

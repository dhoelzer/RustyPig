// 19a FACE-A -- framework/module.cc is the FRAMEWORK Module base TU, NOT a
// table-carrying TU (PLAN §8 + the briefing's spec correction): the link-era
// FACE-A walk (hidden table -> LOAD lines -> CodecApi ver=/size=) NEVER fits
// here -- BUILDING_SO grep-0 x4 + snort_plugins grep-0 x4 MEASURED over
// module.cc/h + reload_tracker.cc/h (scratch receipts row19a; re-run by
// build.sh EVERY build). The line-# cites below are ground module.cc/module.h
// faces (fe29cbe sed-sed): the record shape (ctor :56-:58/:60-:67, init
// :53-:58 with params = null_params :59 -- the HIDDEN null_params Parameter
// table :32-:35 of module.o, walked for real through get_parameters(),
// module.h :136), the is_table/is_list/get_type face (module.h :113-:133),
// the default-virtual census (matches :104, get_gid :107, get_rules :150,
// get_pegs :153, get_commands :147, get_profile :160/:165, get_defaults
// :171, global_stats :177, stats_are_aggregated :182, is_aggregator :187,
// is_bindable :245, counts_need_prep :156, get_usage :241 -- Usage enum
// module.h :216 GLOBAL<CONTEXT<INSPECT<DETECT, DEC-walked in build.sh), the
// Command::get_arg_list walk (module.cc :37-:50: "p and p->name" gate :42 +
// ", " joiner :45) and the verified-trio list guard (module.cc :376-:390:
// verified_set returns FALSE for a LIST while table_level < 2 :379-:380).
// NO table LOAD, NO version/size line: an honest framework-TU face
// (cite-never-fabricate law; the absence face IS the vector line #1).
#include "framework/module.h"
#include "framework/counts.h"
#include <cstdio>
#include <cstring>
using namespace snort;

struct ProbeModule : public Module {
    ProbeModule(const char* s, const char* h) : Module(s, h) { }
    ProbeModule(const char* s, const char* h, const Parameter* p, bool l) : Module(s, h, p, l) { }
};

// the probe-side table rides the SAME inline Parameter ctor as the ground
// null_params rows (module.cc :34, parameter.h :74) -- names are face text,
// the walk COUNT/order and the sentinel Type ordinal are what vectorize.
static const Parameter two_params[] = {
    Parameter("one", Parameter::PT_INT, nullptr, "1", "first arg"),
    Parameter("two", Parameter::PT_STRING, nullptr, nullptr, "second arg"),
    Parameter(nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr)   // sentinel shape cite module.cc :34
};

static int walk_entries(const Parameter* p) { int n = 0; while (p and p->name) { ++n; ++p; } return n; }

int main()
{
    printf("NOLOAD framework-TU BUILDING_SO-grep0-x4 snort_plugins-grep0-x4\n");   // the honest absence face (module.cc/h + cc/h, every build)

    ProbeModule a("modA", "help A");                                  // 2-arg protected ctor module.h :227
    ProbeModule b("modB", "help B", two_params, false);               // 3-arg ctor module.h :228, is_list=false
    ProbeModule c("modC", "help C", two_params, true);                // the LIST face module.cc :65

    printf("REC a is_table=%d is_list=%d type=%d\n",
           (int)a.is_table(), (int)a.is_list(), (int)a.get_type());   // 2-arg ctor h:225 -> name!=null table face h:117
    printf("REC b is_table=%d is_list=%d type=%d\n",
           (int)b.is_table(), (int)b.is_list(), (int)b.get_type());   // 3-arg h:226 is_list=false
    printf("REC c is_table=%d is_list=%d type=%d\n",
           (int)c.is_table(), (int)c.is_list(), (int)c.get_type());   // PT_LIST arm module.h :125-:126

    // the HIDDEN null_params table walk (module.o static :32 via init :59 ->
    // get_parameters(); entries=0 because entry0.name==nullptr; entry0.type
    // rides the PT_MAX sentinel ordinal -- ground-walked in build.sh PYPIN):
    printf("NULLWALK entries=%d sentinel_type=%d\n",
           walk_entries(a.get_parameters()), (int)a.get_parameters()[0].type);
    // Command::get_arg_list over BOTH tables (module.cc :37-:50):
    Command cmd_default { "cmd", nullptr, a.get_parameters(), nullptr };
    Command cmd_two     { "cmd", nullptr, two_params, nullptr };
    printf("ARGS default %s\n", cmd_default.get_arg_list().c_str());
    printf("ARGS two %s\n", cmd_two.get_arg_list().c_str());

    // default-virtual census (every arm module.h sed-pinned above):
    std::string lua;
    printf("DEFS gid=%u rules=%d pegs=%d cmds=%d prof=%d defaults=%d bind=%d agg=%d statagg=%d global=%d prep=%d matches=%d usage=%d\n",
           a.get_gid(), (int)(a.get_rules() != nullptr), (int)(a.get_pegs() != nullptr),
           (int)(a.get_commands() != nullptr), (int)(a.get_profile() != nullptr),
           (int)(a.get_defaults() != nullptr), (int)a.is_bindable(), (int)a.is_aggregator(),
           (int)a.stats_are_aggregated(), (int)a.global_stats(), (int)a.counts_need_prep(),
           (int)a.matches("p", lua), (int)a.get_usage());

    // verified trio (module.cc :376-:394): TABLE arm all-true; LIST arm set=0
    // (list-guard :383-:384, table_level==1 after verified_begin :378).
    // R6-clone law: state-mutating calls stored to bool VARS before printf
    // (argument-eval order is UNSEQUENCED -- table_level++ in verified_begin
    // must precede verified_set's guard read, NEVER rely on arg order).
    Value v(true);   // Value(bool) value.h:44 (unambiguous arm; set() body NEVER reads it -- Module::set default h:98 returns TRUE)
    bool rb = b.verified_begin("f", 0, nullptr);              // :376-:380 (table_level++)
    bool rs = b.verified_set("f", v, nullptr);                // :382-:387
    bool re = b.verified_end("f", 0, nullptr);                // :390-:394 (table_level--)
    printf("VERB table begin=%d set=%d end=%d\n", (int)rb, (int)rs, (int)re);
    bool cb = c.verified_begin("f", 0, nullptr);
    bool cs = c.verified_set("f", v, nullptr);                // list guard :383-:384 FALSE (table_level 1 < 2)
    bool ce = c.verified_end("f", 0, nullptr);
    printf("VERB list begin=%d set=%d end=%d\n", (int)cb, (int)cs, (int)ce);
    printf("order nullwalk:table:32->init:59->get:136 | set-list-guard:384-before-end:390\n");   // eval-order cite (measured ground lines)
    return 0;
}

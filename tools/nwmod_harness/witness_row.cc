// witness_row.cc — row 24k witness mirror (shape-only capture legs for the
// NEVER-LAND walls the row .o's OWN nm -C census enumerates (plain face
// MEASURED every build), plus the REAL-leg strays the four REAL legs drag
// and CANNOT close). EVERY name + namespace placement rides the row's OWN
// raw-NAME nm -C CENSUS face — the compiler ENFORCED the restructure
// honestly. The FOUR legs that link REAL and are NEVER mirrored here:
// framework/module.cc (the Module base the row ctor rides + the REAL
// Command::get_arg_list the commands census drives), framework/parameter.cc
// (the REAL Parameter::get_range + find + index + get_uint the tables and
// FACE-A ride), parser/config_file.cc (the REAL GetChecksumFlags machine
// behind ConfigChecksumDrop/ConfigChecksumMode — the row's OWN set() legs
// drive it) and framework/value.cc (the REAL Value home; the set() drivers
// ride the header INLINES + this leg). The row's OWN two cc-file-statics
// (network_params :37 + network_set_policy :73) are NEVER mirrored — the
// ROW TU DEFINES them (the E9 twin law); the two non-static tables
// (network_set_policy_params :88 + network_cmds :94) ride the ROW TU too.
//
// HONEST WITNESS-INIT DEVIATION (chapter-21 row-24k law, CITED): the probe
// ctor's ONE stack SnortConfig + ONE leaked static SnortConfig (through the
// get_conf mirror) THROUGH THE SHAPE ctors below — the shape-init exists
// ONLY to drive the row's OWN set() writes (num_layers/max_ip6_extensions/
// max_ip_layers) and the policy_map seam the set_policy lua legs ride. The
// ctor/dtor/print bodies echo fixed text: ZERO heap-pointer values, ZERO
// wall-clock, ZERO randomness ride the vectors. main/she-ll.cc, control/
// control.cc, main/policy.cc, managers/*, main/analyzer.cc, detection/
// detection_engine.cc homes NEVER land — their seats are DEFINED for the
// nm/E9 census faces + the shape mirrors the ladder drives (every mirror
// prints name+arg ONLY). NO private-access flag EVER ships.
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <string>
#include <vector>

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/policy.h"
#include "main/analyzer.h"
#include "detection/detection_engine.h"
#include "control/control.h"
#include "log/messages.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/value.h"
#include "main/thread_config.h"
#include "utils/stats.h"
#include "utils/dnet_header.h"
#include "sfip/sf_ip.h"

// the row class fwd + the lua env fwd the mirrors below need (the GROUND
// head main/s"he-ll.h NEVER rides a JOINED include HERE — the foreign
// holder-face law; the member signature below reproduces the mangled-name
// face the row .o drags EXACTLY).
struct lua_State;
class Shell;

using namespace snort;

// ---- framework/module.cc's OWN strays (the stats + instance seats the
// leg drags; the h-lp-era shape pair rides). NEVER fired by this row's
// ladder (the network tables ride NO pegs) — census fuel ONLY. ----
void show_stats(const PegCount*, const PegInfo*, unsigned, const char*)
{ printf("W show_stats (NEVER fired)\n"); }
void show_stats(const PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*)
{ printf("W show_stats_ivecs (NEVER fired)\n"); }
namespace snort {
unsigned get_instance_id() { return 0; }
}
unsigned ThreadConfig::get_instance_max() { return 1; }

// ---- the DataBus home (framework/data_bus.cc NEVER lands): the Net-
// workPolicy NSDMI member (policy.h :163 snort::DataBus dbus) the shape
// ctor/dtor drive — the link face of the witness policy ONLY, NEVER
// fired with any real event traffic (census fuel + the ONE ctor leg). ----
namespace snort {
DataBus::DataBus() { }
DataBus::~DataBus() { }
}

// ---- the dnet addr home NEVER lands (the parameter .cc MAC/IP4/ADDR
// valid legs): the GRAFT-shim-shaped mirror the act-family law rides.
// NEVER fired; the vectors NEVER see these names. ----
int addr_pton(const char*, addr_t*) { return -1; }
int addr_ntop(const addr_t*, char*, unsigned) { return -1; }

// ---- main/policy.cc NEVER lands: get_network_policy() is the row's OWN
// set() seam (config_file.cc legs + the row set() legs BOTH call it). The
// mirror returns ONE leaked static NetworkPolicy whose ctor/dtor ride the
// SHAPE definitions below (the fields ride their header NSDMIs; the ctor
// NEVER fires till the probe's FIRST ladder call — the cited witness-init
// deviation). The dtor NEVER fires (leaked — the vectors order stays
// single-writer; the dtor body exists for the nm/E9 census face ONLY). ----
static NetworkPolicy* g_witness_policy = nullptr;

NetworkPolicy::NetworkPolicy(PolicyId id, PolicyId default_ips_id)
{
    printf("P policy shape-init id=%u ips_id=%u uid=%llu min=%u new=%u eval=0x%x drop=0x%x\n",
        id, default_ips_id,
        (unsigned long long)user_policy_id, (unsigned)min_ttl, (unsigned)new_ttl,
        checksum_eval, checksum_drop);
}
NetworkPolicy::NetworkPolicy(const char*)
{ printf("P policy ctor-string shape (NEVER fired)\n"); }
NetworkPolicy::~NetworkPolicy()
{ printf("W policy dtor (NEVER fired — the leaked shape instance)\n"); }

NetworkPolicy* snort::get_network_policy()
{
    if (!g_witness_policy) g_witness_policy = new NetworkPolicy();
    return g_witness_policy;
}

// ---- the PolicyMap seam (main/policy.cc NEVER lands): the row
// network_set_policy leg calls get_user_network THROUGH
// SnortConfig::get_conf()->policy_map. The mirror answers uid==7 with the
// witness policy (the deterministic HIT face) and nullptr otherwise (the
// MISS face); every call echoes uid. Home cited NF, NEVER fired. The map
// LEAKS (never destroyed) so its dtor NEVER rides exit-time order. ----

NetworkPolicy* PolicyMap::get_user_network(uint64_t user_id) const
{
    printf("W PolicyMap.get_user_network uid=%llu %s\n", (unsigned long long)user_id,
        user_id == 7 ? "HIT" : "miss");
    return user_id == 7 ? g_witness_policy : nullptr;
}
PolicyMap::PolicyMap() { printf("P policy_map shape-init\n"); }
PolicyMap::~PolicyMap() { printf("W PolicyMap.dtor (NEVER fired — leaked)\n"); }

// ---- main/snort_config.cc NEVER lands (the config-owner home): the
// get_conf static the row + the mirrored policy_map seam ride + the shape
// ctor/dtor the probe's ONE stack + ONE leaked instance drive (the CITED
// witness-init deviation — shape-init ONLY, to drive the row's OWN set()
// writes; every field rides its header NSDMI). The leaked instance keeps
// exit-time order clean (the dtor fires INSIDE main for the stack face
// ONLY). policy_map rides the witness map (the CITED seam deviation, the
// row's set_policy legs need it; NSDMI would be nullptr). ----
SnortConfig::SnortConfig(const char* exclude_name)
{
    static PolicyMap* m = new PolicyMap();            // leaked (dtor NEVER rides exit-time)
    printf("W SnortConfig.ctor ex=%s (witness shape-init)\n", exclude_name ? exclude_name : "(none)");
    policy_map = m;
}
SnortConfig::~SnortConfig() { printf("W SnortConfig.dtor (witness shape)\n"); }
void SnortConfig::set_conf(SnortConfig*) { printf("W SnortConfig.set_conf (NEVER fired)\n"); }
const SnortConfig* SnortConfig::get_conf()
{
    static SnortConfig* c = new SnortConfig();   // leaked (the dtor NEVER rides exit-time)
    return c;
}

// ---- main/she-ll.cc NEVER lands (the foreign holder law: NO JOINED head
// include HERE — the signature below reproduces the mangled face the row
// .o drags EXACTLY). The mirror prints name+arg ONLY — the VALID-uid lua
// leg drives through it (the cited NF home, shape mirror fired). ----
void Shell::set_network_policy_user_id(lua_State* l, uint64_t user_id)
{
    printf("W Shell.set_network_policy_user_id L=%d uid=%llu (she-ll home NEVER lands)\n",
        l ? 1 : 0, (unsigned long long)user_id);
}

// ---- control/control.cc NEVER lands: the two row legs + the LogRespond
// macro faces. query_from_lua returns nullptr (the mirror-nil face the
// invalid-uid leg drives — the LogRespond macro then takes its LogMessage
// ELSE branch). respond fires ONLY on the cn-leg face below. Homes cited
// NF, NEVER land. ----
ControlConn* ControlConn::query_from_lua(const lua_State*)
{
    printf("W ControlConn.query_from_lua -> nil (mirror)\n");
    return nullptr;
}
bool ControlConn::respond(const char* format, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    printf("W respond: %s", buf);
    return true;
}
bool ControlConn::respond(const char* format, va_list& ap)
{
    char buf[512];
    va_list cp;
    va_copy(cp, ap);
    vsnprintf(buf, sizeof(buf), format, cp);
    va_end(cp);
    printf("W respond-ive: %s", buf);
    return true; }

// ---- the sfip addr home NEVER lands (the value .cc leg's ONE stray):
// the sfip/sf_ip.cc NEVER-LAND face the get_addr legs drag; shape-only,
// NEVER fired (the vectors NEVER see SfIp), the link face ONLY. ----
SfIpRet snort::SfIp::set(const void* src, int fam)
{ (void)src; (void)fam; return SFIP_FAILURE; }
SfIpRet snort::SfIp::set(const void* src)
{ (void)src; return SFIP_FAILURE; }

// ---- log/messages.cc NEVER lands: the LogRespond ELSE-branch face
// (LogMessage) the invalid-uid leg drives + the ParseError WALL (the
// unknown-token ParseError wall of the row's checksum machine — the DEC
// ladder NEVER fires it, ONLY valid tokens ride; the mirror DEFINES the
// home for the nm/E9 census face; if it EVER prints the law broke). ----
void snort::LogMessage(const char* format, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    printf("W LogMessage[nil-conn]: %s", buf);
}
void snort::LogMessage(FILE*, const char* format, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    printf("W LogMessage[fh]: %s", buf);
}
void snort::ParseError(const char* format, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    printf("W NF ParseError FIRED — the unknown-token wall NEVER fires by law: %s\n", buf);
}

// ---- main/analyzer.cc + detection/detection_engine.cc NEVER land (the
// config_conf wall the config_file LEG carries — config_conf is NEVER
// driven HERE): the pair of seats the leg drags, defined for the link +
// the nm census face ONLY, NEVER fired (cited NF in the probe). ----
void Analyzer::set_main_hook(bool (*)(snort::Packet*))
{ printf("W Analyzer.set_main_hook (NEVER fired — the config_conf wall)\n"); }
bool DetectionEngine::inspect(snort::Packet*)
{ printf("W DetectionEngine.inspect (NEVER fired)\n"); return false; }

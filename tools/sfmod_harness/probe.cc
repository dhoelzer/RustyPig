// row-23c probe.cc — THE DEC session for the sfdaq_module pair (298+89 @
// fe29cbe FRESH cps, md5 0c42d293d1b7989d54b25eb493b7936b /
// 14c6c3676e184501d99c8dc39061d496; cmp-proved in build.sh). THE real-body
// row: the pair .cc compiles VERBATIM vs the REAL libdaq SDK face (the cc
// :179 static_assert(MAX_DAQ_VERDICT == 6) rides the REAL daq_common.h
// 28789a3d — the 23a-ledger ext#4 VALUE-honest face proven LIVE). REAL
// bodies on the link: framework/module.cc (the base), framework/value.cc
// (the REAL Value), the 23a sfdaq_config.cc (SFDAQConfig). The NOT-landed
// homes close through witness_sfmod.cc MIRRORS only (never bodies):
// snort::ParseError (messages.h :51, the end() :156 leg — OWN-1 capture
// mirror), SFDAQ::get_local_instance + SFDAQ::get_stats (the sfdaq.cc
// bodies stay C-UNLINKED; scripted knobs wlocal/wstats), Trough::file_count
// (the trough.h :84 member DEFINITION mirror at zero — the real bump lives
// at trough.cc get_next NOT-LANDED: the honest never-bumped pcaps=0 face).
// FatalError / SnortConfig ctor+dtor+statics / show_stats x2 /
// get_instance_id / ThreadConfig::get_instance_max ride the carried
// witness_conf 4dd91018 family + the 23b noreturn rider (NEVER doubled).
// C++ eval-order law: mutating calls hoisted into locals BEFORE every printf.
#include "packet_io/sfdaq_module.h"   // THE row pair (FRESH cp)
#include "packet_io/sfdaq_config.h"   // the 23a rider REAL body
#include "packet_io/trough.h"         // the fresh-cp DECL rider
#include "framework/value.h"          // THE REAL Value body

#include <cstdio>
#include <cstring>
#include <string>

#include "main/snort_config.h"

using namespace snort;

// witness knobs (definitions live in witness_sfmod.cc; the probe scripts
// externs, NEVER re-defines):
namespace snort {
extern char wpe_buf[4096];  extern unsigned wpe_calls;
extern void* wlocal;
}
extern DAQ_Stats_t wstats;

static std::string join27(const PegCount* p) {
    std::string o;
    for (int i = 0; i < 27; i++) { o += std::to_string(p[i]); o += (i < 26 ? "," : ""); }
    return o;
}

static std::string params_face(const char* tag, const Parameter* p) {
    std::string o = tag; int n = 0;
    for (; p[n].name; n++) {
        char b[180];
        snprintf(b, sizeof b, "%s/%d/%s", p[n].name, (int)p[n].type,
                 p[n].deflt ? p[n].deflt : "-");
        o += ","; o += b;
    }
    char b[64]; snprintf(b, sizeof b, ";rows=%d;sent=%d", n, (int)p[n].type);
    o += b;
    return o;
}

// the PT_LIST child-table walk through the PUBLIC range slot (parameter.h
// :70 `const void* range` — the C Parameter* face, NEVER re-typed):
static std::string child_face(const char* tag, const Parameter* p, int pick) {
    int n = 0;
    while (p[n].name && n < pick) n++;
    return params_face(tag, (const Parameter*)p[n].range);
}

int main() {
    // ================= T0-T5 the static tables + the usage face ========
    SFDAQModule m;
    int npegs = 0, tsum = 0;
    const PegInfo* q = m.get_pegs();
    std::string names, types;
    for (; q[npegs].name; npegs++) {
        tsum += (int)q[npegs].type;
        names += q[npegs].name; names += ",";
        types += std::to_string((int)q[npegs].type); types += ",";
    }
    printf("T0 usage=%d needprep=%d pegs=%d tsum=%d\n",
           (int)m.get_usage(), (int)m.counts_need_prep(), npegs, tsum);
    const Parameter* sp = m.get_parameters();
    std::string spt;
    for (const Parameter* p = sp; p->name; p++) { spt += std::to_string((int)p->type); spt += ","; }
    printf("T1 names=%s sparam-types=%s\n", names.c_str(), spt.c_str());
    printf("T2 %s %s\n", child_face("path", sp, 0).c_str(),    // module_dirs child
           child_face("input", sp, 1).c_str());                // inputs child
    printf("T3 %s\n", child_face("dqmod", sp, 4).c_str());     // modules child
    { const Parameter* dmod = (const Parameter*)sp[4].range;   // variables -> daqvar
      printf("T4 %s\n", child_face("dqvar", dmod, 2).c_str()); }
    printf("T5 peg-types=%s\n", types.c_str());

    // ================= T6-T8 the parse session (begin/set/end) =========
    SnortConfig sc("");                       // the carried-witness ctor
    SFDAQModule m2;
    bool b1 = m2.begin("daq", 0, &sc);
    { Value v("/d1");  bool x = m2.set("daq.module_dirs", v, &sc); (void)x; }
    { Value v("/d2");  (void)m2.set("daq.module_dirs", v, &sc); }
    { Value v("eth0"); (void)m2.set("daq.inputs", v, &sc); }
    { Value v((uint64_t)1500u); (void)m2.set("daq.snaplen", v, &sc); }
    { Value v((uint64_t)32u);   (void)m2.set("daq.batch_size", v, &sc); }
    bool b2 = m2.begin("daq.modules", 0, &sc);        // the idx==0 EARLY-true
    bool b3 = m2.begin("daq.modules", 1, &sc);
    { Value v("alpha"); (void)m2.set("daq.modules.name", v, &sc); }
    bool sm; { uint64_t one = 1; Value v(one); sm = m2.set("daq.modules.mode", v, &sc); } // :137 +1 law -> 2
    { Value v("foo=bar"); (void)m2.set("daq.modules.variables", v, &sc); }
    bool e1 = m2.end("daq.modules", 1, &sc);
    bool e2 = m2.end("daq.modules", 0, &sc);         // the idx-0 early true
    bool e3 = m2.end("daq", 0, &sc);
    {
        SFDAQConfig* c = sc.daq_config;
        printf("T6 b=%d,%d,%d mode=%d e=%d,%d,%d dirs0=%s dirs1=%s in0=%s bs=%u mru=%d tmo=%u mods=%zu nm0=%s md0=%d\n",
               (int)b1,(int)b2,(int)b3,(int)sm,(int)e1,(int)e2,(int)e3,
               c->module_dirs[0].c_str(), c->module_dirs[1].c_str(),
               c->inputs[0].c_str(), c->batch_size, c->mru_size, c->timeout,
               c->module_configs.size(), c->module_configs[0]->name.c_str(),
               (int)c->module_configs[0]->mode);
        std::string vs;
        for (auto& kv : c->module_configs[0]->variables) vs += kv.first + "=" + kv.second + ";";
        printf("T7 vars=%s\n", vs.c_str());
    }

    // ================= T8/T9 the ParseError leg + overlay law ==========
    {
        SFDAQModule m3;
        SnortConfig sc2("");
        SFDAQConfig* old = new SFDAQConfig();     // the EXISTING-conf merge face
        old->batch_size = 5; old->mru_size = 2000; old->timeout = 777;
        sc2.daq_config = old;
        m3.begin("daq", 0, &sc2);
        { Value v((uint64_t)9u);    (void)m3.set("daq.batch_size", v, &sc2); }
        { Value v((uint64_t)1234u); (void)m3.set("daq.snaplen", v, &sc2); }
        m3.begin("daq.modules", 3, &sc2);
        bool bad = m3.end("daq.modules", 3, &sc2);   // EMPTY name -> false + ParseError
        std::string msg(wpe_buf); unsigned calls = wpe_calls;
        bool ok  = m3.end("daq", 0, &sc2);
        printf("T8 bad=%d ok=%d wpe_calls=%u msg=[%s]\n", (int)bad, (int)ok, calls, msg.c_str());
        SFDAQConfig* c2 = sc2.daq_config;
        printf("T9 bs=%u mru=%d tmo=%u mods=%zu dirs=%zu\n",
               c2->batch_size, c2->mru_size, c2->timeout,
               c2->module_configs.size(), c2->module_dirs.size());
    }

    // ================= S0-S8 the stats ladder (prep/reset) =============
    {
        SFDAQModule ms;
        // ---- S0 the null-local GATE (cc :250-:252): wlocal stays NULL:
        ms.prep_counts(false);
        printf("S0 gated=%s\n", join27(reinterpret_cast<const PegCount*>(&daq_stats)).c_str());

        // ---- script the SDK stats face (the get_stats mirror store):
        memset(&wstats, 0, sizeof wstats);
        wstats.hw_packets_received = 8;  wstats.hw_packets_dropped = 1;
        wstats.packets_received = 10;    wstats.packets_filtered = 2;
        wstats.packets_injected = 3;     wstats.packets_outstanding = 4;
        wstats.verdicts[0] = 5;          wstats.verdicts[1] = 2;
        wlocal = (void*)&wstats;         // ANY non-null rides the :251 pass face
        ms.prep_counts(true);            // dump_stats TRUE: the :285-:286 prev store SKIPPED
        printf("S1 dump=%s\n", join27(reinterpret_cast<const PegCount*>(&daq_stats)).c_str());

        // bump the scripted stats; the SECOND dump-prep rides prev ZERO
        // AGAIN (the NEVER-carry face) so the delta == the new face:
        wstats.hw_packets_received = 20; wstats.hw_packets_dropped = 9;
        wstats.packets_received = 50;    wstats.packets_filtered = 12;
        wstats.packets_injected = 30;    wstats.packets_outstanding = 6;
        ms.prep_counts(true);
        printf("S2 never-carry=%s\n", join27(reinterpret_cast<const PegCount*>(&daq_stats)).c_str());

        // the dump_stats=FALSE leg: the :286 store CARRIES the S2 face at
        // prev; the SAME-stats delta = all-zero legs (the :256-:257 law):
        ms.prep_counts(false);
        printf("S3 zero-delta=%s\n", join27(reinterpret_cast<const PegCount*>(&daq_stats)).c_str());

        // the data-RESET arm (new hw 7/3 < carried 20/9 -> the :268-:269
        // ABSOLUTE face, NOT the wrapped delta):
        wstats.hw_packets_received = 7;  wstats.hw_packets_dropped = 3;
        ms.prep_counts(false);
        printf("S4 reset=%s\n", join27(reinterpret_cast<const PegCount*>(&daq_stats)).c_str());

        // a plain DELTA leg on top of the carried face:
        wstats.hw_packets_received = 11; wstats.hw_packets_dropped = 6;
        wstats.packets_received = 15;    wstats.packets_filtered = 0;
        wstats.packets_injected = 30;    wstats.packets_outstanding = 2;
        wstats.verdicts[0] = 9;          wstats.verdicts[2] = 4;
        ms.prep_counts(false);
        printf("S5 delta=%s\n", join27(reinterpret_cast<const PegCount*>(&daq_stats)).c_str());

        // the outstanding_max ladder (the :282-:283 MAX walk):
        wstats.packets_outstanding = 100;
        ms.prep_counts(false);
        printf("S6 o=%llu omax=%llu\n", (unsigned long long)daq_stats.outstanding,
               (unsigned long long)daq_stats.outstanding_max);

        // the REAL base init_stats seed (module.cc :318-:336; the
        // ThreadConfig::get_instance_max() witness = 1) + the :297 BASE
        // reset_stats walk (module.cc :339-:360, the NOW-skip :357):
        ms.init_stats(false);
        int rows = ms.get_num_counts();
        // the reset_stats cc :291-:294 RE-snapshot leg rides the SAME
        // get_stats mirror (prev := 100-outstanding face):
        ms.reset_stats();
        printf("S7 rows=%d post=%s\n", rows, join27(reinterpret_cast<const PegCount*>(&daq_stats)).c_str());

        // the get_counts :228 identity + the Trough never-bumped face
        // (file_count mirror stays 0; the clear rides the trough.h
        // :52-:54 inline):
        PegCount* p0 = ms.get_counts();
        int ident = (p0 == reinterpret_cast<PegCount*>(&daq_stats));
        Trough::clear_file_count();
        unsigned fc = Trough::get_file_count();
        ms.prep_counts(false);
        int pcaps0 = (int)daq_stats.pcaps;
        printf("S8 ident=%d fc=%u pcaps=%d\n", ident, fc, pcaps0);
    }
    return 0;
}

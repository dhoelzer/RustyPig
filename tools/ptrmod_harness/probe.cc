// probe.cc — row 23g DEC session: the packet_tracer MODULE pair (cc 262 L
// f5b3507d8868abda27f3ce94a2af99bd + h 59 L ab0bbe5ebe247315ccf57ffeb65e6e06
// @ fe29cbe, FRESH cps, cmp-proved EVERY build in build.sh). THE REAL-BODY
// row shape (the 23c kin): the row .cc compiles VERBATIM against the
// vendored lua RE-CITE (-I$LJ/src, the fmod/chunk-era Lua law) + the
// FRESH-cp DECL riders (batched_logger / analyzer_command / the profiler
// 6-chain / stopwatch / the stream+ips_context closure). The DEC DRIVES
// the REAL file-static lua fns THROUGH the Command-table fn-ptrs returned
// by the REAL get_commands() (the ONLY invocation face; the probe NEVER
// re-declares the statics) onto a REAL lua_State (lua_open == luaL_newstate
// face): the luaL_opt* legs OBSERVE their pinned defaults through ABSENT
// args. CROSS-ROW REUSE link (one-home law): the 23f packet_tra""cer PAIR
// (VERBATIM cmp-proved; REAL legs thread_init/thread_term/set_constraints/
// configure via the shell end()) + the 23e packet_constr""aints PAIR
// (operator= closed IN-LINK) + the 19a framework/module.cc + value.cc
// REAL bodies + the util/sf_ip/ip REAL legs. NOT-landed walls close
// through the OWN witness_modtrace MIRRORS ONLY: main_broadcast_command
// (stringify capture through the REAL row :82 virtual + ONE cmd STASH —
// the probe drives execute() through the REAL base-ref call: the
// broadcast-then-run face), ControlConn::query_from_lua (cold-null arm,
// cited), BatchedLogManager::set_filter (capture; NEVER doubled vs the
// REUSED 23f tracker's log/flush legs) + the minimal Analyzer DECL
// (reference-forming face ONLY, NEVER dereferenced — the ODR-cited mirror,
// the row body NEVER touches the param). THE 23f witness_tracker.cc rides
// the link VERBATIM cross-row (md5-pinned): its LogMessage/WarningMessage
// capture homes stay ONE home — this probe reads msg_capture/warn_capture
// through it. THE message legs at cc :175-:177 are LogMessage NOT
// WarningMessage (the disk face, pin-armed): the trio rides msg_capture.
// THE regex buffered arm (:181-:199) stays CONFIG-COLD (the carried
// get_conf() face: output_flags==0 per snort_config.h :216 non-REG_TEST
// NSDMI): EVERY regex leg fires the trio + clears the filter; the clamp
// string legs NEVER C-reached (honest cold face, cited — the Rust twin
// drives BOTH arms through the landed LogEngine flag provider). THE 23f
// get_instance_file OUT-param RIDER rides the EXTRACTED carried witness
// verbatim (the D7b open leg REACHES it: the "./"+name CREATES face). lua
// frame law: settop between legs (the shell's consumed-args face); the
// stash free NEVER double-frees. eval-order law: mutating calls hoisted
// into locals BEFORE printf. COLD/LIVE/COLD tracer ladder through the
// REAL tr.o legs.
#include "packet_io/packet_tracer_module.h"   // THE row pair (FRESH cp)
#include "packet_io/packet_tracer.h"          // the 23f REUSE home (REAL legs)
#include "packet_io/packet_constraints.h"     // the 23e REUSE home

#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include <lua.hpp>

#include "main/analyzer_command.h"          // the REAL base decl face
#include "witness_modtrace.h"               // the minimal Analyzer DECL

using namespace snort;                      // the row .cc :40 face re-rides

// witness globals (definitions: the REUSED 23f witness_tracker.cc + this
// row's witness_modtrace.cc; the externs NEVER re-define):
extern std::string msg_capture, warn_capture, batched_capture;
extern std::string bcapture, mfcapture;
extern snort::AnalyzerCommand* bcap_cmd;
void PacketTracerDebug_exec_stash_free();

static std::string params_face(const char* tag, const Parameter* p) {
    std::string o = tag; int n = 0;
    for (; p[n].name; n++) {
        char b[160];
        snprintf(b, sizeof b, "|%s/%d/%s/%s", p[n].name, (int)p[n].type,
                 p[n].range ? (const char*)p[n].range : "-",
                 p[n].deflt ? p[n].deflt : "-");
        o += b;
    }
    char b[64]; snprintf(b, sizeof b, ";rows=%d;sent=%d", n, (int)p[n].type);
    o += b;                       // the sentinel row's PT_MAX ordinal face
    return o;
}

static size_t findcnt(const std::string& hay, const char* needle) {
    size_t c = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) { c++; pos++; }
    return c;
}
static size_t nlcount(const std::string& s) { size_t c = 0; for (char ch : s) if (ch == '\n') c++; return c; }

// push nil for positional args 1..n (the lua absent-arg frame face)
static void frame_nil(lua_State* L, int n) { for (int i = 1; i <= n; i++) lua_pushnil(L); }

// drive a stashed broadcast: execute ONCE through the REAL base-ref call,
// free (the real walker ref-counts; the probe deletes — cited).
static bool run_stashed(Analyzer& an) {
    bool ex = bcap_cmd->execute(an);
    PacketTracerDebug_exec_stash_free();
    return ex;
}

int main() {
    // =============== T0-T2 the module identity + both tables ============
    PacketTracerModule m;
    printf("T0 name=%s help=%s usage=%d\n", m.get_name(), m.get_help(), (int)m.get_usage());
    printf("T1 sp=%s\n", params_face("sp", m.get_parameters()).c_str());
    const Command* c = m.get_commands();
    PacketTracerModule m2;              // a SECOND instance: table ONE-home
    const Command* c2 = m2.get_commands();
    {
        std::string o; int n = 0;
        for (; c[n].name; n++) {
            char b[72];
            snprintf(b, sizeof b, "%s|f%d|p%d|r%d|", c[n].name,
                     (int)(c[n].func != nullptr), (int)(c[n].params != nullptr),
                     (int)c[n].can_run_in_parallel);
            o += b;
        }
        int ptypes = 0; const Parameter* en = c[0].params;
        for (int i = 0; en[i].name; i++) ptypes += (int)en[i].type;
        printf("T2 cmds=%ssent=%d same2=%d %s tsum=%d\n",
               o.c_str(), (int)(c[2].name == nullptr), (int)(c == c2),
               params_face("en", en).c_str(), ptypes);
    }

    lua_State* L = lua_open();
    Analyzer an;   // the minimal mirror (reference-forming ONLY — cited)

    // =============== D0 cold-world enable, ZERO args ===================
    // every luaL_opt* DEFAULTS (proto/sport/dport 0, match_count 1, the
    // strings nullptr, stop false); zero-bit constraints; set_filter("");
    // the broadcast stashes the cmd; execute() -> set_constraints(&cs)
    // hits the REAL tr.cc :234-:236 s_pkt_trace-null EARLY RETURN: NO
    // msg, NO state: the cold-world shell face. rc 0, frame stays 0.
    {
        bcapture.clear(); mfcapture.clear(); msg_capture.clear();
        int rc = c[0].func(L);
        int argc = lua_gettop(L);
        bool ex = run_stashed(an);
        std::string bc = bcapture, mf = mfcapture;
        size_t ml = msg_capture.size();
        printf("D0 rc=%d argc=%d bcast=[%s] filt=[%s] msglen=%zu exec=%d\n",
               rc, argc, bc.c_str(), mf.c_str(), ml, (int)ex);
    }

    // =============== D1 the invalid-IP LogMessage pair (cc :127/:133) ==
    // both SfIp::set legs MISfit on the REAL sf_ip.o (garbage strings) ->
    // TWO capture lines (:128/:134); the unset SfIps stay cleared -> no
    // IP bits; no regex -> set_filter(""). Cold tracer -> early-return
    // face again (msg census holds ONLY the invalid-IP pair).
    {
        msg_capture.clear(); bcapture.clear(); mfcapture.clear();
        frame_nil(L, 1);
        lua_pushstring(L, "nope1");            // arg 2 sipstr
        lua_pushnil(L);                        // arg 3
        lua_pushstring(L, "nope2");            // arg 4 dipstr
        int rc = c[0].func(L);
        int argc = lua_gettop(L);
        bool ex = run_stashed(an);
        size_t lines = nlcount(msg_capture);
        size_t src1 = findcnt(msg_capture, "Invalid source IP address provided: nope1");
        size_t dst1 = findcnt(msg_capture, "Invalid destination IP address provided: nope2");
        std::string mf = mfcapture;
        printf("D1 rc=%d argc=%d mslines=%zu src=%zu dst=%zu filt=[%s] exec=%d\n",
               rc, argc, lines, src1, dst1, mf.c_str(), (int)ex);
        lua_settop(L, 0);
    }

    // =============== D2 the regex trio on the COLD conf face ===========
    // regex "abc" + the carried get_conf()->use_log_buffered()==FALSE face
    // (cc :173): the THREE LogMessage lines (:175-:177 — LogMessage, NOT
    // WarningMessage, the pin-armed disk face) + filter CLEARED (:179) ->
    // set_filter(""). warn_capture STAYS 0 (the face). The clamp
    // :183-:196 NEVER reached (config-cold, cited).
    {
        msg_capture.clear(); warn_capture.clear(); mfcapture.clear();
        frame_nil(L, 6);
        lua_pushstring(L, "abc");              // arg 7 regex
        lua_pushboolean(L, 1);                 // arg 8 stop_after_match
        lua_pushinteger(L, 0);                 // arg 9 match_count (clamp NEVER reached cold)
        int rc = c[0].func(L);
        bool ex = run_stashed(an);
        size_t lines = nlcount(msg_capture), wl = warn_capture.size();
        size_t trio = findcnt(msg_capture, "Regex filtering requires log_buffered")
                    + findcnt(msg_capture, "ignoring regex filter")
                    + findcnt(msg_capture, "add 'log_buffered = true'");
        std::string mf = mfcapture;
        printf("D2 rc=%d mslines=%zu warnsz=%zu trio=%zu filt=[%s] exec=%d\n",
               rc, lines, wl, trio, mf.c_str(), (int)ex);
        lua_settop(L, 0);
    }

    // =============== D3 the LIVE tracer: real thread_init + full cs ====
    // the REAL tr.o ctor (cold log_file "-" -> log_fh stdout, NO file, NO
    // open warning); enable w/ proto 6 / 10.0.0.1:80 / 10.0.0.2:9999 /
    // tenants "7,9" -> set_constraints REACHES update_constraints in the
    // REAL body -> the banner through the REAL ntop + int_vector_to_str:
    // "Debugging packet tracer with 10.0.0.1-80 and 10.0.0.2-9999 6 and
    // tenants:7,9". No regex -> set_filter("") rides.
    {
        PacketTracer::thread_init();
        msg_capture.clear(); warn_capture.clear(); mfcapture.clear();
        lua_pushinteger(L, 6);                 // arg 1 proto
        lua_pushstring(L, "10.0.0.1");         // arg 2
        lua_pushinteger(L, 80);                // arg 3
        lua_pushstring(L, "10.0.0.2");         // arg 4
        lua_pushinteger(L, 9999);              // arg 5
        lua_pushstring(L, "7,9");              // arg 6 tenants
        int rc = c[0].func(L);
        bool ex = run_stashed(an);
        std::string mf = mfcapture;
        size_t banner = findcnt(msg_capture,
            "Debugging packet tracer with 10.0.0.1-80 and 10.0.0.2-9999 6 and tenants:7,9");
        printf("D3 rc=%d banner=%zu filt=[%s] exec=%d\n", rc, banner, mf.c_str(), (int)ex);
        lua_settop(L, 0);
    }

    // =============== D4 the (IpProtocol)proto cast WRAP (cc :145) ======
    // proto 300: the fixed-underlying uint8_t cast face (protocol_ids.h
    // enum class : std::uint8_t) = 44 < PROTO_NOT_SET(255) PASSES the
    // gate (WELL-DEFINED, NEVER UB): the REAL-body banner prints the
    // %hhu 44 + tenants:none face (all other args nil/absent, constraints
    // REBUILT zero-bit per call — the fresh-local face).
    {
        msg_capture.clear();
        lua_pushinteger(L, 300);
        int rc = c[0].func(L);
        bool ex = run_stashed(an);
        size_t fortyfour = findcnt(msg_capture, "44 and tenants:none");
        printf("D4 rc=%d wrap44=%zu exec=%d\n", rc, fortyfour, (int)ex);
        lua_settop(L, 0);
    }

    // =============== D5 the disable leg onto the LIVE tracer ===========
    // disable: broadcast + execute -> set_constraints(nullptr) in the
    // REAL tr.cc :238-:241 -> the "Debugging packet tracer disabled" msg
    // + shell off. stringify SAME-face PACKET_TRACER_DEBUG (the :82 single
    // override serves BOTH commands — the enable/disable bcast census).
    {
        msg_capture.clear(); bcapture.clear();
        int rc = c[1].func(L);
        bool ex = run_stashed(an);
        std::string bc = bcapture;
        size_t dis = findcnt(msg_capture, "Debugging packet tracer disabled");
        printf("D5 rc=%d bcast=[%s] disabled=%zu exec=%d\n", rc, bc.c_str(), dis, (int)ex);
    }

    // =============== D6 thread_term: the flush gate + FLUSH ============
    // buff_len stayed 0 (NEVER a packet logged) -> the term ladder
    // tr.cc :100-:102 gate FALSE (NO spill msg) -> the
    // BatchedLogManager::flush_thread_buffers REUSED-23f-mirror leg
    // appends FLUSH;. The tracer deletes back to the cold face.
    {
        batched_capture.clear(); msg_capture.clear();
        PacketTracer::thread_term();
        std::string bc = batched_capture;
        size_t fl = findcnt(bc, "FLUSH;");
        size_t ml = msg_capture.size();
        printf("D6 flush=%zu msglen=%zu\n", fl, ml);
    }

    // =============== D7a the begin/set/end parse ladder ================
    // the REAL value.cc is()/get_bool/get_uint8 dispatch: the parse-layer
    // contract v.set(param) over the REAL get_parameters() rows (value.h
    // :98 the Parameter* set face — the row :220/:223 is() legs ride).
    // Faces: begin true; enable=true TRUE (:220-:221); output=1 TRUE ->
    // "packet_trace.txt" (:231-:233); output=7 FALSE (:235-:236);
    // output=0 TRUE -> "-" (:227-:229); end TRUE + config consumed
    // (:255-:259); SECOND end -> the config-null else TRUE (:255/:261).
    {
        PacketTracerModule mm;
        const Parameter* sp = mm.get_parameters();
        bool b1 = mm.begin("packet_tracer", 0, nullptr);
        Value v_en(true);  v_en.set(sp + 0);
        Value v_file(static_cast<uint64_t>(1)); v_file.set(sp + 1);
        Value v_bad(static_cast<uint64_t>(7));  v_bad.set(sp + 1);
        Value v_con(static_cast<uint64_t>(0));  v_con.set(sp + 1);
        bool s_en  = mm.set("x.enable", v_en, nullptr);
        bool s_file = mm.set("x.output", v_file, nullptr);
        bool s_bad = mm.set("x.output", v_bad, nullptr);
        bool s_con = mm.set("x.output", v_con, nullptr);
        bool e1 = mm.end("packet_tracer", 0, nullptr);   // configure(true, "-") rides
        bool e2 = mm.end("packet_tracer", 0, nullptr);   // the else arm
        printf("D7a b=%d s_en=%d s_file=%d s_bad=%d s_con=%d end=%d end2=%d\n",
               (int)b1, (int)s_en, (int)s_file, (int)s_bad, (int)s_con, (int)e1, (int)e2);
    }

    // =============== D7b the end->configure->open_file consequence ====
    // fresh module: begin/set output=1/end -> the REAL tr.o configure
    // static leg lands log_file="packet_trace.txt"; thread_init -> the
    // ctor open_file -> get_instance_file RIDER ("./"+name) -> fopen a+
    // CREATES (access 1); remove -> thread_term (buff_len 0: NO spill;
    // FLUSH; again; the dtor fcloses != stdout) -> access 0.
    {
        PacketTracerModule mm2;
        const Parameter* sp = mm2.get_parameters();
        mm2.begin("packet_tracer", 0, nullptr);
        Value v_file(static_cast<uint64_t>(1)); v_file.set(sp + 1);
        bool s1 = mm2.set("x.output", v_file, nullptr);
        bool e1 = mm2.end("packet_tracer", 0, nullptr);
        batched_capture.clear(); warn_capture.clear();
        PacketTracer::thread_init();
        int fexists = (access("packet_trace.txt", F_OK) == 0) ? 1 : 0;
        int removed = (remove("packet_trace.txt") == 0) ? 1 : 0;
        PacketTracer::thread_term();
        int fgone = (access("packet_trace.txt", F_OK) == 0) ? 1 : 0;
        std::string bc = batched_capture;
        size_t wd = warn_capture.size();
        printf("D7b s=%d end=%d file_created=%d removed=%d flush=%zu warnsz=%zu file_gone=%d\n",
               (int)s1, (int)e1, fexists, removed, findcnt(bc, "FLUSH;"), wd, fgone);
    }

    // =============== D7c the console round (reopen-off face) ===========
    // begin/set enable=false + output=CONSOLE/end -> configure(false,"-");
    // thread_init: log_file "-" -> log_fh stdout, NO file, NO warning;
    // thread_term clean. The config_status=false leg: user_enabled false
    // on the ctor (no user-face observable without packets — cited).
    {
        PacketTracerModule mm3;
        const Parameter* sp = mm3.get_parameters();
        mm3.begin("packet_tracer", 0, nullptr);
        Value v_off(false); v_off.set(sp + 0);
        Value v_con(static_cast<uint64_t>(0)); v_con.set(sp + 1);
        bool s1 = mm3.set("x.enable", v_off, nullptr);
        bool s2 = mm3.set("x.output", v_con, nullptr);
        bool e1 = mm3.end("packet_tracer", 0, nullptr);
        warn_capture.clear(); msg_capture.clear();
        PacketTracer::thread_init();
        size_t wd = warn_capture.size();
        PacketTracer::thread_term();
        int fexists = (access("packet_trace.txt", F_OK) == 0) ? 1 : 0;
        printf("D7c s=%d,%d end=%d warnsz=%zu file=%d\n",
               (int)s1, (int)s2, (int)e1, wd, fexists);
    }

    // =============== D8 cold enable w/ regex+stop: trio reruns ========
    // the COLD tracer again: the clamp legs STILL config-cold (the
    // carry-face get_conf NEVER flips); the trio fires AGAIN (mslines 3),
    // filt cleared; execute TWICE before free = idempotent on the cold
    // face (true/true), free ONCE.
    {
        msg_capture.clear(); warn_capture.clear(); mfcapture.clear();
        frame_nil(L, 6);
        lua_pushstring(L, "xyz");              // arg 7
        lua_pushboolean(L, 1);                 // arg 8
        lua_pushinteger(L, 42);                // arg 9 (clamp NEVER reached cold)
        int rc = c[0].func(L);
        bool ex1 = bcap_cmd->execute(an);
        bool ex2 = bcap_cmd->execute(an);
        PacketTracerDebug_exec_stash_free();
        size_t lines = nlcount(msg_capture); std::string mf = mfcapture;
        printf("D8 rc=%d mslines=%zu filt=[%s] exec2=%d,%d\n",
               rc, lines, mf.c_str(), (int)ex1, (int)ex2);
        lua_settop(L, 0);
    }

    // =============== D9 cold disable: the early-return face ============
    // disable on a COLD tracer: the broadcast face stays (same stringify
    // string) but set_constraints(nullptr) hits tr.cc :234-:236 FIRST:
    // NO disabled msg (the D5 pair face distinguishes live vs cold).
    {
        msg_capture.clear(); bcapture.clear();
        int rc = c[1].func(L);
        bool ex = run_stashed(an);
        std::string bc = bcapture;
        size_t dis = findcnt(msg_capture, "Debugging packet tracer disabled");
        printf("D9 rc=%d bcast=[%s] disabled=%zu msglen=%zu exec=%d\n",
               rc, bc.c_str(), dis, msg_capture.size(), (int)ex);
    }

    lua_close(L);
    printf("Z terminator=0\n");
    fflush(stdout);
    return 0;
}

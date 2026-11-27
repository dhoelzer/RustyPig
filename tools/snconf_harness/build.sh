#!/usr/bin/env bash
# build.sh — row 24g harness (chapter-21 SEVENTH body: src/main/snort_config.cc
# 1,138 L md5 a2e0b91f1de2fa295ce7dd7d2be77a5b + src/main/snort_config.h 798 L
# md5 638120b51712c12ce847829308ac5a01 @ fe29cbe = 1,936 L pair — the snort-
# config CONFIG-OWNER PAIR (the config owner itself): every set_* mutator
# body (:567-:980), the merge() two-config overlay (:387-:515: the run_flags
# OR, the daq overlay(), the -k CHECKSUM_FLAG__DEF guard, the DEFAULT_LOG_DIR
# finalize :507-:508 + the per-object state-block ONCE law :512-:514), the
# verify() self-face (:517-:565), the three statics the pair OWNS (:110-
# :112 warning/logging flags + the THREAD_LOCAL log_quiet_bypassed), the
# ScopedLogQuietBypass seat (h :749-:763), the reload-id tracker (:1073-
# :1080), the get_static_name intern map (:1115-:1126), the request/
# release_scratch seats (:1025-:1038), the tunnel_verdicts name-table +
# hex legs (:859-:909), the dst_mac dnet legs (:664-:684) and the static
# logging accessors (h :732-:769).
#
# THE FOURTH ZERO-GATE CONTROL ROW (the 24b/24d/24f pattern; MEASURED, RE-
# MEASURED EVERY build by WALK, NEVER assumed): the in-TU TEST face is
# EXACTLY-0 (TEST_CASE + 'TEST(' + 'CATCH' find-0 in BOTH files) AND the
# UNIT_TEST face is EXACTLY-0 as well (UNLIKE the 24f template's 3-compound-
# post pair: this pair carries ZERO UNIT_TEST posts, so the -DUNIT_TEST post
# is VACUOUS-COMPILE AND 0-DELTA: the nm plain/ut delta MEASURED EXACTLY-0,
# pinned honestly at the walked zero-face; the ut post compiles SILENT).
# The REG_TEST dialect rides EXACTLY-1 leg in the cc (:1102, the
# cleanup_fatal_error inside face — the probe FIRES that body so the vectors
# PROVE the insides NEVER compile) + EXACTLY-3 in the h (:83 :212 :534 — the
# pinned line list); '#ifdef SHELL' rides EXACTLY-1 per file (h :79, cc :485).
# The main/test CMakeLists carries EXACTLY-2 add_cpputest dialect faces
# (thread_test :1 + the ENABLE_SHELL-gated distill_verdict_test whose SOURCES
# ride ../analyzer.cc — NEITHER host names the row TU: grep-c snort_config.cc
# that file EXACTLY-0 MEASURED) and /usr/include/CppUTest find-0. The row
# rides main/CMakeLists.txt EXACTLY-1 .h (:7) + EXACTLY-1 .cc (:51) PLAIN
# seats OUTSIDE the ENABLE_SHELL gate pair (:20/:22). NO gate RUNNER ships
# HERE: NOTHING flips this row — the census STAYS 31 on-disk / legacy 9 x
# 4826fc22 FROZEN / 23 distinct lineages / tracked gre's 6751d1a8 ONLY.
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD (the honest divergence
# face vs the 24f config-MODULE row, NEVER assumed): (1) the fresh-cp BARE
# donor + row pair dies EXACTLY-1 FATAL at cc :34:10 (actions/ips_actions.h,
# the FIRST donor-absent head — the 24f :32 detect.h head MOVED here, the
# walked face); (2) the DONOR-GRAFT closed hull (86 fresh-cp heads + the
# dnet.h GRAFT shim — libdnet ABSENT on this box, the act-family graft
# precedent — + the compiler-SURFACED pair ground-WINS (trace/trace.h, the
# Traces typedef seat the ground trace_config.h :58 needs, + detection/
# detection_engine.h, the row :963 DetectionEngine::inspect seat; the donor
# STALE stubs 8-L/40-L vs ground 180-L/101-L) + the ONE hwloc EXCISION the
# DONOR already rides (its main/thread_config.h MEASURED-identical to ground-
# minus-hwloc; host hwloc find-0)) with the DONOR daq trio (97bca757/
# 9b603f8f/e8a39bf3) IN FORCE: MEASURED EXACTLY-1 error — the config-OWNER
# include surface (detection/detect.h -> detection_options.h) pulls the ONE
# DAQ_PktHdr_t.ts drift leg (the honest divergence from the 24f ZERO-error
# face: this TU rides packet_io/sfdaq.h + sfdaq_config.h + the FULL detect
# surface; the DAQ_MsgType/daq_msg/daq_version families stay ZERO-token —
# the 23a/24d msg-API wall NEVER rides, the 24d 51-error face NEVER copied;
# the flipped arm re-armed at the rc1 + error-count EXACTLY-1 face); (3) the
# REAL libdaq @ c8d4083 head SWAP (3 api heads, md5 pinned vs the LIVE $L
# api face; daq_module_api.h NEVER needed MEASURED — the row NEVER reaches
# the module-API seats; the generated daq_version.h sed face NEVER ships —
# ZERO needed, MEASURED 0 errors WITHOUT it) -> BOTH posts SILENT rc0 (the
# plain .o + the VACUOUS -DUNIT_TEST post). The closure algebra: 140 donor +
# 1 row cc + 86 fresh-cp + 1 dnet GRAFT + 1 packet_constraints.h leg rider =
# EXACTLY-229 (the row .h cp OVERWRITES the donor's GROUND-TWIN seat in
# place — the .h md5-IDENTICAL face MEASURED; the daq trio OVERWRITTEN).
#
# The nm app-undef census plain EXACTLY-84 / ut EXACTLY-84: delta EXACTLY-0,
# BOTH ways (ZERO ut-post legs here; the Catch:: count EXACTLY-0 BOTH +
# catch_set_filter EXACTLY-0 BOTH — the fourth-control honest face vs the
# 24f 98/99 catch_set_filter-only delta and the 24b/24d 137/137 rows). E9
# dup twins EXACTLY-67 (the pair's ~61 T-def twins — the ctor C1/D1 faces
# ride doubled (SnortConfig(char const*) + SnortConfig(ProtocolReference*) +
# ~SnortConfig) + the THREE owned statics + static_names_mutex/static_names
# + the four file-static-free data legs collide; MEASURED, NEVER the
# 24f-12/24d-44/24e-53 faces).
#
# The DEC ladder NEVER drives the walls: the ENTIRE set_uid/set_gid getpwnam/
# getgrnam family (cc :734-:799, main-thread-only), setup()/post_setup-full/
# generate_dump (the ParseRules + thread/getpid/time run walls :335-:394/
# :1082-:1094) and the cc-FILE-STATICS init_policy_mode/init_policies/
# generate_config_dump (NEVER callable — the policy-mode transition rides the
# CITE + FACE-A) — cited NF rows, NEVER fired. NO [[noreturn]] attribute
# ships in this pair (MEASURED at authoring — the noreturn-dead-code-elision
# hazard the 24f law warns of NEVER arises HERE). Six REAL ground legs link:
# packet_io/sfdaq_config.cc (the 23a landed DAQ-config home, batch=64/mru=
# 1518 LIVE) + sfip/sf_cidr.cc (the SfCidr set/clear face the -B legs ride)
# + sfip/sf_ip.cc (the SfIp home the sf_cidr body drags) + utils/util.cc
# (the snort_strdup home the tunnel/dst_mac legs ride) + target_based/
# snort_protocols.cc (the ProtocolReference the ctor new's LIVE) + trace/
# trace_config.cc (the TraceConfig the ctor new's + dtor deletes LIVE) —
# EVERY one compiles SILENT inside the closed hull; the rest of the NEVER-
# LAND wall (PolicyMap/NetworkPolicy/IpsPolicy, ProcessGlobs, ActionManager,
# EventManager, PluginManager, PigPen-free, ThreadConfig, FileService, the
# dump_config outputs, Analyzer::set_main_hook, the parser/rule free-family)
# rides the witness mirror — every mirror leg prints name+arg, deterministic.
# NO stderr wall ships HERE: the pair ships NO banner — honest omission.
# vectors 117 + FACE-A 35 FIRST-RUN-SEED, drift-REFUSED, tamper-proven,
# O0==O2 BYTE-IDENT (both bodies + the cross face). The counts ride the
# W-mirror echo legs the config-OWNER ctor/dtor ladder fires (the pair new's
# the PolicyMap/ActionManager/ThreadConfig walls — the moved face vs the 24f
# 126/14 module-row counts; MEASURED, NEVER stretched to the era face).
# The joined OWN token NEVER rides THIS file (the ZERO law — $MN rides the
# runtime concat); the GROUND name rides PATHS by construction. mod.rs
# STAYS the ONE new line at THIS row ('pub mod snort_configp;' :12, 12 L —
# the 62d6fac law face on disk; THIS harness PINS, NEVER edits).
set -euo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
LJ=/opt/data/tools/luajit-src
MN=sn""conf                              # the OWN token rides ONLY the concat
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
A_CC='snort_config.cc'; A_H='snort_config.h'   # GROUND path seats (carrier law)
mkdir -p "$H" "$H"/o2

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/main/$A_CC)" -eq 1138
test "$(md5sum "$SRC"/src/main/$A_CC | awk '{print $1}')" = "a2e0b91f1de2fa295ce7dd7d2be77a5b"
test "$(wc -l < "$SRC"/src/main/$A_H)" -eq 798
test "$(md5sum "$SRC"/src/main/$A_H | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
test "$(( 1138 + 798 ))" -eq 1936                                         # the pair ledger

# ---- THE ZERO-GATE DIALECT FACE MEASURED EVERY BUILD (by WALK, NEVER
# assumed; the four-way: TEST/TEST_CASE/CATCH/UNIT_TEST find-0 BOTH — the
# ZERO-unit-test-post law, the ut post 0-DELTA VACUOUS) ----
test "$(grep -c 'TEST_CASE' "$SRC"/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'TEST_CASE' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'TEST(' "$SRC"/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'TEST(' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'CATCH' "$SRC"/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'CATCH' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'UNIT_TEST' "$SRC"/src/main/$A_CC || true)" -eq 0         # ZERO posts (the walked 0-delta face)
test "$(grep -c 'UNIT_TEST' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'REG_TEST' "$SRC"/src/main/$A_CC)" -eq 1                  # :1102 (the cleanup_fatal_error inside)
test "$(grep -n 'REG_TEST' "$SRC"/src/main/$A_CC | cut -d: -f1 | paste -sd,)" = "1102"
test "$(grep -c 'REG_TEST' "$SRC"/src/main/$A_H)" -eq 3                   # :83 :212 :534 (the pinned line list)
test "$(grep -n 'REG_TEST' "$SRC"/src/main/$A_H | cut -d: -f1 | paste -sd,)" = "83,212,534"
test "$(grep -c '#ifdef SHELL' "$SRC"/src/main/$A_CC)" -eq 1
test "$(grep -n '#ifdef SHELL' "$SRC"/src/main/$A_CC | cut -d: -f1)" = 485
test "$(grep -c '#ifdef SHELL' "$SRC"/src/main/$A_H)" -eq 1
test "$(grep -n '#ifdef SHELL' "$SRC"/src/main/$A_H | cut -d: -f1)" = 79
test "$(grep -c 'SHELL' "$SRC"/src/main/$A_CC)" -eq 1                     # the RAW SHELL-token walk face
test "$(grep -c 'SHELL' "$SRC"/src/main/$A_H)" -eq 2
test "$(grep -c '^static' "$SRC"/src/main/$A_CC)" -eq 7                   # the file-statics census (the E9 cite pool)
test "$(grep -c 'THREAD_LOCAL' "$SRC"/src/main/$A_CC)" -eq 2              # snort_conf + log_quiet_bypassed (the row OWNS both)
test "$(grep -c 'THREAD_LOCAL' "$SRC"/src/main/$A_H)" -eq 1               # the extern decl face :197
# the cmake posture (the dialect NEVER compiled-in face) ----
test "$(grep -c 'option ( ENABLE_SHELL' "$SRC"/cmake/create_options.cmake)" -eq 1
test "$(grep 'option ( ENABLE_SHELL' "$SRC"/cmake/create_options.cmake | grep -c ' OFF ')" -eq 1
test "$(grep -r REG_TEST "$SRC"/CMakeLists.txt "$SRC"/cmake/ | wc -l)" -eq 0   # the token ABSENT from cmake (MEASURED)
test "$(grep -c 'add_cp'putest "$SRC"/src/main/test/CMakeLists.txt)" -eq 2     # thread_test + the gated distill face (the verbatim split-token arm)
test "$(grep -c "$A_CC" "$SRC"/src/main/test/CMakeLists.txt || true)" -eq 0    # NEITHER dialect list hosts the row TU
test "$(ls /usr/include/CppUTest 2>/dev/null | wc -l)" -eq 0                   # the dialect host ABSENT MEASURED
test "$(grep -c "$A_H" "$SRC"/src/main/CMakeLists.txt)" -eq 1             # the ONE INCLUDES seat
test "$(grep -n "$A_H" "$SRC"/src/main/CMakeLists.txt | cut -d: -f1)" = 7
test "$(grep -c "$A_CC" "$SRC"/src/main/CMakeLists.txt)" -eq 1            # the ONE SOURCES seat
test "$(grep -n "$A_CC" "$SRC"/src/main/CMakeLists.txt | cut -d: -f1)" = 51
test "$(grep -c ENABLE_SHELL "$SRC"/src/main/CMakeLists.txt)" -eq 2       # :20/:22 pair — the row seats ride OUTSIDE the gate

# ---- copy tree = the ipheavy DONOR clone (.o's PURGED after the cp); the
# donor self-heal face (the cd_ipv4.o guard passes on the shipped face) ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H"/o2; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" \( -name "$A_CC" \) | wc -l)" -eq 0                     # the row .cc find-0 BEFORE the cp
test "$(md5sum "$C"/main/$A_H | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"  # the donor carries the GROUND .h TWIN (the OVERWRITE-in-place law, MEASURED md5-IDENTICAL)
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"   # the GRAFT trio IN FORCE (verified in the FRESH clone)
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
test "$(md5sum "$C"/config.h     | awk '{print $1}')" = "b5ad224e236fc4a36c19d3cfb71bb8da"   # the EMPTY dialect seat IN FORCE

# ---- FACE 1 (the fresh-cp BARE E4 die, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at cc :34:10 — actions/
# ips_actions.h, the FIRST donor-absent head (the 24f :32 detect.h head
# MOVED — MEASURED, the walked face) ----
mkdir -p "$C"/main
cp "$SRC"/src/main/$A_CC "$SRC"/src/main/$A_H "$C"/main/
cmp -s "$C"/main/$A_CC "$SRC"/src/main/$A_CC       # VERBATIM cp, NEVER sed
cmp -s "$C"/main/$A_H  "$SRC"/src/main/$A_H
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 141              # 140 donor + 1 row cc (the .h OVERWROTE its twin stage-2 of the algebra)
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -iquote$C/main -I$LJ/src -DHAVE_CONFIG_H"
if $GXX0 -c "$C"/main/$A_CC -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c ':34:10' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'actions/ips_actions.h: No such file' "$H"/E4_bare.txt)" -eq 1   # the ONE head-missing face

# ---- THE full DECL-closure hull: 86 fresh-cp heads (pair form, cmp-PROVED
# every cp; the COLD-WALK face — the full transitive walk, NEVER guessed) ----
FRESH="actions/ips_actions.h detection/detect.h detection/fp_config.h detection/fp_create.h ports/port_group.h framework/mpse_batch.h framework/mpse.h search_engines/search_common.h dump_config/config_data.h dump_config/json_config_output.h dump_config/config_output.h helpers/json_stream.h dump_config/text_config_output.h events/event_queue.h file_api/file_service.h mime/file_mime_config.h file_api/file_api.h filters/detection_filter.h profiler/profiler.h profiler/profiler_defs.h profiler/memory_defs.h profiler/memory_profiler_defs.h profiler/rule_profiler_defs.h time/stopwatch.h profiler/time_profiler_defs.h filters/rate_filter.h filters/sfrf.h filters/sfthreshold.h flow/ha_module.h main/reload_tuner.h framework/policy_selector.h helpers/memcap_allocator.h helpers/challenge_response_auth.h host_tracker/host_cache_segmented.h host_tracker/host_cache.h hash/lru_cache_shared.h host_tracker/host_tracker.h network_inspectors/appid/application_ids.h host_tracker/cache_allocator.h host_tracker/cache_interface.h log/log_stats.h latency/latency_config.h latency/packet_latency_config.h latency/rule_latency_config.h main/process.h managers/action_manager.h managers/codec_manager.h managers/connector_manager.h framework/connector.h managers/event_manager.h framework/logger.h events/event.h managers/inspector_manager.h managers/ips_manager.h detection/detection_options.h detection/ips_context.h detection/detection_buf.h detection/rule_option_types.h latency/rule_latency_state.h trace/trace_api.h framework/ips_option.h framework/cursor.h managers/module_manager.h main/analyzer_command.h managers/mpse_manager.h managers/so_manager.h framework/so_rule.h managers/mp_transport_manager.h managers/trace_logger_manager.h framework/tracer.h memory/memory_config.h packet_io/sfdaq_config.h parser/parser.h detection/rules.h detection/treenodes.h detection/signature.h parser/vars.h sfip/sf_vartable.h payload_injector/payload_injector_config.h ports/rule_port_tables.h profiler/profiler_impl.h main/snort.h target_based/host_attributes.h trace/trace_config.h utils/dnet_header.h main/analyzer.h"
test "$(echo "$FRESH" | wc -w)" -eq 86                                   # the COLD face
for f in $FRESH; do
    mkdir -p "$C/$(dirname "$f")"
    cp "$SRC"/src/"$f" "$C/$f"
    cmp -s "$C/$f" "$SRC"/src/"$f" || { echo "fresh-cp DRIFT: $f"; exit 1; }
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 227                # 140 donor + 1 row cc + 86 fresh-cp

# ---- THE dnet GRAFT (libdnet ABSENT MEASURED: /usr/include/dnet.h +
# dumbnet.h + libdnet find-0 — the act-family graft precedent; the ground
# utils/dnet_header.h :40 rides IT; the row set_dst_mac :664-:677 body
# drives eth_pton — decls ONLY, NEVER a lib claim) ----
test ! -e /usr/include/dnet.h
test ! -e /usr/include/dumbnet.h
cat > "$C"/dnet.h <<'EODNET'
#ifndef SHIM_DNET_H
#define SHIM_DNET_H
#include <stddef.h>
#include <sys/types.h>
typedef struct eth_s eth_t;
typedef struct ip_s ip_t;
typedef struct eth_addr_s { unsigned char data[6]; } eth_addr_t;
#ifdef __cplusplus
extern "C" {
#endif
int eth_pton(const char* name, eth_addr_t* eth);
int eth_ntop(const eth_addr_t* eth, char* buf, int len);
eth_t* eth_open(const char* dev);
ssize_t eth_send(eth_t* e, const void* p, size_t size);
void eth_close(eth_t* e);
ip_t* ip_open(void);
ssize_t ip_send(ip_t* i, const void* p, size_t len);
void ip_close(ip_t* i);
#ifdef __cplusplus
}
#endif
#endif
EODNET
grep -q 'eth_pton' "$C"/dnet.h    # the graft SHIM face (the cc :670 driver seat)
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 228                # +the dnet GRAFT seat

# ---- STALE-DONOR ground-WINS (the compiler-SURFACED pair: trace/trace.h —
# the Traces typedef the ground trace_config.h :58 SEAT needs (the donor
# seat STALE 40 L vs ground 101 L); detection/detection_engine.h — the ONE
# cc :963 DetectionEngine::inspect seat (the donor seat STALE 8 L vs ground
# 180 L)) + the hwloc EXCISION face the DONOR ALREADY RIDES (its main/
# thread_config.h MEASURED byte-IDENTICAL to ground-minus-the-hwloc-include;
# the mod-stor/24e precedent; host /usr/include/hwloc.h ABSENT MEASURED) ----
grep -q 'hwloc_topology_t' "$C"/main/thread_config.h || { echo "the hwloc seat face MOVED — re-plan"; exit 1; }
test "$(grep -c '#include <hwloc.h>' "$C"/main/thread_config.h || true)" -eq 0    # the donor ALREADY EXCISED (MEASURED in the clone)
cp "$SRC"/src/trace/trace.h "$C"/trace/trace.h
cmp -s "$C"/trace/trace.h "$SRC"/src/trace/trace.h || { echo "ground-WINS DRIFT: trace/trace.h"; exit 1; }
cp "$SRC"/src/detection/detection_engine.h "$C"/detection/detection_engine.h
cmp -s "$C"/detection/detection_engine.h "$SRC"/src/detection/detection_engine.h || { echo "ground-WINS DRIFT: detection/detection_engine.h"; exit 1; }
echo "closure algebra: donor 140 -> +row cc 141 (the .h OVERWRITES the donor GROUND-TWIN in place) -> +86 fresh-cp 227 -> +dnet GRAFT 228 -> +packet_constraints.h leg rider 229 (the trio OVERWRITTEN at FACE 3; ZERO daq_module_api/daq_version seats)"

# ---- FACE 2 (the DONOR-GRAFT daq face, MEASURED EXACTLY-1 — the honest
# DIVERGENCE from the 24f ZERO face, NEVER the 24d 51-error wall copied):
# the closed hull under the donor trio pulls the ONE DAQ_PktHdr_t.ts drift
# leg (detection/detect.h -> detection_options.h IN-TU inline :74) — the
# config-OWNER surface, unlike the config-MODULE pair, DOES reach the msg-
# API header legs. The DAQ_MsgType/daq_msg/daq_version token faces STAY
# 0 (MEASURED every build, NEVER assumed; the flipped arm re-armed). ----
if $GXX0 -c "$C"/main/$A_CC -o "$C"/sc_graft.o 2> "$H"/E4_graft.txt; then
    echo "E4 graft face MOVED — the donor daq trio suddenly compiles the row CLEAN; RE-MEASURE"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 1                       # MEASURED EXACTLY-1
test "$(grep -c 'fatal error' "$H"/E4_graft.txt)" -eq 0
test "$(grep -c 'has no member named .ts' "$H"/E4_graft.txt)" -eq 1  # the ONE drift leg
test "$(grep -c 'detection/detection_options.h:74' "$H"/E4_graft.txt)" -eq 1      # the IN-TU inline seat
test "$(grep -c 'DAQ_MsgType' "$H"/E4_graft.txt || true)" -eq 0          # ZERO msg-type tokens
test "$(grep -c 'daq'"_msg" "$H"/E4_graft.txt || true)" -eq 0            # ZERO msg-API legs (contrast the 24d 51-error wall)
test "$(grep -c 'daq_version' "$H"/E4_graft.txt || true)" -eq 0          # ZERO version tokens

# ---- FACE 3 (the RE-CITE: the REAL libdaq @ c8d4083 head SWAP -> SILENT
# rc0 BOTH posts; the 3 api heads md5-pinned vs the LIVE $L face; the
# daq_version.h sed face NOT needed — MEASURED; daq_module_api.h NEVER
# needed — MEASURED (the 24f face MOVED: ZERO extra SDK seats HERE)) ----
test "$(git -C "$L" rev-parse HEAD | cut -c1-7)" = "c8d4083"
for h in daq.h daq_common.h daq_dlt.h; do
    cp "$L"/api/"$h" "$C"/
    cmp -s "$C/$h" "$L/api/$h" || { echo "SDK cp DRIFT: $h"; exit 1; }
done
test "$(md5sum "$C"/daq.h            | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h     | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h        | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(find "$C" -name 'daq_version.h' | wc -l)" -eq 0                  # ZERO sed faces shipped (MEASURED: the closure NEVER asks for it)
test "$(find "$C" -name 'daq_module_api.h' | wc -l)" -eq 0               # the 24f face MOVED — NEVER needed here (MEASURED)
mkdir -p "$H"/o2                                                         # the 24b cold-order law BEFORE any .o writer
$GXX0 -c "$C"/main/$A_CC -o "$C"/sc.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                              # SILENT the plain .o
$GXX0 -DUNIT_TEST -c "$C"/main/$A_CC -o "$H"/o2/sc_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt            # SILENT BOTH posts (the VACUOUS post: ZERO UNIT_TEST posts — the zero-gate honest compile face; the nm delta EXACTLY-0)

# ---- the REAL ground legs (link-REAL bodies beside the row; EVERY one
# compiles SILENT inside the closed hull — the packet_constraints.h leg
# rider cp rides here, the trace_config.cc :30 include seat; sfdaq_config
# the 23a home batch=64/mru=1518 LIVE; sf_cidr+sf_ip the -B obfuscation
# legs; util the snort_strdup home; snort_protocols the ProtocolReference
# the ctor new's; trace_config the TraceConfig the ctor new's. LuaJIT legs
# ride ZERO ($LJ/src NEVER reached). ----
cp "$SRC"/src/packet_io/packet_constraints.h "$C"/packet_io/
cmp -s "$C"/packet_io/packet_constraints.h "$SRC"/src/packet_io/packet_constraints.h || { echo "leg-rider cp DRIFT"; exit 1; }
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 229               # 140 + 1 + 86 + 1 GRAFT + 1 leg rider (the set algebra banked)
for leg in packet_io/sfdaq_config.cc sfip/sf_cidr.cc sfip/sf_ip.cc utils/util.cc target_based/snort_protocols.cc trace/trace_config.cc; do
    o=$(basename "${leg%.cc}")
    $GXX0 -c "$SRC"/src/"$leg" -o "$H"/leg_$o.o 2> "$H"/E_leg_$o.txt
    test ! -s "$H"/E_leg_$o.txt || { echo "leg COMPILE NOISE: $leg"; cat "$H"/E_leg_$o.txt; exit 1; }
done

# ---- the nm app-undef census (MEASURED EXACT at the row; the FOURTH-
# control face: plain 84 / ut 84, delta EXACTLY-0 BOTH arms — NO ut-post
# leg EVER ships, the walked zero-UNIT_TEST law; NO Catch:: CLASS leg EITHER) ----
LEGS="$H/leg_sfdaq_config.o $H/leg_sf_cidr.o $H/leg_sf_ip.o $H/leg_util.o $H/leg_snort_protocols.o $H/leg_trace_config.o"
nm -C -u "$C"/sc.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 84                             # the measured app-undef wall census
nm -C -u "$H"/o2/sc_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 84                                # plain + ZERO ut legs (delta EXACTLY-0 pinned honest)
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | grep -c '^>')" -eq 0 # the delta FACE: EMPTY (the ZERO-post law)
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | grep -c '^<')" -eq 0
test "$(grep -c 'Catch::' "$H"/nm_U_ut.txt || true)" -eq 0               # NO dialect CLASS leg EVER ships
test "$(grep -c 'Catch::' "$H"/nm_U_plain.txt || true)" -eq 0
test "$(grep -c 'catch_set_filter' "$H"/nm_U_ut.txt || true)" -eq 0      # ABSENT BOTH postures (the 24f face MOVED)
test "$(grep -c 'catch_set_filter' "$H"/nm_U_plain.txt || true)" -eq 0
grep -q 'SFDAQConfig::overlay(SFDAQConfig const\*)' "$H"/nm_U_plain.txt  # the merge() daq overlay seat (the REAL 23a leg body)
grep -q 'Analyzer::set_main_hook' "$H"/nm_U_plain.txt                    # the alert/log hook seats (the mirror wall)
grep -q 'PolicyMap::setup_network_policies' "$H"/nm_U_plain.txt          # the ctor->verify wall leg
grep -q 'eth_pton' "$H"/nm_U_plain.txt                                   # the dst_mac dnet GRAFT face
grep -q 'ActionManager::new_config' "$H"/nm_U_plain.txt                  # the ctor init mirror
grep -q 'PluginManager::release_plugins' "$H"/nm_U_plain.txt             # the plug_set dtor wall
grep -q 'snort::SFDAQ::get_tunnel_bypass' "$H"/nm_U_plain.txt            # the tunnel_bypass_enabled seat
grep -q 'snort::SfCidr::set(char const\*)' "$H"/nm_U_plain.txt           # the -B obfuscation face (the REAL sf_cidr leg)

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-67 EVERY build:
# the plain .o beside the ut .o — the pair rides ~61 T-def twins (the ctor
# C1/D1 faces ride TRIPLED — SnortConfig(char const*) + (ProtocolReference*)
# + ~SnortConfig) + the THREE owned statics + static_names_mutex/static_-
# names + the vtable-free data legs; NEVER assumed off the 24f-12/24d-44/
# 24e-53 faces) ----
if g++ -std=c++17 -w "$C"/sc.o "$H"/o2/sc_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 67
rm -f "$H"/.e9dup

# ---- the witness mirror (shape-only capture legs; EVERY namespace place-
# ment rides the row's OWN raw-NAME nm census face — the compiler ENFORCED
# the restructure honestly). NO private-access flag EVER ships: the whole
# ladder is reached through PUBLIC seats + the header INLINES + the row's
# OWN bodies alone. ----
test -f "$H"/witness_row.cc
$GXX0 -x c++ -c "$H"/witness_row.cc -o "$H"/witness.o
$GXX0 -c "$H"/probe.cc       -o "$H"/probe.o
$GXX0 -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o

# ---- vectors (FIRST-RUN-SEED law): the row .o + the witness + the SIX
# REAL ground legs; cmp-PROVEN byte-IDENT vs the TRACKED seed EVERY re-run
# (drift REFUSED); O0==O2 BOTH bodies + the cross face BYTE-IDENT; the
# tamper arm proves the seed. NO stderr wall rides THIS row. ----
WINSL="$H/witness.o $LEGS -ldl -lpthread"
# STATE-AWARE seed guard (the walked face at THIS row: the sibling's staging
# ALREADY carries build.sh in the INDEX while I iterate — the 24f ls-files-0
# arm presumes an unstaged pre-commit face; the refusal semantic KEPT: a
# vectors seed tracked but MISSING on disk = POST face = refuse; untracked vectors
# + absent file = the honest FIRST-RUN-SEED face).
if [ ! -f "$V" ]; then                                   # FIRST-RUN-SEED
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -c vectors_faceA)" -eq 0 || { echo "vectors seed MISSING at POST — refuse"; exit 1; }
    g++ -std=c++17 -w "$H"/probe.o "$C"/sc.o $WINSL -o "$H"/probe_x || exit 1
    "$H"/probe_x > "$H"/vectors_O0.txt || exit 1
    cp "$H"/vectors_O0.txt "$V"
fi
g++ -std=c++17 -w "$H"/probe.o "$C"/sc.o $WINSL -o "$H"/probe_x || exit 1
"$H"/probe_x > "$H"/vectors_O0.txt || exit 1
$GXX0 -O2 -c "$H/probe.cc" -o "$H"/o2/probe.o
$GXX0 -O2 -c "$C/main/$A_CC" -o "$H"/o2/sc.o
for leg in packet_io/sfdaq_config.cc sfip/sf_cidr.cc sfip/sf_ip.cc utils/util.cc target_based/snort_protocols.cc trace/trace_config.cc; do
    o=$(basename "${leg%.cc}"); $GXX0 -O2 -c "$SRC"/src/"$leg" -o "$H"/o2/leg_$o.o
done
O2LEGS="$H/o2/leg_sfdaq_config.o $H/o2/leg_sf_cidr.o $H/o2/leg_sf_ip.o $H/o2/leg_util.o $H/o2/leg_snort_protocols.o $H/o2/leg_trace_config.o"
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/o2/sc.o "$H"/witness.o $O2LEGS -ldl -lpthread -o "$H"/probe_x_O2 || exit 1
"$H"/probe_x_O2 > "$H"/vectors_O2.txt
g++ -std=c++17 -w "$H"/probe.o "$H"/o2/sc.o "$H"/witness.o $O2LEGS -ldl -lpthread -o "$H"/probe_x_cross || exit 1
"$H"/probe_x_cross > "$H"/vectors_O2b.txt
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt  || { echo "DEC O0!=O2 (probe body)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt || { echo "DEC O0!=O2 (row body)"; exit 1; }
test "$(wc -l < "$V")" -eq 117                       # the COLD face (the ctor/dtor W-mirror echo legs MEASURED — the moved face vs the 24f 126 module-row count)
test "$(grep -c '^D0 ctor' "$V")" -eq 1               # the ctor face (run_flags-0 + the rid=1 tracker tick)
test "$(grep -c 'fin=PASS' "$V")" -eq 1               # the ladder tail
grep -q 'NF set_uid noreturn-false cited wall' "$V"   # the cited-wall family rides (the config OWNER has NO Module parameter table — the dialect legs ride FACE-A; NO pfind face HERE, the walked moved shape)
grep -q 'T2 mask=' "$V"                               # the tunnel reject face (the walked determinism arm)
grep -q 'V1 run' "$V"                                 # the merge() run_flags-OR overlay face
test "$(grep -c '^NF ' "$V")" -eq 4                   # the cited-wall family face (uid/gid/setup/generate_dump — NEVER fired)
test "$(grep -c 'W FileService::close' "$V")" -eq 1    # the REG_TEST-inside PROOF face (the dialect NEVER compiled; the close leg RODE)

# ---- FACE-A vectors (the ENUM census at the PLAIN posture; the walked
# 26+2-cited RunFlag face; the 24c..24f law) ----
$GXX0 -O2 -c "$H/probe_faceA.cc" -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o "$C"/sc.o "$H"/witness.o $LEGS -ldl -lpthread -o "$H"/probe_faceA_x && "$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt
if [ ! -f "$VA" ]; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -c vectors_faceA.txt)" -eq 0 || { echo "FACE-A seed MISSING at POST — refuse"; exit 1; }
    cp "$H"/vectors_faceA_O0.txt "$VA"
fi
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o "$H"/o2/sc.o "$H"/witness.o $O2LEGS -ldl -lpthread -o "$H"/probe_faceA_x_O2 && "$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
test "$(wc -l < "$VA")" -eq 35                        # the COLD face (35 rows: the enum census + the ctor/dtor W-echo legs — the moved face vs the 24f 14-row module count, MEASURED NEVER stretched)
grep -q '^A1 runflags_live=26' "$VA"                  # 26 live RunFlag members; the 2 dialect legs ride the cited ABSENT arms
grep -q 'RUN_FLAG__SHELL ABSENT' "$VA"                # the h :79-:81 dialect cited face
grep -q 'RUN_FLAG__EXIT_AFTER_RELOAD ABSENT' "$VA"    # the h :83-:85 dialect cited face
grep -q 'logdir=. pidfile=snort.' "$VA"                # the h :42-:43 DEFAULT faces (wildcard-dot face)
grep -q 'A5 outflags=14' "$VA"                        # the OutputFlag 14-member census
grep -q '^A9 drs=1' "$VA"                             # the get_default_rule_state INHERIT->global-true posture face
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/fin=PASS/fin=BLOCK/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v
sed 's/runflags_live=26/runflags_live=25/' "$VA" > "$H"/.tamper_va; ! cmp -s "$H"/.tamper_va "$H"/vectors_faceA_O0.txt; rm -f "$H"/.tamper_va

# ---- THE CENSUS (MEASURED loops; THE ZERO-GATE FACE: NOTHING flips THIS
# row — 31 on-disk / legacy 9 x 4826fc22 FROZEN / 23 lineages / tracked 1
# (gre's) — read + echoed EVERY leg, the UNMOVED zero-gate control law) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 32                     # UNMOVED (the zero-gate control row)   # [24h rider 31->32: the chapter-21 po-li-cy gate row lands its COPY-LOCAL gate (the 62d6fac complete-flip law, walked face)]
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 24                       # UNMOVED (NO new tail EVER)   # [24h rider 23->24: the 24h gate-tail md5 lineage (the 62d6fac law, walked face)]
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh   # the legacy lineage anchor
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1               # tracked face UNCHANGED: gre's ONLY
test -z "$(find "$H" -name 'gate.txt' 2>/dev/null)"                   # NO gate EVER ships HERE (the zero-gate law by WALK)
test -z "$(find "$H" -name 'gate_main.cc' 2>/dev/null)"               # NO runner HERE (the zero-gate companion)
PCG_H=$R/tools/pc""gate_harness
test "$(git -C "$R" status --porcelain -- "$PCG_H"/gate.txt | wc -l)" -eq 0   # the 23e gate ARTIFACT byte-UNTOUCHED
TCH=$R/tools/t""c_harness
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0     # the 22a gate ARTIFACT byte-UNTOUCHED
PT2=$R/tools/pt""racer_harness
test "$(git -C "$R" status --porcelain -- "$PT2"/gate.txt | wc -l)" -eq 0     # the 23f gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (the direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$PCG_H"/vectors.txt | awk '{print $1}')"       = "0a6e17ca5532f68c59d1c4c5e174d3fd"
test "$(md5sum "$PCG_H"/vectors_faceA.txt | awk '{print $1}')" = "7b1974dcd85a5d3f1ce1f89ef8b093f8"
test "$(md5sum "$PT2"/vectors.txt | awk '{print $1}')"         = "218ec5b6cde11566f9036e7e2f1f374d"
test "$(md5sum "$PT2"/vectors_faceA.txt | awk '{print $1}')"   = "3a9b0a4b31ba291d98e3a980efc0c2de"

# ---- the landed-home faces (the mod.rs 11->12 FLIP ALREADY ON DISK at
# THIS row: the landing child added the ONE wiring line — 62d6fac law,
# walked face; THIS harness PINS, NEVER edits) ----
test "$(wc -l < "$R"/src/main/mod.rs)" -eq 13                             # [24i rider 12->13: the an-al-yzer-com-mand own-er pair's ONE new wiring line in the mo-d-r-s (the 62d6fac complete-flip law, walked face)]                          # THE flip 11->12 at THIS row  # [24g flip 11->12: the snort-config owner pair's ONE new wiring line (the 62d6fac law, walked face)]
test "$(grep -c 'pub mod snort_conf' "$R"/src/main/mod.rs)" -eq 1      # the GROUND name (the C pair is snort_config.cc — NOT an own token; the carrier law)
test -f "$R"/src/main/snort_configp.rs                                 # the landing home (24g; the 1,936-L pair mirror — the ZERO-attribute / ZERO-in-safe law asserted IN the landing + the cold audit, NEVER md5-pinned from the C harness)
test "$(grep -c 'pub const DAQ_VERDICT' "$R"/src/packet_io/sf""daq.rs)" -ge 6   # the LANDED verdict-constant home REUSED (the one-home law)
test "$(grep -c 'fn kick_watchdog\|pub fn update_thread_status' "$R"/src/main/thread_config.rs)" -ge 2  # the 23b home faces (NEVER re-forked HERE)

# ---- landmine NAMING legs (the misc-9 family STAYS 3 occupants NEVER +1;
# the hyphen/bracket-split comment law holds THIS row) ----
test "$(grep -rlE 'ReloadS''urvivor|reload_''survivor' "$R"/src --include=*.rs | wc -l)" -eq 3   # UNMOVED at 3 (the module-registry family cite; the 62d6fac law, walked face; carrier hyphen-split per the family law)
test "$(grep -rl 'struct T''racer' "$R"/src --include=*.rs | wc -l)" -eq 0

# ---- STATE-AWARE docs faces (the 23b/24a split law: the landing commit
# banks the PLAN row + the deviations section; the NEXT.md header/seed bank
# rides the ORCHESTRATOR sibling; at THIS row the joined own-token NEVER
# rides NEXT.md) ----
docbank=$(grep -q "^## .*row 24g" "$R/KNOWN DEVIATIONS.md" && echo banked || echo unbanked)
echo "docs bank state (24g): $docbank"
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -eq 0                    # own joined token ZERO on NEXT (the ZERO-both-branch law)
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c '^| 24g ' "$R/PORTING_PLAN.md")" -eq 1              # the plan-row grep-count-1 law
    test "$(grep -c 'row 24g' "$R/KNOWN DEVIATIONS.md")" -ge 1
    test "$(grep -c "${MN}" "$R/PORTING_PLAN.md")" -eq 0                # the DONE echo NEVER rides docs
    test "$(grep -c "${MN}_DONE" "$R/PORTING_PLAN.md")" -eq 0
    test "$(grep -c "${MN}" "$R/KNOWN DEVIATIONS.md" || true)" -eq 0    # the plan/deviations rows ride HYPHEN forms (sn-conf / snort-config family law)
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the CURRENT HEAD
# docs face; the 900 head face joins the 885..752 x3 family; the NEW 24g
# face rides the docs sibling) ----
test "$(grep -c '900 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3       # the CURRENT seed face x3
test "$(grep -c '885 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
for s in 870 855 841 825 810 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c '5 TES'"T(" "$R/NEXT.md")" -eq 1                        # the drift token EXACT-1 (split form; NEVER typed whole HERE)

# ---- token censuses (the own-token family MEASURED 0 PRE-HITS across
# tools/tests/NEXT.md/src at authoring: the dir token rides ONLY the $MN
# concat; the GROUND name rides PATHS by construction (the 24a/24e/24f
# carrier precedent — the pair it ports is NAMED that); the SELF-scan arms
# prove THIS row adds ZERO joined holders) ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}" "$H"/build.sh || true)" -eq 0                         # SELF-scan (the 23f SELF-HIT law; $MN itself rides a concat)
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/witness_row.cc | grep -c "${MN}" || true)" -eq 0
test "$(grep -c "${MN}" "$R"/src/main/snort_configp.rs || true)" -eq 0        # the landing .rs NEVER carries the dir token
test "$(grep -c "${MN}" "$R"/src/main/mod.rs || true)" -eq 0                  # the wiring line is the GROUND name (pub mod snort_configp — NOT joined)
test "$(grep -rl "${MN}" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --include='*.cc' --exclude-dir="${MN}_harness" 2>/dev/null | wc -l)" -eq 0   # foreign-holder sweep UNMOVED
test "$(grep -rl "${MN}" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0
# the GROUND-name carrier faces UNMOVED at this row (re-measured):
test "$(grep -c 'add_cp'putest "$SRC"/src/main/test/CMakeLists.txt)" -eq 2   # UNDISTURBED (the verbatim split-token arm)
test "$(wc -l < "$SRC"/src/main/analyzer_command.h)" -eq 267                  # the sh-ell-era GROUND wc face UNMOVED

# ---- STATE-AWARE stageables dual guard (7 faces: .gitignore + build.sh +
# probe.cc + probe_faceA.cc + witness_row.cc + the 2 vectors; NO PLAN.md,
# NO gate (the zero-gate row law); the header carries the recon). PRE face:
# the files ON DISK; POST face: the ls-files 7-face + the ZERO-leak arms. ----
for f in .gitignore build.sh probe.cc probe_faceA.cc witness_row.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main/snort_config.cc copy/main/snort_config.h copy/dnet.h copy/packet_io/packet_constraints.h copy/sc.o copy/sc_graft.o copy/daq.h o2/probe.o o2/probe_faceA.o o2/sc.o o2/sc_ut.o probe_x probe_x_O2 probe_x_cross probe_faceA_x probe_faceA_x_O2 probe.o probe_faceA.o witness.o leg_sfdaq_config.o leg_sf_cidr.o leg_sf_ip.o leg_util.o leg_snort_protocols.o leg_trace_config.o vectors_O0.txt vectors_O2.txt vectors_O2b.txt vectors_faceA_O0.txt vectors_faceA_O2.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E9_dup.txt E_leg_sfdaq_config.txt E_leg_sf_cidr.txt E_leg_sf_ip.txt E_leg_util.txt E_leg_snort_protocols.txt E_leg_trace_config.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt .e9dup .tamper_v .tamper_va stageables.txt run1.log run2.log run3.log run4.log run5.log run6.log run_x.log run_x2.log; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
if [ "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -c '^tools/'"$(basename "$H")"'/vectors(_faceA)\?\.txt$')" -eq 2 ]; then
    # the full-7 POST face fires ONLY once BOTH vector seeds ride the INDEX
    # (the walked face at THIS row: the sibling stages PART of this dir mid-
    # iteration — the template's error-unmatch-guarded face presumes an all-
    # committed face; the refusal semantic KEPT at the full face)
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 7
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|build\.sh|probe(_faceA)?\.cc|witness_.*\.cc|vectors(_faceA)?\.txt')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
fi

echo "census (walked, UNMOVED): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $frozen x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor — NO gate ships HERE"
echo "$(printf 'SNC%s_DONE' 'ONF') vectors=$(wc -l < "$V")/$(wc -l < "$VA") md5=$(md5sum "$V" | awk '{print $1}')/$(md5sum "$VA" | awk '{print $1}') closure=229(140+1+86+1+1) graft_err=1(DAQ_PktHdr_t.ts) sdk_sed=0 nm=84/84 delta=0 Catch0 e9=67 legsREAL=6"

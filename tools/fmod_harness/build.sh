#!/usr/bin/env bash
# Ground-truth harness for the file-id Module TU row,
# file_api/file_module.{h,cc} (row 18a, probe-vectors-only).
# Lifted from the PROVEN tools/flog_harness donor (row 17z, freshest); the
# entire cp/objs/graft/shim/gate machinery is donor VERBATIM (retire rule)
# -- deltas marked NEW18a (fmod PLAN 0/2/6). DIR NAME PIN: fmod_harness.
# The row TU has 0 UNIT_TEST fragments and 0 TEST_CASEs at fe29cbe (86+379
# L re-measured; grep-asserted below) -> no grafts/seds/excisions fire on
# the row, ZERO gate delta BY CONSTRUCTION: gate.txt stays byte-ident md5
# 4826fc2233044a2d5429413faf0ae1af (NINTH straight zero-regression row --
# the same 114/22 tail the donor carried; file_module.o rides both links,
# 0 TEST_CASE by the self-check trio).
# NEW18a INVERTED-LANDMINE row (PLAN 2.2/2.3, the fsvc-17y pattern turned
# around): the row .o DOES define what the donor closure witnessed --
# EXACTLY 3 hard collisions vs the 18,267-def donor closure (nm-join,
# scratch 18a recon): T _ZN12FileIdModuleC1Ev (the 17w extern-C standover),
# T FileIdModule::load_config (the witness steal body), B file_trace (the
# TU-standover THREAD_LOCAL). All THREE retired from stubs.cc: the full
# 31-L trio block (md5 9165739e3f4e0119cd21de02acc2f6d7 across finspect/
# fpolicy/fsvc/flog = the dup proof, receipt assert below) is GONE here,
# STAYS in the four donors (per-link rule -- flog_harness is NOT rebuilt).
# The inverted-landmine nm asserts (stubs.o: zero FileIdModule, zero
# file_trace B; row .o: 18 T FileIdModule:: + C1 + load_config + B
# file_trace + the V vtable) close the dup class for good.
# NEW18a cp deltas (PLAN 0.1/2.1, the ONLY mechanical deltas): (a)
# file_module.cc appended to the file_api braces (the .h ALREADY rides
# there since 17w for the stubs include); (b) file_module joins the objs
# loop (d=file_api default, plain VERBATIM compile); (c) 11 header-only
# cps: lua/lua.h (NEW dir; <lua.hpp> resolves LIVE, never a stub) + main/
# {snort.h,analyzer_command.h} + managers/module_manager.h + parser/parser.h
# + detection/{rules,treenodes,signature,rule_option_types}.h + ports/
# port_group.h + framework/mpse_batch.h (zero link contribution, R8 pin);
# (d) TWO witness-header grafts, scratch-proven: the REAL TraceOption
# struct verbatim (trace/trace.h:55-:63) into the EOFTRH witness + the
# DIOCTL_GetSnortLatencyData placeholder into the EOFDAQ witness; (e) FOUR
# new witness bodies close EXACTLY the four app residues of the row .o
# (stubs NEW18a block): W1 parser_append_rules_special (prints (file,
# includer) incl. the empty-magic_file + null-includer arms), W2
# ModuleManager::get_includer (armable null), W3 DecodeConfig::
# set_decompress_buffer_size, W4 ControlConn::query_from_lua (= UPSTREAM
# VERBATIM non-SHELL nullptr, prints NOTHING; LogRespond -> the LOGMSG
# LogMessage arm pins the null-ctrlcon branch); (f) FIRST third-party link
# in the lineage: -L$LUA_SRC -lluajit -lm -ldl on BOTH links (luaL_opt-
# integer/luaL_optlstring are T defs in libluajit.a, assert below; NO
# hand-stubbed luaL_*, R4).
# Post-retirement nm deltas (measured): stubs.o FileIdModule defs 1->0,
# file_trace B 1->0, FileIdModule::load_config T 1->0; row .o adds 18 T +
# 3 W-inline + 3 V (vtable/typeinfo pair + string literal) + B file_trace;
# probe/gate links pick one more .o + the LuaJIT archive, ZERO dup symbols.
# The row TU has 0 UNIT_TEST fragments and 0 TEST_CASEs at fe29cbe (329 L
# re-measured; the two real cps text_log.cc/module.cc likewise 0/0) -> no
# grafts/seds/excisions fire on the row, ZERO gate delta BY CONSTRUCTION
# (gate.txt stays byte-ident md5 4826fc2233044a2d5429413faf0ae1af --
# scratch-proven PLAN 0.6: incremental ld -r over the WHOLE union incl.
# text_log.o module.o file_log.o + donor stubs.o/probe.o exited 0 with an
# EMPTY stderr (scratch ld_err.txt, 0 B) -> ZERO dup symbols).
# NEW17z ZERO-RETIREMENT row (PLAN 2.2 / R5): grep -n 'FileLog\|file_log\|
# TextLog\|Peg' donor stubs.cc = 0 hits -- the donor closure never
# witnessed this row's surface, so NOTHING retires; the dup-proof is the
# nm block below (stubs.o defines ZERO Module::/TextLog_ T defs; the real
# .o's own all 22 Module methods + the vtable/typeinfo pair + all five
# TextLog exports; the TWO new witnesses close exactly the two app
# residues: W1 DataBus::subscribe + W2 the show_stats overload pair).
# NEW17z cp deltas (PLAN 2.1, the ONLY mechanical deltas): (a) file_log.cc
# appended to the :96 file_api braces (NO .h twin -- the braces pattern
# fails on a missing file, which IS the existence pin) + text_log.cc +
# log.h + text_log.h appended to the :125 log braces; (b) THREE dirs join
# the objs loop -- file_log (d=file_api default), text_log (NEW case d=log,
# the second dir case after target_based), module (d=framework default,
# module.h already cp'd at :106); (c) REAL cp src/framework/module.cc +
# compile-only header cps utils/stats.h + main/stats_output_format.h (the
# module.cc:28 -> stats.h:31 chain, header-only, zero link contribution);
# (d) the ONE flowz graft delta since 17q: witness Flow gains uint16_t
# client_port/server_port (real flow.h:586-:587, read at file_log.cc:163-
# :164); (e) the ONE shim delta: snort_config.h gains #include "framework/
# inspector.h" (real main/snort_config.h:35 -- file_log.cc:202 `class
# FileLog : public Inspector` only reaches Inspector through that chain;
# the full-tree ld -r re-proves zero regressions, R8); (f) BOTH links gain
# text_log.o module.o file_log.o link-additively (zero ctor-observed
# behavior: the row TUs' static initializers touch only TU-private
# statics -- gate vectors ZERO delta by construction, the gate never calls
# the row api).
# Closure facts (PLAN 0, measured on the scratch copy tree /opt/data/
# cache/scratch/row17z, re-measured here at build): nm -u copy/file_api/
# file_log.o = 64 U entries = 13 REAL-OBJ (file_type_name, FileContext::
# get_UTF8_fname, FileFlows x2, FileInfo x5, SfIp::ntop, packet_gettime-
# ofday, ts_print, sin_file_flow) + 7 RESIDENT STUB (ConfigLogger::log_flag
# + the Inspector witness block + its typeinfo) + 16 NEW-app (TextLog_ x5
# + Module x8 + vtable/typeinfo x2 + DataBus::subscribe) + 28 libstdc++/
# libc plumbing. The five TextLog + eight Module + two vtable/typeinfo NEW
# entries close in the TWO real cps (text_log.o: 30 U = 3 real + 5 resident
# + 22 plumbing + ZERO app NEW -- the messages.cc-uncp'd guard R6 keeps
# ErrorMessage/FatalError uncollided; module.o: 32 U = 0 real + 2 resident
# + 30 plumbing); the surviving app residue after the union = EXACTLY 2
# entries: snort::DataBus::subscribe (W1) + the two show_stats overloads
# (W2, module.o's only app drag: cc:300/:307 -- stats.cc NEVER cps, the
# monolith include list stats.cc:32-:57). Post-W1/W2 comm-diffs: flog 29
# survivors/0 app, text_log 22/0, module 28/0 (the scratch-pinned 29/22/30
# numbers re-measure here BEFORE the W2 block arms; the build asserts each
# comm-diff exactly).
# Ground-truth harness for the file-service TU row,
# file_api/file_service.{h,cc} (row 17y). Lifted from the PROVEN
# tools/fpolicy_harness donor (row 17x, freshest; 17p-17x lineage); the
# entire cp/objs/graft/shim/gate machinery is donor VERBATIM (retire rule)
# -- deltas marked NEW17y (fsvc PLAN 0/2/6). DIR NAME PIN: fsvc_harness per
# NEXT.md row 17y. The row TU has 0 UNIT_TEST fragments and 0 TEST_CASEs at
# fe29cbe (112+270=382 L re-measured) -> no grafts/seds fire on it, ZERO
# gate delta BY CONSTRUCTION (gate.txt stays byte-ident md5
# 4826fc2233044a2d5429413faf0ae1af -- scratch-proven PLAN 0.6), self-check
# pattern repeats for the row.
# NEW17y cp deltas (PLAN 2.1, the ONLY mechanical deltas): (a) file_service.
# cc appended to the :87 braces (the .h already rides there) + file_service
# and snort_protocols appended to the :426 objs loop (plain VERBATIM
# compiles; snort_protocols needs the new d=target_based case); (b) 13
# compile-only header cp's for the row include closure (main.h at $C root;
# mime cluster x6; decompress/file_decomp.h; helpers/buffer_data.h;
# flow/flow_stash.h; search_engines x2; framework/mpse.h) -- ALL header-
# only, zero link contribution (PLAN 0.2/0.4: zero SearchTool/mpse residue
# entries; the R8 pin below re-arms that); (c) the ONE real cp src/
# target_based/snort_protocols.cc (find BODY at snort_protocols.cc:92; its
# residue = 1 resident STUB SnortConfig::get_static_name + 34 pure
# plumbing, ZERO app NEW -- PLAN 0.5) -> ProtocolReference::find needs NO
# 5th witness (the Rust twin snort_protocols.rs:41-:141 is fully ported ->
# real-TU parity is the better witness).
# Closure facts (PLAN 0.4, measured on the scratch copy tree): nm -u copy/
# file_api/file_service.o = 47 U entries = 14 REAL-OBJ (file_stats x2,
# get_file_config, FileCapture::init/exit, FileFlows x3, FileCache x6) + 3
# RESIDENT STUB (ReloadError stubs.cc:123, SnortConfig::get_conf :55,
# FlowData::create_flow_data_id :753 via the inlined FileFlows::init at
# cc:63) + 5 NEW app + 25 libstdc++/libc plumbing. 4 NEW witness bodies
# close the 4 app entries (main_packet_threads_fully_paused armable int --
# NEVER cp main.cc (:325 walks pigs/Analyzer monolith, R6); MimeSession::
# init/exit print pair (mime row stays queued, NEXT.md:126-:131);
# InspectorManager::get_inspector over the :432 toggle -- the reset() gate
# cc:68); the 5th (ProtocolReference::find) resolves in the real cp.
# RETIRED for the dup-symbol rule R5 (PLAN 2.2 INVERSION -- the real
# file_service.o defines them; 23 HARD collisions: 17 T + 6 B/D; naive
# co-link demo prints 142 lines): the ENTIRE donor FileService witness block
# (stubs.cc:584-:637 -- six statics, six lifecycle printf liveness defs, the
# enable trio + cascade replica, the 3-OR is_file_service_enabled (REAL
# cc:206-:209 is the 2-OR: drift pinned in fsvc V2b, PLAN 5 R3),
# the g_max_file_depth passthrough getter (R4: the setter stays as an inert
# drift arm, the real getter answers the CONFIG), the NEW17w INSTRUMENTED
# set_max_file_depth replica (the 17w "INSTRUMENT it, don't retire" ruling
# SUPERSEDED: the real body links now; the instrumentation lives on the Rust
# test side (file_inspect.rs:230-:267 + frozen finspect SMD vectors,
# UNTOUCHED), get_file_processed_size (:711-:727 verbatim copy of cc:
# 256-:268 -> the row .o owns it now). The extern-C arms fcache_set_file_
# cache/:639, fcache_set_max_file_depth/:732, fcache_set_file_service/:735
# keep working VERBATIM against the REAL statics (scratch-proven: the
# retired-stubs TU links clean against the real row .o).
#  * gate: UNCHANGED (gate delta ZERO by construction, PLAN 2.1): 22 cases /
#    114 assertions stay byte-ident (tail + md5 4826fc22... re-asserted
#    below); file_service.o + snort_protocols.o ride the gate link inert-by-
#    construction (the gate never calls the lifecycle, R9; 34x IMGR acquire
#    -> null + 0 FileInspect greps localise WHAT is identical).
#  * probe: probe.cc = fresh 17y row probe (V1 sizes/enum + V2 enable-cascade
#    + 2-OR quirk + V3 clear-status 5-arm ladder pause-both-ways + V6 real
#    init() id-ladder + V4/V4b verify_reload ReloadError x3 + proto re-arm +
#    V5 post_init EXACTLY once (Mime order pin, capture pair -> closed via
#    the new fsvc_close_capture donor-posture arm) + V8 depth ladders incl.
#    the R4 drift + default-arg-vs-fc-arg pair + V9 reset gate both ways +
#    V10 collect_cache_usage counter over the REAL snapshot.h inlines +
#    V11/V12 close + thread_init/term (REAL file_stats calloc/free) + V13
#    REAL get_file_processed_size three-arms over the fflows single-slot
#    fixture); hygiene gate (no 0x[0-9a-f]{6,}) carried verbatim.
# (rows 17u-17x heritage, kept as context: this script descended from the
# fconf/fcapi/finspect/fpolicy harnesses; the file_config.o 30-U/6-app,
# file_api.o 3-U, file_inspect.o 49-U and file_policy.o 59-U pin blocks
# below stay as link-invariant carry-overs.)
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
NODE_INC=$(ls -d /opt/hermes/tools/node-*-linux-x64/include/node | head -1)
# NEW18a (PLAN 0.1/R4): the FIRST harness in the lineage to LINK a
# third-party lib: the LuaJIT live tree (17k-live) supplies lua.hpp/lua.h/
# lauxlib.h (headers via -I) and the T defs luaL_optinteger/luaL_optlstring
# (nm --defined-only libluajit.a, scratch-measured) via -lluajit. The static
# archive's mmap allocator needs the -lm -ldl tail on BOTH links. The
# archive is linked BY PATH (not -lluajit): -lluajit resolves the .so first
# and the gate probe then dies at load (no rpath): libluajit-5.1.so.2 not
# found -- the static pull is hermetic (scratch-proven, build 3).
LUA_SRC=/opt/data/tools/luajit-src/src
LIBCRYPTO=/usr/lib/x86_64-linux-gnu/libcrypto.so.3
rm -rf "$C"
mkdir -p "$C"/{file_api,pub_sub,framework,main,log,hash,helpers,utils,utils/stats,sfip,protocols,time,target_based,catch,parser,trace,profiler,memory,packet_io,control,mime,flowz,detection,flow,decompress,search_engines,managers,lua,ports}

# ---- VERBATIM sources compiled into the link ----
# NEW17w: cp delta is exactly ONE file -- file_inspect.cc appended to this
# donor braced list (its .h was ALREADY cp'd here: fcapi build.sh:54,
# VERBATIM; stubs.cc includes it, stubs.cc:13). The row TU has 0 UNIT_TEST
# fragments and 0 TEST_CASEs (PLAN 2; hard-asserted below): no grafts/seds
# fire on it, it compiles byte-VERBATIM in the objs loop just below (also
# NEW17w: file_inspect appended to that loop -- no flowz/sed dir
# special-case needed). FIXACC below does NOT gain file_inspect.h: the
# header has NO private:/protected: and the loop's `assert n >= 1` would
# fire (R8 trap; NEXT.md:110's FIXACC parenthetical refers to the
# stubs.cc:13 include context only -- verified untouched this row).
# NEW17y (PLAN 2.1): the row cp delta = file_service.cc appended to the
# braced list (the .h ALREADY rides here, fpolicy build.sh:87) + the ONE
# real cp src/target_based/snort_protocols.cc (find BODY, PLAN 0.5) -- the
# snort_protocols.h cp below gains its .cc twin.
cp "$SRC"/src/file_api/{file_lib.h,file_lib.cc,file_api.h,file_api.cc,file_config.h,file_config.cc,file_identifier.h,file_identifier.cc,file_stats.h,file_stats.cc,file_service.h,file_service.cc,file_capture.h,file_capture.cc,file_cache.h,file_cache.cc,file_cache_share.h,file_cache_share.cc,file_flows.h,file_flows.cc,file_inspect.h,file_inspect.cc,file_segment.h,file_segment.cc,file_module.h,file_mempool.h,file_mempool.cc,circular_buffer.h,circular_buffer.cc,file_policy.h,file_policy.cc,file_log.cc,file_module.cc} "$C"/file_api/
cp "$SRC"/src/pub_sub/{file_events.h,file_events.cc,file_events_ids.h,intrinsic_event_ids.h} "$C"/pub_sub/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc,fnv.h,hashes.h,hashes.cc,xhash.h,xhash.cc,hash_lru_cache.h,hash_lru_cache.cc} "$C"/hash/
cp "$SRC"/src/helpers/{utf.h,utf.cc,event_gen.h,memcap_allocator.h,lockless_ring.h} "$C"/helpers/
cp "$SRC"/src/utils/{util.h,util.cc,util_cstring.h,util_cstring.cc,cpp_macros.h,bits.h,util_net.h,util_net.cc} "$C"/utils/
# real profiler TU pair (file_lib.cc includes profiler/profiler.h;
# upstream default build = no CPU/memory profiling flags -> Profile
# collapses to the no-op contexts; THREAD_LOCAL enabled defs ride in stubs).
cp "$SRC"/src/profiler/{profiler.h,profiler_defs.h,profiler.cc,time_profiler_defs.h,time_profiler.cc,memory_defs.h,memory_profiler_defs.h,rule_profiler_defs.h} "$C"/profiler/
cp "$SRC"/src/utils/stats/{snapshot.h,utils.h} "$C"/utils/stats/
cp "$SRC"/src/framework/{counts.h,base_api.h,ips_action.h,pdu_section.h,decode_data.h,inspector.h,parameter.h,value.h,module.h,mp_transport.h,data_bus.h,mp_data_bus.h,codec.h} "$C"/framework/
cp "$SRC"/src/flow/flow_key.h "$C"/flow/
# real inspector_manager.h is declaration-only (inspector.h + module.h
# closure); its method BODIES live in stubs.cc as witnesses.
mkdir -p "$C"/managers
cp "$SRC"/src/managers/inspector_manager.h "$C"/managers/
cp "$SRC"/src/main/{snort_types.h,thread.h,thread_config.h} "$C"/main/
cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_cidr.cc,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/protocols/{ip.h,ipv4.h,ipv6.h,layer.h,protocol_ids.h,mpls.h,packet.h,geneve.h,packet_manager.h} "$C"/protocols/
cp "$SRC"/src/time/{clock_defs.h,stopwatch.h,packet_time.h,packet_time.cc,timersub.h} "$C"/time/
cp "$SRC"/src/target_based/snort_protocols.h "$C"/target_based/
# NEW17y (PLAN 0.5/2.1): the ONE real cp of the row closure -- find BODY at
# snort_protocols.cc:92; its residue is 1 resident STUB (SnortConfig::
# get_static_name, stubs.cc:57) + 34 pure plumbing: ZERO app NEW, the 5th
# NEW-app entry (ProtocolReference::find) resolves RIGHT HERE (the Rust
# twin src/target_based/snort_protocols.rs:41-:141 is fully ported).
cp "$SRC"/src/target_based/snort_protocols.cc "$C"/target_based/
cp "$SRC"/src/parser/parse_utils.h "$C"/parser/
cp "$SRC"/src/memory/heap_interface.h "$C"/memory/
# NEW17z (PLAN 2.1): text_log.h + text_log.cc + log.h join the log braces
# (text_log.cc:45 includes "log.h"; messages.cc STAYS OUT -- the R6 guard:
# its real bodies would collide with the stubs ErrorMessage/FatalError).
cp "$SRC"/src/log/{messages.h,log_errors.h,log_stats.h,text_log.h,text_log.cc,log.h} "$C"/log/
# NEW17z (PLAN 2.1): the ONE real framework cp + the two compile-only
# header cps of the module.cc:28 -> utils/stats.h -> main/stats_output_
# format.h:31 chain (module.h already cp'd in the :106 braces). ALL
# header-only EXCEPT module.cc: zero show_stats/stats:: T-defs come from
# them (the W2 witnesses own the pair -- pin block below). stats.cc NEVER
# cps (the monolith include list stats.cc:32-:57, PLAN 2.2).
cp "$SRC"/src/framework/module.cc "$C"/framework/
cp "$SRC"/src/utils/stats.h "$C"/utils/
cp "$SRC"/src/main/stats_output_format.h "$C"/main/
cp "$SRC"/src/control/control.h "$C"/control/
cp "$SRC"/src/mime/file_mime_config.h "$C"/mime/
cp "$SRC"/src/packet_io/{active_action.h,active.h,packet_tracer.h,packet_constraints.h} "$C"/packet_io/
cp /opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp "$C"/catch/
# ---- NEW17y (PLAN 0.2/2.1): the row include closure -- 13 compile-only
# header cp's, ALL header-only (zero TU compiles, zero link contribution:
# no SearchTool/mpse/MimeSession entries in the row residue -- the R8 pin
# in the NEW17y block below re-arms that claim). main.h rides the $C ROOT
# (cc:34 includes "main.h"; the main_packet_threads_fully_paused decl at
# src/main.h:56 -- body NEVER cp'd: src/main.cc:325 walks pigs/Analyzer,
# the R6 monolith). The mime cluster enters ONLY via
# mime/file_mime_process.h (cc:37 -> decode/form_data/log/paf/decode_base
# + decompress/file_decomp.h + helpers/buffer_data.h + flow/flow_stash.h
# transitively); the mime row itself stays queued (NEXT.md:126-:131).
# search_tool.h (cc:38) drags framework/mpse.h + search_engines/
# search_common.h -- grep-0 symbol use in the row bodies (header-only
# FREE, NEXT.md:133-:136). Scratch measured 13 iterations to SYNTAX CLEAN.
cp "$SRC"/src/main.h "$C"/
cp "$SRC"/src/mime/{file_mime_process.h,file_mime_decode.h,file_mime_form_data.h,file_mime_log.h,file_mime_paf.h,decode_base.h} "$C"/mime/
cp "$SRC"/src/decompress/file_decomp.h "$C"/decompress/
cp "$SRC"/src/helpers/buffer_data.h "$C"/helpers/
cp "$SRC"/src/flow/flow_stash.h "$C"/flow/
cp "$SRC"/src/search_engines/{search_tool.h,search_common.h} "$C"/search_engines/
cp "$SRC"/src/framework/mpse.h "$C"/framework/
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#include "catch/catch.hpp"
EOF
printf '#pragma once\n#define HAVE_ICONV 1\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h

# ---- main/policy.h graft (PROVEN rules/stx/fstats/filib recipe) ----
cp "$SRC"/src/main/policy.h "$C"/main/

# ---- NEW18a (PLAN 0.1) header-cp chain — the include-closure discovered by
# the scratch fatal-error loop (18a copy tree, scratch compile SYNTAX-OK +
# OBJ-OK, 100,816 B). EVERY entry header-only: zero new TU compiles, zero
# link contribution (the R8 pin below re-arms that). lua/lua.h is the NEW
# dir (no copy/lua existed anywhere in the lineage; the file itself is a
# VERBATIM cp, its <lua.hpp> resolves LIVE from $LUA_SRC, never a stub).
cp "$SRC"/src/lua/lua.h "$C"/lua/
cp "$SRC"/src/main/{snort.h,analyzer_command.h} "$C"/main/
cp "$SRC"/src/managers/module_manager.h "$C"/managers/
cp "$SRC"/src/parser/parser.h "$C"/parser/
cp "$SRC"/src/detection/{rules.h,treenodes.h,signature.h,rule_option_types.h} "$C"/detection/
cp "$SRC"/src/ports/port_group.h "$C"/ports/
cp "$SRC"/src/framework/mpse_batch.h "$C"/framework/
python3 - "$C" <<'FIXPOLICY'
import sys
p = sys.argv[1] + "/main/policy.h"
s = open(p).read()
s = s.replace('#include "framework/data_bus.h"', '#include "framework/data_bus_wit.h"')
s = s.replace('#include "framework/mp_data_bus.h"', '')
blk = s.index("class PolicyMap")
end = s.index("};", blk)
seg = s[blk:end].replace("private:", "public:")
s = s[:blk] + seg + s[end:]
open(p, "w").write(s)
FIXPOLICY
# data_bus.h is REAL here (file_lib.cc publishes through it; publish BODIES
# live in stubs.cc). policy.h's include is swapped to the small witness the
# graft expects; SnortConfig only stores a DataBus member there.
cat > "$C"/framework/data_bus_wit.h <<'EOF'
#pragma once
#include "framework/data_bus.h"
namespace snort { class SnortConfig; }
EOF

# ---- snort_config.h: proven rules_harness shim + members the file_api
# headers/bodies name (max_files_cached etc from file_service.cc paths). ----
python3 - "$C" <<'EOFPY'
import sys, re
cdir = sys.argv[1]
build = open("/opt/data/snort3-rust/tools/rules_harness/build.sh").read()
m = re.search(r"cat > \"\$C\"/main/snort_config\.h <<'EOFCFG'\n(.*?)\nEOFCFG\n", build, re.S)
assert m, "EOFCFG block not found in rules_harness build.sh"
shim = m.group(1)
# real snort_config.h pulls target_based/snort_protocols.h in this closure
assert '#include "target_based/snort_protocols.h"' not in shim
anchor = shim.index("\n", shim.index("#include")) + 1
shim = shim[:anchor] + '#include "target_based/snort_protocols.h"\n' + shim[anchor:]
# NEW17z (PLAN 2.1 / R8): the ONE shim delta -- real main/snort_config.h:35
# includes framework/inspector.h; file_log.cc:202 `class FileLog : public
# Inspector` reaches Inspector ONLY through that chain (every donor TU
# compiled without it -- the full-tree ld -r + the untouched gate md5 are
# the regression pins for this insertion).
assert '#include "framework/inspector.h"' not in shim
_z_anchor = shim.index("\n", shim.index('#include "target_based/snort_protocols.h"')) + 1
shim = shim[:_z_anchor] + '#include "framework/inspector.h"  // NEW17z: real snort_config.h:35 chain\n' + shim[_z_anchor:]
old = "    static bool log_syslog() { return false; }"
assert shim.count(old) == 1, "log_syslog anchor not unique"
new = ("    enum { LOGGING_FLAG__VERBOSE = 0x00000001 };\n"
       "    static bool log_verbose() { return logging_flags & LOGGING_FLAG__VERBOSE; }\n"
       "    uint64_t max_files_cached = 65536;  // real member (file_service.cc)\n"
       "    unsigned max_procs = 1;             // real member (file_service.cc)\n"
       "    bool mp_dbus = false;               // real member\n"
       + old)
shim = shim.replace(old, new, 1)
open(cdir + "/main/snort_config.h", "w").write(shim + "\n")
EOFPY

# ---- daq witness + packet.h surgery (PROVEN rules_harness recipe) ----
cat > "$C"/daq_common.h <<'EOFDAQ'
#pragma once
#include <cstdint>
typedef void* DAQ_Msg_h;
struct DAQ_PktHdr_t {
    uint64_t flags = 0;
    int ingress_group = 0;
    int egress_group = 0;
};
#define DAQ_PKTHDR_UNKNOWN            -1
#define DAQ_PKT_FLAG_SIGNIFICANT_GROUPS 0x0000000000000020

// NEW18a graft (PLAN 0.2b): analyzer_command.h:255 reads a std::vector
// of this DAQ-SDK type; grep of src/ shows it NEVER defined upstream (the
// SDK header is not in-tree). One-field placeholder: analyzer_command.cc
// NEVER compiles, the vector member only needs A type.
struct DIOCTL_GetSnortLatencyData { uint64_t placeholder = 0; };
EOFDAQ
# flow/flow.h is the flow monolith. Grafted witness (PROVEN rules recipe,
# extended AGAIN for file_cache): make_key (file_cache.cc:363-372) reads
# Flow::client_ip/server_ip (real flow.h:523-524), client_group/server_group
# (flow.h:583-584) and key->addressSpaceId (flow_key.h:56 with REAL
# flow/flow_key.h now copied). PINNED truncation: uint32_t addressSpaceId
# -> uint16_t asid (file_cache.h:47) -- pin, never "fix".
cat > "$C"/flowz/flow_fwd.h <<'EOFFLOW'
#pragma once
#include <cstdint>
#include "protocols/layer.h"   // packet.h Layer* member (real chain: flow.h pulled it)
#include "sfip/sf_ip.h"        // Flow::client_ip/server_ip (real flow.h:523-524)
#include "flow/flow_key.h"     // const FlowKey* key (real flow.h:503)
#define SSNFLAG_SEEN_CLIENT         0x00000001
#define SSNFLAG_SEEN_SERVER         0x00000002
#define SSNFLAG_SEEN_BOTH (SSNFLAG_SEEN_SERVER | SSNFLAG_SEEN_CLIENT)
namespace snort {
class Flow {
public:
    using SnortProtocolId_stub = int;
    struct { bool client_initiated : 1; } flags = {};
    struct { int snort_protocol_id = 0; } ssn_state = {};
    uint64_t session_flags = 0;
    const char* service = nullptr;
    uint16_t client_port = 0;    // NEW17z: real flow.h:586
    uint16_t server_port = 0;    // NEW17z: real flow.h:587
    SfIp client_ip = {};       // real flow.h:523
    SfIp server_ip = {};       // real flow.h:524
    int16_t client_group = 0;  // real flow.h:583
    int16_t server_group = 0;  // real flow.h:584
    const FlowKey* key = nullptr;  // real flow.h:503
    bool two_way_traffic() const
    { return (session_flags & SSNFLAG_SEEN_BOTH) == SSNFLAG_SEEN_BOTH; }
};
}
struct FilteringState { uint64_t flow = 0; uint64_t pkt = 0; uint64_t session = 0; };
EOFFLOW
sed -i 's|#include "flow/flow.h"|#include "flowz/flow_fwd.h"|' "$C"/protocols/packet.h

# ---- file_flows.h: same flow.h graft; FlowData comes from the real
# flow_data.h (copied); FileFlows bodies are the REAL TU now (witness block
# retired in stubs.cc). ----
cp "$SRC"/src/flow/flow_data.h "$C"/flowz/
sed -i 's|#include "flow/flow.h"|#include "flowz/flow_fwd.h"\n#include "flowz/flow_data.h"|' "$C"/file_api/file_flows.h

# ---- NEW17q graft delta (PLAN.md 3, the ONLY flowz delta): the witness
# Flow gains get_flow_data(unsigned)/set_flow_data(FlowData*) (real
# flow.h:195/:200; call sites file_flows.cc:141/:149/:159). Bodies live in
# stubs.cc as a PINNED single-slot arm (one probe Flow ever attached); get
# hits the slot iff id == stored fd->get_id() (FlowData::get_id is real
# inline), so the get_file_flows chain + get_file_processed_size witness
# work against real logic (documented deviation: real Flow keeps a vector).
python3 - "$C" <<'FIXFLOW'
import sys
p = sys.argv[1] + "/flowz/flow_fwd.h"
s = open(p).read()
assert "get_flow_data" not in s
s = s.replace("namespace snort {\nclass Flow {",
              "namespace snort {\nclass FlowData;   // NEW17q: single-slot FlowData graft\n"
              "class Flow {")
anchor = "    bool two_way_traffic() const"
assert anchor in s
s = s.replace(anchor,
    "    // NEW17q graft (real flow.h:195/:200 shapes; single-slot witness\n"
    "    // bodies in stubs.cc -- PIN, one attached Flow per probe run)\n"
    "    FlowData* get_flow_data(unsigned id) const;\n"
    "    void set_flow_data(FlowData* fd);\n" + anchor)
open(p, "w").write(s)
FIXFLOW

# ---- main/thread_config.h graft: thread_config.h:22 pulls <hwloc.h>
# (absent on this host); file_cache.cc only uses ThreadConfig::
# get_instance_max() (file_cache.cc:144) -> include excised (documented),
# declarations kept, witness body in stubs.cc. HAVE_NUMA stays undefined
# so both HAVE_NUMA arms vanish inertly. ----
python3 - "$C" <<'FIXTC'
import sys
p = sys.argv[1] + "/main/thread_config.h"
s = open(p).read()
assert "#include <hwloc.h>" in s
s = s.replace("#include <hwloc.h>\n", "")
open(p, "w").write(s)
FIXTC

# ---- thread_config.h graft above. Also: utils/util.cc in this
# toolchain needs <sstream> explicitly (upstream toolchains get it
# transitively from <random>); include added, body untouched (documented).
python3 - "$C" <<'FIXUTIL'
import sys
p = sys.argv[1] + "/utils/util.cc"
s = open(p).read()
assert "#include <sstream>" not in s
s = s.replace("#include <random>", "#include <random>\n#include <sstream>", 1)
open(p, "w").write(s)
FIXUTIL

python3 - "$C" <<'FIXACC'
import sys
c = sys.argv[1]
# NEW17q: + file_api.h — FilePolicyBase::ref_count is read by the policy
# ref-count witness readout (fcache_stub_policy_refs); access-only, the
# arithmetic stays the REAL file_api.cc protocol.
# NEW17t: + pub_sub/file_events.h — the probe arms FileMPEvent's PRIVATE
# members (hashkey/file_ctx) for the S/D/H vectors; access-only, the
# codec walk (file_events.h:82-:127) stays byte-VERBATIM (PLAN 7 precedent).
# NEW17x: + file_api/file_policy.h — the probe READS the private table
# (file_rules/file_shas/verdict_delay/default_rule) and the match_*
# ladders for the V5/V6 readbacks; exactly ONE private: at h:82, 0
# protected: (assert n >= 1 safe, R6). Access-only: the cc bodies
# compile byte-VERBATIM, untouched by this loop's replace (no
# private:/protected: tokens in file_policy.cc).
for f in ("/file_api/file_service.h", "/file_api/file_cache.h", "/file_api/file_flows.h", "/file_api/file_api.h", "/file_api/file_lib.h", "/file_api/file_capture.h", "/pub_sub/file_events.h", "/file_api/file_policy.h"):
    p = c + f
    s = open(p).read()
    n = s.count("private:")
    assert n >= 1, f
    s = s.replace("private:", "public:")   # access only; probe touches seams
    s = s.replace("protected:", "public:") # NEW17r: FileInfo protected members
                                           # (file_name/url/file_type_id/...) are
                                           # read+armed by the P/M/L vectors
    open(p, "w").write(s)
FIXACC
# NOTE (delta vs donor): the mp_data_bus.h include is NOT excised here.
# file_cache.cc:563-571 genuinely uses MPDataBus::get_id/publish when
# SnortConfig::mp_dbus is true -> real header kept, witness BODIES in
# stubs.cc (documented deviation).

# ---- detection engine witness header: file_cache.cc's uses are
# p->context->conf (file_cache.cc:669) + event_gen's queue_event +
# GET_CURRENT_PACKET. witness IpsContext shape: exactly the members the
# closure reads/writes. Bodies in stubs.cc. detection_buf.h REAL. ----
cp "$SRC"/src/detection/{detection_buf.h,fp_detect.h} "$C"/detection/
cat > "$C"/detection/detection_engine.h <<'EOFDE'
#pragma once
#include "detection/detection_buf.h"
#include "main/snort_types.h"
#include "target_based/snort_protocols.h"
namespace snort {
struct Packet;
class Flow;
class SnortConfig;
// witness IpsContext shape: exactly the members file_cache.cc/file_lib.cc
// read/write. `conf` is the real member (flow/ips_context) file_cache.cc:669
// reads. upstream snapshot_flow(Flow*) keeps the Flow* and copies proto_id
// through it -- witness keeps proto_id inline, semantics pinned by the
// probe (documented deviation).
class IpsContext {
public:
    DataPointer file_data = DataPointer(nullptr, 0);
    uint64_t file_data_id = 0;
    unsigned file_pos = 0;
    bool file_type_process = false;
    SnortConfig* conf = nullptr;   // real member read at file_cache.cc:669
    struct { SnortProtocolId proto_id = UNKNOWN_PROTOCOL_ID; } flow;
    uint32_t session_flags = 0;
    void set_snort_protocol_id(SnortProtocolId id) { flow.proto_id = id; }
    SnortProtocolId get_snort_protocol_id() { return flow.proto_id; }
    uint32_t get_session_flags() { return session_flags; }
};
class DetectionEngine {
public:
    DetectionEngine() { }
    static Packet* get_current_packet();
    static Packet* set_next_packet(const Packet* parent = nullptr, Flow* flow = nullptr);
    static int queue_event(unsigned gid, unsigned sid);
}; }
EOFDE

# ---- trace witness: real FILE_DEBUG semantics. file_module.h maps
# FILE_DEBUG(module,oid,level,p,...) -> trace_logf(level,module,oid,p,...)
# -> trace_printf(TraceLevel, const Trace*, TraceOptionID, const Packet*,
# fmt, ...) (real trace_api.h shape). The witness keeps the trace_enabled
# gate VERBATIM (null trace -> false; else level check; the packet-
# constraint arm of the real gate is dropped -> documented deviation).
# Enabled lines print with FILEDBG tag so format strings (PRIi64/%d ...)
# inside file_cache.cc pin verbatim. ----
cat > "$C"/trace/trace.h <<'EOFTRH'
#pragma once
#include <cstdint>
#include <string>
#include "main/snort_types.h"
#define DEFAULT_TRACE_LOG_LEVEL 1
#define TRACE_CRITICAL_LEVEL 2
#define TRACE_ERROR_LEVEL 3
#define TRACE_WARNING_LEVEL 4
#define TRACE_INFO_LEVEL 6
#define TRACE_DEBUG_LEVEL 7
#define DEFAULT_TRACE_OPTION_ID 0
#define DEFAULT_TRACE_OPTION_NAME "all"
using TraceOptionID = uint8_t;
using TraceLevel = uint8_t;
namespace snort {
// NEW18a graft (PLAN 0.2a): REAL struct verbatim from trace/trace.h:55-
// :63. file_module.cc:159 constructs a static TraceOption and get_trace_
// options() (file_module.h:76) returns it -- the class-Trace witness was
// incomplete for that call site.
struct TraceOption
{
    TraceOption(const char* n, TraceOptionID tid, const char* h) :
        name(n), id(tid), help(h) {}

    const char* name;
    TraceOptionID id;
    const char* help;
};

class Trace {
public:
    // witness: real Trace per-option level table collapses to one
    // DEFAULT_TRACE_OPTION_ID level (all file_cache call sites use it).
    uint8_t level = 0;
    std::string mod = "file_cache";
    bool enabled(TraceOptionID, TraceLevel log_level = DEFAULT_TRACE_LOG_LEVEL) const
    { return level >= log_level; }
    const char* module_name() const { return mod.c_str(); }
    const char* option_name(size_t) const { return DEFAULT_TRACE_OPTION_NAME; }
}; }
EOFTRH
cat > "$C"/trace/trace_api.h <<'EOFTR'
#pragma once
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include "main/snort_types.h"
#include "trace/trace.h"
namespace snort { struct Packet; }
static inline bool trace_enabled(const snort::Trace* trace,
    TraceOptionID trace_option_id,
    TraceLevel log_level = DEFAULT_TRACE_LOG_LEVEL,
    const snort::Packet* p = nullptr)
{
    if ( !trace or !trace->enabled(trace_option_id, log_level) )
        return false;
    return true;
}
static inline void trace_printf(TraceLevel log_level,
    const snort::Trace* trace, TraceOptionID trace_option_id,
    const snort::Packet* p, const char* fmt, ...)
{
    if ( !trace_enabled(trace, trace_option_id, log_level, p) )
        return;
    std::printf("FILEDBG[%s] ", trace->module_name());
    va_list ap;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
}
#define trace_logf(...) trace_printf(__VA_ARGS__)
EOFTR

if [ ! -e "$H/probe.cc" ]; then echo "probe.cc missing" >&2; exit 1; fi
if [ ! -e "$H/stubs.cc" ]; then echo "stubs.cc missing" >&2; exit 1; fi

GXX="g++ -std=c++17 -O0 -w -I$C -I$NODE_INC -I$LUA_SRC"
# probe TU list: the full donor closure + NEW17w file_inspect (the row TU,
# plain VERBATIM compile, no graft/sed/excision -- 0 UNIT_TEST fragments).
# file_capture.cc stays a REAL TU here -- the PLAIN .o is dropped from BOTH
# links below: the probe links the UT-compiled TEST_CASE-excised variant,
# the gate the verbatim -DUNIT_TEST copy; PLAN 6).
# NEW17y (PLAN 2.1): file_service appended to the row list + snort_protocols
# (the one real cp) -- plain VERBATIM compiles; snort_protocols adds the
# d=target_based case to the dir switch (the ONLY case-list delta).
# NEW17z (PLAN 2.1): file_log (d=file_api default -- the row), text_log
# (NEW d=log case, the second dir case) and module (d=framework default,
# module.h already cp'd) join the loop -- ALL THREE plain VERBATIM
# compiles (0 UNIT_TEST / 0 TEST_CASE re-asserted below; the scratch
# closure proof compiled them at -O0 -w untouched).
objs=()
for f in file_api file_config file_identifier file_stats file_capture file_cache_share file_mempool circular_buffer file_segment file_events utf util_cstring util util_net hashes ghash hash_key_operations primetable xhash hash_lru_cache packet_time sf_ip sf_cidr file_inspect file_policy file_service snort_protocols file_log text_log module file_module; do
  d=file_api; case $f in utf) d=helpers;; util_cstring|util|util_net) d=utils;; hashes|ghash|hash_key_operations|primetable|xhash|hash_lru_cache) d=hash;; file_events) d=pub_sub;; packet_time) d=time;; sf_ip|sf_cidr) d=sfip;; snort_protocols) d=target_based;; text_log) d=log;; module) d=framework;; esac
  $GXX -fsyntax-only -c "$C/$d/$f.cc" || { echo "SYNTAX FAIL $f"; exit 1; }
  $GXX -c "$C/$d/$f.cc" -o "$C/$d/$f.o"
  objs+=("$C/$d/$f.o")
done
# NEW17r carry: excise ONLY the :1363 [file_info] UNIT_TEST block (keep the
# early :37/:54 fragments: guarded via rfind on "#ifdef UNIT_TEST",
# brace-balance check the result). Both the probe AND the gate use this same
# copy, so the 19 [file_info] cases never leak into fcap gate.txt.
python3 - "$C" <<'FIXLIBUT'
import sys
p = sys.argv[1] + "/file_api/file_lib.cc"
s = open(p).read()
i = s.rfind("#ifdef UNIT_TEST")
assert i > 0 and s.count("#ifdef UNIT_TEST") >= 3, "expected the early fragments + the :1363 block"
tail = s[i:]
assert "[file_info]" in tail and "TEST_CASE" in tail, "last UNIT_TEST block is not [file_info]"
assert tail.count("#endif") == 1 and tail.rstrip().endswith("#endif")
s = s[:i]
assert s.count("{") - s.count("}") == 0, "brace imbalance after excision"
open(p, "w").write(s)
FIXLIBUT
$GXX -fsyntax-only -c "$C"/file_api/file_lib.cc || { echo "SYNTAX FAIL file_lib"; exit 1; }
$GXX -c "$C"/file_api/file_lib.cc -o "$C"/file_api/file_lib.o
$GXX -fsyntax-only -c "$C"/file_api/file_cache.cc || { echo "SYNTAX FAIL file_cache"; exit 1; }
$GXX -c "$C"/file_api/file_cache.cc -o "$C"/file_api/file_cache.o
$GXX -fsyntax-only -c "$C"/file_api/file_flows.cc || { echo "SYNTAX FAIL file_flows"; exit 1; }
$GXX -c "$C"/file_api/file_flows.cc -o "$C"/file_api/file_flows.o

# ---- NEW17s probe-copy excision (PLAN 4 recipe, DELTA vs FIXLIBUT): keep
# the file VERBATIM for the gate; the probe copy keeps ALL early
# #ifdef UNIT_TEST fragments (:45/:65/:100/:112/:197/:203) AND the UT
# scaffolding :620-:807 (hooks + gate + fixture), and excises ONLY the
# 4 TEST_CASE bodies :808-:912 via index("TEST_CASE ("). Guards: exactly 4
# "TEST_CASE (" in the tail, single tail #endif kept, 0 survive, brace +
# UNIT_TEST-arm balance, catch refs cannot leak (PLAN 9-5). ----
python3 - "$C" <<'FIXCAPUT'
import sys
c = sys.argv[1]
p = c + "/file_api/file_capture.cc"
s = open(p).read()
assert s.count("#ifdef UNIT_TEST") == 7, "fragments :45/:65/:100/:112/:197/:203 + block :620"
i = s.index("TEST_CASE (")
tail = s[i:]
assert tail.count("TEST_CASE (") == 4 and s.count("TEST_CASE (") == 4, "exactly 4 [file_capture] TEST_CASEs"
assert "[file_capture]" in tail and tail.count("[file_capture]") == 4
assert tail.count("#endif") == 1 and tail.rstrip().endswith("#endif"), "block #endif :913 must be the tail"
probe_src = s[:i] + "#endif\n"   # re-attach the :620 #ifdef's #endif
assert probe_src.count("TEST_CASE") == 0, "no TEST_CASE may survive in the probe copy"
assert probe_src.count("{") - probe_src.count("}") == 0, "brace imbalance after excision"
assert probe_src.count("#endif") == probe_src.count("#ifdef"), "#ifdef/#endif imbalance"
for frag in ("writer_test_hook", "writer_idle_test_hook", "flush_entry_test_hook", "flush_predicate_test_hook"):
    assert probe_src.count(frag) >= 2, frag + " fragment lost in the probe copy"

# ---- in-TU extern "C" driver: the 4 hook pointers (:65-:70) and the
# static gate ptr (:754) are FILE-LOCAL -- probe.cc cannot arm the ladder
# from outside. The driver mirrors AsyncCaptureFixture arms (:784-:788) and
# gate calls (:698-:740) verbatim through the SAME AsyncWriterGate
# (:663-:752) -- no custom barriers (PLAN 5). ----
driver = '''
// ---- build.sh-appended in-TU extern "C" driver (row 17s probe only) ----
static AsyncWriterGate* fcap_drv_gate = nullptr;
extern "C" void fcap_gate_arm_new(void)
{
    delete fcap_drv_gate;
    fcap_drv_gate = new AsyncWriterGate();
    async_writer_gate = fcap_drv_gate;
    writer_test_hook = wait_in_writer_test_hook;
    writer_idle_test_hook = wait_at_writer_idle_test_hook;
    flush_entry_test_hook = record_flush_entry_test_hook;
    flush_predicate_test_hook = record_flush_predicate_test_hook;
}
extern "C" void fcap_gate_unarm(void)
{
    writer_test_hook = nullptr;
    writer_idle_test_hook = nullptr;
    flush_entry_test_hook = nullptr;
    flush_predicate_test_hook = nullptr;
    delete fcap_drv_gate;
    fcap_drv_gate = nullptr;
    async_writer_gate = nullptr;
}
extern "C" void fcap_init(int64_t m, int64_t b) { FileCapture::init(m, b); }
extern "C" void fcap_exit(void) { FileCapture::exit(); }
extern "C" void fcap_test_reset(void) { FileCaptureTestAccess::reset(); }
extern "C" int fcap_resettable(void) { return FileCaptureTestAccess::resettable() ? 1 : 0; }
extern "C" void fcap_enqueue(void* c) { FileCaptureTestAccess::enqueue(static_cast<FileCapture*>(c)); }
extern "C" void fcap_enqueue2(void* a, void* b) { FileCaptureTestAccess::enqueue(static_cast<FileCapture*>(a), static_cast<FileCapture*>(b)); }
extern "C" uint64_t fcap_released_buffers(void) { return FileCaptureTestAccess::released_buffers(); }
extern "C" int fcap_queue_size(void)
{
    std::lock_guard<std::mutex> lk(FileCapture::capture_mutex);
    return (int)FileCapture::files_waiting.size();
}
extern "C" int fcap_file_storing_now(void)
{
    std::lock_guard<std::mutex> lk(FileCapture::capture_mutex);
    return FileCapture::file_storing ? 1 : 0;
}
// one writer_thread iteration VERBATIM (:83-:117) minus the hooks: the
// hookless-drain deviation vector (probe never arms hooks in this block).
extern "C" void fcap_drain_hookless(void)
{
    while (true)
    {
        std::unique_lock<std::mutex> lk(FileCapture::capture_mutex);
        if (FileCapture::files_waiting.empty())
            break;
        FileCapture* file = FileCapture::files_waiting.front();
        FileCapture::files_waiting.pop();
        FileCapture::file_storing = true;
        lk.unlock();
        file->store_file();
        delete file;
        lk.lock();
        FileCapture::file_storing = false;
        lk.unlock();
        FileCapture::capture_cv.notify_all();
    }
}
extern "C" void fcap_gate_wait_writer(void) { fcap_drv_gate->wait_for_writer(); }
extern "C" void fcap_gate_release_writer(void) { fcap_drv_gate->release_writer(); }
extern "C" void fcap_gate_wait_flush_callers(unsigned n) { fcap_drv_gate->wait_for_flush_callers(n); }
extern "C" void fcap_gate_pause_first_idle(void) { fcap_drv_gate->pause_first_idle_transition(); }
extern "C" void fcap_gate_wait_first_idle(void) { fcap_drv_gate->wait_for_first_idle_transition(); }
extern "C" void fcap_gate_wait_nonempty_idle_eval(void) { fcap_drv_gate->wait_for_nonempty_idle_evaluation(); }
extern "C" void fcap_gate_release_idle(void) { fcap_drv_gate->release_idle_transition(); }
'''
open(c + "/file_api/file_capture_probe.cc", "w").write(probe_src + driver)
FIXCAPUT
$GXX -DUNIT_TEST -fsyntax-only -c "$C"/file_api/file_capture_probe.cc || { echo "SYNTAX FAIL file_capture_probe"; exit 1; }
$GXX -DUNIT_TEST -c "$C"/file_api/file_capture_probe.cc -o "$C"/file_api/file_capture_probe.o
# nm -u residue (PLAN 6): expected witness delta ZERO apart from catch/std
# refs the unlinked scaffolding drags in; no NEW stubs ahead of this check.
diff <(nm -u "$C"/file_api/file_capture.o | sort -u) <(nm -u "$C"/file_api/file_capture_probe.o | sort -u) > "$H/nm_residue.txt" || true
# NEW17u PLAN 3 pin: the row TU's own residue -- file_config.o has exactly
# 30 U entries, of which exactly 6 app symbols (FileIdentifier::add_file_id/
# find_file_type_id/get_magic_rule_ids_from_type/get_rule_from_id -> REAL
# file_identifier.o; InspectorManager::get_file_inspector -> stubs.cc
# witness; SnortConfig::get_conf -> EOFCFG shim). The other 24 are
# libstdc++/libgcc plumbing (string dtors, _Unwind_Resume, __cxa_*,
# operator new/delete, strlen, __throw_*) -- PLAN 3 table, ZERO new stubs.
# NEW17u carry: the config row's residue table (30 U / 6 app) was a write to
# nm_config.txt -- the fcapi .gitignore block carries nm_api.txt INSTEAD
# (PLAN 5 hygiene), so the same 30-U / 6-app assertions run INLINE here with
# no artifact write; the row TU's own residue lands in nm_api.txt below.
fc_res="$(nm -u --demangle "$C"/file_api/file_config.o | sort -u)"
test "$(printf '%s\n' "$fc_res" | grep -c ' U ')" -eq 30
test "$(printf '%s\n' "$fc_res" | grep -cE 'U (FileIdentifier::(add_file_id|find_file_type_id|get_magic_rule_ids_from_type|get_rule_from_id)|snort::InspectorManager::get_file_inspector|snort::SnortConfig::get_conf)')" -eq 6

$GXX -c "$H/stubs.cc" -o "$H/stubs.o"

# ---- NEW17w PLAN 2 row-residue pins (land in nm_inspect.txt) ----
# (a) the row .o's OWN residue: exactly 49 U entries by construction
# (28 app + 21 libstdc++/libgcc plumbing -- scratch recon /opt/data/
# cache/scratch/row17w re-measured here for the copy-tree compile).
nm -u --demangle "$C"/file_api/file_inspect.o | grep ' U ' | sort -u > "$H"/nm_inspect.txt
test "$(wc -l < "$H"/nm_inspect.txt)" -eq 49
# (b) exactly 8 app entries close against the NEW17w witness bodies.
test "$(grep -cE 'U (snort::DataBus::get_id|snort::MPDataBus::register_event_helpers|snort::MPDataBus::subscribe|snort::ConfigLogger::log_flag|snort::ConfigLogger::log_value|FileIdModule::load_config|FileIdModule::FileIdModule)' "$H"/nm_inspect.txt)" -eq 8
# (c) comm-diff vs the WHOLE link-member defined set (MANGLED compare --
# demangled names carry spaces; mangled is exact 1:1): after the witness
# bodies land, exactly the 21 plumbing entries survive, ZERO app hits.
f_u="$(mktemp)"; f_d="$(mktemp)"
nm -u "$C"/file_api/file_inspect.o | awk '{print $2}' | sort -u > "$f_u"
{ for o in "${objs[@]}" "$H/stubs.o" "$C"/file_api/file_lib.o "$C"/file_api/file_cache.o "$C"/file_api/file_flows.o "$C"/file_api/file_capture_probe.o; do nm --defined-only "$o" | awk '$2!="U"{print $NF}'; done; } | sort -u > "$f_d"
test "$(comm -23 "$f_u" "$f_d" | wc -l)" -eq 21
test "$(comm -23 "$f_u" "$f_d" | grep -cE 'snort|FileI|FileC|serialize|6DataBus|ConfigLogger|FileIdModule' )" -eq 0
rm -f "$f_u" "$f_d"
# (d) DUP-SYMBOL verification (R5, the retire landmine): the five retired
# stub bodies must be defined EXACTLY ONCE in the whole link member set,
# in the REAL file_inspect.o only. This is the get_file_adv_pub_id seam
# consumer watch too: the copy's file_lib.cc:658 (publish seam) resolves
# against the real getter now, NEVER a stub shadow.
test "$(nm -C "$C"/file_api/file_inspect.o | grep -cE '^[0-9a-f]+ T (FileInspect::configure|FileInspect::show|get_file_adv_pub_id)')" -eq 3
nm -C "$C"/file_api/file_inspect.o | grep -cE '^[0-9a-f]+ T FileInspect::(~FileInspect|FileInspect)\(FileIdModule\*\)' > /dev/null   # real ctor+dtors present
test "$(nm "$C"/file_api/file_inspect.o | grep -c _Z19get_file_adv_pub_idv)" -eq 1                    # real T def, used by file_lib.o's U ref
test "$(nm "$C"/file_api/file_lib.o | grep -c 'U _Z19get_file_adv_pub_idv')" -eq 1                   # seam consumer still references it
test "$(nm -C "$H/stubs.o" | grep -cE '^[0-9a-f]+ T (FileInspect::configure\(snort::SnortConfig\*\)|FileInspect::show|get_file_adv_pub_id|FileInspect::~FileInspect|FileInspect::FileInspect)')" -eq 0   # zero stub survivors

# ---- NEW17x PLAN 2 row-residue pins (land in nm_policy.txt) ----
# (a) the row .o's OWN residue: exactly 59 U entries by construction
# (14 app + 45 libstdc++/libgcc plumbing -- scratch recon /opt/data/
# cache/scratch/row17x re-measured for the copy-tree compile).
nm -u --demangle "$C"/file_api/file_policy.o | grep ' U ' | sort -u > "$H"/nm_policy.txt
test "$(wc -l < "$H"/nm_policy.txt)" -eq 59
# (b) app-count: exactly 14 app U entries (7 FileInfo + 2 FileCapture +
# 3 FileService::enable (resident stubs.cc:596-:598) + base dtor D2 +
# base typeinfo -- the closure classification, PLAN 2 table).
test "$(grep -cE ' U (snort::FileInfo::|snort::FileService::enable|snort::FileCapture::|snort::FilePolicyBase::~FilePolicyBase|typeinfo for snort::FilePolicyBase)' "$H"/nm_policy.txt)" -eq 14
# (c) comm-diff vs the WHOLE link-member defined set (MANGLED compare):
# after the resident witnesses, exactly the 45 plumbing entries survive,
# ZERO app residue.
fp_u="$(mktemp)"; fp_d="$(mktemp)"
nm -u "$C"/file_api/file_policy.o | awk '{print $2}' | sort -u > "$fp_u"
{ for o in "${objs[@]}" "$H/stubs.o" "$C"/file_api/file_lib.o "$C"/file_api/file_cache.o "$C"/file_api/file_flows.o "$C"/file_api/file_capture_probe.o; do nm --defined-only "$o" | awk '$2!="U"{print $NF}'; done; } | sort -u > "$fp_d"
test "$(comm -23 "$fp_u" "$fp_d" | wc -l)" -eq 45
test "$(comm -23 "$fp_u" "$fp_d" | grep -cE 'snort|FileP|FileR|FileC|FileS')" -eq 0
rm -f "$fp_u" "$fp_d"
# (d) DUP-SYMBOL LANDMINE (R5 INVERSION, the zero-retirement guard): the
# real .o DEFINES the row symbols (>= 6 T defs over the ladder + the
# vtable V pinned in the row .o, Itanium key-function placement R4) and
# stubs.o defines ZERO of them -- no retirements this row and the
# landmine against re-adding FilePolicy/FileRule witness bodies ahead of
# the real .o stays armed for future rows.
test "$(nm -C "$C"/file_api/file_policy.o | grep -cE '^[0-9a-f]+ T (FilePolicy::(load|policy_check|type_lookup|signature_lookup|add_file_id)|FileRule::clear)')" -ge 6
test "$(nm "$C"/file_api/file_policy.o | grep -cE '_ZTV10FilePolicy$')" -eq 1
test "$(nm -C "$H/stubs.o" | grep -cE ' T (FilePolicy::|FileRule::)')" -eq 0

# ---- NEW17y PLAN 0/2 row-residue pins (land in nm_service.txt +
# nm_protocols.txt) ----
# (a) the row .o's OWN residue: exactly 47 U entries by construction
# (14 REAL-OBJ + 3 RESIDENT STUB + 5 NEW-app + 25 libstdc++/libc plumbing
# -- scratch recon /opt/data/cache/scratch/fsvc_recon re-measured for the
# copy-tree compile).
nm -u --demangle "$C"/file_api/file_service.o | grep ' U ' | sort -u > "$H"/nm_service.txt
test "$(wc -l < "$H"/nm_service.txt)" -eq 47
# (b) exactly 5 NEW-app entries (the witness/cp table, PLAN 0.4): 4 close
# against the NEW17y witness bodies in stubs.cc, the 5th (find) resolves in
# the real snort_protocols.o (the ONE real cp -- no 5th witness).
test "$(grep -cE 'U (main_packet_threads_fully_paused|snort::MimeSession::(init|exit)|snort::InspectorManager::get_inspector|snort::ProtocolReference::find)' "$H"/nm_service.txt)" -eq 5
# (b2) R8 pin (PLAN 5): the compile-only header drag must NEVER leak a
# link-time symbol -- zero SearchTool/mpse residue entries.
test "$(grep -cE 'mpse|SearchTool|search_tool' "$H"/nm_service.txt)" -eq 0
# (c) comm-diff vs the WHOLE link-member defined set (MANGED compare --
# the closure proof, PLAN 0.5: after the 4 new witnesses + the real cp,
# exactly the 25 plumbing entries survive, ZERO app residue).
fs_u="$(mktemp)"; fs_d="$(mktemp)"
nm -u "$C"/file_api/file_service.o | awk '{print $2}' | sort -u > "$fs_u"
{ for o in "${objs[@]}" "$H/stubs.o" "$C"/file_api/file_lib.o "$C"/file_api/file_cache.o "$C"/file_api/file_flows.o "$C"/file_api/file_capture_probe.o; do nm --defined-only "$o" | awk '$2!="U"{print $NF}'; done; } | sort -u > "$fs_d"
test "$(comm -23 "$fs_u" "$fs_d" | wc -l)" -eq 25
test "$(comm -23 "$fs_u" "$fs_d" | grep -cE 'snort|File|Mime|main_|mpse|Search')" -eq 0
# NOTE: fs_u/fs_d stay alive for the (e) sub-block's sp comm below (the
# SAME defined-set), cleaned up THERE.
# (d) DUP-SYMBOL LANDMINE, R5 INVERSION (PLAN 2.2 -- this row MANDATES the
# retirement, mirroring the :632-:634 shape): the real row .o owns >= 17 T
# defs over the method ladder SPLIT across two greps (measured exactly 17
# = 16 FileService:: methods + the free snort::get_file_processed_size) AND
# stubs.o defines ZERO FileService/get_file_processed_size T defs (retired:
# any witness that regresses fails the build -- naive co-link demo = 142
# collision lines).
test "$(nm -C "$C"/file_api/file_service.o | grep -cE '^[0-9a-f]+ T (snort::)?FileService::(init|post_init|verify_reload|close|thread_init|thread_term|enable_file_type|enable_file_signature|enable_file_capture|is_file_service_enabled|get_max_file_depth|set_max_file_depth|collect_cache_usage|get_file_cache_clear_status|clear_file_cache|reset)' )" -ge 16
test "$(nm -C "$C"/file_api/file_service.o | grep -cE '^[0-9a-f]+ T snort::get_file_processed_size')" -ge 1
test "$(nm -C "$H/stubs.o" | grep -cE ' T (snort::FileService::|snort::get_file_processed_size)')" -eq 0
# (e) the real cp's own residue (PLAN 0.5): 35 U entries = 1 RESIDENT STUB
# (SnortConfig::get_static_name, stubs.cc:57) + 34 pure plumbing, ZERO app
# NEW -- comm-23 == 34, zero app hits.
nm -u --demangle "$C"/target_based/snort_protocols.o | grep ' U ' | sort -u > "$H"/nm_protocols.txt
test "$(wc -l < "$H"/nm_protocols.txt)" -eq 35
sp_u="$(mktemp)"
nm -u "$C"/target_based/snort_protocols.o | awk '{print $2}' | sort -u > "$sp_u"
test "$(comm -23 "$sp_u" "$fs_d" | wc -l)" -eq 34
test "$(comm -23 "$sp_u" "$fs_d" | grep -c 'snort')" -eq 0
rm -f "$fs_u" "$fs_d" "$sp_u"

# ---- NEW17z PLAN 0/2 row-residue pins (land in nm_flog.txt +
# nm_textlog.txt + nm_module.txt) ----
# (a) the row .o's OWN residue: exactly 64 U entries (13 REAL-OBJ +
# 7 RESIDENT STUB + 16 NEW-app + 28 libstdc++/libc plumbing -- scratch
# recon /opt/data/cache/scratch/row17z re-measured for the copy-tree
# compile).
nm -u --demangle "$C"/file_api/file_log.o | grep ' U ' | sort -u > "$H"/nm_flog.txt
test "$(wc -l < "$H"/nm_flog.txt)" -eq 64
# (b) app-count: exactly 36 app U entries (the PLAN 0 closure table 13+7+16).
test "$(grep -cE 'U (file_type_name|snort::FileContext::get_UTF8_fname|snort::FileFlows::(get_file_flows|get_current_file_context)|snort::FileInfo::|snort::SfIp::ntop|snort::packet_gettimeofday|snort::ts_print|sin_file_flow|snort::ConfigLogger::log_flag|snort::Inspector::|typeinfo for snort::Inspector|snort::TextLog_|snort::Module::|vtable for snort::Module|typeinfo for snort::Module|snort::DataBus::subscribe)' "$H"/nm_flog.txt)" -eq 36
# (c) comm-diff vs the WHOLE link-member defined set (MANGLED compare):
# with W1 in stubs.o, exactly the 28 plumbing entries survive, ZERO app.
fz_u="$(mktemp)"; fz_d="$(mktemp)"
{ for o in "${objs[@]}" "$H/stubs.o" "$C"/file_api/file_lib.o "$C"/file_api/file_cache.o "$C"/file_api/file_flows.o "$C"/file_api/file_capture_probe.o; do nm --defined-only "$o" | awk '$2!="U"{print $NF}'; done; } | sort -u > "$fz_d"
nm -u "$C"/file_api/file_log.o | awk '{print $2}' | sort -u > "$fz_u"
test "$(comm -23 "$fz_u" "$fz_d" | wc -l)" -eq 28
test "$(comm -23 "$fz_u" "$fz_d" | grep -cE 'snort|File|TextLog|Module|DataBus|show_stats|sin_')" -eq 0
# (d) the two REAL cps' OWN residue (PLAN 0 real-cp evaluation):
# text_log.o 30 U = 3 real + 5 resident + 0 app + 22 plumbing; module.o
# 32 U = 0 real + 2 resident + 0 app + 30 plumbing (the 2 app entries of
# the scratch pre-W2 measurement -- the show_stats pair -- close in W2).
nm -u --demangle "$C"/log/text_log.o | grep ' U ' | sort -u > "$H"/nm_textlog.txt
test "$(wc -l < "$H"/nm_textlog.txt)" -eq 30
nm -u "$C"/log/text_log.o | awk '{print $2}' | sort -u > "$H"/nm_tl.tmp
test "$(comm -23 "$H"/nm_tl.tmp "$fz_d" | wc -l)" -eq 22
test "$(comm -23 "$H"/nm_tl.tmp "$fz_d" | grep -cE 'snort|TextLog')" -eq 0
nm -u --demangle "$C"/framework/module.o | grep ' U ' | sort -u > "$H"/nm_module.txt
test "$(wc -l < "$H"/nm_module.txt)" -eq 32
nm -u "$C"/framework/module.o | awk '{print $2}' | sort -u > "$H"/nm_mod.tmp
test "$(comm -23 "$H"/nm_mod.tmp "$fz_d" | wc -l)" -eq 28
test "$(comm -23 "$H"/nm_mod.tmp "$fz_d" | grep -cE 'snort|Module|show_stats')" -eq 0
rm -f "$fz_u" "$fz_d" "$H"/nm_tl.tmp "$H"/nm_mod.tmp
# (e) DUP-SYMBOL LANDMINE, R5 INVERSION (the ZERO-retirement row, the
# scratch ld_err.txt == 0 B pin re-proven by BOTH links above): the real
# .o's DEFINE the row surface, stubs.o defines ZERO of it forever.
test "$(nm -C "$C"/framework/module.o | grep -cE '^[0-9a-f]+ T snort::Module::')" -ge 18   # 22 C2/C1+methods (module_strong.txt ledger)
test "$(nm "$C"/framework/module.o | grep -cE '_ZTVN5snort6ModuleE$')" -eq 1                # vtable V def (typeinfo rides module.o too)
test "$(nm -C "$C"/log/text_log.o | grep -cE '^[0-9a-f]+ T snort::TextLog_')" -eq 9         # Init/Term/Putc/Write/Print/Flush/Avail/Reset/Quote
test "$(nm -C "$C"/file_api/file_log.o | grep -cE '^[0-9a-f]+ T (LogHandler::(log_file_name|handle)|FileLogModule::set|FileLog::show)')" 
test "$(nm "$C"/file_api/file_log.o | grep -cE ' D sin_file$')" -eq 1                        # the row's only data export
test "$(nm -C "$H"/stubs.o | grep -cE ' T snort::TextLog_| T snort::Module::')" -eq 0       # ZERO stub survivors forever
test "$(nm -C "$H"/stubs.o | grep -cE ' T snort::DataBus::subscribe')" -eq 1                 # W1 exactly once
test "$(nm "$H"/stubs.o | grep -cE ' T _Z10show_stats')" -eq 2                               # W2 the pair exactly once
# (f) ZERO-retirement receipt (PLAN 2.2): the donor stubs.cc NEVER
# witnessed this row -- grep the DONOR text (git HEAD copy) = 0 hits.
test "$(git -C /opt/data/snort3-rust show HEAD:tools/fsvc_harness/stubs.cc | grep -cE 'FileLog|file_log|TextLog|Peg[A-Za-z]* ')" -eq 0
# existence pin: NO file_log.h exists upstream (PLAN 1).
test ! -e "$SRC"/src/file_api/file_log.h
# UT-clean self-check (the row's own + the two real cps): 0/0 x3.
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_log.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_log.cc)" -eq 0
test "$(grep -c 'TEST_CASE' "$C"/log/text_log.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/log/text_log.cc)" -eq 0
test "$(grep -c 'TEST_CASE' "$C"/framework/module.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/framework/module.cc)" -eq 0
# TLS notes (R2): fl_stats/tlog ride __thread (USE_THREAD_LOCAL undefined
# in copy/config.h -> snort_types.h:71-:73 collapses THREAD_LOCAL); the
# row .o carries them as TU-local TLS b/t slots, single-thread probe only.
test "$(nm "$C"/file_api/file_log.o | grep -c ' b _ZL4tlog$')" -eq 1
test "$(nm "$C"/file_api/file_log.o | grep -c ' b _ZL8fl_stats$')" -eq 1

# ---- NEW18a PLAN 0/2 row-residue pins + INVERTED-LANDMINE asserts ----
# (a) the row .o's OWN residue: exactly 65 U entries (scratch-join against
# the donor closure; the copy-tree compile re-measures here): 23 resolved
# by the donor closure + 42 survivors = 4 APP-NEW (closed by the four
# NEW18a witness bodies) + 2 LuaJIT REAL (T defs in libluajit.a -- NEVER
# witness-stubbed, R4) + 5 libc + 31 libstdc++/plumbing.
nm -u --demangle "$C"/file_api/file_module.o | grep ' U ' | sort -u > "$H"/nm_fmod.txt
test "$(wc -l < "$H"/nm_fmod.txt)" -eq 65
test "$(grep -cE 'U (parser_append_rules_special|snort::ModuleManager::get_includer|ControlConn::query_from_lua|snort::DecodeConfig::set_decompress_buffer_size)' "$H"/nm_fmod.txt)" -eq 4
test "$(grep -cE 'U (luaL_optinteger|luaL_optlstring)' "$H"/nm_fmod.txt)" -eq 2
# the LuaJIT defs are REAL (the first third-party link in the lineage):
test "$(nm --defined-only "$LUA_SRC"/libluajit.a | grep -cE ' T (luaL_optinteger|luaL_optlstring)$')" -eq 2
# (b) comm-diff vs the WHOLE link-member defined set (MANGED compare): with
# the four witnesses in stubs.o, exactly 38 survivors remain = 36 libc/
# plumbing + the 2 luaL entries (resolved only at the -lluajit link step,
# never by an .o) -- ZERO app residue.
fm_u="$(mktemp)"; fm_d="$(mktemp)"
nm -u "$C"/file_api/file_module.o | awk '{print $2}' | sort -u > "$fm_u"
{ for o in "${objs[@]}" "$H/stubs.o" "$C"/file_api/file_lib.o "$C"/file_api/file_cache.o "$C"/file_api/file_flows.o "$C"/file_api/file_capture_probe.o; do nm --defined-only "$o" | awk '$2!="U"{print $NF}'; done; } | sort -u > "$fm_d"
test "$(comm -23 "$fm_u" "$fm_d" | wc -l)" -eq 38
test "$(comm -23 "$fm_u" "$fm_d" | grep -cE 'snort|File|Module|parser_|Decode|ControlConn|DIOCTL')" -eq 0
test "$(comm -23 "$fm_u" "$fm_d" | grep -c 'luaL')" -eq 2
rm -f "$fm_u" "$fm_d"
# (c) INVERTED LANDMINE (R1/R5 INVERSION, the fsvc-17y pattern turned
# around -- this row IS witness home turf for FOUR donor harnesses): the
# measured hard collisions are EXACTLY 3 (nm-join vs the 18,267-def donor
# closure): T _ZN12FileIdModuleC1Ev, T load_config, B file_trace. All three
# retired: stubs.o carries ZERO survivor (inverted-landmine nm asserts --
# any regrown witness = "defined twice" link death):
test "$(nm --defined-only "$H"/stubs.o | grep -c '_ZN12FileIdModule')" -eq 0
test "$(nm -C --defined-only "$H"/stubs.o | grep -c 'FileIdModule::')" -eq 0
test "$(nm --defined-only "$H"/stubs.o | grep -cE ' B file_trace$')" -eq 0
# and the row .o owns the trio (real T/B defs; the V vtable trio rides too --
# the stubs' old extern-C shim emitted NONE, now the REAL vtable exists once):
test "$(nm "$C"/file_api/file_module.o | grep -cE ' T _ZN12FileIdModuleC1Ev$')" -eq 1
test "$(nm -C "$C"/file_api/file_module.o | grep -cE '^[0-9a-f]+ T FileIdModule::load_config')" -eq 1
test "$(nm "$C"/file_api/file_module.o | grep -cE ' B file_trace$')" -eq 1
test "$(nm -C "$C"/file_api/file_module.o | grep -cE '^[0-9a-f]+ T FileIdModule::')" -eq 18
test "$(nm "$C"/file_api/file_module.o | grep -cE ' V _ZTV12FileIdModule$')" -eq 1
# the four witnesses answer EXACTLY once each in stubs.o (4 app residues):
test "$(nm "$H"/stubs.o | grep -c ' T _Z27parser_append_rules_specialPKcS0_$')" -eq 1
test "$(nm "$H"/stubs.o | grep -c ' T _ZN5snort13ModuleManager12get_includerEPKc$')" -eq 1
test "$(nm "$H"/stubs.o | grep -c ' T _ZN11ControlConn14query_from_luaEPK9lua_State$')" -eq 1
test "$(nm "$H"/stubs.o | grep -c ' T _ZN5snort12DecodeConfig26set_decompress_buffer_sizeEj$')" -eq 1
# (d) retire receipt (the trio block census, PLAN 2.2): the 31-L block is
# byte-ident {finspect,fpolicy,fsvc,flog} = the dup proof; it STAYS in the
# donor (per-link rule), it is GONE from fmod stubs.cc (zero FileIdModule
# witness bodies -- asserted by nm above, text keeps the RETIREMENT comment).
test "$(git -C /opt/data/snort3-rust show HEAD:tools/flog_harness/stubs.cc | sed -n '/NEW17w witness FileIdModule/,/^extern "C" void fcache_set_file_inspector/p' | md5sum | cut -d' ' -f1)" = "9165739e3f4e0119cd21de02acc2f6d7"
test "$(grep -c 'void FileIdModule::load_config' "$H"/stubs.cc)" -eq 0
test "$(grep -c '_ZN12FileIdModuleC1Ev' "$H"/stubs.cc)" -eq 0
test "$(grep -c 'THREAD_LOCAL const snort::Trace\* file_trace = nullptr;' "$H"/stubs.cc)" -eq 0
# (e) zero-TEST_CASE / zero-UNIT_TEST self-checks for the row pair (the .h
# already rode the closure since 17w; the cc joins the objs loop VERBATIM).
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_module.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_module.cc)" -eq 0
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_module.h)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_module.h)" -eq 0
# (f) R8 pin (PLAN 0.1): the 11 compile-only header cps NEVER leak a link-
# time symbol -- zero residue for the drag types (the 6 header chains:
# analyzer_command/DIOCTL, rules/treenodes/signature/rule_option_types,
# port_group, mpse_batch; the ONLY parser_ hit in nm_fmod.txt is the live
# cc:259 witness call, counted separately above == 1... here we pin the
# DRAG types only).
test "$(grep -cE 'analyzer|DIOCTL|treenodes|PortGroup|port_group|mpse_batch|RuleOption|Signature::|detection' "$H"/nm_fmod.txt)" -eq 0
echo "nm_fmod U-entries: $(wc -l < "$H"/nm_fmod.txt) (65 by construction: 23 donor-resolved + 4 app witnesses + 2 REAL LuaJIT + 36 libc/plumbing -- PLAN 0.3)"

# ---- upstream Catch gate: FOUR UT TUs in one link (PLAN 1/2/6) -----------
# [file_capture] NEW (4 cases; assertions pinned from the RUNNER line, never
# grep) + the 17r trio carried verbatim: [file_flows] 8/22, [file_mempool]
# 3/27, [file_cache] 7/42. Duplicate-symbol rule: the plain .o of every
# UT-compiled TU (file_flows.o, file_mempool.o, file_cache.o, file_capture.o)
# is EXCLUDED from the gate objs list.
cat > "$H/catch_main.cc" <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
$GXX -c "$H/catch_main.cc" -o "$H/catch_main.o"
$GXX -DUNIT_TEST -c "$C"/file_api/file_flows.cc -o "$C"/file_api/file_flows_ut.o
$GXX -DUNIT_TEST -c "$C"/file_api/file_mempool.cc -o "$C"/file_api/file_mempool_ut.o
$GXX -DUNIT_TEST -c "$C"/file_api/file_cache.cc -o "$C"/file_api/file_cache_ut.o
$GXX -DUNIT_TEST -c "$C"/file_api/file_capture.cc -o "$C"/file_api/file_capture_ut.o
gate_objs=()
for o in "${objs[@]}"; do case "$o" in */file_flows.o|*/file_mempool.o|*/file_cache.o|*/file_capture.o) ;; *) gate_objs+=("$o");; esac; done
g++ -std=c++17 -O0 -g -w "$H/catch_main.o" "$C"/file_api/file_flows_ut.o "$C"/file_api/file_mempool_ut.o "$C"/file_api/file_cache_ut.o "$C"/file_api/file_capture_ut.o "$C"/file_api/file_lib.o "$H/stubs.o" "${gate_objs[@]}" \
  "$LIBCRYPTO" -lpthread "$LUA_SRC"/libluajit.a -lm -ldl -o "$H/gate"
"$H/gate" > "$H/gate.txt" 2>&1 || { echo GATE_FAIL; cat "$H/gate.txt"; exit 1; }
tail -1 "$H/gate.txt"
# case-name counts pinned from grep (assertions come from the RUNNER line):
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_flows.cc)" -ge 8
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_mempool.cc)" -eq 3
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_cache.cc)" -eq 7
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_capture.cc)" -eq 4 
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_capture_probe.cc)" -eq 0
# NEW17u (PLAN 2/7): the row TU contributes ZERO cases -- file_config.cc is
# already UT-clean (0 TEST_CASE / 0 UNIT_TEST at fe29cbe, grep-verbatim no
# excision) and rides both links in VERBATIM form. The unified gate stays
# 22/114 byte-ident: hard-assert the tail AND recheck the donor gate md5.
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_config.cc)" -eq 0
# NEW17v (PLAN 5): the fcapi row TU is likewise UT-clean -- file_api.{h,cc}
# carry 0 TEST_CASE / 0 UNIT_TEST at fe29cbe (grep-verbatim, no excision),
# so the gate delta is ZERO BY CONSTRUCTION and the same donor pins carry.
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_api.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_api.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_api.h)" -eq 0
# NEW17w (PLAN 2 / PLAN 1): the finspect row TU is UT-clean as re-measured
# -- file_inspect.{h,cc} carry 0 TEST_CASE / 0 UNIT_TEST at fe29cbe (grep-
# verbatim, no excision): the 17v self-check pattern repeats for the row.
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_inspect.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_inspect.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_inspect.h)" -eq 0
# NEW17x (PLAN 1/2): the file_policy row TU is UT-clean as re-measured --
# file_policy.{h,cc} carry 0 TEST_CASE / 0 UNIT_TEST at fe29cbe (grep-
# verbatim, no excision/self-check pattern repeats for the row).
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_policy.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_policy.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_policy.h)" -eq 0
# NEW17y (PLAN 1): the 17y row TU is UT-clean as re-measured (112+270=382 L;
# 0 TEST_CASE / 0 UNIT_TEST x2 -- FIXACC only swaps private:/protected:
# tokens, it never adds/moves UNIT_TEST fragments, so the .h grep stays 0).
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_service.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_service.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_service.h)" -eq 0
# NEW17y hygiene (PLAN 0.4 plumbing pin): the file-scope reload shadows
# (cc:57-:59) are TU-internal -- zero nm residue for their names.
test "$(nm "$C"/file_api/file_service.o | grep -cE ' (B|D|T) ([a-z_]*max_files_cached|capture_memcap|capture_block_size)$')" -eq 0
# NEW17v PLAN 5: the row TU's own residue -- file_api.o has exactly 3 U
# entries, ALL libstdc++/libc plumbing (class_type_info vtable, sized
# operator delete, __assert_fail from the LIVE cc:32/cc:38 asserts), ZERO
# app residue -- the smallest residue of the queue. Nothing to stub.
nm -u --demangle "$C"/file_api/file_api.o | grep ' U ' | sort -u > "$H"/nm_api.txt
test "$(wc -l < "$H"/nm_api.txt)" -eq 3
test "$(nm -u --demangle "$C"/file_api/file_api.o | grep -cE 'U (vtable for __cxxabiv1::__class_type_info|operator delete\(void\*, unsigned long\)|__assert_fail)')" -eq 3
grep -q 'All tests passed (114 assertions in 22 test cases)' "$H/gate.txt"
md5sum "$H/gate.txt" | grep -q '^4826fc2233044a2d5429413faf0ae1af  '
# gate exposure unchanged (PLAN 2): 34x IMGR acquire -> null, ZERO
# FileInspect prints -- the gate never arms the toggle, the md5 pin above
# is the byte-ident invariant; these greps localize WHAT is identical.
test "$(grep -c 'IMGR acquire -> null' "$H/gate.txt")" -eq 34
test "$(grep -c 'FileInspect' "$H/gate.txt")" -eq 0

# ---- probe link (gate already GREEN above): plain file_capture.o EXCLUDED,
# UT-compiled TEST_CASE-excised copy in. NEW17t: file_cache_share.o rides
# in via ${objs[@]} for BOTH links -- PLAN 3 closure: zero new TUs/stubs.
$GXX -c "$H/probe.cc" -o "$H/probe.o"
pobjs=()
for o in "${objs[@]}"; do case "$o" in */file_capture.o) ;; *) pobjs+=("$o");; esac; done
g++ -std=c++17 -O0 -g -w "$H/probe.o" "$H/stubs.o" "$C"/file_api/file_capture_probe.o "$C"/file_api/file_flows.o "$C"/file_api/file_cache.o "$C"/file_api/file_lib.o "${pobjs[@]}" \
  "$LIBCRYPTO" -lpthread "$LUA_SRC"/libluajit.a -lm -ldl -o "$H/probe"
timeout 120 "$H/probe" > "$H/vectors.txt" || { echo PROBE_FAIL; cat "$H/vectors.txt"; exit 1; }
# hygiene gate (context rule): no pointer/0x values in vectors
! grep -E '0x[0-9a-f]{6,}' "$H/vectors.txt"
# NEW17z exposure pins: the gate NEVER touches the row api -- zero W1/
# W2/W5-style witness prints in gate.txt (the two NEW witnesses are
# vectors-side only; the 3 row .o's are link-additive by construction).
test "$(grep -c 'W1 rules_append' "$H/gate.txt")" -eq 0
test "$(grep -c 'W2 get_includer' "$H/gate.txt")" -eq 0
test "$(grep -c 'W3 set_decompress_buffer_size' "$H/gate.txt")" -eq 0
test "$(grep -c 'V1_ctor\|V2_set\|V4_steal\|dump_file_cache' "$H/gate.txt")" -eq 0
test "$(grep -c 'Inspector dtor' "$H/gate.txt")" -eq 0
# vectors hygiene: the probe reached the DONE marker + the row witness
# prints land EXACTLY as designed (W1: subscribe 1x + the V3 readback;
# W2 pair exactly 1 scalar + 1 vector; the CFGLOG show pair 3 arms x2).
grep -q 'FMOD_PROBE_DONE' "$H/vectors.txt"
# PRINTS-FROZEN rule (the row's core observation): the REAL load_config
# (cc:263-:266) has NO print -- the witness-only "FIM load_config stole="
# line NEVER rides this harness (it stays frozen ONLY in the four donors
# that still link the trio).
test "$(grep -c 'FIM load_config' "$H/vectors.txt")" -eq 0
test "$(grep -c 'FIM load_config' "$H/gate.txt")" -eq 0
# the four witnesses land EXACTLY as designed: W1 three times (empty +
# nullic + rules) + W2 three times + W3 once; W4 query_from_lua prints
# NOTHING (upstream-verbatim null body -> LOGMSG arms through LogMessage).
test "$(grep -c 'W1 rules_append' "$H/vectors.txt")" -eq 3
test "$(grep -c 'W2 get_includer' "$H/vectors.txt")" -eq 3
test "$(grep -c 'W3 set_decompress_buffer_size=4096' "$H/vectors.txt")" -eq 1
test "$(grep -c 'LOGMSG File cache not available' "$H/vectors.txt")" -eq 2
test "$(grep -c 'V2_endEmpty' "$H/vectors.txt")" -eq 0
# R3 pins in the fmod transcript (measured this build; the donor's flog
# handle-window pins are GONE -- this row's transcript is the module/
# command surface). SHA ladder: the AB row renders UPPERCASE 3x (2 summary
# dumps + the detail block -- the cc:345 normalize of the lowercase "ab"
# push proves the uppercase arm end-to-end through REAL dump code); the
# count ladder: 2-entry total x3, the displayed-1-of-2 arm once, the -1
# sentinel rides the ALL dump; reject ladders: two row-count rejects (0,
# -2), two usage arms (null + empty sha), the 65-char length reject, the
# zz hex reject, the FFFF no-match arm; the null-cache branch exactly twice
# (both commands through the W4 nullptr -> LOGMSG LogMessage arm).
test "$(grep -c 'ABABABABABABABAB' "$H/vectors.txt")" -eq 3
test "$(grep -c 'Total number of cache entries: 2' "$H/vectors.txt")" -eq 3
test "$(grep -c '... displayed 1 of 2 entries' "$H/vectors.txt" || true)" -eq 1
test "$(grep -c 'Invalid row count' "$H/vectors.txt")" -eq 2
test "$(grep -c 'Usage: file_inspect' "$H/vectors.txt")" -eq 2
test "$(grep -c 'Invalid SHA256 prefix: length' "$H/vectors.txt")" -eq 1
test "$(grep -c 'only hex characters' "$H/vectors.txt")" -eq 1
test "$(grep -c 'No cache entry found matching SHA256: FFFF' "$H/vectors.txt")" -eq 1
test "$(grep -c 'SHA256: ABAB' "$H/vectors.txt")" -eq 1
# end() ladder: THREE W1 lines -- arm 1/2 the EMPTY magic_file quirk
# (file='' with the plain + null includer, R5) and arm 3 the set()-armed
# "include magic.rules" (cc:247-:251 prefix verbatim).
test "$(grep -c "W1 rules_append file='' includer='MODULE-INC'" "$H/vectors.txt")" -eq 1
test "$(grep -c "W1 rules_append file='' includer='(null)'" "$H/vectors.txt")" -eq 1
test "$(grep -c "W1 rules_append file='include magic.rules' includer='MODULE-INC'" "$H/vectors.txt")" -eq 1
# the REAL-ctor fixture seam: V5 pins the null-config arm (fc never set ->
# the real steal hands null; the ~FileInspect if(config) guard rides it).
test "$(grep -c 'V5_wit_ctor cfg_null=1' "$H/vectors.txt")" -eq 1
test "$(grep -c 'V4_steal_a ins_cfg=1 post_null=1' "$H/vectors.txt")" -eq 1
test "$(grep -c 'V4_steal_b pre_null=1 post_got=1 again_null=1' "$H/vectors.txt")" -eq 1
echo "nm_flog U-entries: $(wc -l < "$H"/nm_flog.txt) (64 by construction: 13 real + 7 resident + 16 NEW-app + 28 plumbing -- PLAN 0)"
echo "nm_textlog U-entries: $(wc -l < "$H"/nm_textlog.txt) (30: 3 real + 5 resident + 0 app + 22 plumbing -- the real cp, PLAN 0)"
echo "nm_module U-entries: $(wc -l < "$H"/nm_module.txt) (32: 0 real + 2 resident + 30 plumbing, 0 app NEW -- the real cp)"
echo "zero-retire evidence: real T defs $(nm -C "$C"/framework/module.o | grep -cE ' T snort::Module::') Module + $(nm -C "$C"/log/text_log.o | grep -cE ' T snort::TextLog_') TextLog + 4 row-surface; stubs.o survivors $(nm -C "$H"/stubs.o | grep -cE ' T snort::TextLog_| T snort::Module::') (R5 zero-retire, 0-dup)"
echo "vectors md5: $(md5sum "$H"/vectors.txt)"
echo "gate md5: $(md5sum "$H"/gate.txt)"
echo "FMOD_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"

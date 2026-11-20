#!/usr/bin/env bash
# vocab_harness -- row 18c codec vocabulary: codecs/codec_api.{h,cc} (26+121)
# + misc/cd_default.cc 83 + ip/cd_bad_proto.cc 98 + ip/cd_no_next.cc 116 +
# root/cd_raw.cc 105 = 549 L (PLAN 0: NEXT.md:277-:282 claim re-measured,
# per-file md5s pinned below; real dirs misc//ip//root/, NEXT.md path note).
# PROBE-ONLY harness (PLAN 4 / R4): the 6 row files carry ZERO gate material
# (census below, 0 on each with TEST_CASE|TEST_GROUP|^TEST(|UNIT_TEST) and
# CppUTest is unbuildable on this host DOUBLE-WALLED (geneve self-include:
# wall 1 inside cd_geneve.cc at log/text_log.h, wall 2 the ground tree itself
# at daq_common.h -- both re-proven every build, E4_cpputest_fatal.txt).
# Witnesses per the nm census (PLAN 2) are EXACTLY: 4 cd_*[] witness arrays
# (witness_stubs.cc: cd_ipv4/cd_ipv6/cd_tcp/cd_hopopts -- later rows'
# symbols) + PluginManager::load_plugins (probe.cc witness body, the
# codec_harness/stubs.cc event-witness shape) + probe-side SnortConfig
# bodies (witness_conf.cc heredoc). SnortConfig::hit_ip6_maxopts is INLINE
# at snort_config.h:450-:451 and max_ip6_extensions PUBLIC at :278 -- NO
# access trick, NO snort_config .o compiled.
# Copy tree (PLAN 1): 17d codec_harness donor list VERBATIM (minus the catch
# pulls -- probe-only, grep -ci catch in probe.cc/witness_stubs.cc = 0) +
# the row's 6 files + cp delta EXACTLY 7+5 more ground cps for the
# snort_config.h chain (the 7 auto-loop headers + the 4 named by
# snort_config.h:35-:38) + managers/{plugin_manager.h,plugin.h} (md5
# a9242b71 == the action_harness md5-ident holder, pinned) + ONE graft,
# witness daq_dlt.h: DAQ SDK absent from tree AND host (find 0 hits; daqs/
# ships daq_user.h DLT_USER 230 at :29). DLT_RAW 12 VALUE CITE (R1 --
# vectors pin "DLT 12" twice via cd_raw.cc:31-:32 ADD_DLT help string +
# :62 v.emplace_back): real libpcap pcap/dlt.h (android.googlesource
# mirror, lines 112-:114: DLT_RAW 14 on BSD/OS, 12 = the libpcap/libdaq
# convention). Never assumed; PLAN 1 carries the same cite.
# EVAL-ORDER RULE (R6 -- 17p-lesson sibling, vectors recipe): printf arg
# evaluation order interleaved c->decode() with post-decode field reads and
# printed next_prot_id BEFORE decode ran (scratch probe_fix.cc demo). The
# probe stores decode results to VARS first; assertions below pin the rule.
# Gate lineage (PLAN 4): ZERO-EDIT row -- ships ZERO gate.txt; the 9 holders
# of md5 4826fc2233044a2d5429413faf0ae1af (fcap fcapi fconf fcshare finspect
# flog fmod fpolicy fsvc) are frozen dirs; 18c = 11th straight. fmod double-
# rebuild stays OUTSIDE this script (session ritual, csum pattern); its
# oracle lines are grepped below from the COMMITTED fmod build.sh, and the
# working-tree census runs here every build.
# Values NEVER typed from the PLAN (17p lesson): the ladder greps below are
# the scratch-MEASURED vectors (29 L, md5 5da70e82416b6f769af8177d859331e7
# at BOTH -O levels -- the recon's "28 lines" prose was a miscount; the
# file/md5 are the pinned truth, PLAN 0 correction) re-measured fresh.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy

# ---- ground identity (the 6 row files pinned by their OWN md5, re-measured
# here, NOT typed from the PLAN; wc per PLAN 0 table) ----
test "$(md5sum "$SRC"/src/codecs/codec_api.h | awk '{print $1}')"          = "df2bc9d1f74314408a3ced3be3e4d2ad"
test "$(md5sum "$SRC"/src/codecs/codec_api.cc | awk '{print $1}')"         = "77b4bd8671720d1b6d1afbf33e024ee1"
test "$(md5sum "$SRC"/src/codecs/misc/cd_default.cc | awk '{print $1}')"   = "24af11828b3dc4d14ee646dda38524c2"
test "$(md5sum "$SRC"/src/codecs/ip/cd_bad_proto.cc | awk '{print $1}')"   = "5b1624c2c3bf87f6652736db1119f440"
test "$(md5sum "$SRC"/src/codecs/ip/cd_no_next.cc | awk '{print $1}')"     = "5943bf61b79fe655c85f6fa6d08c4a10"
test "$(md5sum "$SRC"/src/codecs/root/cd_raw.cc | awk '{print $1}')"       = "d34183a11307f2256eef6297f8005c86"
test "$(cat "$SRC"/src/codecs/codec_api.h "$SRC"/src/codecs/codec_api.cc "$SRC"/src/codecs/misc/cd_default.cc "$SRC"/src/codecs/ip/cd_bad_proto.cc "$SRC"/src/codecs/ip/cd_no_next.cc "$SRC"/src/codecs/root/cd_raw.cc | wc -l)" -eq 549
# zero suite material on every row file (PLAN 0 census; the paren-attached
# grep trap from recon -- use the space forms here too):
for f in codecs/codec_api.h codecs/codec_api.cc codecs/misc/cd_default.cc codecs/ip/cd_bad_proto.cc codecs/ip/cd_no_next.cc codecs/root/cd_raw.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST\|TEST_CASE[[:space:]]*(' "$SRC"/src/$f || true)" -eq 0
done
# tree-level census receipt (PLAN 0): 1 Catch TEST_CASE (cd_gre.cc:352, the
# future row's) + 4 CppUTest files (add_cpputest x4) = 17 TEST / 6 GROUP:
test "$(grep -rc 'TEST_CASE[[:space:]]*(' "$SRC"/src/codecs --include='*.cc' --include='*.h' | grep -vc ':0$' || true)" -eq 1
grep -q 'TEST_CASE (' "$SRC"/src/codecs/ip/cd_gre.cc
test "$(grep -h '^TEST(' "$SRC"/src/codecs/*/test/*_test.cc | wc -l)" -eq 17
test "$(grep -h 'TEST_GROUP' "$SRC"/src/codecs/*/test/*_test.cc | wc -l)" -eq 6
# R5 seam safety: ZERO daq_msg reads in every row TU (17d RawData deviation
# stays SAFE; seam defers to row 20 per NEXT.md):
for f in codecs/codec_api.h codecs/codec_api.cc codecs/misc/cd_default.cc codecs/ip/cd_bad_proto.cc codecs/ip/cd_no_next.cc codecs/root/cd_raw.cc; do
    test "$(grep -c 'daq_msg' "$SRC"/src/$f || true)" -eq 0
done

# ---- copy tree: donor (17d codec_harness recipe VERBATIM, minus catch) ----
rm -rf "$C"
mkdir -p "$C"/{framework,codecs,detection,main,protocols,sfip,utils,log,managers,target_based,packet_io,control,helpers,codecs/misc,codecs/ip,codecs/root}
cp "$SRC"/src/framework/{codec.h,codec.cc,decode_data.h,base_api.h,counts.h,parameter.h,value.h,module.h} "$C"/framework/
cp "$SRC"/src/codecs/codec_module.h "$C"/codecs/
cp "$SRC"/src/protocols/{ip.h,ip.cc,ipv4.h,ipv6.h,layer.h,mpls.h,protocol_ids.h} "$C"/protocols/
cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/utils/{cpp_macros.h,bits.h,util.h,util_cstring.h,util_cstring.cc,util_net.h} "$C"/utils/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/main/thread.h "$C"/main/
# 17d printf grafts (greppable in codec_harness/build.sh -- recipes carried):
printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
printf '#pragma once\n#include <cstdarg>\nnamespace snort {\nvoid LogMessage(const char*, ...);\nvoid ErrorMessage(const char*, ...);\n}\n' > "$C"/log/messages.h
printf '#pragma once\n#include <cstdint>\nnamespace snort {\nclass DetectionEngine {\npublic:\n    static int queue_event(unsigned gid, unsigned sid);\n};\n}\n' > "$C"/detection/detection_engine.h

# ---- the row (6 files at ground paths) ----
cp "$SRC"/src/codecs/{codec_api.h,codec_api.cc} "$C"/codecs/
cp "$SRC"/src/codecs/misc/cd_default.cc "$C"/codecs/misc/
cp "$SRC"/src/codecs/ip/{cd_bad_proto.cc,cd_no_next.cc} "$C"/codecs/ip/
cp "$SRC"/src/codecs/root/cd_raw.cc "$C"/codecs/root/

# ---- THE DITTO: E4 walls before the cps (delta census, PLAN 1 auto-loop) ----
# donor-only seeds for the two fatals (undo the cps for the wall arms):
WCP=$H/.wallseed
rm -rf "$WCP"; cp -a "$C" "$WCP"
rm "$WCP"/codecs/ip/cd_no_next.cc "$WCP"/codecs/codec_api.cc "$WCP"/codecs/codec_api.h
g++ -std=c++17 -O0 -w -I"$WCP" -c "$SRC"/src/codecs/ip/cd_no_next.cc -o /dev/null 2> "$H/E4_snort_config.txt" || true
grep -q 'main/snort_config.h: No such file' "$H/E4_snort_config.txt"
g++ -std=c++17 -O0 -w -I"$WCP" -c "$SRC"/src/codecs/codec_api.cc -o /dev/null 2> "$H/E4_plugin_manager.txt" || true
grep -q 'managers/plugin_manager.h: No such file' "$H/E4_plugin_manager.txt"
rm -rf "$H/.wallseed"

# ---- cp delta: EXACTLY the pinned 12-file snort_config closure + managers ----
# snort_config.h REAL cp (NO shim): md5 == ground == action_harness holder.
test "$(md5sum "$SRC"/src/main/snort_config.h | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
test "$(wc -l < "$SRC"/src/main/snort_config.h)" -eq 798
if [ -e /opt/data/snort3-rust/tools/action_harness/copy/main/snort_config.h ]; then
    cmp -s /opt/data/snort3-rust/tools/action_harness/copy/main/snort_config.h "$SRC"/src/main/snort_config.h \
        && test "$(md5sum /opt/data/snort3-rust/tools/action_harness/copy/main/snort_config.h | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
fi
cp "$SRC"/src/main/snort_config.h "$C"/main/
# the closure = 7 (recon auto-loop) + 4 (snort_config.h:35-:38 own includes) --
# EXACTLY 11, pinned as a list; R2 note: later snort_config rows inherit it.
for h in target_based/snort_protocols.h packet_io/active_action.h framework/data_bus.h framework/mp_data_bus.h control/control.h framework/mp_transport.h helpers/lockless_ring.h framework/inspector.h framework/ips_action.h helpers/scratch_allocator.h main/policy.h; do
    cp "$SRC"/src/$h "$C"/$h
done
# managers: 2 md5-pinned cps (action_harness md5-ident precedent for
# plugin_manager.h; plugin.h closure = base_api.h, donor-resident).
test "$(md5sum "$SRC"/src/managers/plugin_manager.h | awk '{print $1}')" = "a9242b711e2ca0ef9d4418dcc0caa014"
test "$(md5sum "$SRC"/src/managers/plugin.h | awk '{print $1}')"         = "4c2ea065852120a2144c06d5382c272b"
cp "$SRC"/src/managers/{plugin_manager.h,plugin.h} "$C"/managers/
if [ -e /opt/data/snort3-rust/tools/action_harness/copy/managers/plugin_manager.h ]; then
    cmp -s /opt/data/snort3-rust/tools/action_harness/copy/managers/plugin_manager.h "$SRC"/src/managers/plugin_manager.h
fi
# THE ONLY graft: witness daq_dlt.h (R1 cite: libpcap pcap/dlt.h lines
# 112-:114 @ android.googlesource mirror -- DLT_RAW 14 BSD/OS, 12 the
# libpcap/libdaq convention; fmod daq_common.h graft precedent).
test "$(find "$SRC" -name daq_dlt.h | wc -l)" -eq 0          # ABSENT in tree
printf '#pragma once\n// witness graft (fmod daq_common.h recipe): DAQ SDK header NOT in tree (fe29cbe) nor on host.\n// DLT_RAW 12 CITE: libpcap pcap/dlt.h lines 112-114 (android.googlesource mirror): 14 on\n// BSD/OS, 12 = libpcap/libdaq convention (PLAN 1 R1). vectors pin "DLT 12" x2.\n#define DLT_RAW 12\n' > "$C"/daq_dlt.h
grep -q '#define DLT_RAW 12' "$H/PLAN.md"    # the cite must ride PLAN too
grep -q 'android.googlesource' "$H/PLAN.md"
grep -q 'lines 112' "$H/PLAN.md"

# ---- copy audit: EVERY non-graft copy byte-identical to ground ----
# (5 grafts = config.h framework/api_options.h log/messages.h
# detection/detection_engine.h daq_dlt.h; everything else cp-identity).
audit=0
while IFS= read -r f; do
    rel=${f#"$C"/}
    case "$rel" in
        config.h|framework/api_options.h|log/messages.h|detection/detection_engine.h|daq_dlt.h) continue;;
    esac
    if [ -e "$SRC"/src/"$rel" ]; then
        cmp -s "$f" "$SRC"/src/"$rel" || { echo "COPY-DRIFT $rel" >&2; audit=1; }
    else
        echo "NOT-IN-GROUND $rel" >&2; audit=1
    fi
done < <(find "$C" -type f)
test "$audit" -eq 0
printf 'cp-audit: every non-graft copy byte-ident vs ground\n' > "$H/cp_audit_ok.txt"

# ---- probe-stageable integrity (md5 pins; witnesses = ONLY the census set) ----
test "$(md5sum "$H"/probe.cc | awk '{print $1}')"          = "e208a41143ce8b1795ef56cebddeab17"
test "$(md5sum "$H"/witness_stubs.cc | awk '{print $1}')"  = "9fad7e9d7a278fbc2ee82c233f86e774"
# witness census: 4 witness arrays (later rows' symbols), nothing else in
# witness_stubs.cc; load_plugins witness rides probe.cc (codec_harness
# stubs.cc shape); no gate material anywhere:
test "$(grep -o 'const BaseApi\* cd_' "$H"/witness_stubs.cc | wc -l)" -eq 8   # 4 extern + 4 def
test "$(grep -c 'cd_ipv4\|cd_ipv6\|cd_tcp\|cd_hopopts' "$H"/witness_stubs.cc)" -ge 4
test "$(grep -c 'void PluginManager::load_plugins' "$H"/probe.cc)" -eq 1
test ! -e "$H"/catch_main.cc
test ! -e "$H"/gate.txt && test ! -e "$H"/gate
# R6 eval-order rule pins: raw arms store to bool r FIRST (VAR-first arms =
# exactly 2), and NO printf line interleaves a next=/next_raw= read with a
# live c->decode call in the same line:
test "$(grep -c 'bool r = c->decode' "$H"/probe.cc)" -eq 2
test "$(grep -c 'next.*c->decode' "$H"/probe.cc || true)" -eq 0

# ---- R4 double-walled CppUTest receipt (re-proven EVERY build) ----
wall1=$(g++ -fsyntax-only -I"$C" "$SRC"/src/codecs/misc/test/geneve_codec_test.cc 2>&1 || true)
echo "$wall1" > "$H/E4_cpputest_fatal.txt"
echo "$wall1" | grep -q 'cd_geneve.cc.*fatal error: log/text_log.h: No such file'   # wall 1: INSIDE the row TU
wall2=$(g++ -fsyntax-only -I"$C" -I"$SRC"/src "$SRC"/src/codecs/misc/test/geneve_codec_test.cc 2>&1 || true)
echo "$wall2" >> "$H/E4_cpputest_fatal.txt"
echo "$wall2" | grep -q 'packet.h.*fatal error: daq_common.h: No such file'          # wall 2: ground tree itself (DAQ absent)
# dialect proof: the CppUTest files are CppUTest, not Catch -- 17 TEST, 0
# TEST_CASE, 4 add_cpputest registrations (CMake path never invoked here):
test "$(grep -h '^TEST(' "$SRC"/src/codecs/*/test/*_test.cc | wc -l)" -eq 17
test "$(grep -rh 'TEST_CASE[[:space:]]*(' "$SRC"/src/codecs/*/test/ | wc -l || true)" -eq 0
test "$(grep -rc 'add_cpputest' "$SRC"/src/codecs/*/test/CMakeLists.txt | awk -F: '{s+=$2} END {print s}')" -eq 4

# ---- E1: compile the 5 row TUs + the 4 donor objs at -O0 ----
GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"   # no spaces in path -> unquoted split safe
for f in codecs/misc/cd_default.cc codecs/ip/cd_bad_proto.cc codecs/ip/cd_no_next.cc codecs/root/cd_raw.cc codecs/codec_api.cc framework/codec.cc protocols/ip.cc sfip/sf_ip.cc utils/util_cstring.cc; do
    $GXX -c "$C"/$f -o "$C"/$(basename "$f" .cc).o
done
$GXX -c "$H"/probe.cc -o "$H"/probe.o
$GXX -c "$H"/witness_stubs.cc -o "$H"/witness_stubs.o

# ---- witness_conf.cc: probe-side SnortConfig bodies (heredoc, regenerated;
# snort_config.cc itself NOT compiled -- inspector/BUS world, 17z note; the
# seams = nm_U_probe.txt: ctor/dtor + 5 statics; PLAN 2) ----
cat > "$H"/witness_conf.cc <<'EOF'
// probe-side witness bodies for SnortConfig (see PLAN 2): the ctor/dtor/statics
// live in snort_config.cc -- NOT compiled here (inspector/DataBus world). The
// nm census (PLAN 2) proves SnortConfig is probe-side-only: NO row .o asks for
// it. max_ip6_extensions PUBLIC (snort_config.h:278), hit_ip6_maxopts INLINE
// (:450-:451) -- no access trick, no SnortConfig object file in the link.
#include "main/snort_config.h"
#include <mutex>
#include <string>
#include <unordered_map>
namespace snort {
SnortConfig::SnortConfig(const char*) : reload_id(0) {}
SnortConfig::~SnortConfig() {}
uint32_t SnortConfig::logging_flags = 0;
THREAD_LOCAL bool SnortConfig::log_quiet_bypassed = false;
uint32_t SnortConfig::warning_flags = 0;
std::mutex SnortConfig::static_names_mutex;
std::unordered_map<std::string, std::string> SnortConfig::static_names;
}
EOF
$GXX -c "$H"/witness_conf.cc -o "$H"/witness_conf.o
# stubs.o: the TRACKED 17d codec_harness/stubs.cc compiled as-is (no second
# copy; queue_event + layer + snort_strdup witnesses) -- md5 pinned:
test "$(md5sum /opt/data/snort3-rust/tools/codec_harness/stubs.cc | awk '{print $1}')" = "be9bdd0b437d1f6c56c841e8155d9e70"
$GXX -c /opt/data/snort3-rust/tools/codec_harness/stubs.cc -o "$H"/stubs.o

# ---- E2: per-TU nm residue census (PLAN 2 table re-run every build) ----
for t in cd_default cd_bad_proto cd_no_next cd_raw codec_api; do
    # name-preserving U-strip (demangled names CONTAIN spaces -- $NF would
    # mangle them; drop only column 1):
    nm -C -u "$C"/$t.o | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H"/nm_U_$t.txt
done
# app-residue per PLAN 2: cd_default/cd_raw ZERO; bad_proto/no_next exactly
# codec_event; codec_api EXACTLY 6 (load_plugins + 5 cd_* externs incl
# cd_default = the row's own .o):
test "$(grep -cE 'snort::|cd_|PluginManager' "$H"/nm_U_cd_default.txt || true)" -eq 0
test "$(grep -cE 'snort::|cd_|PluginManager' "$H"/nm_U_cd_raw.txt || true)" -eq 0
test "$(grep -c 'Codec::codec_event' "$H"/nm_U_cd_bad_proto.txt)" -eq 1
test "$(grep -c 'Codec::codec_event' "$H"/nm_U_cd_no_next.txt)" -eq 1
# (the U-line awk/sed idiom keeps names intact; count lines for codec_api):
test "$(wc -l < "$H"/nm_U_codec_api.txt)" -eq 6
grep -q 'load_plugins' "$H"/nm_U_codec_api.txt
for a in cd_default cd_ipv4 cd_ipv6 cd_tcp cd_hopopts; do grep -q "$a" "$H"/nm_U_codec_api.txt; done
# the 4 witness arrays resolve witness_stubs.o, codec_event resolves the REAL
# framework/codec.o cp (def codec.cc:85), load_plugins resolves probe.cc:
cd_ws=$(nm -C --defined-only "$H"/witness_stubs.o)
test "$(echo "$cd_ws" | grep -cE 'cd_ipv4|cd_ipv6|cd_tcp|cd_hopopts')" -eq 4   # 4 def lines (one per array)
# capture-first (pipefail + early grep -q match = SIGPIPE 141 trap):
cd_code=$(nm -C --defined-only "$C"/codec.o)
cd_probe=$(nm -C --defined-only "$H"/probe.o)
echo "$cd_code" | grep -q 'T snort::Codec::codec_event'
echo "$cd_probe" | grep -q 'T PluginManager::load_plugins'   # load_plugins sits in GLOBAL scope (plugin_manager.h:47, outside the snort namespace of :42) -- nm -C spelling truth

# ---- E5: link + run at -O0 AND -O2; outputs BYTE-IDENTICAL ----
OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/cd_default.o $C/cd_bad_proto.o $C/cd_no_next.o $C/cd_raw.o $C/codec_api.o"
$GXX $OBJS "$H"/probe.o "$H"/witness_conf.o "$H"/stubs.o "$H"/witness_stubs.o -o "$H"/probe   # word-split by design (no spaces in paths)
$GXXA -c "$H"/probe.cc -o "$H"/probe_O2.o
# -O2 link: recompile ALL TUs at -O2 into a shadow objs dir (no mixing):
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in $C/codecs/misc/cd_default.cc $C/codecs/ip/cd_bad_proto.cc $C/codecs/ip/cd_no_next.cc $C/codecs/root/cd_raw.cc $C/codecs/codec_api.cc $C/framework/codec.cc $C/protocols/ip.cc $C/sfip/sf_ip.cc $C/utils/util_cstring.cc; do
    $GXXA -c "$f" -o "$O2"/$(basename "$f" .cc).o
done
$GXXA -c "$H"/witness_stubs.cc -o "$O2"/witness_stubs.o
$GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c /opt/data/snort3-rust/tools/codec_harness/stubs.cc -o "$O2"/stubs.o
$GXXA $(for b in codec ip sf_ip util_cstring cd_default cd_bad_proto cd_no_next cd_raw codec_api; do printf '%s ' "$O2/$b.o"; done) "$H"/probe_O2.o "$O2"/witness_conf.o "$O2"/stubs.o "$O2"/witness_stubs.o -o "$H"/probe_O2
timeout 60 "$H"/probe      > "$H"/vectors_O0.txt || { echo PROBE_FAIL O0; exit 1; }
timeout 60 "$H"/probe_O2   > "$H"/vectors_O2.txt || { echo PROBE_FAIL O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt      # the E5 byte-identity arm
# the TRACKED vectors.txt is the committed pin: fresh output must EQUAL it;
# the file is NEVER regenerated by the build (csum posture).
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')" = "5da70e82416b6f769af8177d859331e7"
test "$(wc -l < "$H"/vectors.txt)" -eq 29
# cross-check the scratch receipt (recon §5 fixed to 29 L):
if [ -e /opt/data/cache/scratch/row18c/vectors_O0.txt ]; then
    test -z "$(diff /opt/data/cache/scratch/row18c/vectors_O0.txt "$H"/vectors.txt)"
fi

# hygiene gate (carry fmod build.sh:1101 VERBATIM recipe -- PLAN R6): no
# 6+-hex-digit pointer-ish values in vectors.
! grep -E '0x[0-9a-f]{6,}' "$H"/vectors.txt

# ---- known-answer ladder (scratch-MEASURED arms; fresh build re-measures;
# every line = the fresh vectors.txt, byte-match -- never a forecast) ----
test "$(grep -c 'size=112 ver=1900547' "$H"/vectors.txt)" -eq 4       # CodecApi pin x4
grep -q '^API unknown type=0 size=112 ver=1900547 features=0 name=unknown$' "$H"/vectors.txt   # cd_default features=0 = NO PLUGIN_SO_RELOAD
grep -q '^API bad_proto type=0 size=112 ver=1900547 features=1 name=bad_proto$' "$H"/vectors.txt
grep -q '^API ipv6_no_next type=0 size=112 ver=1900547 features=1 name=ipv6_no_next$' "$H"/vectors.txt
grep -q '^API raw type=0 size=112 ver=1900547 features=1 name=raw$' "$H"/vectors.txt
test "$(grep -c '^DLT 12$' "$H"/vectors.txt)" -eq 1                   # the get_data_link_type vector arm
test "$(grep -c 'DLT 12' "$H"/vectors.txt)" -eq 2                     # R1 pin x2 total: DLT vector + ADD_DLT HELP string
grep -q '^PID 256$' "$H"/vectors.txt    # FINISHED_DECODE (unknown)
grep -q '^PID 53$'  "$H"/vectors.txt    # SWIPE
grep -q '^PID 77$'  "$H"/vectors.txt    # SUN_ND
grep -q '^PID 59$'  "$H"/vectors.txt    # NONEXT
grep -q '^HELP support for raw IP (DLT 12)$' "$H"/vectors.txt         # ADD_DLT pin
grep -q '^DECODE unknown -> 0$' "$H"/vectors.txt
grep -q '^EV 116 450$' "$H"/vectors.txt # GID_DECODE + BAD_PROTO sid (codec.o witness print)
grep -q '^DECODE bad_proto -> 1$' "$H"/vectors.txt
grep -q '^NN short -> 0$' "$H"/vectors.txt
grep -q '^NN ok -> 1 lyr=8 bits=10000 cnt=1$' "$H"/vectors.txt        # %llx print of 0x10000
grep -q '^EV 116 456$' "$H"/vectors.txt # TOO_MANY_EXTENDED (hit_ip6_maxopts inline arm)
grep -q '^NN maxopts -> 0$' "$H"/vectors.txt
grep -q '^DECODE raw v4 -> 1 next=2048$' "$H"/vectors.txt
grep -q '^DECODE raw v6 -> 1 next=34525$' "$H"/vectors.txt
grep -q '^DECODE raw bad -> 0$' "$H"/vectors.txt
for a in unknown cd_ipv4_stub cd_ipv6_stub cd_tcp_stub cd_hopopts_stub; do grep -q "^LOAD $a$" "$H"/vectors.txt; done
grep -q '^LOADS 5$' "$H"/vectors.txt    # load_codecs() wiring = 5 witness-print LOADs

# ---- gate-lineage receipts (PLAN 4: ZERO-EDIT, 11th-straight argument) ----
FM=/opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" "$FM"
grep -q "4826fc2233044a2d5429413faf0ae1af" "$FM"
# census (working tree): exactly 9 gate.txt carry the chain md5; THIS harness
# owns ZERO gate.txt (probe-only) -- the chain cannot move: ZERO-EDIT row.
test "$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')" -eq 9
test ! -e "$H"/gate.txt
test ! -e "$H"/gate
# vocab vectors stay pointer-free AND the scratch pin cannot drift:
test "$(grep -c '0x' "$H"/vectors.txt || true)" -eq 0   # %llx arms print bare hex

echo "row-TU app residue: cd_default=$(grep -cE 'snort::|cd_' "$H"/nm_U_cd_default.txt || true) bad_proto=$(grep -c 'codec_event' "$H"/nm_U_cd_bad_proto.txt) no_next=$(grep -c 'codec_event' "$H"/nm_U_cd_no_next.txt) raw=$(grep -cE 'snort::|cd_' "$H"/nm_U_cd_raw.txt || true) codec_api=$(wc -l < "$H"/nm_U_codec_api.txt) (=6, witnesses: 4 arrays + load_plugins)"
echo "O0==O2 vectors identity: $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT)"
echo "vectors md5: $(md5sum "$H"/vectors.txt)"
echo "gate census holders: $(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af') (9 = chain intact; vocab gate.txt count 0)"
echo "VOCAB_HARNESS_OK vectors=$(wc -l < "$H"/vectors.txt)"

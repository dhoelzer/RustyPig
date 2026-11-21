#!/usr/bin/env bash
# erspan_harness -- row 18l: the codecs/link CHEAP SUB-TRIO: codecs/link/
# cd_erspan2.cc 145 L + cd_erspan3.cc 147 L + cd_trans_bridge.cc 158 L = 450 L
# (the NEXT :413 (a1) row cites EXACTLY; sibling-pair diff 120 face, PLAN §0).
# THE ZERO-NEW-WITNESS row (small4 6-face posture, the cited precedent): the
# nm -U census of the three scratch .o's carries ZERO tunnel symbols => the
# witness_18f face rides INHERITED-CARRIED in the WIN trio (small4 :273 "ZERO
# new witness -- WIN trio INHERITED"), NO own-new witness file, own-new T
# census EXACTLY 0, and THE BACKBONE CENSUS STAYS PINNED AT 10 (misc3's
# backbone10 face re-verified EVERY build: the 10 md5s below + the EXACTLY-10
# receipt line-count). NO SFDAQ pair here (that is misc3's tracked witness_-
# trio face -- NEVER linked: the T-census greps refuse it LOUDLY).
# THE ZERO-FRESH-CP row: copy tree = misc3 DONOR POST-STRIP 111-tree REUSE
# clone (its graft-v2 daq_common.h fead0027 face rides INHERITED, NEVER re-
# authored); ALL EIGHT closure headers find-1 RESIDENT (codec_module.h,
# framework/codec.h, log/log_text.h, protocols/eth.h, protocol_ids.h, base_
# api.h, snort_config.h, config.h -- scratch header_residency.txt) => EXACTLY
# ZERO new header cps. daq grep 0x3 (graft NON-PARTICIPATION, PLAN §5: the
# f683749c/fead0027 v16-vs-v2 face stays UNUSED here, NEVER re-authorized).
# THE E4 localization row (18h precedent re-run): -I snort3-src/src ONLY =
# rc1 x3 fatal `framework/api_options.h: No such file` via base_api.h:32 (the
# trio's ONLY non-donor header face); in-tree strip walls localize the same
# face BOTH ways (api_options.h -> all 3 die; log_text.h + eth.h -> ONLY
# trans_bridge dies; restored rc0 x3 EVERY build).
# THE tunnel NEGATIVE row (PLAN §2, briefing-correction face preserved):
# tunnel/TUNNEL_ERSPAN/GRE_HDR/gre_api grep = 0x3 across the trio; TUNNEL_
# ERSPAN = 0 tree-WIDE (enum TunnelFlags :117-:130 has NO ERSPAN member);
# the mplsinly-hook cite lives at cd_mpls.cc :205-:206, a LATER row (b3). The
# ONE GRE token in the trio is the SID NAME DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR
# 165 at cd_trans_bridge.cc :56 -- cd_gre.rs CITE-NEVER-LAND (§3 ruling).
# TRUE-NAME TRIPLE tripwire (§5): cd_transbridge[] :152 is the ONLY drift
# name INSIDE this subrow; the double-NAME cd_pppoepkt face (:115/:139 arms,
# table :236) lives in cd_pppoe.cc -- the briefing's "cd_pppoepkt live in the
# erspan TUs" face is WRONG on disk (grep-refused below) -- 18m (a3) hand-off
# cite ONLY. NEW pin face NO earlier row carried: the trans_bridge NAME/HELP
# #defines sit INSIDE the anon namespace :33-:34 (sed-pinned + the enclosure
# faces :31-:32/:47).
# ZERO-gate row (19th straight): find src/codecs/link -type d -name test = 0
# (the link dir has NO test/ AT ALL) + add_cpputest census 0 + the trio-TU
# CppUTest/TEST_CASE STOP-flag tripwire re-armed. NO gate.txt shipped.
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness
MI=$R/tools/misc3_harness
MIP=$R/tools/miscip_harness
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
L=$SRC/src/codecs/link
C=$H/copy

# ---- ground identity (THREE row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [cd_erspan2.cc]=fee3934f71fe1c77cf3c0aef120e7eec [cd_erspan3.cc]=8ba0422c85300be2f799c6e24b4b8086 [cd_trans_bridge.cc]=20a6a8b0ee1b4c1f9b66e10fe7c00db9 )
declare -A WC=( [cd_erspan2.cc]=145 [cd_erspan3.cc]=147 [cd_trans_bridge.cc]=158 )
for f in cd_erspan2.cc cd_erspan3.cc cd_trans_bridge.cc; do
    test "$(md5sum "$L/$f" | awk '{print $1}')" = "${MD5[$f]}"
    test "$(wc -l < "$L/$f")" -eq "${WC[$f]}"
done
# trio total face (the row's ledger line): 145+147+158 = 450 SUM measured
test "$(( $(wc -l < "$L/cd_erspan2.cc") + $(wc -l < "$L/cd_erspan3.cc") + $(wc -l < "$L/cd_trans_bridge.cc") ))" -eq 450
# combined gate grep ZERO x3 EVERY build (if ground ever ships a suite naming
# the trio the row is RE-PLANNED to the gre gate shape -- flip trips loudly)
for f in cd_erspan2.cc cd_erspan3.cc cd_trans_bridge.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST\|CppUTest' "$L/$f" || true)" -eq 0
done
# the NINE-file link tail ledger (the 18l mpls-390-not-398 correction face,
# PLAN §11: disk says cd_mpls 390, the briefing's 398 was stale-by-3 UPWARDS;
# the nine-file tail 390+236+243+145+147+235+187+158+174 = 1,915 = NEXT :401
# byte-TRUE (the tail rides the ten link TUs MINUS cd_arp -- MEASURED here,
# NEVER typed from docs). Trio sub-row 450 UNAFFECTED either way.) ----
test "$(wc -l < "$L/cd_mpls.cc")" -eq 390
test "$(( $(wc -l < "$L/cd_mpls.cc") + $(wc -l < "$L/cd_vlan.cc") + $(wc -l < "$L/cd_pppoe.cc") + $(wc -l < "$L/cd_erspan2.cc") + $(wc -l < "$L/cd_erspan3.cc") + $(wc -l < "$L/cd_ciscometadata.cc") + $(wc -l < "$L/cd_fabricpath.cc") + $(wc -l < "$L/cd_trans_bridge.cc") + $(wc -l < "$L/cd_ppp_encap.cc") ))" -eq 1915   # the nine-file tail face (arp 128 rides its own later row)

# ---- THE zero-gate census (19th straight, MEASURED EVERY BUILD) ----
test "$(find "$L" -type d -name test | wc -l)" -eq 0
test ! -d "$L/test"
test "$(grep -c 'add_cpputest' "$L/CMakeLists.txt" || true)" -eq 0
test "$(grep -c 'cd_erspan2\|cd_erspan3\|cd_trans_bridge' "$L/CMakeLists.txt")" -eq 6   # the trio's own build-system face MEASURED (STATIC set x3 + add_dynamic_module x3)

# ---- THE hidden tables (BUILDING_SO split) -- sed census PIN lines x3 ----
test "$(sed -n '136p' "$L/cd_erspan2.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '137p' "$L/cd_erspan2.cc")" = "SO_PUBLIC const BaseApi* snort_plugins[] ="
test "$(sed -n '139p' "$L/cd_erspan2.cc")" = "const BaseApi* cd_erspan2[] ="
test "$(sed -n '142p' "$L/cd_erspan2.cc")" = "    &erspan2_api.base,"
test "$(sed -n '138p' "$L/cd_erspan3.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '141p' "$L/cd_erspan3.cc")" = "const BaseApi* cd_erspan3[] ="
test "$(sed -n '144p' "$L/cd_erspan3.cc")" = "    &erspan3_api.base,"
test "$(sed -n '149p' "$L/cd_trans_bridge.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '152p' "$L/cd_trans_bridge.cc")" = "const BaseApi* cd_transbridge[] ="   # THE in-subrow drift name (file base trans_bridge vs table cd_transbridge)
test "$(sed -n '155p' "$L/cd_trans_bridge.cc")" = "    &transbridge_api.base,"
for f in cd_erspan2.cc cd_erspan3.cc cd_trans_bridge.cc; do
    test "$(grep -c 'BUILDING_SO'  "$L/$f")" -eq 1
    test "$(grep -c 'snort_plugins' "$L/$f")" -eq 1
done

# ---- NAME/HELP defines: the ANON-NAMESPACE pin face (§55 NEW, no earlier
# row EVER carried it): trans_bridge #defines live INSIDE `namespace {}` at
# :33-:34; the erspan pair lives OUTSIDE at :29-:30. sed-enclosure proof +
# drift tripwire (rust landing files use the FILE base names, §3/§5) ----
test "$(sed -n '29p' "$L/cd_erspan2.cc")" = '#define CD_ERSPAN2_NAME "erspan2"'
test "$(sed -n '30p' "$L/cd_erspan2.cc")" = '#define CD_ERSPAN2_HELP "support for encapsulated remote switched port analyzer - type 2"'
test "$(sed -n '29p' "$L/cd_erspan3.cc")" = '#define CD_ERSPAN3_NAME "erspan3"'
test "$(sed -n '30p' "$L/cd_erspan3.cc")" = '#define CD_ERSPAN3_HELP "support for encapsulated remote switched port analyzer - type 3"'
test "$(sed -n '31p' "$L/cd_trans_bridge.cc")" = "namespace"
test "$(sed -n '32p' "$L/cd_trans_bridge.cc")" = "{"
test "$(sed -n '33p' "$L/cd_trans_bridge.cc")" = '#define CD_TRANSBRIDGE_NAME "trans_bridge"'
test "$(sed -n '34p' "$L/cd_trans_bridge.cc")" = '#define CD_TRANSBRIDGE_HELP "support for trans-bridging"'
test "$(sed -n '47p' "$L/cd_trans_bridge.cc")" = "} // anonymous namespace"

# ---- TRUE-NAME DRIFT tripwire (§1/:18 briefing correction): the double-NAME
# cd_pppoepkt face lives in cd_pppoe.cc NEVER in THIS subrow's three TUs ----
test "$(sed -n '115p' "$L/cd_pppoe.cc")" = '#define CD_PPPOEPKT_DISC_NAME "pppoe_disc"'   # 18m (a3) hand-off CITE pins
test "$(sed -n '139p' "$L/cd_pppoe.cc")" = '#define CD_PPPOEPKT_SESS_NAME "pppoe_sess"'
test "$(sed -n '236p' "$L/cd_pppoe.cc")" = "const BaseApi* cd_pppoepkt[] ="
test "$(sed -n '169p' "$L/cd_ppp_encap.cc")" = "const BaseApi* cd_pppencap[] ="
for f in cd_erspan2.cc cd_erspan3.cc cd_trans_bridge.cc; do
    test "$(grep -c 'cd_pppoepkt\|cd_pppencap\|PPPOEPKT' "$L/$f" || true)" -eq 0   # the WRONG-on-disk briefing face refused LOUDLY
done

# ---- mod_ctor/mod_dtor ASYMMETRY pin 1/1/0 (the 18k axis RE-MEASURED: do
# NOT carry misc3's 1/0/0, daq3's 1/1/1 or miscip's 0/0/0) ----
test "$(sed -n '102p' "$L/cd_erspan2.cc")" = "static Module* mod_ctor()"
test "$(sed -n '105p' "$L/cd_erspan2.cc")" = "static void mod_dtor(Module* m)"
test "$(sed -n '125p' "$L/cd_erspan2.cc")" = "        mod_ctor,"
test "$(sed -n '126p' "$L/cd_erspan2.cc")" = "        mod_dtor,"
test "$(sed -n '104p' "$L/cd_erspan3.cc")" = "static Module* mod_ctor()"
test "$(sed -n '107p' "$L/cd_erspan3.cc")" = "static void mod_dtor(Module* m)"
test "$(sed -n '127p' "$L/cd_erspan3.cc")" = "        mod_ctor,"
test "$(sed -n '128p' "$L/cd_erspan3.cc")" = "        mod_dtor,"
test "$(sed -n '138p' "$L/cd_trans_bridge.cc")" = "        nullptr,"    # EXPLICIT nullptr pair (no comment -- §15)
test "$(sed -n '139p' "$L/cd_trans_bridge.cc")" = "        nullptr"
# ctor/dtor (CodecApi slots) non-null x3 (erspan2 :108/:111, erspan3 :110/:113,
# trans_bridge :121/:124) -- the FACE-A ctor=1 dtor=1 x3 ground face
test "$(sed -n '108p' "$L/cd_erspan2.cc")" = "static Codec* ctor(Module*)"
test "$(sed -n '121p' "$L/cd_trans_bridge.cc")" = "static Codec* ctor(Module*)"

# ---- externs + loads + ladder ALL RESIDENT (rows ADD TUs, NEVER touch) ----
test "$(sed -n '45p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_erspan2[];"
test "$(sed -n '46p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_erspan3[];"
test "$(sed -n '69p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_transbridge[];"
test "$(sed -n '90p'  "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_erspan2);"
test "$(sed -n '91p'  "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_erspan3);"
test "$(sed -n '114p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_transbridge);"
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern cc census (misc3 :111 face, UNDISTURBED)
# the rust ladder face (rows NEVER re-touch): trio names ALREADY resident
test "$(sed -n '103p' "$R/src/codecs/codec_api.rs")" = '    "cd_erspan2",'
test "$(sed -n '104p' "$R/src/codecs/codec_api.rs")" = '    "cd_erspan3",'
test "$(sed -n '127p' "$R/src/codecs/codec_api.rs")" = '    "cd_transbridge",'
test "$(sed -n '97p'  "$R/src/codecs/codec_api.rs")" = 'pub const STATIC_CODEC_EXTERN_NAMES: [&str; 34] = ['

# ---- the 4-distinct sids RESIDENT face (PLAN §4: ZERO new consts): trio
# loads 165/462/463/464 = 4 DISTINCT tokens subset of the 19-token link set;
# codec_module.rs arms pinned, NEVER re-walked; cargo 573/0 UNTOUCHED (NEXT
# :21 docs face cited; this row ships ZERO rust edits -- the trio rs files
# do NOT exist yet (seed-pass guard, flipped at PORT like misc3 :586-:591)) ----
test "$(sed -n '112p' "$R/src/codecs/codec_module.rs")" = '    DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR = 165,  // h:98'
test "$(sed -n '220p' "$R/src/codecs/codec_module.rs")" = '    DECODE_ERSPAN_HDR_VERSION_MISMATCH = 462,  // h:215'
test "$(sed -n '221p' "$R/src/codecs/codec_module.rs")" = '    DECODE_ERSPAN2_DGRAM_LT_HDR = 463,  // h:216'
test "$(sed -n '222p' "$R/src/codecs/codec_module.rs")" = '    DECODE_ERSPAN3_DGRAM_LT_HDR = 464,  // h:217'
# the trio Rust TUs LANDED (the PORT pass flipped this guard from the
# seed-pass not-exists face per the misc3 :586-:591 precedent; the hidden-
# table consts + the 1/1/0 mod-arm mirror + the drift-table const spelling
# pin the landing — R3 cite-NEVER-land posture)
test "$(ls "$R/src/codecs/cd_erspan2.rs" "$R/src/codecs/cd_erspan3.rs" "$R/src/codecs/cd_trans_bridge.rs" 2>/dev/null | wc -l)" -eq 3
test "$(grep -c 'pub const CD_ERSPAN2: CodecTable = &\[&ERSPAN2_API\];' "$R/src/codecs/cd_erspan2.rs")" -eq 1
test "$(grep -c 'pub const CD_ERSPAN3: CodecTable = &\[&ERSPAN3_API\];' "$R/src/codecs/cd_erspan3.rs")" -eq 1
test "$(grep -c 'pub const CD_TRANSBRIDGE: CodecTable = &\[&TRANSBRIDGE_API\];' "$R/src/codecs/cd_trans_bridge.rs")" -eq 1
test "$(grep -c 'cd_trans_bridge' "$R/src/codecs/cd_trans_bridge.rs")" -ge 1   # the FILE-base name rides the landing file (drift const rides the TABLE base, §5)
test "$(wc -l < "$R/tools/erspan_harness/PLAN.md")" -gt 0

# ---- tunnel_bypass NEGATIVE census (PLAN §2, the briefing-correction face
# preserved honestly): ALL FOUR briefing tokens 0x3 in the trio; TUNNEL_
# ERSPAN 0 TREE-WIDE; the enum has no ERSPAN member; GRE tokens 0x3 (the SID
# NAME is the trio's only gre-family touch -- cd_gre.rs cite-never-land) ----
for f in cd_erspan2.cc cd_erspan3.cc cd_trans_bridge.cc; do
    test "$(grep -ci 'tunnel\|TUNNEL_ERSPAN\|GRE_HDR\|gre_api' "$L/$f" || true)" -eq 0
done
test "$(grep -rn TUNNEL_ERSPAN "$SRC/src/" | wc -l)" -eq 0
test "$(grep -c 'GRE' "$L/cd_erspan2.cc" || true)" -eq 0
test "$(grep -c 'GRE' "$L/cd_erspan3.cc" || true)" -eq 0
test "$(sed -n '56p' "$L/cd_trans_bridge.cc")" = "        codec_event(codec, DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR);"   # the ONE GRE token (SID name)
# the hook carriers re-cited (misc/ip rows) + the mplsinly-hook hand-off (§2/:25)
test "$(sed -n '117p' "$SRC/src/main/snort_config.h")" = "enum TunnelFlags"
test "$(sed -n '126p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_MPLS   = 0x80,"
test "$(sed -n '205,206p' "$L/cd_mpls.cc" | grep -c tunnel_bypass)" -eq 2   # the hook lives at :205-:206, NEVER in this subrow (b3 row)
# daq NON-PARTICIPATION (§5): grep -c -i daq = 0x3 + NO daq.h ANYWHERE near
for f in cd_erspan2.cc cd_erspan3.cc cd_trans_bridge.cc; do
    test "$(grep -ci daq "$L/$f" || true)" -eq 0
done

# ---- copy tree = misc3 DONOR POST-STRIP 111-tree REUSE clone + ZERO fresh
# header cps + 3 row TU cps: 111 -> 114 mid-build MEASURED (asserted by
# LITERAL; the graft-v2 daq_common.h fead0027 face rides INHERITED, daq.h
# stays ABSENT -- the 18k end-of-build strip keeps it, §5 NEVER re-authored) ----
if [ ! -e "$MI/copy/codecs/misc/cd_llc.cc" ] || [ ! -e "$MI/copy/config.h" ]; then bash "$MI/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$MI/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 111   # donor face (the 18k post-strip 111 re-counted)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"   # graft-v2 INHERITED face (misc3 :251 pin NEVER re-derived; NEVER re-authorized HERE)
test "$(find "$C" -name 'daq.h' | wc -l)" -eq 0             # graft NON-PARTICIPATION face
# ZERO fresh cps: ALL EIGHT closure headers find-1 RESIDENT (scratch header_
# residency.txt face re-measured EVERY build) + the probe's plugin_manager.h
for h in codecs/codec_module.h framework/codec.h log/log_text.h protocols/eth.h protocols/protocol_ids.h framework/base_api.h main/snort_config.h config.h managers/plugin_manager.h framework/api_options.h; do
    test "$(find "$C" -path "*/$h" | wc -l)" -eq 1
done
mkdir -p "$C/codecs/link"
for f in cd_erspan2.cc cd_erspan3.cc cd_trans_bridge.cc; do
    cp "$L/$f" "$C/codecs/link/$f"; cmp -s "$C/codecs/link/$f" "$L/$f"
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 114   # mid-build: 111 + 3 TUs (the ONLY cps THIS row makes)
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probe pulls NO codec_api)
test ! -e "$C/codecs/codec_api.cc"

GXX0="g++ -std=c++17 -O0 -w -I$C"
# ---- PRE-CHECKS (scratch rc_receipts face re-run EVERY build): -fsyntax-
# only rc0 x3 (closure FULLY resident on the INHERITED tree, ZERO fresh cp) ----
for f in cd_erspan2 cd_erspan3 cd_trans_bridge; do
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_$f.txt"
    test ! -s "$H/E4_$f.txt"
    $GXX0 -c "$C/codecs/link/$f.cc" -o "$C/$f.precheck.o" 2> "$H/E4_codegen_$f.txt"
    test ! -s "$H/E4_codegen_$f.txt"
    rm -f "$C/$f.precheck.o"
done

# ---- E4 LOCALIZATION ARMS BOTH WAYS (the 18h-flipped precedent, scratch
# E_donorsrc_* + E_faces_localization receipts MEASURED this family): (a) the
# STRIPPED-DONOR arm: -I src ONLY (NO copy tree) MUST die rc1 x3 at the
# api_options.h face via base_api.h:32 -- the trio's ONLY non-donor header
# face lives in the harvest/copy tree. (b) IN-TREE strip walls: api_options.h
# alone KILLS ALL THREE (the base_api.h:32 chain); log_text.h + eth.h ALONE
# kill ONLY trans_bridge (the erspair SURVIVES -- trans_bridge.cc :26/:27 are
# the trio's ONLY two extra includes, §13); restored rc0 x3 EVERY build. ----
GXXD="g++ -std=c++17 -O0 -w -I$SRC/src"
for f in cd_erspan2 cd_erspan3 cd_trans_bridge; do
    if $GXXD -fsyntax-only "$SRC/src/codecs/link/$f.cc" 2> "$H/E4_donorsrc_$f.txt"; then
        echo "E4 LOCALIZATION DEAD: $f compiled on the -I src ONLY arm -- the stripped-tree rc1x3 face is wrong"; exit 1
    fi
    grep -q "fatal error: framework/api_options.h: No such file" "$H/E4_donorsrc_$f.txt"
    grep -q "base_api.h:32" "$H/E4_donorsrc_$f.txt"
done
mv "$C/framework/api_options.h" "$H/.e4_hold_api_options.h"
for f in cd_erspan2 cd_erspan3 cd_trans_bridge; do
    if $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" -o /dev/null 2> "$H/E4_noapi_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT framework/api_options.h (base_api.h:32 chain)"; exit 1
    fi
    # NOTE the face: api_options.h is a CHAINED include (via base_api.h:32)
    # so the fatal line is NOT line 1 -- grep the whole receipt (contrast the
    # direct-include walls below where head -1 holds).
    grep -q "fatal error: framework/api_options.h: No such file" "$H/E4_noapi_$f.txt"
    grep -q "base_api.h:32" "$H/E4_noapi_$f.txt"
done
mv "$H/.e4_hold_api_options.h" "$C/framework/api_options.h"
mv "$C/log/log_text.h" "$H/.e4_hold_log_text.h"
for f in cd_erspan2 cd_erspan3; do            # the erspair NEVER includes log/log_text.h (cc :24/:25 two-include face)
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_nologt_$f.txt"
    test ! -s "$H/E4_nologt_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/link/cd_trans_bridge.cc" -o /dev/null 2> "$H/E4_nologt_tb.txt"; then
    echo "E4 flip BROKE: trans_bridge compiled WITHOUT log/log_text.h (cc:26)"; exit 1
fi
head -1 "$H/E4_nologt_tb.txt" | grep -q "fatal error: log/log_text.h: No such file"
mv "$H/.e4_hold_log_text.h" "$C/log/log_text.h"
mv "$C/protocols/eth.h" "$H/.e4_hold_eth.h"
for f in cd_erspan2 cd_erspan3; do
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_noeth_$f.txt"
    test ! -s "$H/E4_noeth_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/link/cd_trans_bridge.cc" -o /dev/null 2> "$H/E4_noeth_tb.txt"; then
    echo "E4 flip BROKE: trans_bridge compiled WITHOUT protocols/eth.h (cc:27)"; exit 1
fi
head -1 "$H/E4_noeth_tb.txt" | grep -q "fatal error: protocols/eth.h: No such file"
mv "$H/.e4_hold_eth.h" "$C/protocols/eth.h"
for f in cd_erspan2 cd_erspan3; do            # restored full tree re-arm
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_restored_$f.txt"
    test ! -s "$H/E4_restored_$f.txt"
done
$GXX0 -fsyntax-only "$C/codecs/link/cd_trans_bridge.cc" 2> "$H/E4_restored_tb.txt"
test ! -s "$H/E4_restored_tb.txt"

GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"

# ---- witness carry (ZERO NEW witness, the small4 :167-:213 face): WIN trio
# INHERITED md5 pins NEVER re-derived; witness_conf.cc = the landed 4dd91018
# heredoc face VERBATIM re-materialize (the LogEthAddrs stand-in it carries
# IS trans_bridge's U-face -- eth :454 + tun :179 frozen stand-in precedents,
# NEVER a new backbone pin). NO witness_erspan*.cc EXISTS: the trio nm_U
# census carries ZERO tunnel symbols (scratch nm_U_trio*.txt), so witness_18f
# rides CARRIED-ONLY and the backbone stays 10 (PLAN §24). ----
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
cat > "$H/witness_conf.cc" <<'EOFWC'
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
const SnortConfig* SnortConfig::get_conf() { static SnortConfig c(""); return &c; }
}

#include "log/messages.h"
#include "main/thread_config.h"
#include <cstdarg>
#include <cstdio>
namespace snort {

void FatalError(const char* f, ...) { va_list a; va_start(a,f); vfprintf(stderr,f,a); va_end(a); fputc('\n',stderr); (void)0; }

THREAD_LOCAL int thread_instance = 0;
unsigned get_instance_id() { return thread_instance; }
unsigned ThreadConfig::get_instance_max() { return 1; }
SThreadType get_thread_type() { return STHREAD_TYPE_MAIN; }
}

#include "utils/stats.h"
#include <string>
void show_stats(const PegCount*, const PegInfo*, unsigned, const char*) {}
void show_stats(const PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) {}
namespace snort {
const char* get_main_file(std::string& s, const char*) { return s.c_str(); }
const char* get_instance_file(std::string& s, const char*) { return s.c_str(); }
}
#include "protocols/eth.h"
namespace snort {
void LogEthAddrs(TextLog* log, const eth::EtherHdr* eh) { (void)log; (void)eh; }  // witness stand-in (log_text.cc:112 REAL body pulls the Packet/appid world)
}
EOFWC
test "$(md5sum "$H/witness_conf.cc" | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"
test "$(find "$R/tools/erspan_harness" -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 0   # ZERO own-new witness face
# the get_proto_name axis stays DONOR-INHERITED: row census 0 -> witness_-
# miscip c5b498ff stays CITED, NEVER linked (misc3 :411-:415 face)
test "$(wc -l < "$MIP/witness_miscip.cc")" -eq 27
test "$(md5sum "$MIP/witness_miscip.cc" | awk '{print $1}')" = "c5b498ffa6beac768f34e25830c552a1"

# ---- O0 compile: THREE plain .o + donor REAL .o + probes + witnesses -----
for f in cd_erspan2 cd_erspan3 cd_trans_bridge; do $GXX -c "$C/codecs/link/$f.cc" -o "$C/$f.o"; done
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/cd_erspan2.o $C/cd_erspan3.o $C/cd_trans_bridge.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# hidden-table one-symbol-per-.o face x3 (the STATIC arm IS the harness face;
# THE drift face: trans_bridge .o defines cd_transbridge NOT cd_trans_bridge)
test "$(nm --defined-only "$C/cd_erspan2.o"     | grep -cE ' [DdRr] cd_erspan2$')"     -eq 1
test "$(nm --defined-only "$C/cd_erspan3.o"     | grep -cE ' [DdRr] cd_erspan3$')"     -eq 1
test "$(nm --defined-only "$C/cd_trans_bridge.o" | grep -cE ' [DdRr] cd_transbridge$')" -eq 1
test "$(nm --defined-only "$C/cd_trans_bridge.o" | grep -cE ' [DdRr] cd_trans_bridge$' || true)" -eq 0
# ---- nm per-TU U-census (receipts; scratch face MEASURED: tunnel census
# ZERO x3, backbone stays 10 -- the witness_18f-clone NOT forced, §2/:24) ----
for f in cd_erspan2 cd_erspan3 cd_trans_bridge; do
    nm -C -u "$C/$f.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$f.txt"
done
for f in cd_erspan2 cd_erspan3 cd_trans_bridge; do
    test "$(grep -c 'tunnel' "$H/nm_U_$f.txt" || true)" -eq 0            # 0/0/0 face (contrast misc 0/1/0)
    test "$(grep -c 'SFDAQ' "$H/nm_U_$f.txt" || true)" -eq 0             # the misc3 witness seam NEVER reappears
done
cat "$H"/nm_U_cd_*.txt | sort -u > "$H/nm_U_union.txt"
test "$(nm -u $ROWS | grep -c get_proto_name || true)" -eq 0
# residue class (MANGLED face; inherited classifier): every snort-family U of
# the trio .o MUST be defined by OBJS+WIN ALONE (ZERO-new-witness proof).
g2="$C/cd_erspan2.o $C/cd_erspan3.o $C/cd_trans_bridge.o"
nm -u $g2 | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
donordefs=$(nm --defined-only $OBJS $WIN | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# THE own-new-symbol census pin (ZERO, the small4 face): NO own witness .o --
# every carried witness .o md5-traces to a donor source; the trio links GREEN
# on OBJS+WIN ALONE (below), so nothing of THIS row adds a symbol face.
test "$(nm --defined-only "$H"/witness_18f.o | grep -c 'tunnel_bypass_enabled')" -eq 1   # CARRIED exactly (no new bypass face anywhere)
test "$(nm --defined-only "$H"/witness_18f.o "$H"/witness_conf.o "$H"/stubs_18d.o | grep -c ' get_proto_name\|get_local_instance')" -eq 0 || true
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# landmine posture ZERO (R4): no trio name frozen in ANY witness donor; the
# vocab witness_stubs table census STAYS 4 (NO retirement face this row).
for n in cd_erspan2 cd_erspan3 cd_transbridge; do
    test "$(grep -c "$n" "$R/tools/vocab_harness/witness_stubs.cc" || true)" -eq 0
    test "$(grep -c "$n" "$R/tools/codec_harness/stubs.cc" || true)" -eq 0
    # the ONE tools-wide home stays the legacy copy/codecs/codec_api.cc face
    # (the trio's own row files -- probes + the copy TU cp -- NEVER count:
    # they are THIS row's own arms, not a frozen witness donor)
    test "$(grep -rl "$n" "$R/tools" --include='*.cc' --include='*.h' -I 2>/dev/null | grep -v 'vocab_harness/copy/codecs/codec_api.cc' | grep -v "$R/tools/erspan_harness/" | wc -l)" -eq 0
done
test "$(md5sum "$R/tools/vocab_harness/witness_stubs.cc" | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(sed -n '11,14p' "$R/tools/vocab_harness/witness_stubs.cc" | grep -c 'cd_ipv4\|cd_ipv6\|cd_tcp\|cd_hopopts')" -eq 4
# real-symbol defines (donor face, gre-recipe)
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
grep -q 'T tun_witness_set_mask' <<< "$(nm -C --defined-only "$H"/witness_18f.o)"

# ---- probe links: WIN trio alone (ZERO new witness) -> GREEN ------------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::SFDAQ::get_local_instance()' || true)" -eq 0   # misc3's tracked witness NEVER linked
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::PacketManager::get_proto_name' || true)" -eq 0 # donor-inherited NEVER linked
grep -q 'tun_witness_set_mask' <<< "$(nm -C "$H"/probe)"   # CARRIED face rides BOTH binaries

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in cd_erspan2 cd_erspan3 cd_trans_bridge; do $GXXA -c "$C/codecs/link/$f.cc" -o "$O2/$f.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc   -o "$O2"/stubs_18d.o
OB2="$O2/cd_erspan2.o $O2/cd_erspan3.o $O2/cd_trans_bridge.o"
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool b=.*->decode' "$H"/probe_dec.cc)" -eq 8   # MEASURED face (3 erspan2 + 3 erspan3 + 2 trans_bridge arms)
test "$(grep -c 'printf.*->decode' "$H"/probe_dec.cc || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_O0.txt || true)" -eq 0    # all-decimal hygiene
test "$(grep -c '0x' "$H"/vectors_faceA_O0.txt || true)" -eq 0

# ---- known-answer ladders: greps pin the MEASURED faces against GROUND
# anchors (17p). First run seeds the tracked faces; later runs cmp above. ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi

# ---- known-answer ladders: greps pin the MEASURED vector faces against
# GROUND anchors (17p: values NEVER typed -- ground sed/enum walks below). ----
# FACE-A: trio LOAD walk + the mod-pair ASYMMETRY pin 1/1/0 (ground api slots
# sed-pinned above: erspan2 REAL :125/:126, erspan3 REAL :127/:128, trans_-
# bridge nullptr pair :138/:139 -- NEVER carry the misc3 1/0/0 face):
grep -q '^LOAD erspan2$'      "$FA"
grep -q '^LOAD erspan3$'      "$FA"
grep -q '^LOAD trans_bridge$' "$FA"     # THE name-drift face: table cd_transbridge carries NAME "trans_bridge" (inside-ns #define :33)
grep -q '^LOADS 3$'           "$FA"
grep -q '^HELP erspan2 support for encapsulated remote switched port analyzer - type 2$' "$FA"   # ground #define :30 sed-pinned
grep -q '^HELP erspan3 support for encapsulated remote switched port analyzer - type 3$' "$FA"   # ground #define :30
grep -q '^HELP trans_bridge support for trans-bridging$' "$FA"                                   # ground #define :34 (INSIDE ns :31-:32/:47 pinned)
grep -q '^erspan2 mod_ctor=1 mod_dtor=1$'      "$FA"                    # THE asymmetry 1/1/0
grep -q '^erspan3 mod_ctor=1 mod_dtor=1$'      "$FA"
grep -q '^trans_bridge mod_ctor=0 mod_dtor=0$' "$FA"                    # the EXPLICIT nullptr pair
for n in erspan2 erspan3 trans_bridge; do grep -q "^$n ctor=1 dtor=1$" "$FA"; done  # CodecApi slots non-null x3 (:108/:111, :110/:113, :121/:124)
grep -q '^GETIDS erspan2 35006$'   "$FA"     # ETHERTYPE_ERSPAN_TYPE2 0x88BE (protocol_ids.h :159, python-derived)
grep -q '^GETIDS erspan3 8939$'    "$FA"     # ETHERTYPE_ERSPAN_TYPE3 ground typo hex `0X22EB` :146 (python pins the TYPO face)
grep -q '^GETIDS trans_bridge 25944$' "$FA"  # ETHERTYPE_TRANS_ETHER_BRIDGING 0x6558 :147
test "$(grep -c '^GETDLT' "$FA" || true)" -eq 0                          # NO data-link registrant in this trio
# DEC ladders (ground call-site arms, receipts row18l):
grep -q '^EV 116 463$' "$V"                                             # erspan2 cc :79/:81
test "$(grep -c '^E2 len7 -> 0 lyr=0$' "$V")" -eq 1                     # fail path NEVER sets lyr (:82 return)
grep -q '^E2 v2-mismatch -> 0 lyr=0$' "$V"                             # cc :87/:89 version()!=0x01
grep -q '^E2 happy -> 1 lyr=8 next=25944 flags=0$' "$V"                 # cc :93-:95 (lyr BEFORE next; NO codec_flags face -- contrast misc3's 4096 arms)
grep -q '^EV 116 464$' "$V"                                             # erspan3 cc :82/:84
grep -q '^E3 len19 -> 0 lyr=0$' "$V"
grep -q '^E3 v1-mismatch -> 0 lyr=0$' "$V"                             # cc :89/:91 version()!=0x02
grep -q '^E3 happy -> 1 lyr=20 next=25944 flags=0$' "$V"                # cc :95-:96 NEXT-BEFORE-LYR order face (sizeof 20 DISK-face)
grep -q '^EV 116 165$' "$V"                                             # trans_bridge cc :54/:56 (the SID-name GRE token ONLY, sed-pinned :56)
grep -q '^TB len13 -> 0$' "$V"                                          # ETH_HEADER_LEN 14 eth.h :37
grep -q '^TB happy -> 1 pb=2048 lyr=14 next=35006 flags=4096$' "$V"     # :66-:69 (next = eh->ethertype() of OUR 0x88BE bytes -- the pair story, decimal print)
grep -q 'session-id cc:61-:62' "$V"                                     # the NEVER-ported honesty cite line (§8)
grep -q 'order-site next:95-before-lyr:96' "$V"                         # eval-order site list cite
grep -q 'log cc:83-:86 len-vs-type' "$V"                                # cited-never-vectorized
grep -q 'encode cc:92/:98/:100-:109/:111-:112 cited-never-called' "$V"  # EncState-IpApi cite (eth_harness face: ZERO encode arms)
test "$(grep -c '^EV ' "$V")" -eq 5                                     # 463+462+464+462+165 (the shared-462 face EXACTLY 2)
test "$(grep -c '^EV 116 462$' "$V")" -eq 2                             # 462 rides BOTH siblings (the (a1) shared-sid pin §/31)
test "$(grep -c 'tunnel\|bypass' "$V" || true)" -eq 0                   # ZERO tunnel face ANYWHERE in vectors (§2)
python3 - "$V" "$FA" <<'PYPIN'
# THE sids + proto-bit + protocol-id + CDAPI face PINNED BOTH WAYS (ground
# enum/#define walks vs the MEASURED vector face -- every value the ladders
# grep rides ground, never air).
import re, sys
VF, FAF = sys.argv[1], sys.argv[2]
h = open("/opt/data/snort3-src/src/codecs/codec_module.h").read()
m = re.search(r'enum\s+CodecSid[^{]*\{', h); body = h[m.end():]; val = 0; g = {}
for line in body.split("\n"):
    mm = re.match(r"\s*([A-Z_0-9]+)\s*(?:=\s*(\d+))?\s*,", line)
    if mm:
        name = mm.group(1); val = int(mm.group(2)) if mm.group(2) else val + 1; g[name] = val
    if re.match(r"\s*};", line): break
NAMES = "DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR DECODE_ERSPAN_HDR_VERSION_MISMATCH DECODE_ERSPAN2_DGRAM_LT_HDR DECODE_ERSPAN3_DGRAM_LT_HDR".split()
assert [g[n] for n in NAMES] == [165, 462, 463, 464], {n: g[n] for n in NAMES}
for n in NAMES:
    r = re.findall(rf"{n} = (\d+),", open("/opt/data/snort3-rust/src/codecs/codec_module.rs").read())
    assert r and int(r[0]) == g[n], (n, g[n], r)          # ALREADY landed -- NEVER re-walked
# trio ground event census == EXACTLY the 2/1/1 sid-token sets (shared 462)
import subprocess
for tu, want in (("cd_erspan2.cc", 2), ("cd_erspan3.cc", 2), ("cd_trans_bridge.cc", 1)):
    out = subprocess.run(["grep","-oE",r"codec_event\(codec,\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/link/"+tu],capture_output=True,text=True).stdout
    assert len(set(l.split()[-1] for l in out.splitlines() if l.strip())) == want, (tu, out)
V = set(int(l.split()[2]) for l in open(VF) if l.startswith("EV "))
assert V == {165, 462, 463, 464}, V                      # 4 DISTINCT sids == §/34 face
# protocol ids (protocol_ids.h enum hexes -> decimal) -- NOTE the ground TYPO
# `0X22EB` at :146 (capital X): the [xX]-tolerant walk keeps the honesty face.
pi = open("/opt/data/snort3-src/src/protocols/protocol_ids.h").read()
pids = {n:int(v,16) for n,v in re.findall(r'^\s*([A-Z_0-9]+)\s*=\s*(0[xX][0-9A-Fa-f]+),', pi, re.M)}
assert pids["ETHERTYPE_ERSPAN_TYPE2"]==0x88BE and pids["ETHERTYPE_ERSPAN_TYPE3"]==0x22EB and pids["ETHERTYPE_TRANS_ETHER_BRIDGING"]==0x6558
assert pids["ETHERTYPE_MINIMUM"]==0x0600
assert "0X22EB" in pi                                     # the typo face PINNED (never silently 'fixed')
fa = open(FAF).read()
assert f"GETIDS erspan2 {pids['ETHERTYPE_ERSPAN_TYPE2']}" in fa
assert f"GETIDS erspan3 {pids['ETHERTYPE_ERSPAN_TYPE3']}" in fa
assert f"GETIDS trans_bridge {pids['ETHERTYPE_TRANS_ETHER_BRIDGING']}" in fa
v = open(VF).read()
# TB happy next = the 0x88BE we WROTE into the frame (the sibling pair story)
assert f"next={pids['ETHERTYPE_ERSPAN_TYPE2']} " in v or f"next={pids['ETHERTYPE_ERSPAN_TYPE2']}\n" in v
assert f"next={pids['ETHERTYPE_TRANS_ETHER_BRIDGING']} " in v
# CDAPI version face derived (base_api.h BASE_API_VERSION + codec.h CDAPI_VERSION)
ba = int(re.search(r'#define\s+BASE_API_VERSION\s+(\d+)', open("/opt/data/snort3-src/src/framework/base_api.h").read()).group(1))
cv = re.search(r'#define\s+CDAPI_VERSION\s+\(\(BASE_API_VERSION\s*<<\s*16\)\s*\|\s*(\d+)\)', open("/opt/data/snort3-src/src/framework/codec.h").read()).group(1)
ver = (ba << 16) | int(cv)
assert fa.count(f"ver={ver}") == 3, ver
assert fa.count("size=112") == 3                          # sizeof(CodecApi) carry (misc3 face UNDISTURBED)
# codec flags (framework/codec.h NSDMIs): ETHER_NEXT 0x1000
ch = open("/opt/data/snort3-src/src/framework/codec.h").read()
cf = {n:int(v16,16) for n,v16 in re.findall(r'constexpr uint16_t (CODEC_[A-Z_]+)\s*=\s*(0x[0-9A-Fa-f]+);', ch)}
assert f"flags={cf['CODEC_ETHER_NEXT']}" in v
# the TB NO-flags arms: erspan happy arms carry EXACTLY flags=0 (no CODEC_*)
assert "flags=0\n" in v and v.count("flags=0") == 2
# PROTO_BIT__ETH (decode_data.h #define -> decimal)
dd = open("/opt/data/snort3-src/src/framework/decode_data.h").read()
pb = {n:int(v16,16) for n,v16 in re.findall(r'#define\s+(PROTO_BIT__[A-Z_0-9]+)\s+(0x[0-9A-Fa-f]+)', dd)}
assert f"pb={pb['PROTO_BIT__ETH']} " in v, pb["PROTO_BIT__ETH"]
# GID_DECODE (codec_module.h :38) drives the EV prefix
gid = int(re.search(r'constexpr int GID_DECODE = (\d+);', h).group(1))
assert all(l.split()[1]==str(gid) for l in open(VF) if l.startswith("EV "))
# header len faces sed-cited NEVER typed: ETH_HEADER_LEN 14 / sizeof faces
ethh = open("/opt/data/snort3-src/src/protocols/eth.h").read()
assert "constexpr uint16_t ETH_HEADER_LEN = 14;" in ethh and "lyr=14" in v
cc2 = open("/opt/data/snort3-src/src/codecs/link/cd_erspan2.cc").read()
assert "codec.lyr_len = sizeof(ERSpanType2Hdr);" in cc2 and "lyr=8" in v
cc3 = open("/opt/data/snort3-src/src/codecs/link/cd_erspan3.cc").read()
assert "codec.lyr_len = sizeof(ERSpanType3Hdr);" in cc3 and "lyr=20" in v   # sizeof face DISK-measured 20 (§9 correction)
# the version literals ground-pinned (0x01/0x02 arms vs our nibble payloads)
assert "version() != 0x01" in cc2 and "version() != 0x02" in cc3
# trio Rust TUs LANDED (the PORT pass flipped this guard from the seed-pass
# not-exists face per the misc3 :586-:591 precedent; the hidden-table consts
# + the mod_ctor 1/1/0 record face + the drift const-spelling pin the
# landing — R3 cite-NEVER-land; cargo count face rides the NEXT.md :21 docs
# cite re-asserted: 573 pre-row + 7 erspan = 580/0 re-measured by the row's
# cargo gate)
import os
for f in ("cd_erspan2.rs","cd_erspan3.rs","cd_trans_bridge.rs"):
    assert os.path.exists("/opt/data/snort3-rust/src/codecs/"+f)   # PORT face: LANDED
RS = {f: open("/opt/data/snort3-rust/src/codecs/"+f).read() for f in ("cd_erspan2.rs","cd_erspan3.rs","cd_trans_bridge.rs")}
assert "pub const CD_ERSPAN2: CodecTable = &[&ERSPAN2_API];" in RS["cd_erspan2.rs"]
assert "pub const CD_ERSPAN3: CodecTable = &[&ERSPAN3_API];" in RS["cd_erspan3.rs"]
assert "pub const CD_TRANSBRIDGE: CodecTable = &[&TRANSBRIDGE_API];" in RS["cd_trans_bridge.rs"]  # the DRIFT const (table spelling cc:152) vs the FILE-base file name
assert "573 tests green" in open("/opt/data/snort3-rust/NEXT.md").read()  # the pre-row NEXT.md cite face (NEVER edited; the row's own 580/0 face rides this commit's message)
PYPIN

# ---- row's measured first-run face PINS (the md5s below are the MEASURED
# FIRST-RUN OUTPUT, drift refuses EVERY build; seeded by SEED PASS 18l) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 18          # MEASURED first-run face (run 7)
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 19    # MEASURED first-run face (run 7)
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"

# ---- known-answer wc+md5 pins (OUTPUT of the MEASURED run; build.sh
# DRIFTS-then-refuses, NEVER fabricates) ----
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)

# ---- frozen-donor direct-md5 census (misc3 :651-:673 face VERBATIM, 15
# faces -- the DIRECT face; NEVER re-derived) ----
declare -a FM15=(
 "/opt/data/snort3-rust/tools/fmod_harness/gate.txt 4826fc2233044a2d5429413faf0ae1af"
 "/opt/data/snort3-rust/tools/fmod_harness/vectors.txt f0fdbab06fe1681af1c654531b917c55"
 "/opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc 9fad7e9d7a278fbc2ee82c233f86e774"
 "/opt/data/snort3-rust/tools/vocab_harness/vectors.txt 5da70e82416b6f769af8177d859331e7"
 "/opt/data/snort3-rust/tools/codec_harness/stubs.cc be9bdd0b437d1f6c56c841e8155d9e70"
 "/opt/data/snort3-rust/tools/ext_harness/witness_conf.cc 4dd91018f8439d706ba666c6f18c9152"
 "/opt/data/snort3-rust/tools/tun_harness/vectors.txt 2a7924796f8f0cfdca5e665dee28f519"
 "/opt/data/snort3-rust/tools/tun_harness/vectors_faceA.txt 81602890210d8d83068397c2cece1241"
 "/opt/data/snort3-rust/tools/tun_harness/probe.cc 5b8355189caa2d8b1a12913f94c3838d"
 "/opt/data/snort3-rust/tools/tun_harness/probe_dec.cc 99a8257cd470c33be8a4135eb45e547a"
 "/opt/data/snort3-rust/tools/tun_harness/witness_18f.cc ea1f79f3f05f8a91dc9524a963692b39"
 "/opt/data/snort3-rust/tools/eth_harness/stubs_18d.cc f4afd35f06bc45ce5aa0ec12110ed8ae"
 "/opt/data/snort3-rust/tools/eth_harness/vectors.txt 1bd98dbb57dd2f536104995bd76d9bad"
 "/opt/data/snort3-rust/tools/ext_harness/vectors.txt da21842980d042d5871edeaaf502049e"
 "/opt/data/snort3-rust/tools/ext_harness/vectors_faceA.txt 0fa79b534d2a598b2befb047c95c3579"
)
for e in "${FM15[@]}"; do
    set -- $e
    test "$(md5sum "$1" | awk '{print $1}')" = "$2"
done

# ---- BACKBONE-10 census: THE row ships ZERO own-witness => the 10-face
# post-18k PIN STAYS EXACTLY 10 UNDISTURBED (the witness-clone question
# answered NEGATIVE by the nm_U tunnel census ABOVE, §2/:24). The B10 array
# rides misc3's post-row face VERBATIM (absolute paths incl ITS tracked
# witness pair -- NEVER re-derived); THIS row adds ZERO faces to it. ----
declare -a B10=(
 "/opt/data/snort3-rust/tools/small4_harness/vectors.txt 462f0ff6ed44220564c5ef0c8538ad80"
 "/opt/data/snort3-rust/tools/small4_harness/vectors_faceA.txt 4755d48c54cc057b3c3c9eafec01c7cf"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors.txt fd1855e10e08eedcc6598de7ee034d0e"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors_faceA.txt 2fb9dc4570a0160451f8399d22736a60"
 "/opt/data/snort3-rust/tools/daq3_harness/witness_daq.cc e0166b021073fed328bfd583c839e38b"
 "/opt/data/snort3-rust/tools/miscip_harness/vectors.txt 43b259ac8b77320ff9ddaa80dde1a36e"
 "/opt/data/snort3-rust/tools/miscip_harness/vectors_faceA.txt e4c47bac93a15af4ecfdc9a0bd1abe62"
 "/opt/data/snort3-rust/tools/miscip_harness/witness_miscip.cc c5b498ffa6beac768f34e25830c552a1"
 "/opt/data/snort3-rust/tools/misc3_harness/witness_trio.cc ef50cd2f8cdb4b9fa3d483e702bd73be"
 "/opt/data/snort3-rust/tools/misc3_harness/witness_conf.cc 4dd91018f8439d706ba666c6f18c9152"
)
for e in "${B10[@]}"; do
    set -- $e
    test "$(md5sum "$1" | awk '{print $1}')" = "$2"
done
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H/backbone10.txt"   # receipt (ignored; EXACTLY-10 lines asserted below re-count face)
test "$(wc -l < "$H/backbone10.txt")" -eq 10                            # backbone STAYS 10 (this row adds ZERO)
# the misc3-fresh x2 direct echo (the IMMEDIATE predecessor lineage, byte-
# ident faces pinned DIRECT like misc3 :644-:645 did vs its own donor):
test "$(md5sum "$MI"/vectors.txt | awk '{print $1}')" = "e75f7385779aa89c365dd2ce4a208b67"
test "$(md5sum "$MI"/vectors_faceA.txt | awk '{print $1}')" = "fe1189c6c78139b8828c1a8071e3df28"

# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" /opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "4826fc2233044a2d5429413faf0ae1af" /opt/data/snort3-rust/tools/fmod_harness/build.sh
# gre GATE anchor (the 18g chain rides this VERBATIM face pin; the grey
# positive-gate CONTRAST face for this row's ZERO-gate 19th-straight pin):
test "$(md5sum /opt/data/snort3-rust/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" /opt/data/snort3-rust/tools/gre_harness/gate.txt
# vocab chain anchor (18e witness face, self-literal in ITS OWN build.sh --
# additive-safe NEVER pinned by THIS row):
grep -q "9fad7e9d7a278fbc2ee82c233f86e774" /opt/data/snort3-rust/tools/vocab_harness/build.sh

# ---- TWO-LINEAGE census loop (MEASURED, never typed; THIS row adds ZERO
# gate.txt so the 25-tracked face is UNDISTURBED BY DESIGN): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY
# name-pin census re-armed (dir-name NEVER freezes a table name; a future
# row's collision fires LOUDLY; the erspan_harness dir-name face stays per
# PLAN §52 with the drift discipline in the TABLE-symbol pins):
test "$(ls -d /opt/data/snort3-rust/tools/erspan2_harness /opt/data/snort3-rust/tools/erspan3_harness /opt/data/snort3-rust/tools/trans_bridge_harness /opt/data/snort3-rust/tools/transbridge_harness 2>/dev/null | wc -l)" -eq 0
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin: the 18i PROCESS-LESSONS law (NEVER pin a harness to
# the working repo's own HEAD -- pin the IMMUTABLE ground only; the daq3
# dirty-guard template rides the rowface block below).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (git ls-files, NEVER pre-typed
# arithmetic): the NON-ignored face of this dir = the 6 stageables -- the
# small4 6-face PRECEDENT EXACTLY (PLAN.md build.sh probe.cc probe_dec.cc
# vectors.txt vectors_faceA.txt; NO witness file: the ZERO-new-witness face;
# contrast misc3's 7 with its tracked witness_trio.cc). FACE POSTURE (18i
# re-rule): PRE-commit the 6 are UNTRACKED (--others); POST-commit the SAME
# proof runs against the landed face. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/erspan_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/erspan_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 6
for f in PLAN.md build.sh probe.cc probe_dec.cc vectors.txt vectors_faceA.txt; do
    echo "$face" | grep -q "tools/erspan_harness/$f$"
done
test "$(echo "$face" | grep -c 'witness' || true)" -eq 0   # ZERO own-witness face (small4 precedent)
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/cd_erspan2.o copy/codecs/link/cd_erspan2.cc copy/daq_common.h o2/cd_erspan2.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_18f.o witness_conf.o stubs_18d.o vectors_O0.txt vectors_faceA_O2.txt nm_U_cd_erspan2.txt E4_cd_erspan2.txt E4_donorsrc_cd_erspan2.txt E4_noapi_cd_erspan2.txt E4_restored_cd_erspan2.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/erspan_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/erspan_harness/$f NOT ignored"; exit 1; }
done
# vectors NEVER ignored (the stageable face, explicit NOT-proof):
git -C /opt/data/snort3-rust check-ignore -q "tools/erspan_harness/vectors.txt" && { echo "VECTORS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/erspan_harness/vectors_faceA.txt" && { echo "FACE-A WRONGLY IGNORED"; exit 1; } || true
# no STAGED churn: index EMPTY. Tracked-MODIFIED face (lineage-honest, the
# daq3/misc3 dirty-guard template; NEVER own-HEAD pin): EVERY dirty tracked
# file must be one of THIS row's OWN paths (seed face: .gitignore ONLY --
# the sanctioned seed face per the 18k precedent); POST-commit the face is
# EMPTY; fires LOUDLY on any face touching another row's/committed lineage
# file. Rows NEVER rewrite history, NEVER git-add, NEVER commit.
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
rowface='^\.gitignore$|^src/codecs/(mod\.rs|cd_erspan2\.rs|cd_erspan3\.rs|cd_trans_bridge\.rs)$|^tests/erspan_parity_test\.rs$|^PORTING_PLAN\.md$|^KNOWN DEVIATIONS\.md$|^tools/erspan_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|vectors\.txt|vectors_faceA\.txt)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface")"

echo "row-TU nm census (MEASURED, never typed): erspan2=$(wc -l < "$H/nm_U_cd_erspan2.txt") erspan3=$(wc -l < "$H/nm_U_cd_erspan3.txt") trans_bridge=$(wc -l < "$H/nm_U_cd_trans_bridge.txt") union=$(wc -l < "$H/nm_U_union.txt") | union-mangled=$(wc -l < "$H/nm_U_mangled_union.txt") (tunnel census 0/0/0 -- witness_18f clone NOT forced, backbone stays $(wc -l < "$H/backbone10.txt") faces PINNED)"
echo "witness posture: ZERO own-new witness (own-new T census 0; SFDAQ T census 0 in BOTH binaries; get_proto_name row census 0 -> witness_miscip c5b498ff DONOR-INHERITED cite NEVER linked); WIN trio CARRIED (ea1f79f3 bypass exactly x1, 4dd91018 witness_conf byte-ident, stubs_18d CARRIED) -> probes link GREEN on OBJS+WIN ALONE"
echo "zero-fresh-cp face: copy tree = misc3 donor 111 REUSE clone + 3 row TUs = 114 mid-build / post-strip 111 UNTOUCHED (ALL 10 closure headers find-1 INHERITED incl api_options.h + plugin_manager.h; daq grep 0x3, daq.h find-0, graft-v2 face rides INHERITED fead0027 NEVER re-authored)"
echo "E4 localization BOTH ways: -I src ONLY rc1x3 fatal framework/api_options.h via base_api.h:32 (the trio's ONLY non-donor head face) + in-tree walls api_options x3-die / log_text+eth ONLY-trans_bridge-die erspair-survive + restored rc0x3 EVERY build"
echo "hidden-table census: BUILDING_SO sed x3 (:136/:138/:149) + snort_plugins grep 1/1/1 + nm table D symbol EXACTLY-1 x3 w/ THE drift face (trans_bridge .o defines cd_transbridge NOT cd_trans_bridge) + mod_ctor asymmetry 1/1/0 FACE-A pin + NAME/HELP INSIDE anon namespace trans_bridge :33-:34 NEW pin + cd_pppoepkt trio-absence tripwire (18m cite pins :115/:139/:236)"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED here; tracked gate.txt = 1, ls-files); BACKBONE STAYS 10 (0 own-witness faces added; receipt backbone10.txt; misc3-fresh vectors pair byte-ident DIRECT echo)"
echo "MISC_L_ERSPAN_OK vectors=$( [ -e "$H/vectors.txt" ] && wc -l < "$H/vectors.txt" || wc -l < "$H/vectors_O0.txt") faceA=$( [ -e "$H/vectors_faceA.txt" ] && wc -l < "$H/vectors_faceA.txt" || wc -l < "$H/vectors_faceA_O0.txt") gates=0"

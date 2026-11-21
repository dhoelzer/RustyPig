#!/usr/bin/env bash
# link6_harness -- row 18m: the codecs/link DRIFT PAIR: codecs/link/
# cd_pppoe.cc 243 L + cd_ppp_encap.cc 174 L = 417 L (PLAN §1 P1 pick; the
# wc_md5_six.txt receipt face: 65109bbd... + 3a254d9e... re-md5 SIX receipt).
# THE DOUBLE-NAME HEADLINE row (PLAN §5): ONE TU cd_pppoe.cc carries TWO
# BaseCodecModule arms -- pppoe_disc NAME :115 + pppoe_sess NAME :139 (sed
# pins) feeding a TWO-entry hidden table cd_pppoepkt[] :236 (feeds :239/:240
# EXACTLY-2, the double-LOAD pin) -- the ONLY double-NAME/double-LOAD face in
# the backlog; the probe's LOAD walk prints TWO lines from ONE table (the
# first such FACE-A face in the port). The second drift name cd_pppencap[]
# :169 rides cd_ppp_encap.cc (file base ppp_encap); the third drift name
# (cd_transbridge) landed 18l -- the docs drift-triple CLOSES in this row.
# THE mod-arm SPLIT across the pair (18l's 1/1/0 NEVER carried): pppoepkt
# BOTH arms REAL (disc_mod_ctor :171 arms :200/:201 + sess_mod_ctor :174 arms
# :222/:223 -- mod_dtor :177 shared) => 1/1 x2; ppp_encap the tail's ONLY
# EXPLICIT nullptr pair :155/:156 (PLAN §5 corrected face; ctor :138/dtor :141
# real) => FACE-A mod_ctor=1/mod_dtor=1/0/0 + ctor=1 dtor=1 x3.
# THE GROUND FAMILY LINK (PLAN §1, disk-not-name): pppoe SESS decode sets
# next_prot_id = ETHERTYPE_PPP at cc :161 (sed pin) and ppp_encap
# get_protocol_ids pushes ETHERTYPE_PPP at cc :52 (sed pin) -- the vectors
# carry the link BOTH sides (PS len6 next == PE GETIDS, python-pinned).
# THE ZERO-fresh-CP row: copy tree = erspan-18l donor REUSE clone VERBATIM
# (non-.o face MEASURED 114 = the 18l 111+3 end-state; the recon PLAN §6
# "113" cite is ONE-DISAGREEMENT on disk -- record honestly, disk wins); + 2
# additive TU cps only => mid-build 116 MEASURED. ALL pair closure headers
# find-1 INHERITED (ZERO fresh cps; PLAN §1 find-1 x3 face pppoe, ZERO face
# ppp_encap). daq.h find-0 + daq grep 0x2 MEASURED (graft NON-PARTICIPATION;
# graft md5 masters daq.h 73fdbc39 / daq_common.h f683749c CITED NEVER cp'd;
# graft-v2 fead0027 rides INHERITED inside the donor, NEVER re-authored).
# THE ZERO-new-WITNESS row (small4/erspan 6-face precedent): nm_U tunnel
# census 0/0 => witness_18f clone NEVER forced; WIN trio INHERITED-CARRIED
# (witness_18f ea1f79f3 T tunnel_bypass_enabled EXACTLY-1 carried face +
# witness_conf 4dd91018 byte-ident + stubs_18d f4afd35f); witness_miscip
# c5b498ff + witness_trio ef50cd2f stay DONOR-INHERITED cites NEVER linked;
# BACKBONE STAYS EXACTLY 10 (B10 array VERBATIM + wc-10 assert EVERY build).
# THE PADT-NEVER-pull row (briefing phrase PADT/SESSION): PADT grep EXACTLY 0
# in BOTH files EVERY build (the ruling: PADT NEVER EXISTS on disk, §5d3); the
# SESSION half TRUE (3 lowercase session tokens cd_pppoe.cc :41/:58/:140
# MEASURED) -- the NEVER-pull rides the negative census assert.
# THE ZERO-gate row (20th straight): link/test find-0 + add_cpputest 0 + the
# pair's OWN CMakeLists face MEASURED 4 (STATIC x2 :10/:11 + dynamic x2
# :22/:23) + CppUTest/TEST STOP-flag grep-0 x2. NO gate.txt shipped.
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness
MI=$R/tools/misc3_harness
MIP=$R/tools/miscip_harness
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
ER=$R/tools/erspan_harness       # THE donor (18l tree) -- REUSE clone, §6
L=$SRC/src/codecs/link
C=$H/copy

# ---- ground identity (the TWO row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [cd_pppoe.cc]=65109bbd2bd8837140568f35bdf98eb5 [cd_ppp_encap.cc]=3a254d9eeb93298d8fc548f84ad6cad0 )
declare -A WC=( [cd_pppoe.cc]=243 [cd_ppp_encap.cc]=174 )
for f in cd_pppoe.cc cd_ppp_encap.cc; do
    test "$(md5sum "$L/$f" | awk '{print $1}')" = "${MD5[$f]}"
    test "$(wc -l < "$L/$f")" -eq "${WC[$f]}"
done
# pair total face (the row's ledger line): 243+174 = 417 SUM measured (recon
# drift-pair 417 L face re-verified EVERY build)
test "$(( $(wc -l < "$L/cd_pppoe.cc") + $(wc -l < "$L/cd_ppp_encap.cc") ))" -eq 417
# six-file chapter ledger (the wc_md5_six.txt face): 390+236+243+235+187+174 =
# 1465 (= nine-file tail 1915 minus landed-18l erspan 450, PLAN §1 cross-check
# MEASURED) + the nine-file tail 1915 face re-pinned (the mpls-390 correction).
test "$(( $(wc -l < "$L/cd_mpls.cc") + $(wc -l < "$L/cd_vlan.cc") + $(wc -l < "$L/cd_pppoe.cc") + $(wc -l < "$L/cd_ciscometadata.cc") + $(wc -l < "$L/cd_fabricpath.cc") + $(wc -l < "$L/cd_ppp_encap.cc") ))" -eq 1465
test "$(wc -l < "$L/cd_mpls.cc")" -eq 390
test "$(( $(wc -l < "$L/cd_mpls.cc") + $(wc -l < "$L/cd_vlan.cc") + $(wc -l < "$L/cd_pppoe.cc") + $(wc -l < "$L/cd_erspan2.cc") + $(wc -l < "$L/cd_erspan3.cc") + $(wc -l < "$L/cd_ciscometadata.cc") + $(wc -l < "$L/cd_fabricpath.cc") + $(wc -l < "$L/cd_trans_bridge.cc") + $(wc -l < "$L/cd_ppp_encap.cc") ))" -eq 1915
# combined gate grep ZERO x2 EVERY build (STOP-flag; if ground ever ships a
# suite naming the pair the row RE-PLANS to the gate shape -- flip trips loud)
for f in cd_pppoe.cc cd_ppp_encap.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST\|CppUTest' "$L/$f" || true)" -eq 0
done

# ---- THE zero-gate census (20th straight, MEASURED EVERY BUILD) ----
test "$(find "$L" -type d -name test | wc -l)" -eq 0
test ! -d "$L/test"
test "$(grep -c 'add_cpputest' "$L/CMakeLists.txt" || true)" -eq 0
test "$(grep -c 'cd_pppoe\|cd_ppp_encap' "$L/CMakeLists.txt")" -eq 4   # pair build-system face MEASURED (STATIC set x2 :10/:11 + add_dynamic_module x2 :22/:23)

# ---- THE hidden tables (BUILDING_SO split) -- sed census PIN lines x2 ----
test "$(sed -n '233p' "$L/cd_pppoe.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '234p' "$L/cd_pppoe.cc")" = "SO_PUBLIC const BaseApi* snort_plugins[] ="
test "$(sed -n '236p' "$L/cd_pppoe.cc")" = "const BaseApi* cd_pppoepkt[] ="   # THE drift name #1 (file base cd_pppoe)
test "$(sed -n '239p' "$L/cd_pppoe.cc")" = "    &pppoepkt_disc_api.base,"      # THE double-LOAD feed #1
test "$(sed -n '240p' "$L/cd_pppoe.cc")" = "    &pppoepkt_sess_api.base,"      # THE double-LOAD feed #2
test "$(sed -n '166p' "$L/cd_ppp_encap.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '169p' "$L/cd_ppp_encap.cc")" = "const BaseApi* cd_pppencap[] =" # THE drift name #2 (file base cd_ppp_encap)
test "$(sed -n '172p' "$L/cd_ppp_encap.cc")" = "    &pppencap_api.base,"
for f in cd_pppoe.cc cd_ppp_encap.cc; do
    test "$(grep -c 'BUILDING_SO'  "$L/$f")" -eq 1
    test "$(grep -c 'snort_plugins' "$L/$f")" -eq 1
done
test "$(grep -c '&pppoepkt_.*_api.base' "$L/cd_pppoe.cc")" -eq 2   # the EXACTLY-2 feed face (double-LOAD pin)

# ---- THE double-NAME macro pins (§5 headline design, NEVER derivable from
# the file base) + namespace ENCLOSURE faces: pppoe NAME/HELP #defines ride
# INSIDE the SECOND anon ns (:113-:114 .. :165); ppp_encap NAME/HELP ride
# OUTSIDE the ns at :29/:30 (ns :32-:33 .. :49) -- the contrast enclosure
# faces BOTH sed-pinned (18l §5 enclosure-law re-pin) ----
test "$(sed -n '115p' "$L/cd_pppoe.cc")" = '#define CD_PPPOEPKT_DISC_NAME "pppoe_disc"'
test "$(sed -n '116p' "$L/cd_pppoe.cc")" = '#define CD_PPPOEPKT_DISC_HELP "support for point-to-point discovery"'
test "$(sed -n '139p' "$L/cd_pppoe.cc")" = '#define CD_PPPOEPKT_SESS_NAME "pppoe_sess"'
test "$(sed -n '140p' "$L/cd_pppoe.cc")" = '#define CD_PPPOEPKT_SESS_HELP "support for point-to-point session"'
test "$(sed -n '113p' "$L/cd_pppoe.cc")" = "namespace"
test "$(sed -n '114p' "$L/cd_pppoe.cc")" = "{"
test "$(sed -n '165p' "$L/cd_pppoe.cc")" = "} // namespace"
test "$(sed -n '29p' "$L/cd_ppp_encap.cc")" = '#define CD_PPPENCAP_NAME "ppp_encap"'
test "$(sed -n '30p' "$L/cd_ppp_encap.cc")" = '#define CD_PPPENCAP_HELP "support for point-to-point encapsulation"'
test "$(sed -n '32p' "$L/cd_ppp_encap.cc")" = "namespace"
test "$(sed -n '33p' "$L/cd_ppp_encap.cc")" = "{"
test "$(sed -n '49p' "$L/cd_ppp_encap.cc")" = "} // namespace"

# ---- TRUE-NAME DRIFT tripwires: the nm face shows the .o defines the TABLE
# name NOT the file base (18l drift-refusal clone x2) + the sibling-TEXT
# refusal: NEITHER file names the other's table (a grep-only family would be
# name-soup; the REAL link is the ETHERTYPE_PPP token below) ----
for f in cd_pppoe.cc cd_ppp_encap.cc; do
    test "$(grep -c 'cd_pppencap' "$L/cd_pppoe.cc" || true)" -eq 0
    test "$(grep -c 'cd_pppoepkt' "$L/cd_ppp_encap.cc" || true)" -eq 0
    test "$(grep -c 'erspan\|trans_bridge\|transbridge' "$L/$f" || true)" -eq 0   # the 18l trio-absence clone (landed-row names NEVER leak into THIS row's TUs)
done
# THE GROUND FAMILY LINK pin (PLAN §1: the pair is a REAL decode-chain family):
test "$(sed -n '161p' "$L/cd_pppoe.cc")" = "    codec.next_prot_id = ProtocolId::ETHERTYPE_PPP;"       # sess decode EMITS the id
test "$(sed -n '52p'  "$L/cd_ppp_encap.cc")" = "{ v.emplace_back(ProtocolId::ETHERTYPE_PPP); }"        # ppp_encap REGISTERS the id

# ---- mod_ctor/mod_dtor face MEASURED ACROSS THE PAIR (18l 1/1/0 NEVER
# carried): pppoepkt BOTH arms REAL; pppencap the tail's ONLY nullptr pair
# :155/:156 (CORRECTED face -- base-struct slots after NAME :153/HELP :154) ----
test "$(sed -n '171p' "$L/cd_pppoe.cc")" = "static Module* disc_mod_ctor()"
test "$(sed -n '174p' "$L/cd_pppoe.cc")" = "static Module* sess_mod_ctor()"
test "$(sed -n '177p' "$L/cd_pppoe.cc")" = "static void mod_dtor(Module* m)"
test "$(sed -n '200p' "$L/cd_pppoe.cc")" = "        disc_mod_ctor,"
test "$(sed -n '201p' "$L/cd_pppoe.cc")" = "        mod_dtor,"
test "$(sed -n '222p' "$L/cd_pppoe.cc")" = "        sess_mod_ctor,"
test "$(sed -n '223p' "$L/cd_pppoe.cc")" = "        mod_dtor,"
test "$(sed -n '155p' "$L/cd_ppp_encap.cc")" = "        nullptr,"    # EXPLICIT nullptr pair (PLAN §5 corrected)
test "$(sed -n '156p' "$L/cd_ppp_encap.cc")" = "        nullptr,"
# CodecApi slots non-null x3 entries (disc_ctor :180 / sess_ctor :183 /
# pppoe_dtor :186 shared; pppencap ctor :138 / dtor :141) -- ctor=1 dtor=1 x3
test "$(sed -n '180p' "$L/cd_pppoe.cc")" = "static Codec* disc_ctor(Module*)"
test "$(sed -n '183p' "$L/cd_pppoe.cc")" = "static Codec* sess_ctor(Module*)"
test "$(sed -n '138p' "$L/cd_ppp_encap.cc")" = "static Codec* ctor(Module*)"

# ---- PADT NEVER-pull negative census (the §5d3 ruling, asserted EVERY
# build) + the SESSION-true half (3 tokens :41 struct field / :58 RuleMap
# text / :140 HELP -- cited-never-ported face in probe_dec) ----
for f in cd_pppoe.cc cd_ppp_encap.cc; do
    test "$(grep -c 'PADT' "$L/$f" || true)" -eq 0
done
test "$(grep -c 'session' "$L/cd_pppoe.cc")" -eq 3
# daq NON-PARTICIPATION (the 18l law re-measured): grep -c -i daq 0x2 + NO
# tunnel face in the pair (the hook stays cd_mpls :205-:206, the b3 row;
# TUNNEL_MPLS 0x80 snort_config.h :126 cites UNDISTURBED)
for f in cd_pppoe.cc cd_ppp_encap.cc; do
    test "$(grep -ci daq "$L/$f" || true)" -eq 0
    test "$(grep -ci 'tunnel\|GRE_HDR\|gre_api' "$L/$f" || true)" -eq 0
    test "$(grep -c 'tunnel_bypass' "$L/$f" || true)" -eq 0   # the hook is cd_mpls :205-:206 ONLY (b3)
done
test "$(sed -n '205,206p' "$L/cd_mpls.cc" | grep -c tunnel_bypass)" -eq 2   # the hook lives there, NEVER here (hand-off cite)
test "$(sed -n '126p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_MPLS   = 0x80,"
# sids: the pair's DECODE_ token census = 4 in pppoe (2 RuleMap :52/:58 + 2
# evt call-sites :132/:156 -- the disk-won 4-vs-5 §5d4 face re-pinned) + ZERO
# codec_event EVER in ppp_encap (:124 default break; the ZERO-event TU face)
test "$(grep -c 'DECODE_' "$L/cd_pppoe.cc")" -eq 4
test "$(grep -c 'codec_event' "$L/cd_ppp_encap.cc" || true)" -eq 0
test "$(grep -c 'codec_event' "$L/cd_pppoe.cc")" -eq 2
test "$(grep -c 'codec_event' "$SRC/src/codecs/link/cd_ppp_encap.cc" || true)" -eq 0

# ---- externs + loads + ladder ALL RESIDENT (rows ADD TUs, NEVER touch) ----
test "$(sed -n '64p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_pppencap[];"
test "$(sed -n '65p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_pppoepkt[];"
test "$(sed -n '109p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_pppencap);"
test "$(sed -n '110p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_pppoepkt);"
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern census UNDISTURBED
# the rust ladder face (rows NEVER re-touch): pair names ALREADY resident
test "$(sed -n '122p' "$R/src/codecs/codec_api.rs")" = '    "cd_pppencap",'
test "$(sed -n '123p' "$R/src/codecs/codec_api.rs")" = '    "cd_pppoepkt",'
test "$(sed -n '97p'  "$R/src/codecs/codec_api.rs")" = 'pub const STATIC_CODEC_EXTERN_NAMES: [&str; 34] = ['

# ---- the 2 sids RESIDENT face (PLAN §4: ZERO new consts): pair loads
# 120/479 both resident codec_module.rs :95/:237, NEVER re-walked; the pair
# rs files LANDED at PORT (seed-pass guard FLIPPED per the misc3 :586-:591
# precedent, exactly like the 18l trio guard flipped at ITS port) ----
test "$(sed -n '95p' "$R/src/codecs/codec_module.rs")" = '    DECODE_BAD_PPPOE_DISC = 120,  // h:78'
test "$(sed -n '237p' "$R/src/codecs/codec_module.rs")" = '    DECODE_BAD_PPPOE_SESS = 479,  // h:232'
test "$(ls "$R/src/codecs/cd_pppoe.rs" "$R/src/codecs/cd_ppp_encap.rs" 2>/dev/null | wc -l)" -eq 2   # LANDED (the PORT-pass flip face)
test "$(grep -c 'pub const CD_PPPOEPKT: CodecTable = &\[&PPPOEPKT_DISC_API, &PPPOEPKT_SESS_API\];' "$R/src/codecs/cd_pppoe.rs")" -eq 1   # the DRIFT const + the DOUBLE feed
test "$(grep -c 'pub const CD_PPPENCAP: CodecTable = &\[&PPPENCAP_API\];' "$R/src/codecs/cd_ppp_encap.rs")" -eq 1   # the drift const (table spelling :169)
test "$(grep -c 'cd_pppoe' "$R/src/codecs/cd_pppoe.rs")" -ge 1         # the FILE-base name rides the landing file (drift const rides the TABLE base, §5)
test "$(grep -c 'cd_ppp_encap' "$R/src/codecs/cd_ppp_encap.rs")" -ge 1 # file base == landing file; drift const CD_PPPENCAP rides the table
# cargo face CITATION (NEXT.md :23 MEASURED lineage face 580 passed / 0
# failed rides the docs cite; THIS row's re-run face 580+link6 / 0 failed
# rides the commit message -- NEXT.md NEVER edited (the PYPIN strings hold)):
grep -q "580 passed / 0 failed" "$R/NEXT.md"

# ---- copy tree = erspan-18l DONOR REUSE clone + ZERO fresh header cps + 2
# row TU cps. DONOR FACE MEASURED 114 non-.o (the 18l end-state 111+3; the
# recon PLAN §6 '113' cite ONE-DISAGREEMENT on disk -- disk wins, recorded in
# §9); mid-build 114+2 = 116 MEASURED. graft-v2 daq_common.h fead0027 rides
# INHERITED (its md5 comes from the donor clone, NEVER re-authored); daq.h
# find-0 (the 18k end-of-strip face kept; ONE-LANDING law daq3 :131-:133,
# graft masters 73fdbc39/f683749c CITED NEVER cp'd HERE) ----
if [ ! -e "$ER/copy/codecs/link/cd_erspan2.cc" ] || [ ! -e "$ER/copy/config.h" ]; then bash "$ER/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$ER/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 114   # donor face MEASURED (recon 113 disagreement face)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"   # graft-v2 INHERITED (misc3 pin; NEVER re-authorized HERE)
test "$(find "$C" -name 'daq.h' | wc -l)" -eq 0             # graft NON-PARTICIPATION face
test "$(md5sum "$D3/copy/daq.h" | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"         # graft master CITE (never cp'd HERE)
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"  # graft v1 master CITE
# ZERO fresh cps: the pair closure + probe headers find-1 RESIDENT (the §1
# include census: pppoe 3 edges / ppp_encap 2 edges incl the NO-codec_module.h
# leanest-include face; ip.h/ipv4.h ride the framework/codec.h closure --
# ppp_encap DRIVES ip::IP4Hdr/IP4_HEADER_LEN at :88/:97 MEASURED rc0) + the
# probe's plugin_manager.h; log_text.h + eth.h find-1 INHERITED but
# NON-PARTICIPANT for this pair (the E4 survival walls BELOW prove it)
for h in codecs/codec_module.h framework/codec.h config.h framework/base_api.h main/snort_config.h managers/plugin_manager.h framework/api_options.h protocols/protocol_ids.h protocols/ip.h protocols/ipv4.h log/log_text.h protocols/eth.h; do
    test "$(find "$C" -path "*/$h" | wc -l)" -eq 1
done
mkdir -p "$C/codecs/link"
for f in cd_pppoe.cc cd_ppp_encap.cc; do
    cp "$L/$f" "$C/codecs/link/$f"; cmp -s "$C/codecs/link/$f" "$L/$f"
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 116   # mid-build: 114 + 2 TUs (the ONLY cps THIS row makes)
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probe pulls NO codec_api)
test ! -e "$C/codecs/codec_api.cc"

GXX0="g++ -std=c++17 -O0 -w -I$C"
# ---- PRE-CHECKS (scratch rc_zeropick face re-run EVERY build): -fsyntax-
# only rc0 x2 (closure FULLY resident on the INHERITED tree, ZERO fresh cp) ----
for f in cd_pppoe cd_ppp_encap; do
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_$f.txt"
    test ! -s "$H/E4_$f.txt"
    $GXX0 -c "$C/codecs/link/$f.cc" -o "$C/$f.precheck.o" 2> "$H/E4_codegen_$f.txt"
    test ! -s "$H/E4_codegen_$f.txt"
    rm -f "$C/$f.precheck.o"
done

# ---- E4 LOCALIZATION ARMS BOTH WAYS (18h precedent; the PAIR-flipped wall
# face): (a) stripped-donor arm -I src ONLY MUST die rc1 x2 at the
# api_options.h face via base_api.h:32 (the scratch E4_donorsrc_cd_* face).
# (b) IN-TREE walls, MEASURED for this pair (contrast 18l: BOTH files pull
# codec.h DIRECT so it kills BOTH; codec_module.h kills ONLY cd_pppoe
# (:25 include face -- ppp_encap's leanest-include face SURVIVES, §1);
# log_text.h + eth.h kill NEITHER (both SURVIVE -- the pair never includes
# them, the non-participant find-1 face); api_options.h CHAINED kills BOTH
# (grep the whole receipt, NOT head-1); restored full tree rc0 x2 EVERY
# build ----
GXXD="g++ -std=c++17 -O0 -w -I$SRC/src"
for f in cd_pppoe cd_ppp_encap; do
    if $GXXD -fsyntax-only "$SRC/src/codecs/link/$f.cc" 2> "$H/E4_donorsrc_$f.txt"; then
        echo "E4 LOCALIZATION DEAD: $f compiled on the -I src ONLY arm -- the stripped-tree rc1x2 face is wrong"; exit 1
    fi
    grep -q "fatal error: framework/api_options.h: No such file" "$H/E4_donorsrc_$f.txt"
    grep -q "base_api.h:32" "$H/E4_donorsrc_$f.txt"
done
mv "$C/codecs/codec_module.h" "$H/.e4_hold_codec_module.h"
if $GXX0 -fsyntax-only "$C/codecs/link/cd_pppoe.cc" -o /dev/null 2> "$H/E4_nocm_cd_pppoe.txt"; then
    echo "E4 flip BROKE: cd_pppoe compiled WITHOUT codecs/codec_module.h (cc:25)"; exit 1
fi
head -1 "$H/E4_nocm_cd_pppoe.txt" | grep -q "fatal error: codecs/codec_module.h: No such file"
$GXX0 -fsyntax-only "$C/codecs/link/cd_ppp_encap.cc" 2> "$H/E4_nocm_cd_ppp_encap.txt"   # the leanest-include face SURVIVES
test ! -s "$H/E4_nocm_cd_ppp_encap.txt"
mv "$H/.e4_hold_codec_module.h" "$C/codecs/codec_module.h"
mv "$C/framework/codec.h" "$H/.e4_hold_codec.h"
for f in cd_pppoe cd_ppp_encap; do
    if $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" -o /dev/null 2> "$H/E4_nofwcd_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT framework/codec.h (cc:26/:25 DIRECT)"; exit 1
    fi
    head -1 "$H/E4_nofwcd_$f.txt" | grep -q "fatal error: framework/codec.h: No such file"
done
mv "$H/.e4_hold_codec.h" "$C/framework/codec.h"
mv "$C/log/log_text.h" "$H/.e4_hold_log_text.h"
mv "$C/protocols/eth.h" "$H/.e4_hold_eth.h"
for f in cd_pppoe cd_ppp_encap; do            # the pair NEVER includes log_text/eth (18l trans_bridge face CONTRAST)
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_noeth_$f.txt"
    test ! -s "$H/E4_noeth_$f.txt"
done
mv "$H/.e4_hold_log_text.h" "$C/log/log_text.h"
mv "$H/.e4_hold_eth.h" "$C/protocols/eth.h"
mv "$C/framework/api_options.h" "$H/.e4_hold_api_options.h"
for f in cd_pppoe cd_ppp_encap; do
    if $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" -o /dev/null 2> "$H/E4_noapi_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT framework/api_options.h (base_api.h:32 chain)"; exit 1
    fi
    grep -q "fatal error: framework/api_options.h: No such file" "$H/E4_noapi_$f.txt"
    grep -q "base_api.h:32" "$H/E4_noapi_$f.txt"
done
mv "$H/.e4_hold_api_options.h" "$C/framework/api_options.h"
for f in cd_pppoe cd_ppp_encap; do            # restored full tree re-arm
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_restored_$f.txt"
    test ! -s "$H/E4_restored_$f.txt"
done

GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"

# ---- witness carry (ZERO NEW witness, the small4/erspan face): WIN trio
# INHERITED md5 pins NEVER re-derived; witness_conf.cc = the landed 4dd91018
# heredoc face VERBATIM re-materialize. NO witness_pppoe*.cc EXISTS: the
# pair nm_U census carries ZERO tunnel symbols (scratch nm_U_cd_*.txt: U-
# lines 22/8 the leanest pair face; tunnel grep 0/0), so witness_18f rides
# CARRIED-ONLY and the backbone stays 10 (PLAN §2). ----
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
test "$(find "$H" -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 0   # ZERO own-new witness face
# the get_proto_name axis stays DONOR-INHERITED: row census 0 -> witness_
# miscip c5b498ff stays CITED, NEVER linked (misc3 :411-:415 face); the
# witness_trio ef50cd2f face rides the B10 array below UNDISTURBED
test "$(wc -l < "$MIP/witness_miscip.cc")" -eq 27
test "$(md5sum "$MIP/witness_miscip.cc" | awk '{print $1}')" = "c5b498ffa6beac768f34e25830c552a1"

# ---- O0 compile: TWO plain .o + donor REAL .o + probes + witnesses ----
for f in cd_pppoe cd_ppp_encap; do $GXX -c "$C/codecs/link/$f.cc" -o "$C/$f.o"; done
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/cd_pppoe.o $C/cd_ppp_encap.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# hidden-table one-symbol-per-.o face x2 + THE DRIFT refusal x2 (the .o
# defines the TABLE name; the FILE-base table symbol face EXACTLY 0)
test "$(nm --defined-only "$C/cd_pppoe.o"     | grep -cE ' [DdRr] cd_pppoepkt$')"  -eq 1
test "$(nm --defined-only "$C/cd_pppoe.o"     | grep -cE ' [DdRr] cd_pppoe$' || true)" -eq 0
test "$(nm --defined-only "$C/cd_ppp_encap.o" | grep -cE ' [DdRr] cd_pppencap$')"  -eq 1
test "$(nm --defined-only "$C/cd_ppp_encap.o" | grep -cE ' [DdRr] cd_ppp_encap$' || true)" -eq 0
# ---- nm per-TU U-census (receipts; scratch nm_U_cd_pppoe=22 /
# nm_U_cd_ppp_encap=8 the leanest pair face MEASURED; tunnel 0/0 =>
# witness_18f clone NOT forced, backbone stays 10, PLAN §2) ----
for f in cd_pppoe cd_ppp_encap; do
    nm -C -u "$C/$f.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$f.txt"
    test "$(wc -l < "$H/nm_U_$f.txt")" -ge 8                       # the 22/8 face lower-bound (drift-safe pin)
done
test "$(wc -l < "$H/nm_U_cd_pppoe.txt")" -eq 22                    # MEASURED face (the leanest pair) re-refused on drift
test "$(wc -l < "$H/nm_U_cd_ppp_encap.txt")" -eq 8
for f in cd_pppoe cd_ppp_encap; do
    test "$(grep -c 'tunnel' "$H/nm_U_$f.txt" || true)" -eq 0            # 0/0 face (mpls b3 row is the ONLY U-carrier)
    test "$(grep -c 'SFDAQ' "$H/nm_U_$f.txt" || true)" -eq 0             # the misc3 witness seam NEVER reappears
    test "$(grep -c 'PADT' "$H/nm_U_$f.txt" || true)" -eq 0              # PADT NEVER-pull face on the OBJECT side too
done
cat "$H"/nm_U_cd_*.txt | sort -u > "$H/nm_U_union.txt"
test "$(nm -u $ROWS | grep -c get_proto_name || true)" -eq 0
# residue class (MANGLED face; inherited classifier): every snort-family U of
# the pair .o MUST be defined by OBJS+WIN ALONE (ZERO-new-witness proof).
nm -u $ROWS | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
donordefs=$(nm --defined-only $OBJS $WIN | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# THE own-new-symbol census pin (ZERO, the small4/erspan face): NO own
# witness .o -- every carried witness .o md5-traces to a donor source; the
# pair links GREEN on OBJS+WIN ALONE (below), so nothing of THIS row adds a
# symbol face.
test "$(nm --defined-only "$H"/witness_18f.o | grep -c 'tunnel_bypass_enabled')" -eq 1   # CARRIED exactly (pair nm_U carries NO bypass U -- no new pin)
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# landmine posture ZERO (R4): no pair name frozen in ANY witness donor; the
# vocab witness_stubs table census STAYS 4 (NO retirement face this row).
for n in cd_pppoepkt cd_pppencap; do
    test "$(grep -c "$n" "$R/tools/vocab_harness/witness_stubs.cc" || true)" -eq 0
    test "$(grep -c "$n" "$R/tools/codec_harness/stubs.cc" || true)" -eq 0
    # the ONE tools-wide home stays the legacy copy/codecs/codec_api.cc face
    test "$(grep -rl "$n" "$R/tools" --include='*.cc' --include='*.h' -I 2>/dev/null | grep -v 'vocab_harness/copy/codecs/codec_api.cc' | grep -v "$R/tools/link6_harness/" | wc -l)" -eq 0
done
test "$(md5sum "$R/tools/vocab_harness/witness_stubs.cc" | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(sed -n '11,14p' "$R/tools/vocab_harness/witness_stubs.cc" | grep -c 'cd_ipv4\|cd_ipv6\|cd_tcp\|cd_hopopts')" -eq 4
# real-symbol defines (donor face, gre-recipe)
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"

# ---- probe links: WIN trio alone (ZERO new witness) -> GREEN ------------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::SFDAQ::get_local_instance()' || true)" -eq 0   # misc3's tracked witness NEVER linked
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::PacketManager::get_proto_name' || true)" -eq 0 # donor-inherited NEVER linked
grep -q 'tun_witness_set_mask' <<< "$(nm -C "$H"/probe_dec)"       # CARRIED face rides BOTH binaries

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in cd_pppoe cd_ppp_encap; do $GXXA -c "$C/codecs/link/$f.cc" -o "$O2/$f.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc   -o "$O2"/stubs_18d.o
OB2="$O2/cd_pppoe.o $O2/cd_ppp_encap.o"
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
test "$(grep -c 'bool b=.*->decode' "$H"/probe_dec.cc)" -eq 14   # MEASURED face (2 disc + 2 sess + 10 ppp_encap arms)
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
# FACE-A: THE double-NAME LOAD headline (ONE table cd_pppoepkt -> TWO LOAD
# lines feeds :239/:240) + the pppencap single feed + the mod-arm SPLIT
# 1,1/1,1/0,0 (ground api slots sed-pinned above: disc :200/:201 + sess
# :222/:223 REAL vs pppencap nullptr pair :155/:156 -- NEVER carry 18l):
grep -q '^LOAD pppoe_disc$'  "$FA"                             # THE double-NAME face line #1
grep -q '^LOAD pppoe_sess$'  "$FA"                             # THE double-NAME face line #2 (ONE table, TWO names)
grep -q '^LOADS 2$'          "$FA"                             # the EXACTLY-2 feed walk (cd_pppoepkt :239/:240)
grep -q '^LOAD ppp_encap$'   "$FA"                             # THE name-drift face: table cd_pppencap carries NAME "ppp_encap" (#define :29 OUTSIDE the ns)
grep -q '^LOADS 1$'          "$FA"
grep -q '^HELP pppoe_disc support for point-to-point discovery$' "$FA"   # ground #define :116 sed-pinned
grep -q '^HELP pppoe_sess support for point-to-point session$'   "$FA"   # ground #define :140
grep -q '^HELP ppp_encap support for point-to-point encapsulation$' "$FA" # ground #define :30 (OUTSIDE ns :32 :49 pinned)
grep -q '^pppoe_disc mod_ctor=1 mod_dtor=1$' "$FA"             # THE pair face 1,1/1,1/0,0
grep -q '^pppoe_sess mod_ctor=1 mod_dtor=1$' "$FA"
grep -q '^ppp_encap mod_ctor=0 mod_dtor=0$'  "$FA"             # the EXPLICIT nullptr pair :155/:156
for n in pppoe_disc pppoe_sess ppp_encap; do grep -q "^$n ctor=1 dtor=1$" "$FA"; done  # CodecApi slots non-null x3 (:180/:183/:186, :138/:141)
grep -q '^GETIDS pppoe_disc 34915$'  "$FA"   # ETHERTYPE_PPPOE_DISC 0x8863 (protocol_ids.h :155, python-derived)
grep -q '^GETIDS pppoe_sess 34916$'  "$FA"   # ETHERTYPE_PPPOE_SESS 0x8864 :156
grep -q '^GETIDS ppp_encap 34827$'   "$FA"   # ETHERTYPE_PPP 0x880B :152 -- THE family-link id
test "$(grep -c '^GETDLT' "$FA" || true)" -eq 0                          # NO data-link registrant in this pair
# DEC ladders (ground call-site arms, receipts row18m):
grep -q '^EV 116 120$' "$V"                                             # pppoe_disc cc :130-:132
test "$(grep -c '^EV 116 120$' "$V")" -eq 1
grep -q '^PD len5 -> 0 lyr=0$' "$V"                                    # len<6 gate PPPOE_HEADER_LEN :86; lyr NEVER set on fail (:133 return)
grep -q '^PD len6 -> 1 lyr=0 next=34915$' "$V"                         # cc :136 happy: ZERO lyr/next EVER set (next rides the CodecData init ctor face codec.h :148 -- cited)
grep -q '^EV 116 479$' "$V"                                             # pppoe_sess cc :154-:156
test "$(grep -c '^EV 116 479$' "$V")" -eq 1
grep -q '^PS len5 -> 0 lyr=0$' "$V"
grep -q '^PS len6 -> 1 lyr=6 next=34827$' "$V"                         # :160 BEFORE :161 -- THE PAIR-LINK pin (next == ETHERTYPE_PPP == PE GETIDS)
grep -q 'order-site lyr:160-before-next:161' "$V"                      # eval-order cite
grep -q 'session-hdr cc:41' "$V"                                        # cited-never-ported; PADT grep-0 NEVER-pull
grep -q 'PD encode cc:92-:105 cited-never-called' "$V"                 # EncState-IpApi face (eth/tun/erspan ZERO-encode precedent)
grep -q '^PE len1 -> 0 lyr=0$' "$V"                                    # :58-:59 return false, NO event (ZERO-codec_event TU :124 census)
grep -q '^PE comp21 -> 1 lyr=1 next=2048$' "$V"                        # :61-:67 lyr=1; compressed half-octet 0x21 NUMERICALLY == PPP_IP 0x0021 :44 -> :82/:103 (rfc1661 collision face rides ground)
grep -q '^PE comp2d -> 0 lyr=1 next=34827$' "$V"                       # lyr=1 then 0x2d == PPP_VJ_COMP :82 return false; lyr STAYS
grep -q '^PE ip -> 1 lyr=2 next=2048$' "$V"                            # :71-:73 2-octet; PPP_IP :82->:103
grep -q '^PE vjcomp -> 0 lyr=2 next=34827$' "$V"                       # :83 return false, lyr 2 STAYS (lyr:73-before-switch:80)
grep -q '^PE vjucomp21 -> 0 lyr=2$' "$V"                               # :88-:91 len gate vs IP4_HEADER_LEN 20 (ipv4.h :38)
grep -q '^PE vjucomp22 -> 1 lyr=2 next=2048 proto9=6$' "$V"            # :97-:98 const_cast set_proto(TCP) FIXIT-M face PRINTED + fall-through :100->:103
grep -q '^PE ipv6 -> 1 lyr=2 next=34525$' "$V"                         # :106-:107 ETHERTYPE_IPV6 0x86DD :151
grep -q '^PE ipx -> 1 lyr=2 next=33079$' "$V"                          # :110-:111 ETHERTYPE_IPX 0x8137 :150
grep -q '^PE default -> 1 lyr=2 next=34827$' "$V"                      # :114-:115 true; next UNSET (init face)
grep -q 'order-site lyr:73-before-switch:80' "$V"                      # eval-order cite
grep -q 'PE encode cc:120-:132 cited-never-called' "$V"
test "$(grep -c '^EV ' "$V")" -eq 2                                    # 120 + 479 ONCE each (the pair's TWO soft gates)
test "$(grep -c 'tunnel\|bypass' "$V" || true)" -eq 0                  # ZERO tunnel face ANYWHERE in vectors (§2)
python3 - "$V" "$FA" <<'PYPIN'
# THE sids + protocol-id + CDAPI + family-link face PINNED BOTH WAYS (ground
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
assert g["DECODE_BAD_PPPOE_DISC"] == 120 and g["DECODE_BAD_PPPOE_SESS"] == 479
for n in ("DECODE_BAD_PPPOE_DISC","DECODE_BAD_PPPOE_SESS"):
    r = re.findall(rf"{n} = (\d+),", open("/opt/data/snort3-rust/src/codecs/codec_module.rs").read())
    assert r and int(r[0]) == g[n], (n, g[n], r)          # ALREADY landed -- NEVER re-walked
# pair ground event census: pppoe = 2 sites 2 DISTINCT tokens; ppp_encap ZERO
import subprocess
out = subprocess.run(["grep","-oE",r"codec_event\(codec,\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/link/cd_pppoe.cc"],capture_output=True,text=True).stdout
assert set(l.split()[-1] for l in out.splitlines() if l.strip()) == {"DECODE_BAD_PPPOE_DISC","DECODE_BAD_PPPOE_SESS"}
assert subprocess.run(["grep","-c","codec_event","/opt/data/snort3-src/src/codecs/link/cd_ppp_encap.cc"],capture_output=True).stdout == b"0\n"
V = set(int(l.split()[2]) for l in open(VF) if l.startswith("EV "))
assert V == {120, 479}, V                                # 2 DISTINCT sids == §4 face
# PADT NEVER-pull ground re-census (§5d3): zero on disk BOTH files
for tu in ("cd_pppoe.cc","cd_ppp_encap.cc"):
    assert subprocess.run(["grep","-c","PADT","/opt/data/snort3-src/src/codecs/link/"+tu],capture_output=True).stdout == b"0\n"
# protocol ids (protocol_ids.h enum hexes -> decimal)
pi = open("/opt/data/snort3-src/src/protocols/protocol_ids.h").read()
pids = {n:int(v,16) for n,v in re.findall(r'^\s*([A-Z_0-9]+)\s*=\s*(0[xX][0-9A-Fa-f]+),', pi, re.M)}
assert pids["ETHERTYPE_PPPOE_DISC"] == 0x8863 and pids["ETHERTYPE_PPPOE_SESS"] == 0x8864 and pids["ETHERTYPE_PPP"] == 0x880B
assert pids["ETHERTYPE_IPV4"] == 0x0800 and pids["ETHERTYPE_IPV6"] == 0x86DD and pids["ETHERTYPE_IPX"] == 0x8137
fa = open(FAF).read()
assert f"GETIDS pppoe_disc {pids['ETHERTYPE_PPPOE_DISC']}" in fa
assert f"GETIDS pppoe_sess {pids['ETHERTYPE_PPPOE_SESS']}" in fa
assert f"GETIDS ppp_encap {pids['ETHERTYPE_PPP']}" in fa
v = open(VF).read()
# THE decode-chain family link BOTH sides (GROUND: sess decode EMITS the id
# at cc :161 -- sed-pinned -- and ppp_encap REGISTERS it at cc :52):
assert f"next={pids['ETHERTYPE_PPP']}\n" in v, "FACE-A/D family link broken"
# CDAPI version face derived (base_api.h BASE_API_VERSION + codec.h CDAPI_VERSION)
ba = int(re.search(r'#define\s+BASE_API_VERSION\s+(\d+)', open("/opt/data/snort3-src/src/framework/base_api.h").read()).group(1))
cv = re.search(r'#define\s+CDAPI_VERSION\s+\(\(BASE_API_VERSION\s*<<\s*16\)\s*\|\s*(\d+)\)', open("/opt/data/snort3-src/src/framework/codec.h").read()).group(1)
ver = (ba << 16) | int(cv)
assert fa.count(f"ver={ver}") == 3, ver
assert fa.count("size=112") == 3                          # sizeof(CodecApi) carry (misc3 face UNDISTURBED)
# PPPOE_HEADER_LEN ground pin (:86) + the lyr=6 face
ccp = open("/opt/data/snort3-src/src/codecs/link/cd_pppoe.cc").read()
assert "constexpr uint16_t PPPOE_HEADER_LEN = 6;" in ccp and "lyr=6" in v
assert "if (raw.len < PPPOE_HEADER_LEN)" in ccp
# ppp_encap const ladder ground-pinned (0x0021/:44 .. :48 face, names AND values)
cce = open("/opt/data/snort3-src/src/codecs/link/cd_ppp_encap.cc").read()
for n, hexv in (("PPP_IP","0x0021"),("PPP_IPV6","0x0057"),("PPP_VJ_COMP","0x002d"),("PPP_VJ_UCOMP","0x002f"),("PPP_IPX","0x002b")):
    assert re.search(rf"static const uint16_t {n} = {hexv};", cce), n
assert "ip::IP4_HEADER_LEN" in cce
i4 = open("/opt/data/snort3-src/src/protocols/ipv4.h").read()
assert "constexpr uint8_t IP4_HEADER_LEN = 20;" in i4     # the 21-vs-22 arms boundary ground
# the compression-collision face ground: the ODD-octet branch NEVER masks
assert "if (raw.data[0] & 0x01)" in cce and "codec.lyr_len = 1;" in cce
# GID_DECODE (codec_module.h :38) drives the EV prefix
gid = int(re.search(r'constexpr int GID_DECODE = (\d+);', h).group(1))
assert all(l.split()[1]==str(gid) for l in open(VF) if l.startswith("EV "))
# pair Rust TUs LANDED (the PORT pass flipped this guard from the seed-
# pass NOT-exists half, like misc3 :586-:591 and the 18l trio guard flipped
# at THEIR ports; the landing consts + the drift face pin the landing; the
# NEXT.md :23 docs cite 580/0 stays NEVER edited, this row's re-run cargo
# face rides the commit msg)
import os
for f in ("cd_pppoe.rs","cd_ppp_encap.rs"):
    assert os.path.exists("/opt/data/snort3-rust/src/codecs/"+f)
RS = {f: open("/opt/data/snort3-rust/src/codecs/"+f).read() for f in ("cd_pppoe.rs","cd_ppp_encap.rs")}
assert "pub const CD_PPPOEPKT: CodecTable = &[&PPPOEPKT_DISC_API, &PPPOEPKT_SESS_API];" in RS["cd_pppoe.rs"]  # DRIFT const + DOUBLE feed
assert "pub const CD_PPPENCAP: CodecTable = &[&PPPENCAP_API];" in RS["cd_ppp_encap.rs"]                       # drift const (table spelling :169)
assert "580 passed / 0 failed" in open("/opt/data/snort3-rust/NEXT.md").read()   # docs CITE only; NEXT.md NEVER touched
PYPIN

# ---- row's measured first-run face PINS (the md5s below are the MEASURED
# FIRST-RUN OUTPUT, drift refuses EVERY build; seeded by SEED PASS 18m — the
# first seed run carries the PLACEHOLDER shapes below, dies loudly, and the
# REAL measured md5s are substituted into this block, then EVERY later run
# refuses drift; build.sh NEVER fabricates) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 20          # MEASURED first-run face
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 20    # MEASURED first-run face
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "e59f7a8a70d172261dcb847dcfdcb36a"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "d2fc5591bc45c1787fcee7393675a3d8"

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
# answered NEGATIVE by the nm_U tunnel census 0/0 ABOVE, §2). The B10 array
# rides misc3's post-row face VERBATIM (absolute paths incl ITS tracked
# witness pair -- NEVER re-derived); THIS row adds ZERO faces to it (the
# erspan 18l + misc3-fresh carriers UNDISTURBED). ----
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
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H/backbone10.txt"   # receipt (ignored; EXACTLY-10 lines asserted re-count face)
test "$(wc -l < "$H"/backbone10.txt)" -eq 10                            # backbone STAYS 10 (this row adds ZERO)
# the erspan-fresh x2 direct echo (the IMMEDIATE predecessor lineage = the
# DONOR tree this row clones, byte-ident faces pinned DIRECT like 18l did
# vs misc3):
test "$(md5sum "$ER"/vectors.txt | awk '{print $1}')" = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$ER"/vectors_faceA.txt | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"
test "$(md5sum "$MI"/vectors.txt | awk '{print $1}')" = "e75f7385779aa89c365dd2ce4a208b67"
test "$(md5sum "$MI"/vectors_faceA.txt | awk '{print $1}')" = "fe1189c6c78139b8828c1a8071e3df28"

# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" /opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "4826fc2233044a2d5429413faf0ae1af" /opt/data/snort3-rust/tools/fmod_harness/build.sh
# gre GATE anchor (the 18g chain rides this VERBATIM face pin; the grey
# positive-gate CONTRAST face for this row's ZERO-gate 20th-straight pin):
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
# row's collision fires LOUDLY):
test "$(ls -d /opt/data/snort3-rust/tools/pppoe_harness /opt/data/snort3-rust/tools/ppp_encap_harness /opt/data/snort3-rust/tools/pppoepkt_harness /opt/data/snort3-rust/tools/pppencap_harness 2>/dev/null | wc -l)" -eq 0
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin: the 18i PROCESS-LESSONS law (NEVER pin a harness to
# the working repo's own HEAD -- pin the IMMUTABLE ground only; the daq3
# dirty-guard template rides the rowface block below).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (git ls-files, NEVER pre-typed
# arithmetic): the NON-ignored face of this dir = the 6 stageables -- the
# small4/erspan 6-face PRECEDENT EXACTLY (PLAN.md build.sh probe.cc
# probe_dec.cc vectors.txt vectors_faceA.txt; NO witness file: the
# ZERO-new-witness face). FACE POSTURE (18i re-rule): PRE-commit the 6 are
# UNTRACKED (--others); POST-commit the SAME proof runs vs the landed face. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/link6_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/link6_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 6
for f in PLAN.md build.sh probe.cc probe_dec.cc vectors.txt vectors_faceA.txt; do
    echo "$face" | grep -q "tools/link6_harness/$f$"
done
test "$(echo "$face" | grep -c 'witness' || true)" -eq 0   # ZERO own-witness face (small4/erspan precedent)
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/cd_pppoe.o copy/codecs/link/cd_pppoe.cc copy/daq_common.h o2/cd_pppoe.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_18f.o witness_conf.o stubs_18d.o vectors_O0.txt vectors_faceA_O2.txt nm_U_cd_pppoe.txt E4_cd_pppoe.txt E4_donorsrc_cd_pppoe.txt E4_noapi_cd_pppoe.txt E4_restored_cd_pppoe.txt E4_nocm_cd_ppp_encap.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/link6_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/link6_harness/$f NOT ignored"; exit 1; }
done
# vectors NEVER ignored (the stageable face, explicit NOT-proof):
git -C /opt/data/snort3-rust check-ignore -q "tools/link6_harness/vectors.txt" && { echo "VECTORS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/link6_harness/vectors_faceA.txt" && { echo "FACE-A WRONGLY IGNORED"; exit 1; } || true
# no STAGED churn: index EMPTY. Tracked-MODIFIED face (lineage-honest, the
# daq3/misc3/erspan dirty-guard template; NEVER own-HEAD pin): EVERY dirty
# tracked file must be one of THIS row's sanctioned faces: .gitignore (the
# seed face of the link6 block) OR NEXT.md -- NOTE the honest EXTRA face:
# NEXT.md rides MODIFIED by the sibling DOCS child (row18m docs pass, NOT
# this harness pass): tolerated, NEVER touched/NEVER staged HERE (the
# face-guard refuses ANY other file). POST-commit the face is EMPTY; fires
# LOUDLY on any face touching another row's/committed lineage file. Rows
# NEVER rewrite history, NEVER git-add, NEVER commit.
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
# rowface guard: the PORT-pass face lists the row's FULL 13 dirty-face
# paths (the erspan :702 / misc3 :754 landed precedent -- the seed-pass
# face carried ONLY .gitignore + harness stageables; NEXT.md stays
# tolerated for the sibling docs child but is NEVER staged HERE).
rowface='^\.gitignore$|^NEXT\.md$|^src/codecs/(mod\.rs|cd_pppoe\.rs|cd_ppp_encap\.rs)$|^tests/link6_parity_test\.rs$|^PORTING_PLAN\.md$|^KNOWN DEVIATIONS\.md$|^tools/link6_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|vectors\.txt|vectors_faceA\.txt)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface")"

echo "row-TU nm census (MEASURED, never typed): pppoe=$(wc -l < "$H/nm_U_cd_pppoe.txt") ppp_encap=$(wc -l < "$H/nm_U_cd_ppp_encap.txt") union=$(wc -l < "$H/nm_U_union.txt") | union-mangled=$(wc -l < "$H/nm_U_mangled_union.txt") (the 22/8 leanest-pair face; tunnel census 0/0 -- witness_18f clone NOT forced, backbone stays $(wc -l < "$H/backbone10.txt") faces PINNED)"
echo "witness posture: ZERO own-new witness (own-new T census 0; SFDAQ T census 0 in BOTH binaries; get_proto_name row census 0 -> witness_miscip c5b498ff DONOR-INHERITED cite NEVER linked); WIN trio CARRIED (ea1f79f3 bypass exactly x1 -- the pair carries NO bypass U, 4dd91018 witness_conf byte-ident, stubs_18d CARRIED) -> probes link GREEN on OBJS+WIN ALONE"
echo "zero-fresh-cp face: copy tree = erspan-18l donor 114 REUSE clone (recon-113 ONE-DISAGREEMENT face recorded, disk wins) + 2 row TUs = 116 mid-build (ALL 12 closure/probe headers find-1 INHERITED incl api_options.h + plugin_manager.h; ip.h/ipv4.h find-1 via the framework/codec.h closure MEASURED-DRIVEN at :88/:97; daq grep 0x2, daq.h find-0, graft masters 73fdbc39/f683749c CITED NEVER cp'd, graft-v2 rides INHERITED fead0027 NEVER re-authored)"
echo "E4 localization BOTH ways: -I src ONLY rc1x2 fatal framework/api_options.h via base_api.h:32 + in-tree walls: codec_module kills ONLY pppoe (ppp_encap leanest-include SURVIVES §1 face) / codec.h DIRECT kills BOTH / log_text+eth kill NEITHER (pair SURVIVE -- 18l trans_bridge CONTRAST) / api_options CHAINED kills BOTH + restored rc0x2 EVERY build"
echo "hidden-table census: BUILDING_SO sed x2 (:233/:166) + snort_plugins grep 1/1 + nm D face (cd_pppoepkt EXACTLY-1 + cd_pppoe\$ EXACTLY-0 / cd_pppencap EXACTLY-1 + cd_ppp_encap\$ EXACTLY-0 drift refusals) + double-LOAD feeds :239/:240 EXACTLY-2 + double-NAME #defines :115/:139 INSIDE ns :113/:165 vs pppencap :29/:30 OUTSIDE ns :32/:49 + mod arms REAL x2 (:200/:201, :222/:223) vs nullptr pair :155/:156 + family-link seds cd_pppoe :161 + cd_ppp_encap :52 (ETHERTYPE_PPP)"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED here; tracked gate.txt = 1, ls-files); BACKBONE STAYS 10 (0 own-witness faces added; receipt backbone10.txt; erspan-fresh vectors pair byte-ident DIRECT echo -- the DONOR face)"
echo "LINK6_PPP_OK vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=0"

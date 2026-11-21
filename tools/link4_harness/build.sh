#!/usr/bin/env bash
# link4_harness -- row 18n: the codecs/link CHAPTER TAIL TRIO: codecs/link/
# cd_vlan.cc 236 L + cd_ciscometadata.cc 235 L + cd_fabricpath.cc 187 L = 658 L
# (PLAN PICK q3; the wc_md5_four.txt face fe9747e8/8cd594aa/f3fee8d9 re-md5
# receipt -- mpls 390 (e2911ad5) DEFERS to its own future row, PLAN q4 law).
# THE GRAFT-V3 HEADLINE (FIRST graft-EXTENSION row in the port): the vlan TU
# pulls <daq.h> cc :29 -- the frozen daq3 graft masters (daq.h 73fdbc39 33 L /
# daq_common.h f683749c) ride a NEW heredoc ONLY (misc3 :220-:249 EOFGRAFT /
# daq3 :202-:236 EOFDAQ per-link isolation law; masters byte-frozen, CITED,
# NEVER edited -- md5-asserted UNDISTURBED at the ladder head AND tail).
# graft-v3 = the master 33 L face + EXACTLY-2 DECL rows (daq_msg_get_pkthdr +
# DAQ_PKT_FLAG_IGNORE_VLAN -- the ONLY 2 missing face-sites, cd_vlan.cc
# :141:32/:142:23, the E_vlan_extface.txt EXACTLY-2-errors receipt); the TYPE
# face DAQ_PktHdr_t ALREADY rides the INHERITED graft-v2 daq_common.h :4
# (fead0027 from the donor clone, NEVER re-authored) => DECL-only extension,
# Option-B landing md5 face 0f7016a6 (39 L) copy-LOCAL (scratch daq.h.master-
# face 73fdbc39 stays parked UNDISTURBED). THE LADDER re-runs EVERY build:
# pre (daq.h find-0) rc1 head-1 daq.h face -> +master-face RE-RIDE rc1 EXACTLY-
# 2 errors (:141:32 + :142:23 -- THE extension face) -> +v3 EXT rows rc0
# syntax/-c/O2 x3. THE TWO-TINY-CP row: protocols/vlan.h 50 L e68dcca9 (arpa-
# only) + protocols/cisco_meta_data.h 43 L f5f66631 (arpa-only; the header-
# symmetric duo, §5.3) fresh cps, both find-0 in the donor PRE-cp (MEASURED --
# the § cisco f5f66631 pin face VERIFIED: 1 cp, not 2); cd_fabricpath is the
# ZERO-cp free-ride (PRE-cp -fsyntax-only rc0 = its closure face, E_pre_cd_-
# fabricpath EMPTY). THE ONE-NEW-WITNESS face (disk wins vs the zero-witness
# expectation, honestly §9): the graft-v3 DECL puts daq_msg_get_pkthdr on the
# vlan .o UNDEF face -- trial L1 census MEASURED: rows+OBJS+WIN alone die at
# EXACTLY-1 undefined (the cd_mpls hook row NEVER carries this; the daq3 +4
# witness_daq precedent at 1/4 the size) => witness_pkthdr.cc TRACKED (7
# stageables, the daq3 7-face law, NOT the small4/erspan 6-face); backbone
# STAYS EXACTLY 10 (this row adds ZERO backbone10 ARRAY faces; the WIN trio +
# miscip c5b498ff + trio ef50cd2f stay CARRIED/CITED, NEVER re-authored);
# tunnel-U census 0/0/0 (the bypass hook stays cd_mpls :205-:206, mpls owns
# its OWN future row, NEVER built here). nm_U 48/24/21 = the 18m §1 face EXACT
# re-pin (658-L trio). ALL THREE tables TRUE-NAME (cd_vlan[] :231 / cd_cisco-
# metadata[] :230 / cd_fabricpath[] :181 -- the 18m drift pair needs NO drift
# discipline HERE); mod arms ALL REAL x3 (:217/:218, :216/:217, :167/:168 --
# the nullptr-free tail face, contrast 18m pppencap). THE ZERO-gate row (21st
# straight): link/test find-0 + add_cpputest 0 + own CMakeLists face 2x3.
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness
MI=$R/tools/misc3_harness
MIP=$R/tools/miscip_harness
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
L6=$R/tools/link6_harness          # THE donor (18m tree, zero-witness 6-stageable) -- REUSE clone, §6
L=$SRC/src/codecs/link
C=$H/copy

# ---- ground identity (the THREE row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [cd_vlan.cc]=fe9747e87a7383eeacf43ce381b5ab7c [cd_ciscometadata.cc]=8cd594aa2a6576c56ea0136b1b2bdc05 [cd_fabricpath.cc]=f3fee8d9caf01be7686c9d1907e8f18b )
declare -A WC=( [cd_vlan.cc]=236 [cd_ciscometadata.cc]=235 [cd_fabricpath.cc]=187 )
for f in cd_vlan.cc cd_ciscometadata.cc cd_fabricpath.cc; do
    test "$(md5sum "$L/$f" | awk '{print $1}')" = "${MD5[$f]}"
    test "$(wc -l < "$L/$f")" -eq "${WC[$f]}"
done
# trio total face (the row's ledger line): 236+235+187 = 658 SUM measured (the
# PLAN q3 pick band face, like 18m's 604 P2); the six-file chapter ledger 1465
# face re-pin (18m law, UNDISTURBED) + the deferred mpls 390 (q4 own-row law).
test "$(( $(wc -l < "$L/cd_vlan.cc") + $(wc -l < "$L/cd_ciscometadata.cc") + $(wc -l < "$L/cd_fabricpath.cc") ))" -eq 658
test "$(( $(wc -l < "$L/cd_mpls.cc") + $(wc -l < "$L/cd_vlan.cc") + $(wc -l < "$L/cd_pppoe.cc") + $(wc -l < "$L/cd_ciscometadata.cc") + $(wc -l < "$L/cd_fabricpath.cc") + $(wc -l < "$L/cd_ppp_encap.cc") ))" -eq 1465
test "$(wc -l < "$L/cd_mpls.cc")" -eq 390
# combined gate grep ZERO x3 EVERY build (STOP-flag; if ground ever ships a
# suite naming the trio the row RE-PLANS to the gate shape -- flip trips loud)
for f in cd_vlan.cc cd_ciscometadata.cc cd_fabricpath.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST\|CppUTest' "$L/$f" || true)" -eq 0
done

# ---- THE zero-gate census (21st straight, MEASURED EVERY BUILD) ----
test "$(find "$L" -type d -name test | wc -l)" -eq 0
test ! -d "$L/test"
test "$(grep -c 'add_cpputest' "$L/CMakeLists.txt" || true)" -eq 0
for f in cd_vlan cd_ciscometadata cd_fabricpath; do
    test "$(grep -c "add_dynamic_module($f codecs $f.cc)" "$L/CMakeLists.txt")" -eq 1   # per-file face MEASURED (STATIC set + add_dynamic_module x2 per name)
done

# ---- THE hidden tables (BUILDING_SO split) -- sed census PIN lines x3 ----
test "$(sed -n '228p' "$L/cd_vlan.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '231p' "$L/cd_vlan.cc")" = "const BaseApi* cd_vlan[] ="            # TRUE-NAME table #1
test "$(sed -n '234p' "$L/cd_vlan.cc")" = "    &vlan_api.base,"
test "$(sed -n '227p' "$L/cd_ciscometadata.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '230p' "$L/cd_ciscometadata.cc")" = "const BaseApi* cd_ciscometadata[] ="  # TRUE-NAME table #2
test "$(sed -n '233p' "$L/cd_ciscometadata.cc")" = "    &ciscometadata_api.base,"
test "$(sed -n '178p' "$L/cd_fabricpath.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '181p' "$L/cd_fabricpath.cc")" = "const BaseApi* cd_fabricpath[] ="  # TRUE-NAME table #3
test "$(sed -n '184p' "$L/cd_fabricpath.cc")" = "    &fabricpath_api.base,"
for f in cd_vlan.cc cd_ciscometadata.cc cd_fabricpath.cc; do
    test "$(grep -c 'BUILDING_SO'  "$L/$f")" -eq 1
    test "$(grep -c 'snort_plugins' "$L/$f")" -eq 1
done

# ---- TRUE-NAME pins + NAME/HELP macro faces (sed x3; the trio's table names
# EQUAL the file bases -- the 18m drift-TRIPWIRE face needs NO refusal here,
# but the file-base-vs-table EQUALITY rides the nm D-face pins below) ----
test "$(sed -n '38p' "$L/cd_vlan.cc")" = '#define CD_VLAN_NAME "vlan"'
test "$(sed -n '39p' "$L/cd_vlan.cc")" = '#define CD_VLAN_HELP "support for local area network"'
test "$(sed -n '31p' "$L/cd_ciscometadata.cc")" = '#define CD_CISCOMETADATA_NAME "ciscometadata"'
test "$(sed -n '32p' "$L/cd_ciscometadata.cc")" = '#define CD_CISCOMETADATA_HELP "support for cisco metadata"'
test "$(sed -n '29p' "$L/cd_fabricpath.cc")" = '#define CD_FABRICPATH_NAME "fabricpath"'
test "$(sed -n '30p' "$L/cd_fabricpath.cc")" = '#define CD_FABRICPATH_HELP "support for fabricpath"'

# ---- mod arms ALL REAL x3 (PLAN §8: the tails = the nullptr-free face,
# contrast 18m pppencap :155/:156) -- ctor :191/:193/:144 dtor :194/:196/:147
# + api arms :217/:218, :216/:217, :167/:168 + CodecApi ctor/dtor ----
test "$(sed -n '191p' "$L/cd_vlan.cc")" = "static Module* mod_ctor()"
test "$(sed -n '217p' "$L/cd_vlan.cc")" = "        mod_ctor,"
test "$(sed -n '218p' "$L/cd_vlan.cc")" = "        mod_dtor,"
test "$(sed -n '193p' "$L/cd_ciscometadata.cc")" = "static Module* mod_ctor()"
test "$(sed -n '216p' "$L/cd_ciscometadata.cc")" = "        mod_ctor,"
test "$(sed -n '217p' "$L/cd_ciscometadata.cc")" = "        mod_dtor,"
test "$(sed -n '144p' "$L/cd_fabricpath.cc")" = "static Module* mod_ctor()"
test "$(sed -n '167p' "$L/cd_fabricpath.cc")" = "        mod_ctor,"
test "$(sed -n '168p' "$L/cd_fabricpath.cc")" = "        mod_dtor,"
test "$(sed -n '197p' "$L/cd_vlan.cc")" = "static Codec* ctor(Module* m)"      # the mod ? :200 default-tpids face
test "$(sed -n '199p' "$L/cd_ciscometadata.cc")" = "static Codec* ctor(Module*)"
test "$(sed -n '150p' "$L/cd_fabricpath.cc")" = "static Codec* ctor(Module*)"

# ---- THE graft-v3 token census (masters byte-frozen; the EXACTLY-2 missing
# face-sites; the TYPE face INHERITED -- the extension = DECL-only, NOT a
# 3-row face (the 18m NEXT-3-token one-disagreement RE-CONFIRMED): 8 sites ----
test "$(md5sum "$D3/copy/daq.h"       | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"   # master face CITE (ladder RE-RIDES via heredoc, NEVER cp'd, NEVER edited)
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"  # v1 master face CITE
test "$(grep -c 'daq_msg_get_pkthdr\|DAQ_PKT_FLAG_IGNORE_VLAN' "$D3/copy/daq.h" || true)" -eq 0        # tokens grep-0 IN the master
test "$(grep -c 'daq_msg_get_pkthdr\|DAQ_PKT_FLAG_IGNORE_VLAN' "$D3/copy/daq_common.h" || true)" -eq 0 # grep-0 in BOTH masters
test "$(grep -c 'daq_msg_get_pkthdr' "$L/cd_vlan.cc")" -eq 1                    # cc :141 USE-site EXACTLY-1
test "$(grep -c 'DAQ_PKT_FLAG_IGNORE_VLAN' "$L/cd_vlan.cc")" -eq 1              # cc :142 USE-site EXACTLY-1
# the daq PARTICIPATION face of the trio (contrast 18m grep 0x2): vlan = the
# ONE graft-consuming TU (27 non-mpls lines -> 3 daq-line face :29/:141/:142),
# cisco + fabricpath ZERO-daq (the lean non-participants)
test "$(grep -ci daq "$L/cd_vlan.cc")" -eq 3
for f in cd_ciscometadata.cc cd_fabricpath.cc; do
    test "$(grep -ci daq "$L/$f" || true)" -eq 0
    test "$(grep -c 'tunnel_bypass' "$L/$f" || true)" -eq 0
done
test "$(grep -c 'tunnel_bypass' "$L/cd_vlan.cc" || true)" -eq 0                 # the trio carries NO hook face (mpls :205-:206 owns it, q4)
test "$(sed -n '205,206p' "$L/cd_mpls.cc" | grep -c tunnel_bypass)" -eq 2       # the hook lives there, NEVER here (hand-off cite)
# the deferred-mpls NEVER-land negative census (name grep-0 harness face;
# the cite-prose lives in build.sh / PLAN ONLY, NEVER in the probes):
for f in probe.cc probe_dec.cc witness_pkthdr.cc; do
    test "$(grep -c 'cd_mpls\|MPLS' "$H/$f" || true)" -eq 0
done
test "$(sed -n '49p' "$L/cd_vlan.cc")" = 'static const char* default_tpids = "0x9100 0x9200";'   # the GETIDS tpid-face cite (37120/37376 decimal)
test "$(sed -n '98p' "$L/cd_vlan.cc")" = "constexpr unsigned int ETHERNET_MAX_LEN_ENCAP = 1518;    /* 802.3 (+LLC) or ether II ? */"
test "$(sed -n '70p' "$L/cd_fabricpath.cc")" = "constexpr uint8_t FABRICPATH_HEADER_LEN = 16;"

# ---- externs + loads + ladder ALL RESIDENT (rows ADD TUs, NEVER touch) ----
test "$(sed -n '43p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_ciscometadata[];"
test "$(sed -n '49p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_fabricpath[];"
test "$(sed -n '72p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_vlan[];"
test "$(sed -n '88p'  "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_ciscometadata);"
test "$(sed -n '94p'  "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_fabricpath);"
test "$(sed -n '117p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_vlan);"
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern census UNDISTURBED
# the rust ladder face (rows NEVER re-touch): trio names ALREADY resident
test "$(sed -n '101p' "$R/src/codecs/codec_api.rs")" = '    "cd_ciscometadata",'
test "$(sed -n '107p' "$R/src/codecs/codec_api.rs")" = '    "cd_fabricpath",'
test "$(sed -n '130p' "$R/src/codecs/codec_api.rs")" = '    "cd_vlan",'
test "$(sed -n '97p'  "$R/src/codecs/codec_api.rs")" = 'pub const STATIC_CODEC_EXTERN_NAMES: [&str; 34] = ['

# ---- the 6 sids RESIDENT face (PLAN §1: 6/6 ZERO new consts): trio sids
# 130/467/468-471 ALL ride codec_module.rs :96/:225/:226-:229 (ZERO new
# consts; the trio rs files LANDED at the PORT pass -- seed-pass guard
# FLIPPED per the misc3 :586-:591 / link6 :187-:194 precedent, exactly like
# the 18l/18m guards flipped at THEIR ports) ----
test "$(sed -n '96p'  "$R/src/codecs/codec_module.rs")" = '    DECODE_BAD_VLAN = 130,  // h:79'
test "$(sed -n '225p' "$R/src/codecs/codec_module.rs")" = '    DECODE_FPATH_HDR_TRUNC = 467,  // h:220'
test "$(sed -n '226p' "$R/src/codecs/codec_module.rs")" = '    DECODE_CISCO_META_HDR_TRUNC = 468,  // h:221'
test "$(sed -n '227p' "$R/src/codecs/codec_module.rs")" = '    DECODE_CISCO_META_HDR_OPT_LEN = 469,  // h:222'
test "$(sed -n '228p' "$R/src/codecs/codec_module.rs")" = '    DECODE_CISCO_META_HDR_OPT_TYPE = 470,  // h:223  // = 470'
test "$(sed -n '229p' "$R/src/codecs/codec_module.rs")" = '    DECODE_CISCO_META_HDR_SGT = 471,  // h:224'
test "$(ls "$R/src/codecs/cd_vlan.rs" "$R/src/codecs/cd_ciscometadata.rs" "$R/src/codecs/cd_fabricpath.rs" 2>/dev/null | wc -l)" -eq 3   # LANDED (the PORT-pass flip face)
test "$(grep -c 'pub const CD_VLAN: CodecTable = &\[&VLAN_API\];' "$R/src/codecs/cd_vlan.rs")" -eq 1                                  # TRUE-NAME table const (:231 feed :234)
test "$(grep -c 'pub const CD_CISCOMETADATA: CodecTable = &\[&CISCOMETADATA_API\];' "$R/src/codecs/cd_ciscometadata.rs")" -eq 1       # TRUE-NAME table const (:230 feed :233)
test "$(grep -c 'pub const CD_FABRICPATH: CodecTable = &\[&FABRICPATH_API\];' "$R/src/codecs/cd_fabricpath.rs")" -eq 1                # TRUE-NAME table const (:181 feed :184)
for f in cd_vlan cd_ciscometadata cd_fabricpath; do
    test "$(grep -c "$f" "$R/src/codecs/$f.rs")" -ge 1                                                                            # the FILE-base name rides the landing file (the TRUE-NAME equality face -- the 18m drift CONTRAST needs NO refusal HERE)
    test "$(grep -ci 'mpls' "$R/src/codecs/$f.rs" || true)" -eq 0                                                                  # q4 NEVER-land twin census Rust-side (the probe-side face rides :141-:143)
done
# cargo face CITATION (LINK6 :198 lineage UNDISTURBED; 588 = 580+8 rides the
# NEXT.md :39/:165 docs cite -- the docs-child's committed content, NEVER
# re-typed into this row's assertions, NEVER run HERE, NEXT.md NEVER edited):
grep -q "580 passed / 0 failed" "$R/NEXT.md"
grep -q "588 tests green / 0 FAILED" "$R/NEXT.md"

# ---- copy tree = link6-18m DONOR REUSE clone (the zero-witness 6-stageable
# 116-tree face, 114 erspan end-state + the 18m pair TUs) + the header-symmetric
# arpa-only duo cps + graft-v3 heredoc daq.h + 3 row TU cps. graft-v2
# daq_common.h fead0027 rides INHERITED (its md5 comes from the donor clone;
# DAQ_PktHdr_t grep-1 at :4 = the TYPE face the DECL extension rides, NEVER
# re-authored); daq.h find-0 PRE-heredoc (ONE-LANDING law daq3 :131-:133). ----
if [ ! -e "$L6/copy/codecs/link/cd_pppoe.cc" ] || [ ! -e "$L6/copy/config.h" ]; then bash "$L6/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$L6/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 116   # donor face MEASURED (the 18m mid-build 116 = landing head)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"   # graft-v2 INHERITED (misc3 pin; NEVER re-authorized HERE)
test "$(sed -n '4p' "$C/daq_common.h")" = "struct DAQ_PktHdr_t {"                            # the TYPE-face grep-1 (flags uint64_t = 0 rides line 5)
test "$(find "$C" -name 'daq.h' | wc -l)" -eq 0             # PRE-heredoc face (the ladder arm #1)
# fresh-cp census: BOTH trio headers find-0 in the donor (MEASURED -- the
# cisco f5f66631 PIN face VERIFIED copy-local: ONE cp not two; vlan.h 50 L)
test "$(find "$C" -name 'vlan.h' | wc -l)" -eq 0
test "$(find "$C" -path '*/protocols/vlan.h' | wc -l)" -eq 0
test "$(find "$C" -name 'cisco_meta_data.h' | wc -l)" -eq 0
test "$(wc -l < "$SRC/src/protocols/vlan.h")" -eq 50
test "$(md5sum "$SRC/src/protocols/vlan.h" | awk '{print $1}')" = "e68dcca97e07de298204e9f7243d9e92"
test "$(wc -l < "$SRC/src/protocols/cisco_meta_data.h")" -eq 43
test "$(md5sum "$SRC/src/protocols/cisco_meta_data.h" | awk '{print $1}')" = "f5f666319de9a2ce3d68b9ac61dccc3e"
test "$(grep -c '#include' "$SRC/src/protocols/vlan.h")" -eq 1            # arpa-only face (the header-symmetric duo, §5.3)
test "$(grep -c '#include' "$SRC/src/protocols/cisco_meta_data.h")" -eq 1
# the flowz decoy refusal face (the 18m §5.7 law re-cited): the flow/ path
# stays find-0; the donor flowz/flow_data.h NEVER participates in the trio
test "$(find "$C" -path '*flow/flow_data.h' | wc -l)" -eq 0
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probe pulls NO codec_api)
test ! -e "$C/codecs/codec_api.cc"
mkdir -p "$C/protocols" "$C/codecs/link"
cp "$SRC/src/protocols/vlan.h" "$C/protocols/vlan.h";                             cmp -s "$C/protocols/vlan.h" "$SRC/src/protocols/vlan.h"
cp "$SRC/src/protocols/cisco_meta_data.h" "$C/protocols/cisco_meta_data.h";       cmp -s "$C/protocols/cisco_meta_data.h" "$SRC/src/protocols/cisco_meta_data.h"
for f in cd_vlan.cc cd_ciscometadata.cc cd_fabricpath.cc; do
    cp "$L/$f" "$C/codecs/link/$f"; cmp -s "$C/codecs/link/$f" "$L/$f"
done

GXX0="g++ -std=c++17 -O0 -w -I$C"
# ---- THE GRAFT-V3 LADDER (re-run EVERY build; the Option-A heredoc rides ONLY
# this build.sh -- misc3 :220-:249 EOFGRAFT / daq3 :202-:236 EOFDAQ per-link
# isolation law; the daq3 masters stay byte-frozen, asserted at ladder TAIL).
# ARM #2 (master-face RE-RIDE): the 33 L daq3 face materialized copy-locally
# -> vlan MUST die at EXACTLY-2 errors :141:32 + :142:23 (THE extension face,
# scratch E_vlan_extface.txt receipt re-armed): ----
cat > "$C/daq.h" <<'EOFMQ'
#ifndef DAQ_H
#define DAQ_H
// 18i CANDIDATE graft (scratch rehearsal only, NOT landed): the DAQ SDK
// header is not in the snort3 tree nor on the host (find whole-repo = 0
// hits at fe29cbe). Shapes drawn from the MEASURED call faces ONLY:
// cd_udp.cc:263-270/:420, cd_icmp4.cc:132-139, cd_icmp6.cc:125-132.
#include <cstdint>
#include <daq_common.h>           // rides the fmod 16 L graft (byte-ident in copy trees)
typedef enum
{
    DAQ_META_FIRST = 0,
    DAQ_PKT_META_DECODE_DATA,     // trio :133/:126/:264 2nd arg
    DAQ_PKT_META_NAPT_INFO        // cd_udp.cc:420 2nd arg
} DAQ_MetaType;
#define DAQ_PKT_DECODE_OFFSET_INVALID (-1)   // compared vs pdd->l4_offset
struct DAQ_PktDecodeData_t
{
    struct { struct { unsigned l4_checksum : 1;
                      unsigned udp         : 1;
                      unsigned icmp        : 1;
                      unsigned l4          : 1; } bits; } flags;
    int32_t l4_offset;            // :268/:137/:130 vs OFFSET_INVALID
};
struct DAQ_NAPTInfo_t
{
    uint32_t src_port;            // cd_udp.cc:422-424 ntohs
    uint32_t dst_port;
    uint8_t  ip_layer;            // :421 vs codec.ip_layer_cnt
};
struct _daq_msg;                  // fwd = framework/codec.h :38 face (same TU)
const void*    daq_msg_get_meta(const struct _daq_msg*, DAQ_MetaType);
const uint8_t* daq_msg_get_data(const struct _daq_msg*);
#endif
EOFMQ
test "$(wc -l < "$C/daq.h")" -eq 33
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"   # master face byte-EXACT via heredoc (the RE-RIDE law: heredoc materialize, NEVER cp, NEVER edit)
if $GXX0 -fsyntax-only "$C/codecs/link/cd_vlan.cc" -o /dev/null 2> "$H/E4_vlan_extface.txt"; then
    echo "EXT-FACE DEAD: vlan compiled on the 33 L master graft face -- the EXACTLY-2 DECL gap is wrong"; exit 1
fi
test "$(grep -c 'error:' "$H/E4_vlan_extface.txt")" -eq 2
# locale-robust greps (gcc smart-quotes ride UTF-8 in some locales -- the
# quote bytes NEVER ride the pattern):
grep -q "cd_vlan.cc:141:32: error: .*daq_msg_get_pkthdr.* was not declared in this scope" "$H/E4_vlan_extface.txt"
grep -q "cd_vlan.cc:142:23: error: .*DAQ_PKT_FLAG_IGNORE_VLAN.* was not declared in this scope" "$H/E4_vlan_extface.txt"
# ARM #3 (graft-v3 EXTENSION): the SAME 33 L + the EXACTLY-2 DECL rows BEFORE
# #endif -- copy-LOCAL landing face (Option-B pin md5 0f7016a6 = the scratch
# daq.h candidate face, daq.h.masterface 73fdbc39 parked UNDISTURBED; the
# daq_common.h enum EXTENSION #2 (9b603f8f / MAX_DAQ_VERDICT==6, scratch E_mpls_-
# v3) NEVER rides here -- that face belongs to the deferred mpls row, q4): ----
cat > "$C/daq.h" <<'EOFG3'
#ifndef DAQ_H
#define DAQ_H
// 18i CANDIDATE graft (scratch rehearsal only, NOT landed): the DAQ SDK
// header is not in the snort3 tree nor on the host (find whole-repo = 0
// hits at fe29cbe). Shapes drawn from the MEASURED call faces ONLY:
// cd_udp.cc:263-270/:420, cd_icmp4.cc:132-139, cd_icmp6.cc:125-132.
#include <cstdint>
#include <daq_common.h>           // rides the fmod 16 L graft (byte-ident in copy trees)
typedef enum
{
    DAQ_META_FIRST = 0,
    DAQ_PKT_META_DECODE_DATA,     // trio :133/:126/:264 2nd arg
    DAQ_PKT_META_NAPT_INFO        // cd_udp.cc:420 2nd arg
} DAQ_MetaType;
#define DAQ_PKT_DECODE_OFFSET_INVALID (-1)   // compared vs pdd->l4_offset
struct DAQ_PktDecodeData_t
{
    struct { struct { unsigned l4_checksum : 1;
                      unsigned udp         : 1;
                      unsigned icmp        : 1;
                      unsigned l4          : 1; } bits; } flags;
    int32_t l4_offset;            // :268/:137/:130 vs OFFSET_INVALID
};
struct DAQ_NAPTInfo_t
{
    uint32_t src_port;            // cd_udp.cc:422-424 ntohs
    uint32_t dst_port;
    uint8_t  ip_layer;            // :421 vs codec.ip_layer_cnt
};
struct _daq_msg;                  // fwd = framework/codec.h :38 face (same TU)
const void*    daq_msg_get_meta(const struct _daq_msg*, DAQ_MetaType);
const uint8_t* daq_msg_get_data(const struct _daq_msg*);

// row18n graft-v3 EXTENSION CANDIDATE (harness-copy-LOCAL; daq3 master NEVER
// mutated): vlan.cc :141/:142 decl face MEASURED grep-0 in master -- DAQ_PktHdr_t
// ALREADY rides graft daq_common.h :4 so ONLY 2 DECL rows needed.
const struct DAQ_PktHdr_t* daq_msg_get_pkthdr(const struct _daq_msg*);
#define DAQ_PKT_FLAG_IGNORE_VLAN 0x0000000000000040
#endif
EOFG3
test "$(wc -l < "$C/daq.h")" -eq 39
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"   # graft-v3 landing face (Option-B pin, scratch byte-ident; per-link isolation law re-cited -- NEVER edit frozen harnesses)
# masters UNDISTURBED at the ladder TAIL (byte-frozen law re-armed after BOTH
# heredoc arms wrote ONLY the copy-local face):
test "$(md5sum "$D3/copy/daq.h"       | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"   # INHERITED face survived (NO enum #2 here -- mpls q4 row owns it)
# post-ladder: trio rc0 x3 faces (vlan v3 / cisco 1-cp / fabricpath ZERO-cp):
for f in cd_vlan cd_ciscometadata cd_fabricpath; do
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_$f.txt"
    test ! -s "$H/E4_$f.txt"
    $GXX0 -c "$C/codecs/link/$f.cc" -o "$C/$f.precheck.o" 2> "$H/E4_codegen_$f.txt"
    test ! -s "$H/E4_codegen_$f.txt"
    rm -f "$C/$f.precheck.o"
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 122   # mid-build: 116 donor + daq.h + vlan.h + cisco cp + 3 TUs (the ONLY cps THIS row makes)

# ---- E4 LOCALIZATION ARMS BOTH WAYS (18h precedent; the TRIO-flipped walls):
# (a) stripped-donor arm -I src ONLY MUST die rc1 x3: vlan at the head-1 daq.h
# DIRECT :29 face (scratch E4_donorsrc_cd_vlan head-1), cisco + fabricpath at
# framework/api_options.h via base_api.h:32 (the landed 18h/18m wall face).
# (b) IN-TREE walls, MEASURED for this trio: protocols/vlan.h drop kills ONLY
# vlan (the fresh-cp face; cisco + fabricpath SURVIVE -- never include it);
# cisco_meta_data.h drop kills ONLY cisco; daq.h drop kills ONLY vlan (the
# graft NON-participation face of the pair, 18m law trio-extended); log/
# text_log.h drop kills vlan + cisco (both include DIRECT :33/:26) and
# fabricpath SURVIVES (the leanest include face of the trio, §1 fabricpath
# include census config/codec_module/codec ONLY); codec.h + codec_module.h
# CHAINED kill ALL THREE; restored full tree rc0 x3 EVERY build ----
GXXD="g++ -std=c++17 -O0 -w -I$SRC/src"
for f in cd_vlan cd_ciscometadata cd_fabricpath; do
    if $GXXD -fsyntax-only "$SRC/src/codecs/link/$f.cc" 2> "$H/E4_donorsrc_$f.txt"; then
        echo "E4 LOCALIZATION DEAD: $f compiled on the -I src ONLY arm -- the stripped-tree rc1x3 face is wrong"; exit 1
    fi
done
head -1 "$H/E4_donorsrc_cd_vlan.txt" | grep -q "fatal error: daq.h: No such file"        # the head-1 DIRECT face (18m CONTRAST: ppp pair never hit this)
for f in cd_ciscometadata cd_fabricpath; do
    grep -q "fatal error: framework/api_options.h: No such file" "$H/E4_donorsrc_$f.txt"
    grep -q "base_api.h:32" "$H/E4_donorsrc_$f.txt"
done
mv "$C/protocols/vlan.h" "$H/.e4_hold_vlan.h"
for f in cd_ciscometadata cd_fabricpath; do            # vlan.h drop: the pair SURVIVES
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_novlan_$f.txt"
    test ! -s "$H/E4_novlan_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/link/cd_vlan.cc" -o /dev/null 2> "$H/E4_novlan_cd_vlan.txt"; then
    echo "E4 flip BROKE: cd_vlan compiled WITHOUT protocols/vlan.h (cc:34)"; exit 1
fi
head -1 "$H/E4_novlan_cd_vlan.txt" | grep -q "fatal error: protocols/vlan.h: No such file"
mv "$H/.e4_hold_vlan.h" "$C/protocols/vlan.h"
mv "$C/protocols/cisco_meta_data.h" "$H/.e4_hold_cisco.h"
for f in cd_vlan cd_fabricpath; do                     # cisco hdr drop: the OTHER pair SURVIVES
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_nocisco_$f.txt"
    test ! -s "$H/E4_nocisco_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/link/cd_ciscometadata.cc" -o /dev/null 2> "$H/E4_nocisco_cd_ciscometadata.txt"; then
    echo "E4 flip BROKE: cd_ciscometadata compiled WITHOUT protocols/cisco_meta_data.h (cc:27)"; exit 1
fi
head -1 "$H/E4_nocisco_cd_ciscometadata.txt" | grep -q "fatal error: protocols/cisco_meta_data.h: No such file"
mv "$H/.e4_hold_cisco.h" "$C/protocols/cisco_meta_data.h"
mv "$C/daq.h" "$H/.e4_hold_daq.h"
for f in cd_ciscometadata cd_fabricpath; do            # daq.h drop: the pair SURVIVES (graft NON-participation face)
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_nodaq_$f.txt"
    test ! -s "$H/E4_nodaq_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/link/cd_vlan.cc" -o /dev/null 2> "$H/E4_nodaq_cd_vlan.txt"; then
    echo "E4 flip BROKE: cd_vlan compiled WITHOUT the graft-v3 daq.h"; exit 1
fi
head -1 "$H/E4_nodaq_cd_vlan.txt" | grep -q "fatal error: daq.h: No such file"
mv "$H/.e4_hold_daq.h" "$C/daq.h"
mv "$C/log/text_log.h" "$H/.e4_hold_text_log.h"
for f in cd_vlan cd_ciscometadata; do                  # text_log.h drop kills BOTH includers (DIRECT edge faces)
    if $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" -o /dev/null 2> "$H/E4_notxtlog_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT log/text_log.h (cc:33/:26 DIRECT)"; exit 1
    fi
    head -1 "$H/E4_notxtlog_$f.txt" | grep -q "fatal error: log/text_log.h: No such file"
done
$GXX0 -fsyntax-only "$C/codecs/link/cd_fabricpath.cc" 2> "$H/E4_notxtlog_cd_fabricpath.txt"   # the leanest-include face SURVIVES (trio §1 census)
test ! -s "$H/E4_notxtlog_cd_fabricpath.txt"
mv "$H/.e4_hold_text_log.h" "$C/log/text_log.h"
mv "$C/codecs/codec_module.h" "$H/.e4_hold_codec_module.h"
mv "$C/framework/codec.h" "$H/.e4_hold_codec.h"
for f in cd_vlan cd_ciscometadata cd_fabricpath; do    # the CHAINED wall: BOTH DIRECT edges kill ALL THREE
    if $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" -o /dev/null 2> "$H/E4_noapi_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT codec_module.h+codec.h (the DIRECT trio edges)"; exit 1
    fi
    head -1 "$H/E4_noapi_$f.txt" | grep -q "fatal error: codecs/codec_module.h: No such file"
done
mv "$H/.e4_hold_codec_module.h" "$C/codecs/codec_module.h"
mv "$H/.e4_hold_codec.h" "$C/framework/codec.h"
for f in cd_vlan cd_ciscometadata cd_fabricpath; do    # restored full tree re-arm
    $GXX0 -fsyntax-only "$C/codecs/link/$f.cc" 2> "$H/E4_restored_$f.txt"
    test ! -s "$H/E4_restored_$f.txt"
done

GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"

# ---- witness posture: ONE OWN-NEW witness (the graft-v3 +1 UNDEF face, the
# 18i witness_daq precedent shape -- NOT the small4/erspan ZERO face; disk won,
# §9 records) + the WIN trio CARRIED (witness_18f ea1f79f3 T tunnel_bypass EX-
# ACTLY-1 carried face + witness_conf 4dd91018 VERBATIM re-materialize + stubs
# _18d f4afd35f); witness_miscip c5b498ff + witness_trio ef50cd2f stay DONOR-
# INHERITED cites NEVER linked (misc3 :411-:415 face re-cited). ----
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
test "$(find "$H" -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 1   # EXACTLY-1 own-new = witness_pkthdr.cc (the graft-v3 delta face, daq3 precedent)
test "$(find "$H" -name 'witness_*.cc' ! -name witness_conf.cc | grep -c witness_pkthdr)" -eq 1
test "$(wc -l < "$H/witness_pkthdr.cc")" -eq 21
test "$(md5sum "$H/witness_pkthdr.cc" | awk '{print $1}')" = "3777a89442b9bd5d6b65df4376a1c0dc"   # THE tracked witness face (measured landing run; daq3 witness_daq e0166b02 pin precedent re-armed)
test "$(wc -l < "$MIP/witness_miscip.cc")" -eq 27
test "$(md5sum "$MIP/witness_miscip.cc" | awk '{print $1}')" = "c5b498ffa6beac768f34e25830c552a1"

# ---- O0 compile: THREE plain .o + donor REAL .o + probes + witnesses ----
for f in cd_vlan cd_ciscometadata cd_fabricpath; do $GXX -c "$C/codecs/link/$f.cc" -o "$C/$f.o"; done
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc   -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc    -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc     -o "$H"/stubs_18d.o
$GXX -c "$H"/witness_pkthdr.cc  -o "$H"/witness_pkthdr.o   # the own-new face (its md5 = the source face; tracked stageable #7)

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/cd_vlan.o $C/cd_ciscometadata.o $C/cd_fabricpath.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# hidden-table one-symbol-per-.o face x3 (TRUE-NAME tables: the nm D-face
# EQUALS the file base -- the 18m drift-inequality face NEVER applies HERE):
test "$(nm --defined-only "$C/cd_vlan.o"          | grep -cE ' [DdRr] cd_vlan$')"          -eq 1
test "$(nm --defined-only "$C/cd_ciscometadata.o" | grep -cE ' [DdRr] cd_ciscometadata$')" -eq 1
test "$(nm --defined-only "$C/cd_fabricpath.o"    | grep -cE ' [DdRr] cd_fabricpath$')"    -eq 1
# the table-name-vs-file-base drift TRIPWIRE re-armed (the name-pin law): a
# future row whose table drifts from another file base fires LOUDLY here:
test "$(ls -d "$R/tools/vlan_harness" "$R/tools/ciscometadata_harness" "$R/tools/fabricpath_harness" 2>/dev/null | wc -l)" -eq 0
# ---- nm per-TU U-census (receipts; scratch nm_U 48/24/21 = the 18m §1 face
# EXACT re-pin; tunnel 0/0/0 => the bypass-HOOK witness clone NEVER forced --
# witness_18f rides CARRIED, backbone stays 10; mpls 27+1 rides the DEFERRED
# q4 row receipt face, NEVER built here) ----
for f in cd_vlan cd_ciscometadata cd_fabricpath; do
    nm -C -u "$C/$f.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$f.txt"
    test "$(grep -c 'tunnel' "$H/nm_U_$f.txt" || true)" -eq 0            # 0/0/0 face (the hook is mpls :205/:206 ONLY, q4)
    test "$(grep -c 'SFDAQ' "$H/nm_U_$f.txt" || true)" -eq 0             # the misc3 witness seam NEVER reappears
    test "$(grep -ci mpls "$H/nm_U_$f.txt" || true)" -eq 0               # the deferred row's symbols NEVER leak (q4 NEVER-land face)
done
test "$(wc -l < "$H/nm_U_cd_vlan.txt")" -eq 48                         # MEASURED face (18m §1 re-pin) drift-refused on drift
test "$(wc -l < "$H/nm_U_cd_ciscometadata.txt")" -eq 24
test "$(wc -l < "$H/nm_U_cd_fabricpath.txt")" -eq 21
# the graft-v3 UNDEF face rides the vlan .o EXACTLY-1 (the witness-forcing face):
test "$(grep -c 'daq_msg_get_pkthdr' "$H/nm_U_cd_vlan.txt")" -eq 1
for f in cd_ciscometadata cd_fabricpath; do test "$(grep -c 'daq_msg_get' "$H/nm_U_$f.txt" || true)" -eq 0; done
cat "$H"/nm_U_cd_*.txt | sort -u > "$H/nm_U_union.txt"
test "$(nm -u $ROWS | grep -c get_proto_name || true)" -eq 0
# residue class (MANGLED face; inherited classifier): every snort-family U +
# the daq_msg face of the trio .o MUST be defined by OBJS+WIN+witness_pkthdr
# (the EXACTLY-own-new-census face: NO other symbol of THIS row leaks).
nm -u $ROWS | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
donordefs=$(nm --defined-only $OBJS $WIN "$H"/witness_pkthdr.o | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*|*11daq_msg_get*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# THE witness delta face (the trial-row18n census MEASURED -- rows+OBJS+WIN
# ALONE die at EXACTLY-1 undefined: daq_msg_get_pkthdr; the +1 own-new face
# vs the 18m ZERO face, honestly §9):
if $GXX $ROWS $OBJS "$H"/probe.o $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: trio linked WITHOUT witness_pkthdr -- the +1 graft-v3 delta is wrong"; exit 1
fi
grep "undefined reference to" "$H/L1_link_face.txt" > "$H/L1_undefined.txt"
grep -q "undefined reference to \`daq_msg_get_pkthdr" "$H/L1_link_face.txt"
test "$(grep -oE "undefined reference to \`[^']*'" "$H/L1_link_face.txt" | sort -u | wc -l)" -eq 1   # EXACTLY-1 undefined face
rm -f "$H/.L1_probe"
# witness_18f carries the tunnel T EXACTLY-1 (carried face; the trio carries
# NO bypass U -- nm greps ABOVE prove the backbone never moves):
test "$(nm --defined-only "$H"/witness_18f.o | grep -c 'tunnel_bypass_enabled')" -eq 1
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# landmine posture ZERO (R4): no trio name frozen in ANY witness donor; the
# vocab witness_stubs table census STAYS 4 (NO retirement face this row).
for n in cd_vlan cd_ciscometadata cd_fabricpath; do
    test "$(grep -c "$n" "$R/tools/vocab_harness/witness_stubs.cc" || true)" -eq 0
    test "$(grep -c "$n" "$R/tools/codec_harness/stubs.cc" || true)" -eq 0
    # the ONE tools-wide home stays the legacy copy/codecs/codec_api.cc face
    # (fresh census THIS pass: only vocab copy + THIS dir's own probes)
    test "$(grep -rl "$n" "$R/tools" --include='*.cc' --include='*.h' -I 2>/dev/null | grep -v 'vocab_harness/copy/codecs/codec_api.cc' | grep -v "$R/tools/link4_harness/" | wc -l)" -eq 0
done
test "$(md5sum "$R/tools/vocab_harness/witness_stubs.cc" | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(sed -n '11,14p' "$R/tools/vocab_harness/witness_stubs.cc" | grep -c 'cd_ipv4\|cd_ipv6\|cd_tcp\|cd_hopopts')" -eq 4
# real-symbol defines (donor face, gre-recipe)
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
# the own-new witness defines EXACTLY the graft face (the T-census face):
test "$(nm --defined-only "$H"/witness_pkthdr.o | grep -c 'daq_msg_get_pkthdr')" -eq 1

# ---- probe links: WIN trio + witness_pkthdr (the +1 face) -> GREEN ---------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN "$H"/witness_pkthdr.o -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN "$H"/witness_pkthdr.o -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::SFDAQ::get_local_instance()' || true)" -eq 0   # misc3's tracked witness NEVER linked
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::PacketManager::get_proto_name' || true)" -eq 0 # donor-inherited NEVER linked
grep -q 'tun_witness_set_mask' <<< "$(nm -C "$H"/probe_dec)"       # CARRIED face rides BOTH binaries (witness_18f inherited arm)
grep -q 'pkthdr_witness_set_flags' <<< "$(nm -C "$H"/probe_dec)"   # the OWN graft-v3 observable rides the DEC binary

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in cd_vlan cd_ciscometadata cd_fabricpath; do $GXXA -c "$C/codecs/link/$f.cc" -o "$O2/$f.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc   -o "$O2"/stubs_18d.o; $GXXA -c "$H"/witness_pkthdr.cc -o "$O2"/witness_pkthdr.o
OB2="$O2/cd_vlan.o $O2/cd_ciscometadata.o $O2/cd_fabricpath.o"
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_pkthdr.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_pkthdr.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool b=.*->decode' "$H"/probe_dec.cc)" -eq 16   # MEASURED face (7 vlan + 2 fab + 7 cisco)
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
# FACE-A: THREE TRUE-NAME tables -> THREE single loads (LOADS 1 x3, the
# 18m double-LOAD CONTRAST face):
grep -q '^LOAD vlan$'          "$FA"
grep -q '^LOAD ciscometadata$' "$FA"
grep -q '^LOAD fabricpath$'    "$FA"
test "$(grep -c '^LOADS 1$' "$FA")" -eq 3                     # EXACTLY-3 single-feed face (:234/:233/:184)
test "$(grep -c '^LOADS' "$FA")" -eq 3
grep -q '^HELP vlan support for local area network$'          "$FA"   # ground #define :39 sed-pinned
grep -q '^HELP ciscometadata support for cisco metadata$'     "$FA"   # #define :32
grep -q '^HELP fabricpath support for fabricpath$'            "$FA"   # #define :30
# mod arms ALL REAL x3 (the nullptr-free tail face, contrast 18m 1,1/1,1/0,0):
grep -q '^vlan mod_ctor=1 mod_dtor=1$'          "$FA"
grep -q '^ciscometadata mod_ctor=1 mod_dtor=1$' "$FA"
grep -q '^fabricpath mod_ctor=1 mod_dtor=1$'    "$FA"
for n in vlan ciscometadata fabricpath; do grep -q "^$n ctor=1 dtor=1$" "$FA"; done  # CodecApi slots non-null x3 (:197/:203, :199/:202, :150/:153)
# GETIDS (PROTOCOL_ENUMS ground-walked in python; the vlan SET face asserts AS
# A SET -- unordered_set id_set :103 order NEVER pinned, §8 caution):
grep -q '^GETIDS ciscometadata 35081$' "$FA"   # ETHERTYPE_CISCO_META 0x8909 (protocol_ids.h :161)
grep -q '^GETIDS fabricpath 35075$'    "$FA"   # ETHERTYPE_FPATH 0x8903 :160
test "$(grep -c '^GETIDS vlan ' "$FA")" -eq 4  # the set face: 8021Q + 8021AD + tpid defaults x2 (:103-:112 + ctor default_tpids)
test "$(grep -c '^GETDLT' "$FA" || true)" -eq 0                          # NO data-link registrant in this trio
# DEC ladders (ground call-site arms, receipts row18n + trial):
grep -q '^EV 116 130$' "$V"
test "$(grep -c '^EV 116 130$' "$V")" -eq 3                             # len3 + vid0 + vid4095 ONCE each (the vid0-IGNORE arm NEVER fires it -- THE eval-order pin)
grep -q '^V len3 -> 0 lyr=0$' "$V"                                      # cc :120-:123 EV 130; lyr NEVER set (:123)
grep -q '^V ok -> 1 lyr=4 next=2048 pb=1024$' "$V"                      # :137+:139+:150 face (flag OFF; PROTO_BIT__VLAN 0x400 decode_data.h :97)
grep -q '^V llc -> 1 lyr=4 next=263$' "$V"                              # :134-:135 LLC face (ETHERNET_LLC 0x0107 :134)
grep -q '^V qinq -> 1 lyr=4 next=34984$' "$V"                           # :137 cast face (proto 0x88A8 as-cast)
grep -q '^V vid0-ignore -> 1 lyr=4 next=2048 pb=0$' "$V"                # THE graft-v3 arm: :143 return TRUE BEFORE :145-:148 -> NO EV 130, pb NEVER set (:150 unreached) -- the ext is NOT decorative
grep -q '^V vid0 -> 1 lyr=4 pb=1024$' "$V"                              # SAME bytes flag OFF: :147-:148 fires + :150 -- the V5/V6 CONTRAST
grep -q '^V vid4095 -> 1 lyr=4 pb=1024$' "$V"                           # :147 upper reserved arm
grep -q 'ext:141->143-before-badvid:145->148 pb0-vs-1024' "$V"          # eval-order cite
grep -q '^F len15 -> 0 lyr=0$' "$V"                                     # cc :78-:81 EV 467 (HEADER_LEN 16 cc :70)
grep -q '^F len16 -> 1 next=261 lyr=16$' "$V"                           # :84 next=ETHERNET_802_3 261 (0x0105 :132) BEFORE :85 lyr (the R6 clone)
grep -q 'order-site next:84-before-lyr:85' "$V"                         # fab order cite (18m :160/:161 kin face)
grep -q '^EV 116 468$' "$V"; test "$(grep -c '^EV 116 468$' "$V")" -eq 1 # cc :109 (sizeof hdr 8, copy-tree header)
grep -q '^C len7 -> 0 lyr=0$' "$V"
grep -q '^C ver0 -> 0 lyr=0$' "$V"                                      # :116-:120 stats-only cc :118 -- NO EVENT face (ver0 rides NO EV line)
grep -q '^C lenf0 -> 0 lyr=0$' "$V"                                     # :122-:126 NO EVENT face
grep -q '^EV 116 469$' "$V"; test "$(grep -c '^EV 116 469$' "$V")" -eq 1 # :137 (0x2001 >> OPT_LEN_SHIFT 13 > VALID_OPT_LEN 0)
grep -q '^C optlen1 -> 0 lyr=0$' "$V"
grep -q '^EV 116 470$' "$V"; test "$(grep -c '^EV 116 470$' "$V")" -eq 1 # :144 (type 0x1FFF-mask 2 != SGT 1)
grep -q '^C opttype2 -> 0 lyr=0$' "$V"
grep -q '^EV 116 471$' "$V"; test "$(grep -c '^EV 116 471$' "$V")" -eq 1 # :152 SOFT event sgt 0xFFFF then CONTINUES
grep -q '^C sgtffff -> 1 lyr=8 next=2048 flags=4096 pb=131072$' "$V"    # :155/:157/:159/:160 (CODEC_ETHER_NEXT 0x1000 :106; CISCO_META pb 0x20000 decode_data.h :104)
grep -q '^C clean -> 1 lyr=8 next=2048 flags=4096 pb=131072$' "$V"      # NO-event happy arm, same tail face
grep -q 'ver:116-len:122-opt:130-type:141-sgt:149-lyr:155' "$V"         # cisco order cite
grep -q 'CountType-END:53' "$V"                                         # the peg face cited-not-vectorized (18m §P3 law re-cite)
test "$(grep -c '^EV ' "$V")" -eq 8                                     # 130x3 + 467 + 468 + 469 + 470 + 471
test "$(grep -c 'tunnel\|bypass' "$V" || true)" -eq 0                   # ZERO tunnel face ANYWHERE in vectors (§2/q4)
test "$(grep -c '^EV 11[0-9] 17[0-6]$' "$V" || true)" -eq 0                      # the mpls sid band NEVER fires (q4 NEVER-land face on the vector side; EV-prefixed ONLY -- cite line-numbers NEVER count)
python3 - "$V" "$FA" <<'PYPIN'
# THE sids + protocol-id + CDAPI + extension-face PINNED BOTH WAYS (ground
# enum/#define walks vs the MEASURED vector face -- every value the ladders
# grep rides ground, never air).
import re, sys, subprocess
VF, FAF = sys.argv[1], sys.argv[2]
h = open("/opt/data/snort3-src/src/codecs/codec_module.h").read()
m = re.search(r'enum\s+CodecSid[^{]*\{', h); body = h[m.end():]; val = 0; g = {}
for line in body.split("\n"):
    mm = re.match(r"\s*([A-Z_0-9]+)\s*(?:=\s*(\d+))?\s*,", line)
    if mm:
        name = mm.group(1); val = int(mm.group(2)) if mm.group(2) else val + 1; g[name] = val
    if re.match(r"\s*};", line): break
assert g["DECODE_BAD_VLAN"] == 130 and g["DECODE_FPATH_HDR_TRUNC"] == 467
assert g["DECODE_CISCO_META_HDR_TRUNC"] == 468 and g["DECODE_CISCO_META_HDR_OPT_LEN"] == 469
assert g["DECODE_CISCO_META_HDR_OPT_TYPE"] == 470 and g["DECODE_CISCO_META_HDR_SGT"] == 471
for n in ("DECODE_BAD_VLAN","DECODE_FPATH_HDR_TRUNC","DECODE_CISCO_META_HDR_TRUNC",
          "DECODE_CISCO_META_HDR_OPT_LEN","DECODE_CISCO_META_HDR_OPT_TYPE","DECODE_CISCO_META_HDR_SGT"):
    r = re.findall(rf"{n} = (\d+),", open("/opt/data/snort3-rust/src/codecs/codec_module.rs").read())
    assert r and int(r[0]) == g[n], (n, g[n], r)          # ALREADY resident -- NEVER re-walked
V = set(int(l.split()[2]) for l in open(VF) if l.startswith("EV "))
assert V == {130, 467, 468, 469, 470, 471}, V            # 6 DISTINCT == §1 6/6 resident face
# ground event census of the trio: EXACTLY the 6 tokens call-site-face
for tu, sids in (("cd_vlan.cc",{"DECODE_BAD_VLAN"}),
                 ("cd_fabricpath.cc",{"DECODE_FPATH_HDR_TRUNC"}),
                 ("cd_ciscometadata.cc",{"DECODE_CISCO_META_HDR_TRUNC","DECODE_CISCO_META_HDR_OPT_LEN","DECODE_CISCO_META_HDR_OPT_TYPE","DECODE_CISCO_META_HDR_SGT"})):
    out = subprocess.run(["grep","-oE",r"codec_event\(codec,\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/link/"+tu],capture_output=True,text=True).stdout
    assert set(l.split()[-1] for l in out.splitlines() if l.strip()) == sids, tu
# protocol ids (protocol_ids.h enum hexes -> decimal)
pi = open("/opt/data/snort3-src/src/protocols/protocol_ids.h").read()
pids = {n:int(v,16) for n,v in re.findall(r'^\s*([A-Z_0-9]+)\s*=\s*(0[xX][0-9A-Fa-f]+),', pi, re.M)}
assert pids["ETHERTYPE_8021Q"] == 0x8100 and pids["ETHERTYPE_8021AD"] == 0x88A8
assert pids["ETHERTYPE_FPATH"] == 0x8903 and pids["ETHERTYPE_CISCO_META"] == 0x8909
assert pids["ETHERNET_802_3"] == 0x0105 and pids["ETHERNET_LLC"] == 0x0107
fa = open(FAF).read()
assert f"GETIDS ciscometadata {pids['ETHERTYPE_CISCO_META']}" in fa
assert f"GETIDS fabricpath {pids['ETHERTYPE_FPATH']}" in fa
# THE vlan GETIDS SET face (the §8 unordered-set caution: assert the SET,
# NEVER the iteration order -- id :103-:105 inserts + the ctor tpids :49):
vl = sorted(int(l.split()[2]) for l in open(FAF) if l.startswith("GETIDS vlan "))
assert vl == sorted([pids["ETHERTYPE_8021Q"], pids["ETHERTYPE_8021AD"], 0x9100, 0x9200]), vl
# THE GRAFT-V3 eval-order ground pins (the DEC arms ride these faces ONLY):
ccv = open("/opt/data/snort3-src/src/codecs/link/cd_vlan.cc").read()
assert "codec.lyr_len = sizeof(vlan::VlanTagHdr);" in ccv
assert "const DAQ_PktHdr_t* pkth = daq_msg_get_pkthdr(raw.daq_msg);" in ccv
assert "if (pkth->flags & DAQ_PKT_FLAG_IGNORE_VLAN)" in ccv
l_lyr  = ccv.index("codec.lyr_len = sizeof(vlan::VlanTagHdr);")
l_ext  = ccv.index("daq_msg_get_pkthdr")
l_bad  = ccv.index("if (vid == 0 || vid == 4095)")
l_pb   = ccv.index("codec.proto_bits |= PROTO_BIT__VLAN;")
assert l_lyr < l_ext < l_bad < l_pb, "graft-v3 ground order face moved"
v = open(VF).read()
assert "V vid0-ignore -> 1 lyr=4 next=2048 pb=0" in v and "V vid0 -> 1 lyr=4 pb=1024" in v  # THE contrast face
assert v.count("EV 116 130") == 3
# CDAPI version face derived (base_api.h BASE_API_VERSION + codec.h CDAPI_VERSION)
ba = int(re.search(r'#define\s+BASE_API_VERSION\s+(\d+)', open("/opt/data/snort3-src/src/framework/base_api.h").read()).group(1))
cv = re.search(r'#define\s+CDAPI_VERSION\s+\(\(BASE_API_VERSION\s*<<\s*16\)\s*\|\s*(\d+)\)', open("/opt/data/snort3-src/src/framework/codec.h").read()).group(1)
ver = (ba << 16) | int(cv)
assert fa.count(f"ver={ver}") == 3, ver
assert fa.count("size=112") == 3                          # sizeof(CodecApi) carry (misc3 face UNDISTURBED)
# fabricpath + cisco ground const ladders sed-pinned (names AND values)
ccf = open("/opt/data/snort3-src/src/codecs/link/cd_fabricpath.cc").read()
assert "constexpr uint8_t FABRICPATH_HEADER_LEN = 16;" in ccf
assert "codec.next_prot_id = ProtocolId::ETHERNET_802_3;" in ccf
i_n, i_l = ccf.index("codec.next_prot_id = ProtocolId::ETHERNET_802_3;"), ccf.index("codec.lyr_len = FABRICPATH_HEADER_LEN;")
assert i_n < i_l                                          # the R6 next-before-lyr order face cc :84-:85
ccc = open("/opt/data/snort3-src/src/codecs/link/cd_ciscometadata.cc").read()
for n, val in (("CISCO_META_VALID_HDR_VER","1"),("CISCO_META_VALID_HDR_LEN","1"),
               ("CISCO_META_VALID_OPT_LEN","0"),("CISCO_META_OPT_LEN_SHIFT","13"),
               ("CISCO_META_OPT_TYPE_SGT","1"),("CISCO_META_OPT_TYPE_MASK","0x1FFF")):
    assert re.search(rf"constexpr uint\d+_t {n} = {val};", ccc), n
# copy-tree header sizes the DEC arms ride (the fresh-cp face, trial MEASURED):
assert "constexpr int GID_DECODE = 116;" in h             # the EV prefix face
import subprocess as sp
assert sp.run(["grep","-c","CountType::END","/opt/data/snort3-src/src/codecs/link/cd_ciscometadata.cc"],capture_output=True).stdout == b"1\n"
# the trio rs files LANDED (the PORT-pass flip -- the misc3 :586-:591 /
# link6 :590-:594 precedent; the 588 docs face rides NEXT.md CITES ONLY,
# NEVER asserted here -- this row's re-run cargo face rides the commit msg)
import os
for f in ("cd_vlan.rs","cd_ciscometadata.rs","cd_fabricpath.rs"):
    assert os.path.exists("/opt/data/snort3-rust/src/codecs/"+f)
RS = {f: open("/opt/data/snort3-rust/src/codecs/"+f).read() for f in ("cd_vlan.rs","cd_ciscometadata.rs","cd_fabricpath.rs")}
assert "pub const CD_VLAN: CodecTable = &[&VLAN_API];" in RS["cd_vlan.rs"]                                  # TRUE-NAME const (:231)
assert "pub const CD_CISCOMETADATA: CodecTable = &[&CISCOMETADATA_API];" in RS["cd_ciscometadata.rs"]        # TRUE-NAME const (:230)
assert "pub const CD_FABRICPATH: CodecTable = &[&FABRICPATH_API];" in RS["cd_fabricpath.rs"]                 # TRUE-NAME const (:181)
assert "580 passed / 0 failed" in open("/opt/data/snort3-rust/NEXT.md").read()   # docs CITE only; NEXT.md NEVER touched
PYPIN

# ---- row's measured first-run face PINS (the md5s below are the MEASURED
# FIRST-RUN OUTPUT, drift refuses EVERY build; seeded by the row18n PORT pass --
# the first seed run carries the PLACEHOLDER shapes below, dies loudly, and the
# REAL measured md5s are substituted into this block, then EVERY later run
# refuses drift; build.sh NEVER fabricates) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 28          # MEASURED first-run face
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 24    # MEASURED first-run face
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "c7f5808fa326b7831603813c16a3b01e"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "9fdfc50da8fee22b473028f1f9b29c12"

# ---- known-answer wc+md5 pins (OUTPUT of the MEASURED run; build.sh
# DRIFTS-then-refuses, NEVER fabricates) ----
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)

# ---- frozen-donor direct-md5 census (link6 :616-:636 face VERBATIM, 15
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

# ---- BACKBONE-10 census: the 10-face post-18k PIN STAYS EXACTLY 10 UNDIS-
# TURBED -- the B10 array rides link6 :644-:655 VERBATIM (absolute paths,
# NEVER re-derived); THIS row adds ZERO faces to the array (the own-new wit-
# ness adds +1 BACKBONE SYMBOL face -- the L1 census above -- NEVER a backbone
# ARRAY entry; the array pins the CARRIED lineage). ----
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
test "$(wc -l < "$H"/backbone10.txt)" -eq 10                            # backbone STAYS 10 (this row adds ZERO array faces)
# the link6-fresh x2 direct echo (the IMMEDIATE predecessor lineage = the
# DONOR tree this row clones, byte-ident faces pinned DIRECT like 18m did
# vs erspan):
test "$(md5sum "$L6"/vectors.txt | awk '{print $1}')" = "e59f7a8a70d172261dcb847dcfdcb36a"
test "$(md5sum "$L6"/vectors_faceA.txt | awk '{print $1}')" = "d2fc5591bc45c1787fcee7393675a3d8"
# the erspan-18l pair echo (grandparent donor lineage, link6 :665-:666 face
# re-carried so the TWO predecessor vector-pairs ride byte-ident):
test "$(md5sum "$R/tools/erspan_harness/vectors.txt" | awk '{print $1}')" = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$R/tools/erspan_harness/vectors_faceA.txt" | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"
test "$(md5sum "$MI"/vectors.txt | awk '{print $1}')" = "e75f7385779aa89c365dd2ce4a208b67"
test "$(md5sum "$MI"/vectors_faceA.txt | awk '{print $1}')" = "fe1189c6c78139b8828c1a8071e3df28"

# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" /opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "4826fc2233044a2d5429413faf0ae1af" /opt/data/snort3-rust/tools/fmod_harness/build.sh
# gre GATE anchor (the 18g chain rides this VERBATIM face pin; the grey
# positive-gate CONTRAST face for this row's ZERO-gate 21st-straight pin):
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
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin: the 18i PROCESS-LESSONS law (NEVER pin a harness to
# the working repo's own HEAD -- pin the IMMUTABLE ground only; the daq3
# dirty-guard template rides the rowface block below).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (git ls-files, NEVER pre-typed
# arithmetic): the NON-ignored face of this dir = the 7 stageables -- the
# daq3 7-face PRECEDENT (PLAN.md build.sh probe.cc probe_dec.cc vectors.txt
# vectors_faceA.txt + ONE own-new witness, witness_pkthdr.cc): the +1 graft-
# v3 witness face (trial L1 EXACTLY-1 undefined census) FLIPS the small4/erspan/
# link6 6-face posture (§9 honest record; the ZERO-witness expectation of the
# PLAN §2 headline DISAGREED with the graft-v3 DECL U-face on disk). FACE
# POSTURE (18i re-rule): PRE-commit the 7 are UNTRACKED (--others); POST-commit
# the SAME proof runs vs the landed face. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/link4_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/link4_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 7
for f in PLAN.md build.sh probe.cc probe_dec.cc witness_pkthdr.cc vectors.txt vectors_faceA.txt; do
    echo "$face" | grep -q "tools/link4_harness/$f$"
done
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/cd_vlan.o copy/codecs/link/cd_vlan.cc copy/daq.h copy/daq_common.h o2/cd_vlan.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_18f.o witness_conf.o stubs_18d.o witness_pkthdr.o vectors_O0.txt vectors_faceA_O2.txt nm_U_cd_vlan.txt E4_cd_vlan.txt E4_donorsrc_cd_vlan.txt E4_noapi_cd_vlan.txt E4_restored_cd_vlan.txt E4_vlan_extface.txt L1_link_face.txt L1_undefined.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/link4_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/link4_harness/$f NOT ignored"; exit 1; }
done
# witness_pkthdr.cc NEVER ignored (the tracked stageable face, explicit NOT-
# proof -- the daq3 witness_daq.cc law):
git -C /opt/data/snort3-rust check-ignore -q "tools/link4_harness/witness_pkthdr.cc" && { echo "WITNESS WRONGLY IGNORED"; exit 1; } || true
# vectors NEVER ignored (the stageable face, explicit NOT-proof):
git -C /opt/data/snort3-rust check-ignore -q "tools/link4_harness/vectors.txt" && { echo "VECTORS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/link4_harness/vectors_faceA.txt" && { echo "FACE-A WRONGLY IGNORED"; exit 1; } || true
# no STAGED churn: index EMPTY. Tracked-MODIFIED face (lineage-honest, the
# daq3/misc3/erspan/link6 dirty-guard template; NEVER own-HEAD pin): EVERY dirty
# tracked file must be one of THIS row's sanctioned faces: .gitignore (the
# seed face of the link4 block) OR NEXT.md -- NOTE the honest EXTRA face:
# NEXT.md rides MODIFIED by the sibling DOCS child (NOT this harness pass):
# tolerated, NEVER touched/NEVER staged HERE (the face-guard refuses ANY other
# file). POST-commit the face is EMPTY; fires LOUDLY on any face touching
# another row's/committed lineage file. Rows NEVER rewrite history, NEVER
# git-add, NEVER commit.
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
# rowface guard: the PORT-pass face lists the row's FULL 14 dirty-face
# paths (the erspan :702 / misc3 :754 / link6 :734 landed precedent -- the
# seed-pass face carried ONLY .gitignore + harness stageables; NEXT.md stays
# tolerated for the sibling docs child but is NEVER staged HERE).
rowface='^\.gitignore$|^NEXT\.md$|^src/codecs/(mod\.rs|cd_vlan\.rs|cd_ciscometadata\.rs|cd_fabricpath\.rs)$|^tests/link4_parity_test\.rs$|^PORTING_PLAN\.md$|^KNOWN DEVIATIONS\.md$|^tools/link4_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|witness_pkthdr\.cc|vectors\.txt|vectors_faceA\.txt)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface")"
# SINGLE-TENANT census (orchestrator law, disk-re-checked EVERY build): no
# OTHER harness dir carries dirty TRACKED churn; the ?? fresh dirs NEVER
# collide with this row's face:
dirtyother=$(git -C /opt/data/snort3-rust status --porcelain tools | grep -vE '^\?\? tools/(link4|misc9)_harness/' | grep -v '^.M \.gitignore$' || true)
test -z "$dirtyother"

echo "row-TU nm census (MEASURED, never typed): vlan=$(wc -l < "$H/nm_U_cd_vlan.txt") cisco=$(wc -l < "$H/nm_U_cd_ciscometadata.txt") fab=$(wc -l < "$H/nm_U_cd_fabricpath.txt") union=$(wc -l < "$H/nm_U_union.txt") | union-mangled=$(wc -l < "$H/nm_U_mangled_union.txt") (the 48/24/21 face = the 18m §1 EXACT re-pin; tunnel census 0/0/0 -- the bypass witness NEVER forced, backbone stays $(wc -l < "$H/backbone10.txt") faces PINNED)"
echo "witness posture: ONE own-new witness EXACTLY (witness_pkthdr.cc -- the graft-v3 DECL +1 face, trial L1 EXACTLY-1 undefined census; daq3 +4 precedent cited-SAMPLED; witness_18f bypass T carried exactly x1; SFDAQ/get_proto_name NEVER linked; miscip c5b498ff + trio ef50cd2f DONOR-INHERITED cites) -> probes link GREEN on OBJS+WIN+witness_pkthdr"
echo "graft-v3 ladder: pre find-0 rc1 head-1 daq.h -> master RE-RIDE 33L md5-73fdbc39 rc1 EXACTLY-2 errors (:141:32/:142:23) -> EXT +2 DECL rows 39L md5-0f7016a6 rc0 x3 (syntax/-c/O2; daq3 masters 73fdbc39/f683749c asserts UNDISTURBED ladder-head AND -tail; daq_common.h INHERITED fead0027 DAQ_PktHdr_t :4; enum #2 9b603f8f NEVER here -- mpls q4 owns it)"
echo "fresh-cp face: copy tree = link6-18m 116-tree REUSE clone + daq.h heredoc + vlan.h 50L e68dcca9 + cisco_meta_data.h 43L f5f66631 (the arpa-only header-symmetric duo, cisco cp face 1-NOT-2 VERIFIED f5f66631 pin) + 3 TUs = 122 mid-build (fabricpath ZERO-cp PRE-cp rc0 face re-armed via the trio rc0x3)"
echo "E4 localization BOTH ways: -I src ONLY rc1x3 (vlan head-1 daq.h :29 / cisco+fab api_options via base_api.h:32) + in-tree: vlan.h kills ONLY vlan / cisco hdr kills ONLY cisco / daq.h kills ONLY vlan (pair NON-participation) / text_log kills vlan+cisco, fab SURVIVES (leanest-include trio §1) / codec_module+codec CHAINED kills ALL THREE + restored rc0x3 EVERY build"
echo "hidden-table census: BUILDING_SO sed x3 (:228/:227/:178) + snort_plugins grep 1/1/1 + nm D face TRUE-NAME EQUALITY x3 (cd_vlan/cd_ciscometadata/cd_fabricpath = file bases -- the 18m drift CONTRAST) + feeds :234/:233/:184 + mod arms REAL x6 seds (:217-:218/:216-:217/:167-:168, nullptr faces ABSENT -- contrast 18m) + NAME macros :38/:39 :31/:32 :29/:30 + q4 NEVER-land greps (MPLS 0 in probes; sid band 170-176 0 in vectors)"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED here; tracked gate.txt = 1, ls-files); BACKBONE STAYS 10 (0 own witness ARRAY faces added via the B10 VERBATIM array; receipt backbone10.txt; link6-fresh vectors pair byte-ident DIRECT echo -- the DONOR face)"
echo "LINK4_VLAN_OK vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=0"

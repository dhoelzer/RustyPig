#!/usr/bin/env bash
# mpls_harness -- row 18o: codecs/link/cd_mpls.cc ALONE, 390 L md5 e2911ad5
# (the q4 banked OWN-ROW; the LAST chapter-18 link TU -- the six-file chapter
# ledger 1465 face closes HERE, asserted EVERY build; PLAN §9 pick (a)
# LAND-NOW, (b) defer refused: ch19/19a already landed the framework pair).
# THE HEAVIEST-CLOSURE ROW OF THE LINK CHAPTER (the headline cost): 7 FRESH
# CPS -- flow/flow.h 637 L (the ip-rows PRE-PAY rider: flow_data/flow_stash/
# deferred_trust/ips_context_chain + time/clock_defs riders 5) + utils/safec.h
# 42 L. The clock_defs face CORRECTS the 18n-docs 6-cp face (closure step-6
# fatal flow.h:51, scratch row18o/closure_log.txt -- riders 5, total 7).
# THE EXT#2 GRAD EXTENSION (the SECOND graft-extension row): flow.h :541
# DAQ_Verdict last_verdict = MAX_DAQ_VERDICT -- grep-0 NEVER-LAND face in all
# four landed daq faces; the flow.h cp DEMANDS it (disk forced, CONDITIONAL
# arm) -> graft-v2 daq_common.h fead0027 + the enum#2 rows (PASS..MAX=6, the
# sfdaq_module.cc :179 static_assert face) = 34 L md5 9b603f8f heredoc
# COPY-LOCAL ONLY (the masters daq.h 73fdbc39 / daq_common f683749c + the
# link4 INHERITED copy face fead0027 md5-asserted UNDISTURBED ladder HEAD
# AND TAIL; NEVER promoted, row 20 re-cites the REAL SDK; SYNTHETIC enum
# values NEVER ABI truth). graft-v3 daq.h 0f7016a6 rides INHERITED from the
# 122-tree clone AND is NEVER consumed by this TU (daq grep-ci cd_mpls = 0 --
# the daq.h-drop SURVIVES rc0 inversion face vs 18n where it killed vlan).
# THE SAFEC STOCK-SHIM DECISION (MEASURED, C15 receipts): config.h HAVE_SAFEC
# grep-0 -> the stock 42-L safec.h takes its #else shim (memcpy_s -> memcpy);
# the EXACTLY-1 use-site :267 needs ZERO safe_*_lib grafts and ZERO shim
# authoring (the strip arm moves the wall to the :30 include, NOT to :267).
# THE WITNESS FACE, MEASURED NOT PRE-PICKED (PLAN §7 stageable law): the hook
# U CLOSES against the INHERITED witness_18f (ea1f79f3 T tunnel_bypass EX-
# ACTLY-1, zero clone cost -- the tunnel twin arm rides the tun mask probe);
# OWN L1 census (row .o + OBJS + WIN + probe, own witness WITHOUT) = EX-
# ACTLY-1 distinct undefined ROW symbol: snort::Flow::get_mpls_layer_per_dir
# (bool) (definer census find-0 across ALL harness .o) -> witness_flow.cc
# own-new 7-stageable FLIP (the daq3/link4/misc9 7-face law; the 27-L miscip
# mirror shape; backbone array STAYS EXACTLY 10 -- symbol-vs-array rule).
# THE -DNDEBUG law (misc9 precedent re-armed): cd_mpls.cc :259 is the row's
# own assert face; ground production arm compiles BOTH the row TU and the
# graph -DNDEBUG; honest nm delta face: non-NDEBUG era 28 U (scratch) vs the
# NDEBUG row face (MEASURED this build, one __assert_fail pull lighter).
# THE ZERO-GATE row (the 19a-docs lineage face counts 24 straight INCLUDING 19a; this row adds the 25th): link/test find-0 + add_cpputest 0 + gate
# tokens grep-0 in the TU (CppUTest host find-0 era law). vectors: the sid
# band 170-176 FIRES POSITIVE in ITS OWN vectors THE FIRST TIME (the q4
# NEVER-land census FLIPS AT the row; landed harnesses UNDISTURBED -- their
# own NEVER-land greps stay TRUE). NAME/HELP DISK :34/:35 (the docs :33/:34
# face DEAD, re-sed). PROTO_BIT__MPLS 512 = the rtn_checks.rs :34 RESIDENT
# reuse face (the row-scoped-NEW const docs face STALE).
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness
L4=$R/tools/link4_harness            # THE donor (18n 122-tree) -- REUSE clone
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
L=$SRC/src/codecs/link
C=$H/copy

# ---- ground identity (the OWNING TU pinned by OWN md5 + wc, measured) ----
test "$(md5sum "$L/cd_mpls.cc" | awk '{print $1}')" = "e2911ad515d5f416415acd1ee9967379"
test "$(wc -l < "$L/cd_mpls.cc")" -eq 390
# the chapter ledger FACE CLOSES at this row: 390+236+235+187+207+210 = 1465
test "$(( $(wc -l < "$L/cd_mpls.cc") + $(wc -l < "$L/cd_vlan.cc") + $(wc -l < "$L/cd_pppoe.cc") + $(wc -l < "$L/cd_ciscometadata.cc") + $(wc -l < "$L/cd_fabricpath.cc") + $(wc -l < "$L/cd_ppp_encap.cc") ))" -eq 1465
# gate-token grep ZERO (STOP-flag; zero-gate lineage: 19a/docs count
# 19a as the 24th straight -- THIS row's re-measures = the 25th)
test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST\|CppUTest' "$L/cd_mpls.cc" || true)" -eq 0

# ---- THE zero-gate census (MEASURED EVERY BUILD, never typed) ----
test ! -d "$L/test"
test "$(find "$L" -type d -name test | wc -l)" -eq 0
test "$(grep -c 'add_cpputest' "$L/CMakeLists.txt" || true)" -eq 0
test "$(grep -c 'add_dynamic_module(cd_mpls codecs cd_mpls.cc)' "$L/CMakeLists.txt")" -eq 1

# ---- THE hidden table (BUILDING_SO split) -- sed census PIN lines ----
test "$(sed -n '382p' "$L/cd_mpls.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '383p' "$L/cd_mpls.cc")" = "SO_PUBLIC const BaseApi* snort_plugins[] ="
test "$(sed -n '385p' "$L/cd_mpls.cc")" = "const BaseApi* cd_mpls[] ="     # TRUE-NAME table (18n equality law)
test "$(sed -n '386p' "$L/cd_mpls.cc")" = "#endif"
test "$(sed -n '388p' "$L/cd_mpls.cc")" = "    &mpls_api.base,"
test "$(grep -c 'BUILDING_SO'  "$L/cd_mpls.cc")" -eq 1
test "$(grep -c 'snort_plugins' "$L/cd_mpls.cc")" -eq 1

# ---- NAME/HELP at the DISK-CORRECTED :34/:35 (the NEXT :33/:34 docs face
# re-sed DEAD this pass; use-sites :80/:111/:369/:370) ----
test "$(sed -n '34p' "$L/cd_mpls.cc")" = '#define CD_MPLS_NAME "mpls"'
test "$(sed -n '35p' "$L/cd_mpls.cc")" = '#define CD_MPLS_HELP "support for multiprotocol label switching"'

# ---- mod arms ALL REAL + the CONFIG-CARRYING ctor :347 (the 'if (m)'
# :349-:354 thread -- contrast link4 trio :199/:150 Module*-ignored ctors) ----
test "$(sed -n '341p' "$L/cd_mpls.cc")" = "static Module* mod_ctor()"
test "$(sed -n '344p' "$L/cd_mpls.cc")" = "static void mod_dtor(Module* m)"
test "$(sed -n '347p' "$L/cd_mpls.cc")" = "static Codec* ctor(Module* m)"
test "$(sed -n '371p' "$L/cd_mpls.cc")" = "        mod_ctor,"
test "$(sed -n '372p' "$L/cd_mpls.cc")" = "        mod_dtor,"

# ---- Parameters :48-:57 TWO params (the -1 depth sentinel + the enum-
# alignment face :41 'Entries must align with payload_type enum') ----
test "$(sed -n '50p' "$L/cd_mpls.cc")" = '    { "max_stack_depth", Parameter::PT_INT, "-1:255", "-1",'
test "$(sed -n '53p' "$L/cd_mpls.cc")" = '    { "payload_type", Parameter::PT_ENUM, "auto | eth | ip4 | ip6", "auto",'
test "$(sed -n '41p' "$L/cd_mpls.cc")" = '    // Entries must align with payload_type enum parameter in mpls_params'

# ---- RuleMap :59-:69: sids :61-:67 (7) + terminator :68; the 7/7 RESIDENT
# face codec_module.rs :113-:119 (ZERO new consts; grep-c 7 below) ----
test "$(sed -n '61p' "$L/cd_mpls.cc")" = "    { DECODE_BAD_MPLS, \"bad MPLS frame\" },"
test "$(sed -n '67p' "$L/cd_mpls.cc")" = "    { DECODE_MPLS_LABEL_STACK, \"too many MPLS headers\" },"
test "$(sed -n '68p' "$L/cd_mpls.cc")" = "    { 0, nullptr }"
test "$(grep -c 'codec_event' "$L/cd_mpls.cc")" -eq 7
for i in 113 114 115 116 117 118 119; do
    grep -q 'DECODE_.*MPLS' <(sed -n "${i}p" "$R/src/codecs/codec_module.rs")
done
test "$(sed -n '113p' "$R/src/codecs/codec_module.rs")" = "    DECODE_BAD_MPLS = 170,  // h:100"
test "$(sed -n '119p' "$R/src/codecs/codec_module.rs")" = "    DECODE_MPLS_LABEL_STACK = 176,  // h:106"

# ---- the bypass hook :205/:206 (the trio's 0/0/0 hand-off CLOSED) + the
# TUNNEL_MPLS 0x80 pin + the row-scoped PROTO_BIT RESIDENT face ----
test "$(sed -n '205,206p' "$L/cd_mpls.cc" | grep -c tunnel_bypass)" -eq 2
test "$(sed -n '126p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_MPLS   = 0x80,"
test "$(grep -c 'PROTO_BIT__MPLS             0x000200' "$SRC/src/framework/decode_data.h")" -eq 1
test "$(sed -n '34p' "$R/src/detection/rtn_checks.rs")" = "pub const PROTO_BIT__MPLS: u32 = 0x000200;"   # RESIDENT -- ZERO new const (the row-scoped-NEW docs face MOVED)
# flowip NEVER pulled + the EXACTLY-1 memcpy_s face + the daq NON-
# participation face (the TU itself NEVER names daq -- contrast vlan :29):
test "$(grep -ci 'flowip\|flow_ip' "$L/cd_mpls.cc" || true)" -eq 0
test "$(grep -c 'memcpy_s' "$L/cd_mpls.cc")" -eq 1
test "$(grep -ci daq "$L/cd_mpls.cc" || true)" -eq 0
# the Flow-method decl face + the ground definer (the mirror's cite):
test "$(sed -n '223p' "$SRC/src/flow/flow.h")" = "    Layer* get_mpls_layer_per_dir(bool);"
test "$(sed -n '447p' "$SRC/src/flow/flow.cc" | grep -c 'Flow::get_mpls_layer_per_dir')" -eq 1

# ---- externs + loads + ladder ALL RESIDENT (rows ADD TUs, NEVER touch) ----
test "$(sed -n '61p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_mpls[];"
test "$(sed -n '106p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_mpls);"
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern census UNDISTURBED
test "$(sed -n '119p' "$R/src/codecs/codec_api.rs")" = '    "cd_mpls",'
test "$(sed -n '97p'  "$R/src/codecs/codec_api.rs")" = 'pub const STATIC_CODEC_EXTERN_NAMES: [&str; 34] = ['  # tripwire UNDISTURBED

# ---- NEXT.md cargo CITE faces (docs CITE only, NEVER edited, NEVER run
# here): the 19a docs pass SEEDED the 605 face FOR this harness (grep law);
# the 597 exact-count trio stays misc9 :462/:607's pin NEVER re-asserted here.
grep -q "605 tests green / 0 FAILED" "$R/NEXT.md"
grep -q "580 passed / 0 failed" "$R/NEXT.md"
grep -q "588 tests green / 0 FAILED" "$R/NEXT.md"

# ---- copy tree = link4-18n 122-tree REUSE clone (the graft-v3 daq.h
# 0f7016a6 + graft-v2 daq_common.h fead0027 ride INHERITED, NEVER re-author-
# ed); daq_dlt.h face rides; daq.h NEVER consumed by this TU (grep-ci daq 0
# above -- the daq.h-drop SURVIVES inversion arm rides E4). ----
# donor self-heal guard (the cross-script 'bash link4/build.sh' auto-heal was
# DROPPED here for lifecycle-scanner budget reasons -- the 122-tree census
# RIGHT BELOW fires LOUDLY if the donor was ever pruned; the operator re-runs
# the 18n row by hand in that case; NO silent depth-2 script invocation):
test -e "$L4/copy/codecs/link/cd_vlan.cc" -a -e "$L4/copy/config.h" || { echo "DONOR DEAD: tools/link4_harness/copy pruned -- re-run the 18n link4 row by hand (NEVER auto-heal from this script)"; exit 1; }
rm -rf "$C"; cp -a "$L4/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 122   # donor face MEASURED (the 18n landing head)
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"       # graft-v3 INHERITED (the ladder rides ONLY ext#2)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf" # graft-v2 INHERITED head face
# THE flowz DECOY law re-armed (18m §5.7): the include TEXT flow/flow_data.h
# = find-0; the donor flowz/ copy NEVER satisfies it -- fresh cp MEASURED:
test "$(find "$C" -name 'flow.h' | wc -l)" -eq 0
test "$(find "$C" -name 'safec.h' | wc -l)" -eq 0
test "$(find "$C" -name 'flow_data.h' -not -path '*flowz*' | wc -l)" -eq 0
test "$(find "$C" -name 'deferred_trust.h' | wc -l)" -eq 0
test "$(find "$C" -name 'flow_stash.h' | wc -l)" -eq 0
test "$(find "$C" -name 'ips_context_chain.h' | wc -l)" -eq 0
test "$(find "$C" -name 'clock_defs.h' | wc -l)" -eq 0
# the clock_defs rider face (the 6-vs-7 CPS CORRECTION rides here: step-6
# fatal flow.h:51 at the reconstructed head -- closure_log.txt receipt):
test "$(wc -l < "$SRC/src/flow/flow.h")" -eq 637
test "$(md5sum "$SRC/src/flow/flow.h" | awk '{print $1}')" = "765663d466f59ac9af76344d4ba1de9b"
test "$(wc -l < "$SRC/src/utils/safec.h")" -eq 42
test "$(md5sum "$SRC/src/utils/safec.h" | awk '{print $1}')" = "4d366338cf2c774a0e744d32c428b980"
test "$(grep -c 'HAVE_SAFEC' "$C/config.h" || true)" -eq 0        # the stock #else-shim decision face (C15 law)
test "$(grep -c 'memcpy' "$SRC/src/utils/safec.h")" -ge 1          # the shim IS in the stock header (:23+ face)
mkdir -p "$C/flow" "$C/time" "$C/detection" "$C/utils" "$C/codecs/link"
cp "$SRC/src/flow/flow.h" "$C/flow/flow.h";                         cmp -s "$C/flow/flow.h" "$SRC/src/flow/flow.h"
cp "$SRC/src/utils/safec.h" "$C/utils/safec.h";                     cmp -s "$C/utils/safec.h" "$SRC/src/utils/safec.h"
cp "$SRC/src/flow/flow_data.h" "$C/flow/flow_data.h";               cmp -s "$C/flow/flow_data.h" "$SRC/src/flow/flow_data.h"
cp "$SRC/src/flow/deferred_trust.h" "$C/flow/deferred_trust.h";     cmp -s "$C/flow/deferred_trust.h" "$SRC/src/flow/deferred_trust.h"
cp "$SRC/src/flow/flow_stash.h" "$C/flow/flow_stash.h";             cmp -s "$C/flow/flow_stash.h" "$SRC/src/flow/flow_stash.h"
cp "$SRC/src/detection/ips_context_chain.h" "$C/detection/ips_context_chain.h"; cmp -s "$C/detection/ips_context_chain.h" "$SRC/src/detection/ips_context_chain.h"
cp "$SRC/src/time/clock_defs.h" "$C/time/clock_defs.h";             cmp -s "$C/time/clock_defs.h" "$SRC/src/time/clock_defs.h"
cp "$L/cd_mpls.cc" "$C/codecs/link/cd_mpls.cc";                     cmp -s "$C/codecs/link/cd_mpls.cc" "$L/cd_mpls.cc"

GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C"

# ---- THE EXT#2 LADDER (re-run EVERY build; graft-v3 law: COPY-LOCAL her-
# edoc ONLY, masters md5-asserted UNDISTURBED head AND tail). ARM #1 (pre-
# ext): the 7-cp tree MUST die at EXACTLY-1 error -- flow.h:541 MAX_DAQ_-
# VERDICT not declared (the CONDITIONAL-arm trigger, scratch E_final_preext
# face re-armed; NEVER decorative: the flow.h cp DEMANDS the enum): ----
if $GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" -o /dev/null 2> "$H/E4_preext_cd_mpls.txt"; then
    echo "EXT-FACE DEAD: cd_mpls compiled on the graft-v2 enum face -- the MAX_DAQ_VERDICT closure gap is wrong"; exit 1
fi
test "$(grep -c 'error:' "$H/E4_preext_cd_mpls.txt")" -eq 1
grep -q "flow/flow.h:541:.*MAX_DAQ_VERDICT.* was not declared" "$H/E4_preext_cd_mpls.txt"
# masters CITE head (the heredoc NEVER cp's, NEVER edits them):
test "$(md5sum "$D3/copy/daq.h"       | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$L4/copy/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"
# the NEVER-land census RE-PROVED (the ext rides copy-local ONLY):
for f in "$D3/copy/daq.h" "$D3/copy/daq_common.h" "$L4/copy/daq_common.h" "$C/daq.h"; do
    test "$(grep -c 'MAX_DAQ_VERDICT' "$f" || true)" -eq 0
done
# ARM #2 (enum EXTENSION #2): the graft-v2 28 L base + the MAX=6 face on the
# 3 lines flow.h :541 + sfdaq_module.cc :179 demand (the enum-transcription
# face; SYNTHETIC values NEVER ABI truth -- row 20 re-cites the real SDK).
cat > "$C/daq_common.h" <<'EOFEXT2'
#pragma once
#include <cstdint>
typedef const void* DAQ_Msg_h;
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
// scratch row18k probe EXTENSION: the sfdaq-pair face NEVER pulled by ANY
// earlier row (grep census: DAQ_Config_h DAQ_Instance_h DAQ_RecvStatus
// DAQ_Stats_t DAQ_Verdict DAQ_IoctlCmd DAQ_SUCCESS + the const face of
// DAQ_Msg_h the ground cd_user.cc:101 aggregate-init demands).
#undef  DAQ_Msg_h_placeholder
typedef uint32_t DAQ_IoctlCmd;
typedef void* DAQ_Config_h;
typedef void* DAQ_Instance_h;
// row18n graft-v3 EXTENSION #2 CANDIDATE (copy-local ONLY, master NEVER touched):
// flow.h :541 `DAQ_Verdict last_verdict = MAX_DAQ_VERDICT` + ground
// sfdaq_module.cc:179 static_assert MAX_DAQ_VERDICT == 6. graft-v2 enum carries
// PASS/DROP ONLY (fead0027 :25) => enum-extension face w/ MAX_DAQ_VERDICT == 6:
typedef enum { DAQ_Verdict_PASS = 0, DAQ_Verdict_DROP = 1, DAQ_Verdict_PAUSE = 2,
    DAQ_Verdict_IGNORE = 3, DAQ_Verdict_WAITING = 4, DAQ_Verdict_COUNT = 5,
    MAX_DAQ_VERDICT = 6 } DAQ_Verdict;
typedef enum { DAQ_RECV_STATUS_OK = 0 } DAQ_RecvStatus;
typedef struct { uint64_t pkgs_received; } DAQ_Stats_t;
#define DAQ_SUCCESS 0
EOFEXT2
test "$(wc -l < "$C/daq_common.h")" -eq 34
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"   # the banked candidate face md5-EXACT (scratch row18n -> row18o survival re-proved)
# the sfdaq static_assert face RE-ARMED standalone (the :179 path-trap cite
# ground: sfdaq_module.cc NOT main/):
cat > "$H/.assert_ext2.cc" <<'EOFAS'
#include <daq_common.h>
static_assert(MAX_DAQ_VERDICT == 6, "Verdict peg counts must align with MAX_DAQ_VERDICT");
int main(){ return (int)MAX_DAQ_VERDICT - 6; }
EOFAS
$GXX0 "$H/.assert_ext2.cc" -o "$H/.assert_ext2"      # compile rc0
"$H/.assert_ext2"; test "$?" -eq 0                    # run rc0 (6-6)
test "$(cat "$SRC/src/packet_io/sfdaq_module.cc" | sed -n '179p' | grep -c 'static_assert(MAX_DAQ_VERDICT == 6')" -eq 1
# post-ext rc0 x3 (syntax / -c / O2 -- the NDEBUG production arm):
$GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" 2> "$H/E4_postext_cd_mpls.txt"
test ! -s "$H/E4_postext_cd_mpls.txt"
# masters + the link4 INHERITED face UNDISTURBED at the ladder TAIL (the
# heredoc wrote ONLY the copy-local face):
test "$(md5sum "$D3/copy/daq.h"       | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$L4/copy/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 130   # 122 donor + 7 cps + THIS TU (RE-DERIVED, never pre-assumed as a carried count)

# ---- E4 LOCALIZATION ARMS BOTH WAYS: (a) stripped-donor arm -I src ONLY
# MUST die rc1 at the flow.h:39 <daq_common.h> chained fatal (the C14
# donor face re-armed); (b) IN-TREE walls MEASURED for this row: flow.h
# drop -> fatal :26; flow_data drop -> flow.h:43; clock_defs drop ->
# flow.h:51 (the rider face); safec drop -> fatal :30 (NOT :267 -- the
# stock-shim absorbs the use-site, the C15 strip receipt law); daq.h drop ->
# SURVIVES rc0 (the DAQ NON-PARTICIPATION inversion: the trio rule that
# daq.h kills ONLY vlan NEVER claims mpls); the chained codec_module+codec
# wall kills the row; restored full tree rc0 EVERY build ----
GXXD="g++ -std=c++17 -DNDEBUG -O0 -w -I$SRC/src"
if $GXXD -fsyntax-only "$SRC/src/codecs/link/cd_mpls.cc" 2> "$H/E4_donorsrc_cd_mpls.txt"; then
    echo "E4 LOCALIZATION DEAD: cd_mpls compiled on the -I src ONLY arm -- the stripped-tree rc1 face is wrong"; exit 1
fi
# NOTE the face vs link4's head-1 pin: the mpls fatal is NESTED (flow.h:39
# reached via cc:26) so line-1 is the "In file included from" face -- the
# fatal + the flow.h:39 chain face are grepped SEPARATELY (C14 receipt face).
grep -q "fatal error: daq_common.h: No such file" "$H/E4_donorsrc_cd_mpls.txt"
grep -q "flow/flow.h:39" "$H/E4_donorsrc_cd_mpls.txt"
head -1 "$H/E4_donorsrc_cd_mpls.txt" | grep -q "In file included from .*cd_mpls.cc:26"
mv "$C/flow/flow.h" "$H/.e4_hold_flow.h"
if $GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" -o /dev/null 2> "$H/E4_noflow_cd_mpls.txt"; then
    echo "E4 flip BROKE: cd_mpls compiled WITHOUT flow/flow.h (cc:26)"; exit 1
fi
head -1 "$H/E4_noflow_cd_mpls.txt" | grep -q "fatal error: flow/flow.h: No such file"
mv "$H/.e4_hold_flow.h" "$C/flow/flow.h"
mv "$C/flow/flow_data.h" "$H/.e4_hold_flow_data.h"
if $GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" -o /dev/null 2> "$H/E4_noflowdata_cd_mpls.txt"; then
    echo "E4 flip BROKE: cd_mpls compiled WITHOUT the fresh flow_data.h cp (the flowz decoy NEVER satisfies flow/)"; exit 1
fi
grep -q "flow/flow.h:43.*flow_data.h" "$H/E4_noflowdata_cd_mpls.txt"
mv "$H/.e4_hold_flow_data.h" "$C/flow/flow_data.h"
mv "$C/time/clock_defs.h" "$H/.e4_hold_clock_defs.h"
if $GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" -o /dev/null 2> "$H/E4_noclock_cd_mpls.txt"; then
    echo "E4 flip BROKE: compiled WITHOUT time/clock_defs.h -- the 7th-cp (rider-5) face is wrong"; exit 1
fi
grep -q "flow/flow.h:51.*clock_defs.h" "$H/E4_noclock_cd_mpls.txt"
mv "$H/.e4_hold_clock_defs.h" "$C/time/clock_defs.h"
mv "$C/utils/safec.h" "$H/.e4_hold_safec.h"
if $GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" -o /dev/null 2> "$H/E4_nosafec_cd_mpls.txt"; then
    echo "E4 flip BROKE: compiled WITHOUT utils/safec.h"; exit 1
fi
head -1 "$H/E4_nosafec_cd_mpls.txt" | grep -q "fatal error: utils/safec.h: No such file"
test "$(grep -c 'cd_mpls.cc:267' "$H/E4_nosafec_cd_mpls.txt" || true)" -eq 0   # the wall is the INCLUDE, never the :267 use-site (stock #else-shim absorbs it)
mv "$H/.e4_hold_safec.h" "$C/utils/safec.h"
mv "$C/daq.h" "$H/.e4_hold_daq.h"
$GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" 2> "$H/E4_nodaq_cd_mpls.txt"   # the SURVIVES inversion (dq.h NON-participation face -- flow.h's <daq_common.h> rides the copy-local ext2, NOT daq.h)
test ! -s "$H/E4_nodaq_cd_mpls.txt"
mv "$H/.e4_hold_daq.h" "$C/daq.h"
mv "$C/codecs/codec_module.h" "$H/.e4_hold_codec_module.h"
mv "$C/framework/codec.h" "$H/.e4_hold_codec.h"
if $GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" -o /dev/null 2> "$H/E4_noapi_cd_mpls.txt"; then
    echo "E4 flip BROKE: cd_mpls compiled WITHOUT codec_module.h+codec.h (the DIRECT chained edges)"; exit 1
fi
head -1 "$H/E4_noapi_cd_mpls.txt" | grep -q "fatal error: codecs/codec_module.h: No such file"
mv "$H/.e4_hold_codec_module.h" "$C/codecs/codec_module.h"
mv "$H/.e4_hold_codec.h" "$C/framework/codec.h"
$GXX0 -fsyntax-only "$C/codecs/link/cd_mpls.cc" 2> "$H/E4_restored_cd_mpls.txt"
test ! -s "$H/E4_restored_cd_mpls.txt"

# ---- witness posture: ONE own-new witness (the MEASURED EXACTLY-+1 L1 face
# -- Flow::get_mpls_layer_per_dir, the encode-path mirror) + the carried WIN
# trio (witness_18f ea1f79f3 CARRIED -- the hook U needs ZERO clone: the 18n
# clone face; witness_conf 4dd91018 VERBATIM re-materialize; stubs_18d
# f4afd35f). The bypass-ON/OFF arms ride the witness_18f tun_mask observable
# (the tun_harness mask-pair precedent; TUNNEL_MPLS 0x80). ----
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
test "$(wc -l < "$H/witness_flow.cc")" -eq 27
test "$(find "$H" -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 1   # EXACTLY-1 own-new
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

GXX="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"

# ---- O0 compile: the row .o + donor REAL .o + probes + witnesses ----
$GXX -c "$C/codecs/link/cd_mpls.cc" -o "$C/cd_mpls.o"
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc   -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc    -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc     -o "$H"/stubs_18d.o
$GXX -c "$H"/witness_flow.cc    -o "$H"/witness_flow.o     # the own-new face (tracked stageable #7)

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROW="$C/cd_mpls.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# hidden-table one-symbol face (TRUE-NAME table: the nm D-face EQUALS the
# file base -- the 18m drift-inequality NEVER applies at this row):
test "$(nm --defined-only "$C/cd_mpls.o" | grep -cE ' [DdRrBb] cd_mpls$')" -eq 1

# ---- nm per-TU U-census (receipts; the NDEBUG row face MEASURED this build
# -- the non-NDEBUG scratch era face 28 rides §11 with the honest __assert_-
# fail delta; tunnel-U EXACTLY-1 closes vs the CARRIED witness; the gre-
# harness exactly-ONE-U census law re-armed): ----
nm -C -u "$C/cd_mpls.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_cd_mpls.txt"
test "$(grep -c 'SnortConfig::tunnel_bypass_enabled' "$H/nm_U_cd_mpls.txt")" -eq 1   # the gre :298 exactly-ONE-U clone
test "$(grep -c 'Flow::get_mpls_layer_per_dir' "$H/nm_U_cd_mpls.txt")" -eq 1         # the witness-FORCING face (MEASURED, never pre-picked)
test "$(grep -ci 'daq_msg\|SFDAQ' "$H/nm_U_cd_mpls.txt" || true)" -eq 0              # the graft/U non-participation face (the TU NEVER names daq)
test "$(grep -c '__assert_fail' "$H/nm_U_cd_mpls.txt" || true)" -eq 0                # the NDEBUG production arm face
# the mirror's definer census re-proved MEASURED (find-0 across EVERY harness
# .o EXCLUDING this row's own -- misc9-excluded per the copy law):
defin=0
for o in "$R"/tools/*/copy/*.o "$R"/tools/*/*.o; do
    case "$o" in "$H"/*) continue;; esac
    [ -e "$o" ] || continue
    if nm --defined-only "$o" 2>/dev/null | grep -q 'get_mpls_layer_per_dir'; then defin=$((defin+1)); fi
done
test "$defin" -eq 0
cat "$H"/nm_U_cd_mpls.txt | sort -u > "$H/nm_U_union.txt"
nm -u $ROW | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
# residue class (MANGLED face; inherited classifier): every snort-family U
# of the row MUST be defined by OBJS+WIN+witness_flow (the EXACTLY-own-new
# census face -- NO other symbol of THIS row leaks):
donordefs=$(nm --defined-only $OBJS $WIN "$H"/witness_flow.o | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# THE witness delta face (the staged L1 census MEASURED -- row+OBJS+WIN+probe
# WITHOUT the own witness die at EXACTLY-1 undefined: the Flow method; the
# +1 own-new face vs the 18m ZERO face, honestly recorded §11):
if $GXX $ROW $OBJS "$H"/probe.o $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: the row linked WITHOUT witness_flow -- the +1 Flow delta is wrong"; exit 1
fi
grep "undefined reference to" "$H/L1_link_face.txt" > "$H/L1_undefined.txt"
grep -q "undefined reference to \`snort::Flow::get_mpls_layer_per_dir" "$H/L1_link_face.txt"
test "$(grep -oE "undefined reference to \`[^']*'" "$H/L1_link_face.txt" | sort -u | wc -l)" -eq 1   # EXACTLY-1 undefined face
rm -f "$H/.L1_probe"
# witness_18f carries the tunnel T EXACTLY-1 (the INHERITED face -- the hook
# cost ZERO clones; backbone NEVER moves):
test "$(nm --defined-only "$H"/witness_18f.o | grep -c 'tunnel_bypass_enabled')" -eq 1
test "$(nm --defined-only "$H"/witness_flow.o | grep -c 'get_mpls_layer_per_dir')" -eq 1   # the own-new T census
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# landmine posture: the vocab witness_stubs table stays the ONLY retirement
# landmine (4 externs); mpls retires NOTHING (grep-0 face):
for n in cd_mpls mpls; do
    test "$(grep -c "$n" "$R/tools/vocab_harness/witness_stubs.cc" || true)" -eq 0
    test "$(grep -c "$n" "$R/tools/codec_harness/stubs.cc" || true)" -eq 0
done
test "$(md5sum "$R/tools/vocab_harness/witness_stubs.cc" | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(sed -n '11,14p' "$R/tools/vocab_harness/witness_stubs.cc" | grep -c 'cd_ipv4\|cd_ipv6\|cd_tcp\|cd_hopopts')" -eq 4
# real-symbol defines (donor face, gre-recipe):
grep -q 'T snort::Codec::codec_event' <<< "$(nm -C --defined-only "$C"/codec.o)"
grep -q 'T snort::Module::Module' <<< "$(nm -C --defined-only "$C"/module.o)"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"   # the log():332 U-close (cited-never-CALLED face)

# ---- probe links: WIN trio + witness_flow (the +1 face) -> GREEN ---------
$GXX $ROW $OBJS "$H"/probe.o      $WIN "$H"/witness_flow.o -o "$H"/probe
$GXX $ROW $OBJS "$H"/probe_dec.o $WIN "$H"/witness_flow.o -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::SFDAQ::get_local_instance()' || true)" -eq 0   # misc3's tracked witness NEVER linked
grep -q 'tun_witness_set_mask' <<< "$(nm -C "$H"/probe_dec)"       # the CARRIED bypass-hook observable rides DEC (witness_18f inherited arm)
test "$(nm -C "$H"/probe_dec | grep -c 'T snort::Flow::get_mpls_layer_per_dir' || true)" -eq 1   # the own-new T rides the DEC binary -- the encode arm is LIVE, never cited-dead HERE

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
$GXXA -c "$C/codecs/link/cd_mpls.cc" -o "$O2/cd_mpls.o"
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc   -o "$O2"/stubs_18d.o; $GXXA -c "$H"/witness_flow.cc -o "$O2"/witness_flow.o
OB2="$O2/cd_mpls.o"
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_flow.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_flow.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool b=.*->decode' "$H"/probe_dec.cc)" -eq 18   # MEASURED face RE-PINNED this run (18 decode arms; my seed draft predicted 19 -- the pin follows the GREP, never the draft)
test "$(grep -c 'bool e0=\|bool e1=' "$H"/probe_dec.cc)" -eq 2   # the encode VAR arms
test "$(grep -c 'printf.*->decode' "$H"/probe_dec.cc || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_O0.txt || true)" -eq 0    # all-decimal hygiene
test "$(grep -c '0x' "$H"/vectors_faceA_O0.txt || true)" -eq 0

# ---- known-answer seeds: FIRST run seeds the tracked faces; later runs
# cmp-refuse drift. ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi

# ---- known-answer ladders: greps pin the MEASURED faces against GROUND
# anchors (17p: values NEVER typed -- ground sed/enum walks below). ----
# FACE-A (the config-carrying load face):
grep -q '^LOAD mpls$'                    "$FA"
test "$(grep -c '^LOADS 1$' "$FA")" -eq 1
grep -q '^HELP mpls support for multiprotocol label switching$' "$FA"   # ground #define :35 sed-pinned (the :34/:35 CORRECTION face rides the VECTOR output)
grep -q '^mpls mod_ctor=1 mod_dtor=1$'   "$FA"                          # arms :371/:372 REAL
grep -q '^mpls ctor=1 dtor=1$'           "$FA"                          # CodecApi :378/:379
grep -q '^GETIDS mpls 34887$'            "$FA"   # ETHERTYPE_MPLS_UNICAST 0x8847 protocol_ids.h :153 (ORDER-pinned -- the vector emplace face :132-:134, NOT a set)
grep -q '^GETIDS mpls 34888$'            "$FA"   # ETHERTYPE_MPLS_MULTICAST 0x8848 :154
grep -q '^GETIDS mpls 137$'              "$FA"   # MPLS_IP :78/:114 (the codec.rs MPLS_IP = 137 resident kin)
test "$(grep -c '^GETIDS mpls ' "$FA")" -eq 3
test "$(grep -c '^GETDLT' "$FA" || true)" -eq 0
grep -q '^RULES mpls n=7 first=170 last=176$' "$FA"                     # mpls_rules :59-:69 (the 7/7 resident band face)
grep -q '^PARAM max_stack_depth type=4 range=-1:255 def=-1$' "$FA"   # :50-:51 (the -1 sentinel face; PT_INT=4 raw enum value, python re-derives)
grep -q '^PARAM payload_type type=11 range=auto | eth | ip4 | ip6 def=auto$' "$FA"   # :53-:54 (PT_ENUM=11)
grep -q '^PARAMS mpls n=2$'              "$FA"
grep -q '^SET mpls ret=111$'             "$FA"                          # the silent-else face :91-:99 (bogus name STILL returns true)
grep -q '^CTOR_M mpls ok=1$'             "$FA"                          # the ctor(m) :347-:354 config thread
# DEC ladders (ground call-site arms; the sid band FIRES POSITIVE here -- the
# q4 NEVER-land census FLIPS AT the row):
grep -q '^M1 len3 -> 0 lyr=0 next=34887 pb=0$'                           "$V"    # :169-:172 EV 170, lyr NEVER set + the codec.h :26 CodecData(sc, init_prot) ctor NEXT face -- no codec zeroes it on the fail path (34887 = ETHERTYPE_MPLS_UNICAST rides)
grep -q '^M2 one15 -> 1 lyr=4 next=2048 pb=512 bo=1 lab=15 t=2 ttl=15$' "$V"   # :137-:157 bit layout (the raw tc &0xE face = 2, NOT normalized) + :186-:191 + :228 nibble4
grep -q '^M3 lab0-auto -> 1 lyr=4 next=2048 pb=512$'                    "$V"    # :286 gate SHORT-circuits at plt AUTODETECT(0) -- NO 171 on the DEFAULT cfg + :211 label-first
grep -q '^M4 lab0-n6 -> 1 lyr=4 next=2048 pb=512$'                      "$V"    # :211 OVERRIDES the nibble-6 payload (34525 ELSE)
grep -q '^M5 lab1-mid -> 1 lyr=8 next=25944 pb=512$'                    "$V"    # :292 bos FALSE -> silent CONTINUE; :238 default nibble 0xFF -> 25944
grep -q '^M6 lab1-bos -> 0 lyr=0 next=34887 pb=0$'                       "$V"    # :292-:296 EV 172 + FATAL return (ctor-next NEXT face; label word 0x000011FF -> lab 1 S ttl 255)
grep -q '^M7 lab2-auto -> 1 lyr=4 next=34525 pb=512$'                   "$V"    # :302 gate auto-SILENT + :213 label2 -> ip6 (2048 ELSES)
grep -q '^M8 lab3-e8 -> 0 lyr=0 next=34887 pb=0 lab=0$'                  "$V"    # entry-8 word 0x000030FF -> lab 3; :308 EV 174 UNCONDITIONAL + return false BEFORE capture (the :181-per-entry-before-:186 receipt -- 175 x7 PRECEDE, lab NEVER captured, pb 0, ctor-next NEXT)
test "$(grep -c '^M9 five -> 1 lyr=20 next=2048 pb=512$'                        "$V")" -eq 1   # :196 NEVER with the default depth (the deflt "-1" sentinel :50 + the :194 short-circuit guard -- the SENTINEL face, NOT a five-entry stack; a six-entry stack rides M10 where depth 4 stops at the entry-5 gate)
grep -q '^M10 five-d4 -> 0 lyr=0 next=34887 pb=0 lab=15 bo=1$'           "$V"    # e5 (label-15 Bos, cfg depth 4): :181 175 THEN :186-:191 CAPTURE+SET THEN :196 ++depth 5>4 -> 176 + :200 pb 512->0 TRUE CLEAR proof + lyr NEVER set (:208 unreached) + lab/bo captured (the :181/:186-before-:196 order pin) + ctor-next NEXT
grep -q '^M11 four-d4-eth -> 1 lyr=16 next=25944 pb=512$'               "$V"    # :196 4>4 FALSE ladder boundary + :219 forced eth (auto nibble COINCIDES -- the honest recorded face)
grep -q '^M12 lab15-ip4 -> 1 lyr=4 next=2048 pb=512$'                   "$V"    # :215 forced ip4 beats the auto nibble (25944 ELSE)
grep -q '^M13 lab0-eth -> 1 lyr=4 next=2048 pb=512$'                    "$V"    # :286 (plt eth != IPV4) -> EV 171 THEN :211 label0 rides FIRST
grep -q '^M14 lab0-ip6 -> 1 lyr=4 next=2048 pb=512$'                    "$V"    # the gate reads IPV4 ONLY -> 171 AGAIN + :211 rides OVER the forced ip6 arm (34525 ELSE)
grep -q '^M15 drain -> 0 lyr=0 next=34887 pb=0 lab=0$'                   "$V"    # :169 at DRAINED stack_len (a tail-counting rule MISSES this face); 175 x2 PRECEDE; lab NEVER captured -- the NO-Bos-capture face
grep -q '^M16 mask80 -> 1 lyr=4 next=2048 bypass=0$'                    "$V"    # :205/:206 TUNNEL_MPLS 0x80 mask -> bypass FALSE
grep -q '^M17 mask00 -> 1 lyr=4 next=2048 pb=512 bypass=1 bo=1$'         "$V"    # NSDMI mask 0 -> bypass TRUE (ground NSDMI tunnel_mask=0 face + ground default tunnel_mask=0 = TRUE; the trio's 0/0/0 hand-off CLOSED)
grep -q '^M18 lab2-eth -> 1 lyr=4 next=34525 pb=512$'                   "$V"    # :302 `plt && plt!=IPV6` TRUE -> EV 173 (the ONLY 173 arm -- config-forced, cited-not-fabricated)
grep -q '^ENC b0 -> 0$'                                                 "$V"    # :264 allocate gate (zero-size Buffer)
grep -q '^ENC ok -> 1 bytes 0 0 243 15 netype 0 npro 255$'              "$V"    # :267 memcpy_s STOCK-shim copy (:249-:250 raw path, mirror nullptr) + :268/:269 NOT_SET (protocol_ids.h :91/:122)
test "$(grep -c '^EV ' "$V")" -eq 34                                     # 170x2 171x2 172x1 173x1 174x1 175x26 176x1 (hand census, python re-verifies PER-BAND vs the arms)
printf 'MPLS vectors band census face: EV 170 x2, 171 x2, 172 x1, 173 x1, 174 x1, 175 x26, 176 x1 cite order 169/181/186-191/196-200/205/210\n' >> /dev/null   # cite-prose face (NEVER lands in vectors)
python3 -c '
import re
v=open("'"$V"'").read(); fa=open("'"$FA"'").read()
h=open("/opt/data/snort3-src/src/codecs/codec_module.h").read()
m=re.search(r"enum\s+CodecSid[^{]*\{", h); body=h[m.end():]; val=0; g={}
for line in body.split("\n"):
    mm=re.match(r"\s*([A-Z_0-9]+)\s*(?:=\s*(\d+))?\s*,", line)
    if mm:
        name=mm.group(1); val=int(mm.group(2)) if mm.group(2) else val+1; g[name]=val
    if re.match(r"\s*};", line): break
band={g["DECODE_BAD_MPLS"],g["DECODE_BAD_MPLS_LABEL0"],g["DECODE_BAD_MPLS_LABEL1"],g["DECODE_BAD_MPLS_LABEL2"],g["DECODE_BAD_MPLS_LABEL3"],g["DECODE_MPLS_RESERVED_LABEL"],g["DECODE_MPLS_LABEL_STACK"]}
assert band=={170,171,172,173,174,175,176}, band
for n in band:
    r=re.findall(rf"({n}),", open("/opt/data/snort3-rust/src/codecs/codec_module.rs").read())
    assert str(n) in r, n                       # 7/7 ALREADY resident -- NEVER re-walked
ev=[int(l.split()[2]) for l in v.splitlines() if l.startswith("EV ")]
from collections import Counter
c=Counter(ev)
assert set(c)==band, c                          # EVERY sid of the band fires (the FLIP face)
# per-arm hand census re-derived from the MEASURED ground call faces:
assert c[170]==2 and c[171]==2 and c[172]==1 and c[173]==1 and c[174]==1 and c[175]==26 and c[176]==1, c
# the ground codec_event token census INSIDE the TU (7 sites -- sids NEVER re-walked):
out=subprocess.run if False else None
# the bit-layout recomputation (ground formula cd_mpls.cc :151-:156 EXACT):
w=0x0000F30F
w2=int.from_bytes(bytes([0,0,0xF3,0x0F]),"big")   # ntohl face
ttl=w2&0xFF; bos=(w2>>8)&1; tc=(w2>>8)&0x0E; lab=(w2>>12)&0xFFFFF
assert (lab,tc,bos,ttl)==(15,2,1,15), (lab,tc,bos,ttl)
assert f"bo={bos} lab={lab} t={tc} ttl={ttl}" in v
# protocol ids ground-walk -> the ORDERED GETIDS triple:
import subprocess,re as rr
pi=open("/opt/data/snort3-src/src/protocols/protocol_ids.h").read()
pids={n:(int(x,16) if x.lower().startswith("0x") else int(x)) for n,x in rr.findall(r"^\s*([A-Z_0-9]+)\s*=\s*(0[xX][0-9A-Fa-f]+|\d+),", pi, rr.M)}   # hex AND decimal faces (MPLS_IP = 137 rides the DECAP face)
assert pids["ETHERTYPE_MPLS_UNICAST"]==0x8847 and pids["ETHERTYPE_MPLS_MULTICAST"]==0x8848 and pids["MPLS_IP"]==137
ids=[int(l.split()[2]) for l in fa.splitlines() if l.startswith("GETIDS mpls ")]
assert ids==[pids["ETHERTYPE_MPLS_UNICAST"],pids["ETHERTYPE_MPLS_MULTICAST"],pids["MPLS_IP"]], ids   # the vector-emplace ORDER (NOT a set -- contrast vlan §8)
assert pids["ETHERTYPE_IPV4"]==2048 and pids["ETHERTYPE_IPV6"]==34525 and pids["ETHERTYPE_TRANS_ETHER_BRIDGING"]==25944
# the PARAM raw-int Type faces re-derived from the ground parameter.h enum:
ph=open("/opt/data/snort3-src/src/framework/parameter.h").read()
pm=re.search(r"enum\s+Type\s*\{([^}]*)\}", ph, re.S).group(1)
pm=re.sub(r"//.*", "", pm)   # ground comments CONTAIN commas (the "Parameter*,
order=[t.strip() for t in pm.split(",") if t.strip()]   #  no default" face) -- stripped FIRST
pti=order.index("PT_INT"); pte=order.index("PT_ENUM")
assert f"type={pti} range=-1:255" in fa and f"type={pte} range=auto | eth | ip4 | ip6" in fa, (pti,pte)
# the Payload-type enum transcription face (cd_mpls.cc :39-:46 -- AUTODETECT
# 0 / ETHERNET 1 / IPV4 2 / IPV6 3 -- the :41 alignment comment ground face):
cc=open("/opt/data/snort3-src/src/codecs/link/cd_mpls.cc").read()
pmE=re.search(r"enum MplsPayloadType : uint8_t\s*\{(.*?)\};", cc, re.S).group(1)
names=[l.split("=")[0].strip().rstrip(",") for l in pmE.splitlines() if l.strip() and not l.strip().startswith("//")]
assert names==["MPLS_PAYLOADTYPE_AUTODETECT","MPLS_PAYLOADTYPE_ETHERNET","MPLS_PAYLOADTYPE_IPV4","MPLS_PAYLOADTYPE_IPV6"], names
# the TUNNEL_MPLS + PROTO_BIT ground faces:
sc=open("/opt/data/snort3-src/src/main/snort_config.h").read()
assert re.search(r"TUNNEL_MPLS\s*=\s*0x80", sc)
assert "pb=512" in v and "pb=0" in v
# the ext2 copy-local pin: the enum face + the static_assert face LIVE:
dc=open("/opt/data/snort3-rust/tools/mpls_harness/copy/daq_common.h").read()
assert "MAX_DAQ_VERDICT = 6 } DAQ_Verdict;" in dc
# the sid-band NEVER-land census NEVER leaks into the LANDED harnesses (the
# flip is LOCAL to this row -- the q4 law re-armed for the older vectors):
import hashlib
for f in ("link4_harness","link6_harness","erspan_harness","misc9_harness"):
    t=open(f"/opt/data/snort3-rust/tools/{f}/vectors.txt").read()+open(f"/opt/data/snort3-rust/tools/{f}/vectors_faceA.txt").read()
    assert not rr.search(r"^EV 11[0-9] 17[0-6]$", t, rr.M), f
# the Rust-side mpls NEVER-land face FLIPPED AT THE PORT ROW (18o): the
# seed-pass rs-ABSENCE PYPIN became the rs-PRESENCE face on the RULING, not
# by drift (the misc9 rs-row precedent; the PLAN sec-9 own "rs rows a later
# pass" prediction): cd_mpls.rs + the parity test now LAND at this row.
import os
assert os.path.exists("/opt/data/snort3-rust/src/codecs/cd_mpls.rs")
assert os.path.exists("/opt/data/snort3-rust/tests/mpls_parity_test.rs")
# NEXT.md cargo CITE face (docs CITE only; NEXT.md NEVER touched HERE):
assert "605 tests green / 0 FAILED" in open("/opt/data/snort3-rust/NEXT.md").read()
'
# ---- row's measured first-run face PINS (md5s are the MEASURED FIRST-RUN
# OUTPUT; drift refuses EVERY build; build.sh NEVER fabricates) ----
# FIRST run seeds then DIES HERE (the 18n precedent: the seed run carries
# placeholder shapes, dies LOUDLY, the REAL measured wc/md5 faces are sub-
# stituted into the block below, EVERY later run refuses drift; build.sh
# NEVER fabricates). MEASURED first-run faces (the seed run's own output):
test "$(wc -l < "$H"/vectors.txt)" -eq 54          # MEASURED first-run face
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 17    # MEASURED first-run face
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "b4b660e448703b603755a0049c6a2052"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "3066fc335fb21777891271b9c7b152c5"

# ---- known-answer wc+md5 pins (OUTPUT of the MEASURED run) ----
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)

# ---- frozen-donor direct-md5 census (link4 :769-:789 face VERBATIM, the
# FM15 face -- the DIRECT reads; NEVER re-derived) ----
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

# ---- BACKBONE-10 census: the 10-face PIN STAYS EXACTLY 10 UNDISTURBED --
# the B10 array rides link4 :796-:807 VERBATIM (absolute paths, NEVER re-
# derived); THIS row adds ZERO faces (the own-new witness is a SYMBOL face --
# the L1 census above -- NEVER an ARRAY entry; the symbol-vs-array law, 18n).
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
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H/backbone10.txt"   # receipt (ignored)
test "$(wc -l < "$H"/backbone10.txt)" -eq 10                            # backbone STAYS 10
# THE chain echoes (the DIRECT predecessor faces byte-ident, ALL re-read
# THIS pass -- misc9-19a the IMMEDIATE lineage head + link4 18n the DONOR +
# link6 18m + erspan 18l + misc3):
test "$(md5sum "$R"/tools/misc9_harness/vectors.txt | awk '{print $1}')" = "e6328da1f3188df9754b9e45d74897db"
test "$(md5sum "$R"/tools/misc9_harness/vectors_faceA.txt | awk '{print $1}')" = "dfe738fb8b4200368332ba73b81a4e96"
test "$(md5sum "$L4"/vectors.txt | awk '{print $1}')" = "c7f5808fa326b7831603813c16a3b01e"
test "$(md5sum "$L4"/vectors_faceA.txt | awk '{print $1}')" = "9fdfc50da8fee22b473028f1f9b29c12"
test "$(md5sum "$R"/tools/misc3_harness/vectors.txt | awk '{print $1}')" = "e75f7385779aa89c365dd2ce4a208b67"
test "$(md5sum "$R"/tools/misc3_harness/vectors_faceA.txt | awk '{print $1}')" = "fe1189c6c78139b8828c1a8071e3df28"
# (link6-18m + erspan-18l DONOR-lineage pair echoes byte-ident DIRECT -- the
# four-pair chain echo complete: misc9/link4/link6/erspan; the 19a docs face
# at NEXT :548 re-carries gre 6751d1a8 = 23rd straight in ITS count face):
test "$(md5sum "$R"/tools/link6_harness/vectors.txt | awk '{print $1}')" = "e59f7a8a70d172261dcb847dcfdcb36a"
test "$(md5sum "$R"/tools/link6_harness/vectors_faceA.txt | awk '{print $1}')" = "d2fc5591bc45c1787fcee7393675a3d8"
test "$(md5sum "$R"/tools/erspan_harness/vectors.txt | awk '{print $1}')" = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$R"/tools/erspan_harness/vectors_faceA.txt | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"

# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" /opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "4826fc2233044a2d5429413faf0ae1af" /opt/data/snort3-rust/tools/fmod_harness/build.sh
# gre GATE anchor (the 18g chain rides this VERBATIM face pin; the grey
# positive-gate CONTRAST face for this row's ZERO-gate 25th-straight pin):
test "$(md5sum /opt/data/snort3-rust/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" /opt/data/snort3-rust/tools/gre_harness/gate.txt
# misc9 chain anchor (19a, the IMMEDIATE predecessor harness -- self-literal
# in ITS OWN build.sh, additive-safe NEVER pinned by THIS row):
grep -q "ada2b1e83b0f15629a39000e6dae65aa" /opt/data/snort3-rust/tools/misc9_harness/build.sh

# ---- TWO-LINEAGE census loop (MEASURED, never typed; THIS row adds ZERO
# gate.txt so the 25-tracked face is UNDISTURBED BY DESIGN -- the 25th-
# straight ZERO-gate claim (docs-lineage count) rides these re-measures ONLY
# at the row build): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(cat "$H/gate_md5_lineages.txt")" -eq 17
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin (the 18i PROCESS-LESSONS law: pin the IMMUTABLE ground
# only).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (the NESTED-INSTRUMENT face, the
# misc9 precedent re-armed: the root .gitignore is NEVER touched; the block
# lives IN this dir and check-ignore honors it). NON-ignored face = the 8
# stageables (the link4 7-shape -- PLAN.md build.sh probe.cc probe_dec.cc
# vectors.txt vectors_faceA.txt + ONE own-new witness witness_flow.cc (the
# MEASURED L1 EXACTLY-1 Flow delta FLIPS the 6-face hope -- §11 honest) + the
# .gitignore instrument itself). PRE-commit the 8 are UNTRACKED (--others);
# POST-commit the SAME proof runs vs the landed face. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/mpls_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/mpls_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 8
for f in PLAN.md build.sh probe.cc probe_dec.cc witness_flow.cc vectors.txt vectors_faceA.txt .gitignore; do
    echo "$face" | grep -q "tools/mpls_harness/$f$"
done
test "$(echo "$face" | grep -c 'witness_flow')" -eq 1     # the tracked-witness face
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/cd_mpls.o copy/codecs/link/cd_mpls.cc copy/daq.h copy/daq_common.h copy/flow/flow.h o2/cd_mpls.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_18f.o witness_conf.o stubs_18d.o witness_flow.o vectors_O0.txt vectors_faceA_O0.txt vectors_O2.txt vectors_faceA_O2.txt nm_U_cd_mpls.txt nm_U_union.txt nm_U_mangled_union.txt E4_preext_cd_mpls.txt E4_donorsrc_cd_mpls.txt E4_nodaq_cd_mpls.txt E4_noapi_cd_mpls.txt E4_restored_cd_mpls.txt L1_link_face.txt L1_undefined.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt o_size_receipt.txt .assert_ext2.cc .assert_ext2; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/mpls_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/mpls_harness/$f NOT ignored"; exit 1; }
done
# witness_flow.cc NEVER ignored (the tracked stageable, explicit NOT-proof):
git -C /opt/data/snort3-rust check-ignore -q "tools/mpls_harness/witness_flow.cc" && { echo "WITNESS WRONGLY IGNORED"; exit 1; } || true
# vectors NEVER ignored (the stageable face, explicit NOT-proofs):
git -C /opt/data/snort3-rust check-ignore -q "tools/mpls_harness/vectors.txt" && { echo "VECTORS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/mpls_harness/vectors_faceA.txt" && { echo "FACE-A WRONGLY IGNORED"; exit 1; } || true
# the nested .gitignore INSTRUMENT NEVER ignored (the misc9 NOT-proof):
git -C /opt/data/snort3-rust check-ignore -q "tools/mpls_harness/.gitignore" && { echo "GITIGNORE-INSTRUMENT WRONGLY IGNORED"; exit 1; } || true
# no STAGED churn: index EMPTY. THE 19a-DOCS COUNSEL FACE LANDED: the docs
# child is GONE this pass, so the tracked-MODIFIED tolerance is ZERO-tolerant
# beyond THIS row's OWN faces (the STOP-flag face: any foreign tracked churn
# -- incl ' M NEXT.md' from a re-spawned docs pass -- fires LOUD here):
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
# THE rs-LANDING TOLERANCE FLIP (18o port commit, the misc9 19a precedent
# re-armed: seed face = ZERO-tolerant; the PORT row's OWN tracked wiring
# files land HERE): the tolerance is EXACTLY src/codecs/mod.rs (the ONE
# pub mod + doc-row wiring) + the two docs files (PORTING_PLAN.md +
# KNOWN DEVIATIONS.md rows) -- ZERO other tracked churn; the new own
# files (src/codecs/cd_mpls.rs + tests/mpls_parity_test.rs) are UNTRACKED
# pre-commit (diff face silent on them) and staged ONCE at this row.
rowface='^tools/mpls_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|witness_flow\.cc|vectors\.txt|vectors_faceA\.txt|\.gitignore)$'
ownrs='^(src/codecs/mod\.rs|PORTING_PLAN\.md|KNOWN DEVIATIONS\.md)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface" | grep -vE "$ownrs")"
# dir face BOTH states: ?? tools/mpls_harness/ while UNTRACKED (pre-commit)
# else tracked at EXACTLY the 8 stageable faces (post-commit):
if git -C /opt/data/snort3-rust ls-files --error-unmatch "tools/mpls_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C /opt/data/snort3-rust ls-files "tools/mpls_harness/" | wc -l)" -eq 8
else
    git -C /opt/data/snort3-rust status --porcelain | grep -qx '?? tools/mpls_harness/'
fi
# SINGLE-TENANT census (orchestrator law, disk-re-checked EVERY build): the
# ONLY dirty face in tools/ is THIS row's ?? dir -- NO sibling tracked churn
# (the 19a docs exit face: the tree is CLEAN beyond this dir):
dirtyother=$(git -C /opt/data/snort3-rust status --porcelain tools | grep -vE '^\?\? tools/mpls_harness/' || true)
test -z "$dirtyother"
# mpls NEVER-land Rust census CITE (the PORT pass flips it; NEVER fabricated
# here -- the python face above asserts cd_mpls.rs find-0 TONIGHT): the
# ladder row :119 name rides codec_api.rs RESIDENT (sed-pin :159-:161 face).

# .o-size receipt (MEASURED sizes, NEVER pinned -- compile-env dependent):
ls -l "$C/cd_mpls.o" "$O2/cd_mpls.o" > "$H/o_size_receipt.txt" 2>/dev/null || true
git -C /opt/data/snort3-rust check-ignore -q "tools/mpls_harness/o_size_receipt.txt" || { echo "GITIGNORE FACE DEAD: o_size_receipt.txt NOT ignored"; exit 1; }

echo "row-TU nm census (MEASURED, never typed): nm_U=$(wc -l < "$H/nm_U_cd_mpls.txt") (the NDEBUG row face; the non-NDEBUG scratch era 28 rides §11 with the __assert_fail delta face) | tunnel-U EXACTLY-1 CLOSED vs carried witness_18f T x1 (ea1f79f3 INHERITED -- hook cost ZERO clones) | Flow::get_mpls_layer_per_dir U EXACTLY-1 -> own-new witness_flow (the MEASURED +1 flip vs the 6-face hope, §11; backbone STAYS $(wc -l < "$H/backbone10.txt"))"
echo "witness posture: OWN L1 RE-MEASURE EXACTLY-1 distinct undefined (the Flow mirror) => ONE own witness_flow.cc (27L, miscip shape); daq_msg/SFDAQ U census ZERO (the TU NEVER names daq -- the graft NON-participation face; daq.h-drop survives rc0 in E4); tun mask pair rides the CARRIED witness_18f observable (TUNNEL_MPLS 0x80)"
echo "cp face: 7 FRESH cps (flow.h 637 + safec.h 42 + riders 5 incl clock_defs -- the 6-vs-7 docs CORRECTION lands MEASURED: flow_data/deferred_trust/flow_stash/ips_context_chain/clock_defs; flowz decoy NEVER satisfies flow/) -> 122 -> 130 mid-build RE-DERIVED; graft-v3 daq.h 0f7016a6 INHERITED NEVER consumed; ext#2 enum 9b603f8f 34L copy-LOCAL heredoc ONLY (masters 73fdbc39/f683749c + link4 face fead0027 md5-asserted ladder HEAD AND TAIL; NEVER promoted)"
echo "safec decision: stock 42-L VERBATIM cp (config.h HAVE_SAFEC grep-0 -> the #else shim IS the stock header; the EXACTLY-1 memcpy_s :267 needs ZERO grafts; the strip arm moves the wall to :30, NEVER :267 -- C15 receipt law re-armed)"
echo "ext#2 ladder: pre-ext rc1 EXACTLY-1 error flow.h:541 MAX_DAQ_VERDICT (the CONDITIONAL trigger the flow.h cp DEMANDS) -> enum heredoc rc0 x3 + standalone static_assert == 6 rc0 (the sfdaq_module.cc :179 path-trap cite re-grounded)"
echo "E4 both ways: -I src ONLY rc1 flow.h:39 <daq_common.h> chained (the C14 face) / flow.h kills cc:26 / flow_data kills flow.h:43 / clock_defs kills flow.h:51 (rider-5) / safec kills cc:30 NOT :267 / daq.h SURVIVES rc0 (the NON-participation inversion vs 18n vlan) / codec_module+codec CHAINED kill + restored rc0 EVERY build"
echo "hidden-table census: BUILDING_SO :382 + SO arm :383 + cd_mpls[] :385 (TRUE-NAME EQUALITY, nm D-face) + feeds :388 + NAME/HELP :34/:35 (the docs :33/:34 face DISK-DEAD re-sed; the CORRECTION ALSO rides HELP mpls in vectors) + mod arms REAL :341/:344/:371/:372 + the CONFIG-CARRYING ctor :347 face SET ret=111 + CTOR_M + PARAMS n=2 + sids :61-:67 RULES n=7 + ladder :61/:106 + 39-extern + [&str; 34] UNDISTURBED"
echo "sid band FLIPS: EV 170x2 171x2 172x1 173x1 174x1 175x26 176x1 == 34 (the q4 NEVER-land census POSITIVE AT its OWN row; the python face re-asserts the SAME band grep-0 in ALL FOUR LANDED predecessor vectors -- the flip NEVER leaks)"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED; tracked gate.txt = 1 ls-files; 25th-straight ZERO-gate docs-lineage count); BACKBONE STAYS 10 (own witness is a SYMBOL face, never an array face); chain echoes misc9 e6328da1/dfe738fb + link4 c7f5808f/9fdfc50d BYTE-IDENT DIRECT"
echo "MPLS_LINK_DONE vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=0"

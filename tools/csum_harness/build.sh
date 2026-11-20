#!/usr/bin/env bash
# csum_harness -- row 18b ip/checksum.h (284 L all-inline header lib).
# PROBE-ONLY harness (PLAN 4.5 / R4): known-answer ladder + guard/quirk arms
# vs the ground header at fe29cbe. NO gate binary, NO third Catch gate, NO
# stubs/witnesses: the row adds ZERO .o to ANY donor link (nm-proven PLAN 2:
# header-as-TU = zero text symbols; consumer TU = W-only COMDATs) and the
# CppUTest suite is NOT buildable on this host (E4 wall re-proven below) --
# a Catch gate would be the 17p fake-gate anti-pattern.
# Gate lineage (PLAN 4): ZERO-EDIT row. Every gate.txt (the 9 holders of
# md5 4826fc2233044a2d5429413faf0ae1af: flog + fmod + 7 older f*) is a
# frozen directory; this harness touches NOTHING in them and adds no gate --
# 18b = the 10th straight byte-ident claim; receipts re-censused below and
# the fmod double-rebuild (session-ritual insurance, NEXT.md 341-:342) runs
# OUTSIDE this script; its md5 pins are the fmod build.sh:1083-:1084 lines
# grepped verbatim below as the oracle proof (committed script, not memory).
# Copy tree (PLAN 1): the include closure of checksum.h = <cstddef>
# <cstring> <protocols/protocol_ids.h> (checksum.h:23-:26, measured) -- ALL
# libstdc++ system headers + protocol_ids.h which the fmod donor ALREADY
# cp's (fmod build.sh:222 brace list): ZERO cp delta vs the donor. cp delta
# of THIS row = exactly ONE file, the row header itself (codecs/ip/
# checksum.h) -- E1 compiles against the two-file tree with no grafts, no
# shims, no FIXACC, no witness headers (scratch SYNTAX+OBJ-OK first try;
# byte-identity vs the donor's resident protocol_ids.h asserted below).
# E5 (PLAN 5): BOTH -O levels compile+link+run the ladder; outputs must be
# BYTE-IDENTICAL (scratch ka_O0.txt == ka_O2.txt). Values NEVER typed from
# the PLAN (17p lesson): the pins below are the scratch MEASURED ladder used
# to cross-check the fresh build-run output (ka_* transcript, scratch row18b).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
F=$SRC/src/codecs/ip/checksum.h

# ---- ground identity + include closure re-armed (PLAN 0/1 pins) ----
# the ground header pinned by its own md5 (fe29cbe truth; re-measured here,
# NOT typed from the PLAN): vectors/O0/O2/donor receipts all ride THIS file.
test "$(md5sum "$F" | awk '{print $1}')" = "b43628f369e16b1d5c093ff447d3e954"
test "$(wc -l < "$F")" -eq 284
grep -q '#include <protocols/protocol_ids.h>' "$F"
if [ -e /opt/data/snort3-rust/tools/fmod_harness/copy/protocols/protocol_ids.h ]; then
    # ZERO cp delta proof vs the donor (PLAN 1): the donor tree ALREADY
    # carries protocol_ids.h -- byte-identical, so the row needs no new cp.
    test -z "$(diff /opt/data/snort3-rust/tools/fmod_harness/copy/protocols/protocol_ids.h "$SRC"/src/protocols/protocol_ids.h)"
fi

rm -rf "$C"
mkdir -p "$C"/protocols "$C"/codecs/ip
cp "$SRC"/src/protocols/protocol_ids.h "$C"/protocols/
# THE row cp (the only one -- the header itself; path style matches both
# consumer include forms ("checksum.h" / "codecs/ip/checksum.h") under -I$C.
cp "$F" "$C"/codecs/ip/checksum.h

GXX="g++ -std=c++17 -O0 -w -I$C"      # fmod chain MINUS the lua/node -I (PLAN 1)
GXXA='g++ -std=c++17 -O2 -w -I'"$C"

if [ ! -e "$H/probe.cc" ]; then echo "probe.cc missing" >&2; exit 1; fi
# probe-only posture receipts (PLAN 4.5/R4): no stubs TU, no gate artifact.
test ! -e "$H/stubs.cc"
test ! -e "$H/catch_main.cc"

# ---- E4 wall receipt (PLAN 2 E4): the CppUTest suite CANNOT compile here --
# the 16g/16h Rust-side-translation precedent, re-proven every build. The
# -I$SRC/src second path matches the scratch receipt exactly (utils/endian.h
# at test :34 RESOLVES there -- PLAN 2: "the checksum.h + endian.h lines
# WOULD resolve; the runner header cannot") so the wall lands precisely on
# <CppUTest/CommandLineTestRunner.h> at test :36. ----
if g++ -fsyntax-only -I"$C" -I"$SRC"/src "$SRC"/src/codecs/ip/test/checksum_test.cc 2> "$H/cpputest_fatal.txt"; then
    echo "E4 NEGATED: CppUTest suddenly buildable -- rethink the Rust-side ruling" >&2; exit 1
fi
grep -q 'CppUTest/CommandLineTestRunner.h: No such file' "$H/cpputest_fatal.txt"
# dialect proof: the suite is CppUTest, not Catch -- 10 TEST( / 0 TEST_CASE:
test "$(grep -c '^TEST(' "$SRC"/src/codecs/ip/test/checksum_test.cc)" -eq 10
test "$(grep -c 'TEST_CASE' "$SRC"/src/codecs/ip/test/checksum_test.cc || true)" -eq 0

# ---- E3: the header AS a TU = zero text symbols (the all-inline proof) ----
printf '#include "codecs/ip/checksum.h"\n' > "$H/hdr_tu.cc"
$GXX -c "$H/hdr_tu.cc" -o "$H/hdr_tu.o"
nm "$H/hdr_tu.o" | sort > "$H/nm_hdrtu.txt"
test "$(nm "$H/hdr_tu.o" | grep -cE ' [TW] ' || true)" -eq 0
test "$(nm "$H/hdr_tu.o" | grep -c ' r ')" -eq 5   # 3 MIN_HEADER_LEN + 2 protocol_ids statics

# ---- E1: consumer TU compiles at BOTH -O levels (zero grafts/shims) ----
$GXX -c "$H/probe.cc" -o "$H/probe.o"
eval "$GXXA -c \"\$H/probe.cc\" -o \"\$H/probe_O2.o\""

# ---- E2: nm residue -- checksum app-residue vs the donor closure = ZERO ----
nm -u "$H/probe.o" | grep ' U ' | awk '{print $NF}' | sort -u > "$H/residue_U.txt"
test "$(wc -l < "$H/residue_U.txt")" -eq 1
test "$(cat "$H/residue_U.txt")" = "printf"        # the ONLY U (libc-resident)
nm "$H/probe.o" | sort > "$H/probe_D.txt"
test "$(grep -c ' W ' "$H/probe_D.txt")" -eq 11    # the 11 COMDAT checksum W's (PLAN 2 E3)
grep -q ' t _ZN8checksumL9cksum_addEPKvm' "$H/probe_D.txt"   # the :59 fwd-decl witness
FDEF=/opt/data/snort3-rust/tools/fmod_harness/copy
if [ -d "$FDEF" ]; then
    { for o in "$FDEF"/*/*.o /opt/data/snort3-rust/tools/fmod_harness/stubs.o; do
        [ -e "$o" ] && nm --defined-only "$o" | awk '$2!="U"{print $NF}';
      done; } | sort -u > "$H/donor_defs.txt"
    # zero-witness receipt (PLAN 2 E3): nobody in the donor closure touches
    # the checksum surface -- 0 hits = zero dups, zero retirements, no
    # witness can ever be needed for this row.
    test "$(grep -cE 'cksum|Pseudoheader|add_tcp_header|add_udp_header|add_ip_header' "$H/donor_defs.txt" || true)" -eq 0
    # comm survivor check: the probe's UNDEF vs the donor def-union -> printf
    # only (libc), i.e. EMPTY app residue against the 17m-18a donor tree.
    test "$(comm -23 "$H/residue_U.txt" "$H/donor_defs.txt" | grep -vc '^printf$' || true)" -eq 0
    test ! -e /opt/data/snort3-rust/tools/fmod_harness/stubs.cc || \
        test "$(grep -cE 'cksum|Pseudoheader' /opt/data/snort3-rust/tools/fmod_harness/stubs.cc || true)" -eq 0
else
    : > "$H/donor_defs.txt"
fi

# ---- E5: link + run at -O0 and -O2; outputs BYTE-IDENTICAL ----
$GXX "$H/probe.o" -o "$H/probe"
eval "$GXXA \"\$H/probe_O2.o\" -o \"\$H/probe_O2\""
timeout 60 "$H/probe"   > "$H/vectors_O0.txt" || { echo PROBE_FAIL O0; exit 1; }
timeout 60 "$H/probe_O2" > "$H/vectors_O2.txt" || { echo PROBE_FAIL O2; exit 1; }
cmp "$H/vectors_O0.txt" "$H/vectors_O2.txt"     # the E5 byte-identity arm
cp "$H/vectors_O0.txt" "$H/vectors.txt"

# hygiene gate (carry fmod build.sh:1101 VERBATIM -- PLAN R6): no 6+-hex-digit
# pointer-ish values in vectors (all ladder values <= 4 hex digits by design).
! grep -E '0x[0-9a-f]{6,}' "$H/vectors.txt"

# ---- known-answer ladder (scratch-MEASURED arms; the build re-measures;
# every line below = the fresh vectors.txt, byte-matched -- never forecast).
grep -q 'G_tcp len4->len=0 cks=0x0000 ptr_moved=0' "$H/vectors.txt"   # Q3 all three guard facts
grep -q 'G_udp len4->len=0 cks=0x0000' "$H/vectors.txt"
grep -q 'G_ip  len4->len=0 cks=0x0000' "$H/vectors.txt"
grep -q 'G_tcp len0->len=0' "$H/vectors.txt"
grep -q 'P_tcp4_len4=0xf9ff' "$H/vectors.txt"
grep -q 'P_tcp6_len4=0xffff' "$H/vectors.txt"
grep -q 'P_udp4_len4=0xeeff' "$H/vectors.txt"
grep -q 'P_ip_len4=0xffff' "$H/vectors.txt"
grep -q 'K_tcp4 sum=0x9e7c reverify=1' "$H/vectors.txt"
grep -q 'K_ip4 sum=0x1d0c reverify=1' "$H/vectors.txt"
grep -q 'K_cksum16=0xbc43' "$H/vectors.txt"
grep -q 'K_cksum15=0xbb44' "$H/vectors.txt"   # Q1 odd-tail = the swap-breaking arm
grep -q 'K_cksum1=0xffdd' "$H/vectors.txt"
grep -q 'K_cksum0=0xffff' "$H/vectors.txt"    # Q2 len=0 complement arm
grep -q 'PH4 arr=007f 0100 007f 0100 0600 1400 sizeof=12' "$H/vectors.txt"  # Q5 word pun
grep -q 'PH6 sizeof=36 arr17=0x1400' "$H/vectors.txt"
test "$(wc -l < "$H/vectors.txt")" -eq 16
# cross-check vs the scratch receipt (ka_O0.txt, the E5 transcript): the
# fresh build-run ladder must reproduce it byte-for-byte.
if [ -e /opt/data/cache/scratch/row18b/ka_O0.txt ]; then
    test -z "$(diff /opt/data/cache/scratch/row18b/ka_O0.txt "$H/vectors.txt")"
fi

# ---- gate-lineage receipts (PLAN 4: ZERO-EDIT, 10th-straight argument) ----
FM=opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" "/$FM"
grep -q "4826fc2233044a2d5429413faf0ae1af" "/$FM"
# census (working tree): exactly 9 gate.txt carry the chain md5; THIS harness
# owns ZERO gate.txt (probe-only) -- the chain cannot move: zero-EDIT.
test "$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')" -eq 9
test ! -e "$H/gate.txt"
test ! -e "$H/gate"

echo "hdr_tu text symbols: $(nm "$H/hdr_tu.o" | grep -cE ' [TW] ' || true) (0 = the all-inline proof)"
echo "probe -u entries: $(wc -l < "$H/residue_U.txt") (1 = printf only; app residue 0)"
n_surf=0; if [ -s "$H/donor_defs.txt" ]; then n_surf=$( (grep -cE 'cksum|Pseudoheader' "$H/donor_defs.txt" || true) ); fi
echo "donor-closure checksum-surface defs: $n_surf (0 = zero witness, zero retirement; donor_union=$( [ -e "$H/donor_defs.txt" ] && wc -l < "$H/donor_defs.txt" || echo NA ) symbols)"
echo "O0==O2 vectors identity: $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "vectors md5: $(md5sum "$H"/vectors.txt)"
echo "CSUM_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"

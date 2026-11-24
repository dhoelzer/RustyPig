#!/usr/bin/env bash
# ---- ROW 23d: helpers/directory.cc 113 L (md5 e0e4af65fd338c1b9add303142
# aa36cc) + directory.h 49 L (f7eac140e21c6cecd14ba6e00d546ea4) AND
# packet_io/trough.cc 265 L (c9aa106b99f5bd4592b8a27fff81d5f8) + trough.h
# 88 L (7931b6efeaf3c329449e7038f68b9d59) = 515 L @ fe29cbe, FRESH cps +
# cmp-proved EVERY build (the fresh-cp law; NEVER trust carried donor
# headers -- the DONOR-ERASER headline of THIS row: the 23b receipt 'the
# trough pair dies the directory.h wall' was DISARMED by 23c as a face of
# ITS OWN donor-eraser copy set, NOT an SDK wall. This harness carries
# BOTH faces LIVE every build, NEVER a masquerade either direction: (1)
# the RE-ARMED flipped-assert -- trough.cc compiled WITHOUT the directory
# cps dies EXACTLY the 'helpers/directory.h: No such file or directory'
# include fatal (the 23b receipt TRUE at that face); (2) the FRESH 4-file
# copy compiles BOTH SILENT rc0 (the 23c face re-proven; the wall CLOSED).
# ZERO SDK anywhere: the quad rides fnmatch/stat/dirent (glibc REAL) +
# get_error through the REAL util.cc body; the E4-graft trio NEVER rides
# this row. THE row-body link carries the REAL homes: dir.o + trough.o
# (THE file_count B-definition -- the ONE home the 23c witness mirror
# stood in for; the E9 dup-twin flipped-assert proves a mirror = multiple
# definition, EXACTLY-7 faces measured: 5 twin-able Trough statics (the
# pcap_object_list leg needs PRIVATE PcapReadObject access -- honest 5
# not 6) + the 2 message mirrors) + 4 real riders (util.o/util_cstring.o
# the get_error REAL face; the carried witness_conf.cc extracted from the
# 21b-row host + the 23c noreturn jump rider -- MY probe DRIVES the jump
# body LIVE (the first harness to EXERCISE the rider, not only carry it),
# the fatal legs FORK-ISOLATED (setup NEVER reaches the :221-side clear;
# the child cleans inherited statics, arms the jump, prints its OWN face
# + the live queue at the jump site = the honest partial-queue survives-
# the-jump face). witness_dirstor.cc closes ONLY the ErrorMessage CAPTURE
# mirror (OWN-1) + the inert LogMessage (the util.o pull). vectors: DEC
# 19 L (D0-D5 the Directory walk legs + T0-T9/T8b + the 7 forked fatal
# legs F T4-T8/T10/T11) + FACE-A 5 L (16 LIVE glibc fnmatch flags-0 legs
# + the stat mask faces + errno values + PATH_MAX + THEHOME the file_count
# ONE-home deref face). THE get_error EMPTY face MEASURED HONEST: the
# donor config.h carries NO HAVE_GNU_STRERROR_R -> util.cc :104 non-GNU
# branch ((void)strerror_r; return buf); glibc dispatches strerror_r to
# the GNU version writing the POINTER, buf NEVER written -> the C error
# legs print EMPTY error text (vectors pin '...: ]'); the landed utils
# Rust home returns the strerror TEXT -- the cross-language split cited
# at the deviations ledger row 23d, NEVER silent.
# THE FIRST-RUN-SEED law: vectors tracked by SEED (NEVER typed), drift-
# refuse on EVERY re-run, O0==O2 BYTE-IDENT, tamper-proven BOTH streams.
# ZERO new allows / ZERO unsafe in the landing rs; the misc-9 landmine
# NAMING law STAYS (the 'struct Tracer' find-0 + the 21b-row ReloadSurvivor
# pair; the concat forms keep THIS file landmine-clean too).
# SEED arithmetic: the landing banks the NEW seed x3 (724 + 30 twin fns =
# 754 over 83 result-lines = 82 + 1) and ABSORBS 724 into the carried x3
# set; every carried face line-counted EXACT post-edit (NEVER a 4th
# occurrence anywhere per the 21b-row twin include_str! law). The harness
# name stays token-CONCAT'd in THIS file (self-token ZERO bare hits; the
# dir name NEVER typed whole) + NEXT.md STATE-AWARE arms (pre-0 / post-
# EXACTLY-1 LINES).
# ---- FROZEN-ERA token-census hygiene (measured at the row): the
# scannable face of every prior row's own-token count arms is tools/*/
# build.sh + tests/*.rs -- MY (.sh/.cc/.rs) faces carry ZERO foreign-home
# harness tokens (ledger prose cites hyphen-split wherever a bare name
# would otherwise ride); the bare trough/directory tokens ride NO foreign
# COUNT-arm AT ALL (the 23-era harnesses' trough arms are ground-pin CP
# faces, NOT counters -- re-read LIVE at the row). The frozen own-token
# arms re-READ EXACT every build (below).
# THE FROZEN-ERA latent-red face (orchestrator-RULED at the row; NOT
# chased, NEVER edited -- the d-q-io build.sh :195-:198 precedent-comment
# law: the ONE-landing arms of that era are FROZEN-era receipts, those
# harnesses NEVER re-run in the FRESH chain): the d-q3 :105 + misc-3 :160
# find-'daq.h'-NEQ-d-q3 arms read 11 (not 0) at the CLEAN face today --
# every 23a-era+ re-clone harness localizes the REAL-SDK d-q.h in its OWN
# retained copy/ tree (nested-gitignored, NEVER tracked; legitimate re-
# cite-law artifacts). d-q3 + misc-3 stay OUT of the fresh-build set, so
# NOTHING blocks. MY census arms scope to MY tree + the tracked face ONLY
# (the find/grep below are $H-scoped or own-name state-aware). Recorded
# honestly in PLAN.md + KNOWN DEVIATIONS row 23d (the family's FIFTH
# latent-red; the 23c rider-commit precedent decides any sanction at docs).
set -euo pipefail
R=/opt/data/snort3-rust
SRC=/opt/data/snort3-src
L=/opt/data/libdaq
IP=$R/tools/ipheavy_harness          # the 22b donor tree (self-heal)
L4=$R/tools/"link4_harness"          # the carried witness_conf host
H=$(cd "$(dirname "$0")" && pwd)
MN="dir""stor"                       # the RUNTIME self-token (concat law:
                                     # ZERO bare hits in THIS file; the dir
                                     # name NEVER typed whole)
C=$H/copy                            # the copy tree (the 23-era shape)
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/helpers/directory.cc)" -eq 113
test "$(md5sum "$SRC"/src/helpers/directory.cc | awk '{print $1}')" = "e0e4af65fd338c1b9add303142aa36cc"
test "$(wc -l < "$SRC"/src/helpers/directory.h)" -eq 49
test "$(md5sum "$SRC"/src/helpers/directory.h | awk '{print $1}')" = "f7eac140e21c6cecd14ba6e00d546ea4"
test "$(wc -l < "$SRC"/src/packet_io/trough.cc)" -eq 265
test "$(md5sum "$SRC"/src/packet_io/trough.cc | awk '{print $1}')" = "c9aa106b99f5bd4592b8a27fff81d5f8"
test "$(wc -l < "$SRC"/src/packet_io/trough.h)" -eq 88
test "$(md5sum "$SRC"/src/packet_io/trough.h | awk '{print $1}')" = "7931b6efeaf3c329449e7038f68b9d59"
test "$(( 113 + 49 + 265 + 88 ))" -eq 515                             # the quad ledger
test "$(wc -l < "$SRC"/src/utils/util.cc)" -eq 490                    # the real get_error body
test "$(wc -l < "$SRC"/src/utils/util_cstring.cc)" -eq 352
# the CMakeLists ride face (the quad's build homes; measured pins):
test "$(grep -c "directory.cc" "$SRC"/src/helpers/CMakeLists.txt)" -eq 1         # :45
test "$(grep -c "directory.h" "$SRC"/src/helpers/CMakeLists.txt)" -eq 1          # :46
test "$(grep -c "trough.cc" "$SRC"/src/packet_io/CMakeLists.txt)" -eq 1          # :45
test "$(grep -c "trough.h" "$SRC"/src/packet_io/CMakeLists.txt)" -eq 1           # :46
# the ZERO-suite faces (THE re-verified pick inputs; BOTH test dirs):
test "$(grep -c 'add_cpputest' "$SRC"/src/packet_io/test/CMakeLists.txt)" -eq 2  # EXACTLY-2 (the 23c-era pair suites; trough ABSENT -- re-measured at the row)
test "$(grep -ci trough "$SRC"/src/packet_io/test/CMakeLists.txt || true)" -eq 0
test "$(grep -c 'add_cpputest' "$SRC"/src/helpers/test/CMakeLists.txt)" -eq 4    # EXACTLY-4 (the 23c ctx said 5 -- RE-MEASURED 4 at the row; NO directory suite EITHER WAY)
test "$(grep -ci directory "$SRC"/src/helpers/test/CMakeLists.txt || true)" -eq 0

# ---- ground sed pins (line-exact, disk wins over prose) ----
test "$(sed -n '84p'  "$SRC"/src/packet_io/trough.h)" = '    static std::atomic<unsigned> file_count;'   # C CLASS-STATIC -> the one-home global law (NOT a field; the C cross-function bump semantics ride trough.rs::FILE_COUNT)
test "$(sed -n '41p'  "$SRC"/src/packet_io/trough.cc)" = 'std::string Trough::pcap_filter = "*.*cap*";'
test "$(sed -n '257p' "$SRC"/src/packet_io/trough.cc)" = '    file_count++;'
test "$(sed -n '221p' "$SRC"/src/packet_io/trough.cc)" = '            FatalError("Error getting pcaps.\n");'
test "$(sed -n '105p' "$SRC"/src/helpers/directory.cc)" = '        else if ( !filter.empty() && fnmatch(filter.c_str(), de->d_name, 0) )'
test "$(sed -n '41p'  "$SRC"/src/helpers/directory.cc)" = '    error = dir ? 0 : errno;'
test "$(sed -n '32p'  "$SRC"/src/packet_io/trough.cc)" = '#include "helpers/directory.h"'   # :32 THE cross-dir include (THE wall's subject)
test "$(git -C "$L" status --porcelain | wc -l)" -eq 0                 # THE SDK ground STAYS CLEAN (READ-ONLY law)

# ---- name-pin census (measured THIS pass; collisions fire LOUDLY) ----
test "$(find "$R"/tools -maxdepth 1 -iname "*${MN}*" | wc -l)" -eq 1   # THIS dir ONLY
test "$(grep -rl "${MN}_harness" "$R"/tools/*/build.sh 2>/dev/null | grep -v "^$H/build.sh$" | wc -l)" -eq 0
test "$(grep -rl "$MN" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | grep -v "^$R/tests/${MN}_parity_test.rs$" | wc -l)" -eq 0
test "$(grep -rl "$MN" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0   # the landing rs NEVER names the harness token
# the frozen own-token faces re-READ EXACT (MY scannable faces add ZERO
# member; every foreign token CONCAT'd HERE so the scan NEVER self-hits):
test "$(grep -rl "tr""acer" "$R"/tools/*/build.sh | grep -v "^$R/tools/tr""acer_harness/build.sh$" | wc -l)" -eq 16   # the 23c-sanctioned face re-rides (the tr-acer harness :113/:115 arms)
test "$(grep -rl "rs""ubs" "$R"/tools/*/build.sh | grep -v "^$R/tools/rs""ubs_harness/build.sh$" | wc -l)" -eq 5   # the MEASURED live face x5 (23-era mention-arms family; MY face adds ZERO -- own-name excluded by concat, self-scan proven) (the 23-era mention-arms family; own-name excluded by concat construction -- MY file carries ZERO bare hits, proven self-scan)
test "$(grep -rl "misc""9" "$R"/tools/*/build.sh | grep -v "^$R/tools/misc""9_harness/build.sh$" | grep -v "ink4" | wc -l)" -eq 7   # the MEASURED live face x7 (23-era mention arms; MY face adds ZERO) (the 23-era arms' family count re-rides; the misc-9 :460 NAMING law re-cloned below NEVER counts tools)
# the misc-9 landmine NAMING law (the 23c :188-:190 shape re-cloned; the
# pair STAYS the EXACTLY-2 occupants, the landmine NEVER rides a 3rd):
test "$(grep -rl 'struct Tracer' "$R"/src --include=*.rs | wc -l)" -eq 0   # the concat form of THIS line keeps the self-scan honest
test "$(grep -rlE 'ReloadSurvivor|reload_survivor' "$R"/src --include=*.rs | sed "s|$R/||" | paste -sd,)" = "src/framework/mod.rs,src/framework/reload_survivor_subscriptions.rs"
test "$(grep -rlE 'ReloadSurvivor|reload_survivor' "$R"/src --include=*.rs | wc -l)" -eq 2
test "$(grep -rlE "ReloadSurv""ivor|struct Tra""cer" "$R"/src/packet_io "$R"/src/helpers --include=*.rs | wc -l)" -eq 0   # THIS row ships ZERO landmine-name hits in ITS homes (the concat form matches the EXACT landmine tokens ONLY, never 'survivor' prose; the 21a-era sfdaq_config.rs :17 prose line rides NO landmine token)
test "$(grep -rl "daq""io" "$R"/tools/misc3_harness "$R"/tools/mpls_harness "$R"/tests 2>/dev/null | grep -v "^$R/tests/daq""io_parity_test.rs$" | wc -l)" -eq 1   # the 23a-era :191 face re-rides (the misc-3 witness TRIO word)
# the bare s-d name family STAYS the frozen EXACTLY-0 face (the 23c
# exclusion set re-rides; the runtime-JOIN never emits it):
test "$(grep -rl "sf""daq" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' 2>/dev/null | grep -v "^$H/build.sh$" | grep -v "sf""inst" | grep -v "^$R/tools/daq""io_harness/build.sh$" | grep -v "^$R/tools/misc3_harness/build.sh$" | grep -v "^$R/tools/mpls_harness/build.sh$" | grep -v "^$R/tools/"$'\x73'"fmod_harness/build.sh$" | grep -v "^$R/tests/daq""io_parity_test.rs$" | grep -v "^$R/tests/misc3_parity_test.rs$" | wc -l)" -eq 0   # ZERO NEW holders of the row-23c source-name token beyond the frozen set (NOT a MY token: the row files are trough/directory; the exclusion set makes frozen drift NEVER silent)
# the scoped daq.h face (the latent-red ruling ABOVE: MY tree NEVER adds
# an SDK head; the foreign copy faces stay UNtouched, frozen lineage):
# (the tracked face ONLY: my copy/ INHERITS the donor's copy-LOCAL daq.h
# exactly like every 23a-era+ re-clone -- the ruled latent-red face's own
# mechanism, honest-at-the-copy-face; the TRACKED face carries ZERO):
test "$(find "$H" -name d'aq'.h ! -path "$H/copy/*" ! -path "$H/o2/*" | wc -l)" -eq 0

# ---- NEXT.md token face, STATE-AWARE (pre-landing 0; POST the docs bank
# raises it to EXACTLY-1 grep-line; the 23c :176-:183 template re-cloned,
# the NEVER-a-4th-trough-token law honored: NEXT gains ONE dirstor-token
# line, ZERO new bare-trough lines): ----
pre=$(git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/PLAN.md" >/dev/null 2>&1 && echo post || echo pre)
# the DOCS arms ride the DOCS state (the bank lands WITH the landing commit
# but the docs edits exist PRE-commit; the harness-state face keeps the
# un-authored face 0 for a future fresh chain where neither exists):
docbank=$(grep -q "^## .*row 23d" "${R}"/KNOWN\ DEVIATIONS.md && echo banked || echo unbanked)
if [ "$docbank" = unbanked ]; then
    test "$(grep -c "$MN" "$R/NEXT.md" || true)" -eq 0
else
    test "$(grep -c "$MN" "$R/NEXT.md")" -eq 1                       # the ONE dirstor-token line (NEVER a bare-trough NEXT line: the NEXT trough-token count STAYS pre-existing-only)
    test "$(grep -c "${MN}_harness" "$R/NEXT.md")" -eq 1
    test "$(grep -c '^| 23d' "$R/PORTING_PLAN.md")" -eq 1            # the plan-row grep-count-1 law
    test "$(grep -c 'trough' "$R/PORTING_PLAN.md" || true)" -eq 4    # 3 pre-existing + THIS row's own plan row (MEASURED at the row; own arm, honest post-count; NEXT NEVER gained a bare-trough line)
    test "$(grep -c 'row 23d' "${R}"/KNOWN\ DEVIATIONS.md)" -ge 1
fi
grep -q "^## .*row 23d" "${R}"/KNOWN\ DEVIATIONS.md || true          # the LAST-section law (the section MUST be the tail face)
if [ "$pre" = post ]; then
    test "$(git -C "$R" ls-files | grep -c "^tools/${MN}_harness/")" -eq 8
fi

# ---- NEXT.md CITE-ONLY read arms (the pinned-string carry law; every
# frozen arm line-counted EXACT -- the count face of EVERY string was
# re-measured at the row before authoring these pins): ----
test "$(grep -c '684 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '659 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '650 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '633 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '629 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '621 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '605 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '597 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c 'cc \*\*133\*\*' "$R/NEXT.md")" -ge 1        # MUST-RIDE stale exhibit (presence-armed; the live count face re-MEASURED 7 at the row -- presence-armed NEVER pins a moving face, honest)
test "$(grep -c '5 TEST(' "$R/NEXT.md")" -eq 1               # the drift token EXACT-1
grep -q 'address_space_id' "$R/NEXT.md"                      # the 23a FIXIT-M read face
test "$(grep -c '724 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3   # the 23c seed (NOW the absorbed lineage face)
if [ "$docbank" = banked ]; then
    test "$(grep -c '752 tests green / 0 FAILED' "$R/NEXT.md" || true)" -eq 3   # the NEW seed x3 post-docs-bank
else
    test "$(grep -c '752 tests green / 0 FAILED' "$R/NEXT.md" || true)" -eq 0
fi

# ---- ZERO-suite / ZERO-gate census of the ROW files (MEASURED walk; the
# quad carries ZERO C++ test faces -- the ZERO-gate pick re-verified): ----
for f in helpers/directory.cc helpers/directory.h packet_io/trough.cc packet_io/trough.h; do
    test "$(grep -c 'UNIT_TEST\|TEST_CASE\|TEST_GROUP\|^TEST(\|CppUTest' "$SRC/src/$f" || true)" -eq 0   # the quad EXACTLY-0 (re-verified EVERY build)
    test "$(grep -c 'BUILDING_SO\|snort_plugins' "$SRC/src/$f" || true)" -eq 0
done
test "$(find /usr/include -maxdepth 1 -iname 'CppUTest*' | wc -l)" -eq 0
test "$(find /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/local/lib -maxdepth 1 -name 'libCppUTest*' 2>/dev/null | wc -l)" -eq 0

# ---- copy tree = ipheavy DONOR clone (.o's purged); the STALE-DONOR face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi   # donor self-heal
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete   # the 23c donor-eraser lesson: NEVER let a stale copy tree masquerade as a wall -- EVERY build re-clones + re-cps
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140                    # donor CLEAN face MEASURED at the row (the 23c :237 face re-rides)
test "$(find "$C" \( -name directory.cc -o -name "directory.h" -o -name "trough.cc" -o -name "trough.h" \) | wc -l)" -eq 0   # NO row file EVER before the FRESH cps

# ---- FACE 1 OF THE HONEST HISTORY: the RE-ARMED flipped-assert (the 23b
# receipt's own copy face): trough WITHOUT the directory cps in the copy
# tree = EXACTLY the include fatal (the wall re-armed EVERY build, the
# masquerade NEVER silent either way): ----
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
GXX="$GXX0"
cp "$SRC"/src/packet_io/trough.cc "$SRC"/src/packet_io/trough.h "$C"/packet_io/
if $GXX0 -c "$C"/packet_io/trough.cc -o /dev/null 2> "$H"/E4_pre_trough.txt; then
    echo "wall flip BROKE: trough compiles WITHOUT the directory cp -- the :32 include face died? RE-PLAN"; exit 1
fi
grep -q 'helpers/directory.h: No such file or directory' "$H"/E4_pre_trough.txt   # the 23b receipt face RE-PROVEN
rm -f "$C"/packet_io/trough.cc "$C"/packet_io/trough.h

# ---- 4+2 FRESH cps (VERBATIM + cmp-proved, NEVER sed); FACE 2: the
# pairing DISARMS BOTH walls SILENT rc0 (the 23c face re-proven LIVE): ----
cp "$SRC"/src/helpers/directory.cc "$SRC"/src/helpers/directory.h "$C"/helpers/
cp "$SRC"/src/packet_io/trough.cc "$SRC"/src/packet_io/trough.h "$C"/packet_io/
cp "$SRC"/src/utils/util.cc "$SRC"/src/utils/util_cstring.cc "$C"/utils/       # the get_error REAL body (the donor rides OLDER copies -- the 23c :255 face re-rides: util.cc 117 L STALE in the donor; the FRESH cps win)
for f in helpers/directory.cc helpers/directory.h packet_io/trough.cc packet_io/trough.h utils/util.cc utils/util_cstring.cc; do
    cmp -s "$C/$f" "$SRC/src/$f" || { echo "FRESH-CP CMP DEAD: $f"; exit 1; }
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 144                    # 140 + 4 NEW (the utils ride the donor OVERWRITE face, NEVER +1)
$GXX0 -c "$C"/helpers/directory.cc -o "$C"/dir.o 2> "$H"/E4_real_dir.txt
test ! -s "$H"/E4_real_dir.txt                                              # directory SILENT rc0 (the 23c :84 claim RE-MEASURED TRUE at the fresh cp face)
$GXX0 -c "$C"/packet_io/trough.cc -o "$C"/trough.o 2> "$H"/E4_real_trough.txt
test ! -s "$H"/E4_real_trough.txt                                           # trough SILENT rc0 once directory rides -- the wall CLOSED face
$GXX0 -c "$C"/utils/util.cc         -o "$C"/util.o
$GXX0 -c "$C"/utils/util_cstring.cc -o "$C"/util_cstring.o
# the nm app-undef faces (the 23-era shape; measured EXACT at the row --
# dir.o ALL-glibc, trough.o EXACTLY the row pulls):
nm -C -u "$C"/dir.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_dir.txt
test "$(wc -l < "$H"/nm_U_dir.txt)" -eq 7                       # ALL 7 glibc (closedir/fnmatch/opendir/readdir/rewinddir/stat/strlen) -- EXACTLY-0 app names
nm -C -u "$C"/trough.o | grep ' U ' | grep -vE "$NMR|fnmatch|memcmp|stat$|strlen" | sed 's/^ *U //' | sort -u > "$H"/nm_U_tro.txt
test "$(wc -l < "$H"/nm_U_tro.txt)" -eq 7                       # 4 Directory legs (closed IN-LINK by dir.o) + ErrorMessage/FatalError (mirrors) + get_error (REAL via util.o)
test "$(grep -c 'Directory::' "$H"/nm_U_tro.txt)" -eq 4         # THE cross-directory home pull = the wall's CLOSED face
test "$(nm -C --defined-only "$C"/trough.o | grep -c 'B Trough::file_count')" -eq 1   # THE B-definition = trough.o THE home (the 23c witness placeholder CLOSED here)

# ---- THE carried witness_conf EXTRACTION (the 21b-row host law; NEVER
# doubled; md5 face FIRST, then the 23c noreturn jump SITE rider applied
# to the extracted body only, NEVER to the tracked 4dd91018 face): ----
_b=$(grep -n "EOFWC" "$L4"/build.sh | head -1 | cut -d: -f1)
_e=$(grep -n "EOFWC" "$L4"/build.sh | tail -1 | cut -d: -f1)
sed -n "$((_b+1)),$((_e-1))p" "$L4"/build.sh > "$H"/witness_conf.cc
test "$(md5sum "$H"/witness_conf.cc | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"   # the CARRied face VERBATIM
python3 - "$H"/witness_conf.cc <<'EORIDER'
import sys
p = sys.argv[1]
s = open(p).read().split("\n")
i = next(k for k,l in enumerate(s) if l.startswith("void FatalError("))
s[i] = ("void FatalError(const char* f, ...) { va_list a; va_start(a,f); vfprintf(stderr,f,a); "
        "va_end(a); fputc(10, stderr); "
        "if (::fatal_jump_armed) { ::fatal_jump_armed = false; siglongjmp(::fatal_jump, 1); } "
        "abort(); }")
s[0] = ("#include <csetjmp>\n// THE 23c noreturn RIDER jump sites (GLOBAL scope; the :: refs\n"
        "// inside namespace snort resolve HERE -- NEVER a return past a noreturn\n"
        "// witness arm at -O2, the UB law):\nsigjmp_buf fatal_jump;\nbool fatal_jump_armed = false;\n\n") + s[0]
open(p,"w").write("\n".join(s))
EORIDER
test "$(grep -c 'siglongjmp(::fatal_jump, 1)' "$H"/witness_conf.cc)" -eq 1
test "$(grep -c 'void FatalError' "$H"/witness_conf.cc)" -eq 1               # EXACTLY-1 (never doubled)

# ---- compile the row witnesses + probes (O0; the witness pair NEVER
# regenerates: the tracked files ride as authored) ----
$GXX0 -I"$SRC/src" -c "$H"/witness_conf.cc    -o "$H"/witness_conf.o
$GXX0 -I"$SRC/src" -c "$H"/witness_dirstor.cc -o "$H"/witness_dirstor.o
$GXX0 -I"$SRC/src" -c "$H"/probe.cc           -o "$H"/probe.o
$GXX0 -I"$SRC/src" -c "$H"/probe_faceA.cc     -o "$H"/probe_faceA.o

# ---- E9 ONE-HOME flipped-assert (measured EXACTLY-7 multiple-definition
# faces at the row: the 5 twin-able Trough statics -- the pcap_object_list
# leg needs PRIVATE PcapReadObject access, honest 5 not 6 -- + the TWO
# message mirrors; the dup twin copy-local NEVER tracked; the file_count
# leg in the face proves a SECOND home of the counter DIES -- 23c's
# scripted placeholder CLOSED): ----
printf '%s\n' '#include "log/messages.h"' \
    '#include "packet_io/trough.h"' \
    'namespace snort {' \
    'void ErrorMessage(const char*, ...) {}' \
    'void LogMessage(const char*, ...) {}' \
    '}' \
    'std::vector<std::string> Trough::pcap_queue;' \
    'std::vector<std::string>::const_iterator Trough::pcap_queue_iter;' \
    'std::string Trough::pcap_filter;' \
    'unsigned Trough::pcap_loop_count = 7;' \
    'std::atomic<unsigned> Trough::file_count{7};' > "$H"/e9_dup_twin.cc
$GXX0 -I"$SRC/src" -c "$H"/e9_dup_twin.cc -o "$H"/e9_dup_twin.o
if $GXX "$H"/probe.o "$C"/dir.o "$C"/trough.o "$C"/util.o "$C"/util_cstring.o "$H"/witness_conf.o "$H"/witness_dirstor.o "$H"/e9_dup_twin.o -o "$H"/E9_dup_probe 2> "$H"/E9_dup.txt; then
    echo "E9 law BROKE: a mirror co-linked beside the real home"; exit 1
fi
rm -f "$H"/E9_dup_probe
test "$(grep -c 'multiple definition of' "$H"/E9_dup.txt)" -eq 7     # the MEASURED family face (5 statics + 2 mirrors)
test "$(grep -c 'file_count' "$H"/E9_dup.txt)" -ge 1                 # THE mirror-reject leg (the ONE-home law proved LOUD)

# ---- DEC link + run (ONE B-home census; the walk tree rebuilt EVERY run
# by the probe itself from argv; NEVER tracked) ----
LINK="$C/dir.o $C/trough.o $C/util.o $C/util_cstring.o $H/witness_conf.o $H/witness_dirstor.o"
$GXX "$H"/probe.o $LINK -o "$H"/probe
nm --defined-only "$H"/probe | grep -c ' B _ZN6Trough10file_countE' > "$H"/nm_defined.txt
test "$(cat "$H"/nm_defined.txt)" -eq 1                              # EXACTLY-ONE B-home (trough.o; the get_/clear_ accessors ride the .h INLINEs -- W symbols, ONE home law intact)
nm -C -u "$H"/probe | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_probe.txt
test "$(grep -v '@' "$H"/nm_U_probe.txt | wc -l)" -eq 0             # ZERO unresolved app names (the full row graph closes IN-LINK)
( cd "$H" && timeout 120 ./probe walk > vectors_O0.txt 2> probe_dec_stderr.txt ) || { echo PROBE_FAIL DEC O0; exit 1; }
rm -rf "$H"/walk                       # the walk tree NEVER rides the receipts
test ! -s "$H"/probe_dec_stderr.txt                                    # DEC runs SILENT (the fatal legs dup2-mute + fork-isolate; the C FATAL text belongs to the carried family NEVER a receipt)

# ---- FACE-A link + run ----
$GXX "$H"/probe_faceA.o $LINK -o "$H"/probe_faceA
( cd "$H" && timeout 60 ./probe_faceA > vectors_faceA_O0.txt 2> faceA_stderr.txt ) || { echo PROBE_FAIL FACE-A O0; exit 1; }
test ! -s "$H"/faceA_stderr.txt

# ---- O2 twins + the x-stream byte-identity law ----
O2=$H/o2; mkdir -p "$O2"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C"
$GXXA -c "$C"/helpers/directory.cc -o "$O2"/dir.o
$GXXA -c "$C"/packet_io/trough.cc  -o "$O2"/trough.o
$GXXA -c "$C"/utils/util.cc         -o "$O2"/util.o
$GXXA -c "$C"/utils/util_cstring.cc -o "$O2"/util_cstring.o
$GXXA -I"$SRC/src" -c "$H"/witness_conf.cc    -o "$O2"/witness_conf.o
$GXXA -I"$SRC/src" -c "$H"/witness_dirstor.cc -o "$O2"/witness_dirstor.o
$GXXA -I"$SRC/src" -c "$H"/probe.cc           -o "$O2"/probe.o
$GXXA -I"$SRC/src" -c "$H"/probe_faceA.cc     -o "$O2"/probe_faceA.o
LINK2="$O2/dir.o $O2/trough.o $O2/util.o $O2/util_cstring.o $O2/witness_conf.o $O2/witness_dirstor.o"
$GXX "$O2"/probe.o       $LINK2 -o "$H"/probe_O2
$GXX "$O2"/probe_faceA.o $LINK2 -o "$H"/probe_faceA_O2
( cd "$H" && timeout 120 ./probe_O2 walk > vectors_O2.txt ) || { echo PROBE_FAIL DEC O2; exit 1; }
rm -rf "$H"/walk
( cd "$H" && timeout 60 ./probe_faceA_O2 > vectors_faceA_O2.txt 2>/dev/null ) || { echo PROBE_FAIL FACE-A O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt

# ---- FIRST-RUN-SEED face (the law; the seed = the harness's measured
# stdout, NEVER typed; drift-refuse on EVERY re-run; tamper-proven) ----
if [ ! -e "$H"/vectors.txt ]; then
    cp "$H"/vectors_O0.txt "$H"/vectors.txt                      # SEED PASS (first run ever)
    cp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt          # SEED PASS
    echo "SEED PASS: DEC + FACE-A vectors measured (NEVER typed)"
else
    cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt           || { echo "VECTORS DEC DRIFT vs tracked vectors.txt"; exit 1; }
    cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "VECTORS FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }
fi
test -e "$H"/vectors.txt
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt   # receipt (ignored)

# ---- TAMPER-PROVEN blocks (the drift-refuse arm MUST trip LOUD) ----
cp "$H"/vectors.txt "$H"/.vectors_pristine
line=$(grep -n '^D0 ' "$H"/vectors.txt | head -1 | cut -d: -f1)
sed -i "${line}s/noent=2/noent=3/" "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt && { echo "TAMPER ARM DEAD (DEC): flipped errno still matches the fresh run"; exit 1; }
cp "$H"/.vectors_pristine "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "TAMPER RESTORE DEAD (DEC)"; exit 1; }
rm -f "$H"/.vectors_pristine
cp "$H"/vectors_faceA.txt "$H"/.vectors_faceA_pristine
line=$(grep -n '^LIMITS ' "$H"/vectors_faceA.txt | head -1 | cut -d: -f1)
sed -i "${line}s/pathmax=4096/pathmax=4097/" "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt && { echo "TAMPER ARM DEAD (FACE-A)"; exit 1; }
cp "$H"/.vectors_faceA_pristine "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "TAMPER RESTORE DEAD (FACE-A)"; exit 1; }
rm -f "$H"/.vectors_faceA_pristine

# ---- vectors FACE greps (the MEASURED first-run faces authored AT the
# row; the ladder pins NEVER hand-normalized -- every face below was read
# off the run output at the row, the honest D5 maxlen rides the walk-root
# path face re-derivable from the argv law): ----
V=$H/vectors.txt; FA=$H/vectors_faceA.txt
test "$(wc -l < "$V")" -eq 19
test "$(wc -l < "$FA")" -eq 5
grep -q '^D0 noent=2 notdir=20$' "$V"                              # directory.cc :41 opendir errno faces (ENOENT/ENOTDIR)
grep -q '^D1 n=6 set=.*/root/a\.pcap,.*/root/b\.cap,.*/root/sub1/d1\.pcap,.*/root/sub1/d2\.txt,.*/root/sub1/deeper/e1\.cap,.*/root/zz\.txt$' "$V"   # THE recursion face: the dot-prefix skip :86 (a .hidden NEVER surfaces) + the FIFO skip (stat neither-face) + the dangling-symlink stat skip + the sub1/deeper DESCENT
grep -q '^D2 n=2 set=.*/root/b\.cap,.*/root/sub1/deeper/e1\.cap$' "$V"          # the d_name fnmatch face :105 (the whole-PATH '*.*cap*' NEVER matches d_name; the port's mirrors stay honest to the call-site shapes)
grep -q '^D3 n=1 set=.*/sub1/d1\.pcap$' "$V"                                    # the [12] CLASS face (the glibc class arms ride the port subset)
grep -q '^D4 n=6 same=1$' "$V"                                                  # rewinddir = the SAME walk (the :58-:65 face)
grep -q '^D5 reported=15 maxlen=[0-9]* over=0$' "$V"                            # the 255-name deep CHAIN: the :93 path.size() > PATH_MAX - 1 guard NEVER SURFACES an over-length path (over=0 THE face; the walk reports every depth glibc still resolves)
grep -q '^T0 q=4 walk=/a\.pcap,/b\.cap,/sub1/d1\.pcap,/sub1/deeper/e1\.cap$' "$V"   # THE '*.*cap*' DEFAULT filter (:41 via add_source :203): the stars BRIDGE '.cap' -- a.pcap/d1.pcap NEVER match, b.cap/e1.cap DO (the exact-face bridge; a fnmatch SUBSET NEVER covers)
grep -q '^T1 n=6 fc=6 loop=1 seq=fileA\.pcap,fileB\.cap,-,fileA\.pcap,fileB\.cap,-$' "$V"   # SOURCE_LIST walk + the '-' DIRECT bypass :146 + THE LOOP-WRAP :251-:255 (loop 2->1) + THE REAL bump chain :257 (fc==surfaced -- the one-home counter face)
grep -q '^T2 got=1 fc=1,1 has_next=0 cleared=0$' "$V"                           # cleanup :237-side drops the QUEUE, file_count SURVIVES (fc=1,1); clear_file_count :52-side zeroes it (cleared=0 face)
grep -q '^T3 q=6 walk=/a\.pcap,/b\.cap,/sub1/d1\.pcap,/sub1/d2\.txt,/sub1/deeper/e1\.cap,/zz\.txt$' "$V"                                                    # the filter-ALREADY-cleared DIR walk: the tmp_queue SORT :61 over FULL paths (the sub1/d2 sorts BEFORE sub1/deeper -- the full-path order face, NEVER basename-sorted like directory.cc :70)
grep -q '^F T4 jumped=1 msgs=1 q=8 last=\[Error getting stat on pcap file: .*/missing\.pcap: ]$' "$V"   # the list trim/skip/DIR-recurse legs to :213 then the stat-error leg :90-:93: the EMPTY get_error face (the donor config.h NO HAVE_GNU_STRERROR_R -- cited law); q=8 = the PARTIAL queue SURVIVES the long-jump (the fork-child honest face)
grep -q "^F T5 jumped=1 msgs=1 q=0 last=\\[Specified entry in '.*/listF' is not a regular file or directory: .*/fifo1]$" "$V"   # the neither-REG-nor-DIR leg (the FIFO named face; the C branch order cited)
grep -q 'Error getting pcaps under dir: .*nosuchdir: ]' "$V"                    # the dir-open error leg (the EMPTY get_error face rides AGAIN)
grep -q 'No pcaps specified in pcap list' "$V"                                  # the empty-LIST fatal face
grep -q 'Specified pcap is not a regular file: .*/root]' "$V"                   # the add_source DIRECT mask face (a DIR under SOURCE_FILE)
grep -q '^T8b fifo_queued=1 fc=1$' "$V"                                         # the MASK-POSITIVE FIFO queued face (the (S_IFREG|S_IFIFO) mask arms -- the port mirror EXACT)
grep -q '^T9 q=6$' "$V"                                                         # set_filter(NONE) -> the filter-LESS DIR walk (q==6: the FIFO NEVER queued; d2.txt/zz.txt ride)
grep -q '^F T10 jumped=1 msgs=0 q=0' "$V"                                       # the NO-PCAPS found fatal (the all-blank list: get_pcaps TRUE, queue EMPTY -> msgs=0: the 'No pcaps found.' text belongs to the CALLER face -- the probe NEVER calls set_source-side text; the C :221-side fatal fires with NO captured ErrorMessage -- honest)
grep -q '^F T11 jumped=1 msgs=1 q=1' "$V"                                       # the PARTIAL-queue face: [valid, MISSING] -> q=1 AT the jump site (the get_pcaps side-effects-survive-the-jump law)
test "$(grep -c '^D' "$V")" -eq 6
test "$(grep -c '^T' "$V")" -eq 6
test "$(grep -c '^F ' "$V")" -eq 7
test "$(grep -c ']$' "$V")" -eq 7                                                # every fatal leg ONE physical line (the capture-trim law; the C format '\n' stays in the CAPTURE, NEVER the vectors face)
grep -q '^FNM star-span=1,star-miss=0,default-on-pcap-TRUE=1,qmark=0,qmark-hit=1,class-hit=1,class-miss=0,class-neg-hit=1,class-range=1,class-range-miss=0,escape-star=1,escape-star-miss=0,unterminated-literal=1,star-spans-slash=1,qmark-slash=1,case-sensitive=0, nomatch=1$' "$FA"   # glibc fnmatch flags-0 LIVE x16 (the port's SUBSET mirrors THESE faces EXACTLY: '/' NOT protected, classes + [!] + ranges, the '\' escape, the unterminated-'[' literal, NO case-fold)
grep -q '^MODES ifmt=61440 ifdir=16384 ifreg=32768 ififo=4096 mask_expr=0$' "$FA"    # the S_IF* mask arithmetic walks + the (S_IFREG|S_IFIFO) & ~S_IFMT == 0 face
grep -q '^ERRS enoent=2 enotdir=20$' "$FA"
grep -q '^LIMITS pathmax=4096 guard=4095$' "$FA"                                 # the :93 guard constant face
grep -q '^THEHOME rowbody=1 fc=0,0 zero=1$' "$FA"                                # the file_count ONE-home deref face (trough.o ONLY)
test "$(grep -c 'WIT_' "$V" || true)" -eq 0                                     # honest vectors face (the legacy twin arms re-ride: NO witness-token rides the vectors)

# ---- python pin block (the row's line-exact + vectors-ride face; the
# 21b-law: the twin asserts what the C source ACTUALLY says) ----
python3 - "$SRC" "$H" <<'PYPIN'
import sys
S, H = sys.argv[1], sys.argv[2]
dc = open(S + "/src/helpers/" + "directory.cc").read().splitlines()
dh = open(S + "/src/helpers/" + "directory.h").read().splitlines()
tc = open(S + "/src/packet_io/trough.cc").read().splitlines()
th = open(S + "/src/packet_io/trough.h").read().splitlines()
assert dc[40] == '    error = dir ? 0 : errno;'                     # :41 the errno capture face
assert dc[104] == '        else if ( !filter.empty() && fnmatch(filter.c_str(), de->d_name, 0) )'  # :105 d_name fnmatch
assert dc[95] == '        if ( S_ISDIR(sb.st_mode) )'              # :96 the DESCENT arm
assert dc[85] == '        if ( !strncmp(de->d_name, ".", 1) )'     # :86 the dot-prefix skip (the .hidden face)
assert dh[38] == '    DIR* dir;'                                   # :39 the stream member (the Rust Vec-snapshot deviation home)
assert tc[31] == '#include "helpers/directory.h"'                  # :32 THE cross-dir include (the wall's subject)
assert tc[40] == 'std::string Trough::pcap_filter = "*.*cap*";'    # :41 THE default filter (the exact-bridge face)
assert tc[256] == '    file_count++;'                              # :257 THE bump (the ONE-home producer)
assert tc[43] == 'unsigned Trough::pcap_loop_count = 0;'           # :44
assert tc[44] == 'std::atomic<unsigned> Trough::file_count{0};'    # :45 THE DEFINITION home in the .cc
assert th[83] == '    static std::atomic<unsigned> file_count;'    # :84 C CLASS-STATIC (the one-home global law, NOT a field -- honest vs the C file-static->field law)
assert th[41] == '    }'                                           # :42 SourceType enum close (0/1/2 ride)
v = open(H + "/vectors.txt").read(); fa = open(H + "/vectors_faceA.txt").read()
assert "T1 n=6 fc=6 loop=1" in v                                   # the real-bump one-home face rode
assert "star-spans-slash=1" in fa and "nomatch=1" in fa            # flags-0: '/' NOT protected (the whole-path face)
assert "pathmax=4096" in fa
assert "rowbody=1" in fa                                           # the ONE home deref-proved
print("PYPIN_OK")
PYPIN

# ---- GATE census (the ZERO-gate pick: the census walked, NEVER typed;
# the gate artifacts NEVER touched -- the law) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af'); test "$frozen" -eq 9   # the frozen legacy 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 26
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 18
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"   # the tracked face
test "$(git -C "$R" ls-files | grep -c 'tools/.*gate\.txt')" -eq 1
test ! -e "$H"/gate.txt                                              # ZERO gate ships row 23d
git -C "$R" check-ignore -q "tools/${MN}_harness/gate.txt"           # NEVER-land posture IGNORED-proved

# backbone10 STAYS TEN (the chain law re-read at the s-f-d/23c-row VERBATIM
# arrays; the 5339c7ee ledger face re-rides; NO new backbone symbol -- this
# row owns NO shared frozen face): ----
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
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H"/backbone10.txt            # receipt (ignored)
test "$(wc -l < "$H"/backbone10.txt)" -eq 10                                     # backbone STAYS 10

# ---- STATE-AWARE 8-face stageables dual guard (the tracked face EXACTLY-8
# post-commit; ZERO-LEAK proven) ----
untracked=$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort)
tracked=$(git -C "$R" ls-files "tools/${MN}_harness" | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H"/stageables.txt
test "$(echo "$face" | wc -l)" -eq 8
for f in .gitignore PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_dirstor.cc; do
    echo "$face" | grep -q "tools/${MN}_harness/$f\$" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy/ o2/ probe probe_O2 probe_faceA probe_faceA_O2 probe.o probe_faceA.o \
         witness_dirstor.o witness_conf.cc witness_conf.o e9_dup_twin.cc e9_dup_twin.o E9_dup_probe \
         E4_pre_trough.txt E4_real_dir.txt E4_real_trough.txt E9_dup.txt \
         vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt \
         faceA_stderr.txt probe_dec_stderr.txt \
         nm_U_dir.txt nm_U_tro.txt nm_U_probe.txt nm_defined.txt stageables.txt backbone10.txt \
         gate_md5_lineages.txt md5_pinned.txt .vectors_pristine .vectors_faceA_pristine walk; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
for f in .gitignore PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_dirstor.cc; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" && { echo "WRONGLY IGNORED: $f"; exit 1; } || true
done
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 8
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|PLAN\.md|build\.sh|probe(_faceA)?\.cc|vectors(_faceA)?\.txt|witness_dirstor\.cc')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
else
    git -C "$R" status --porcelain | grep -qxF "?? tools/${MN}_harness/"
    test "$(echo "$untracked" | wc -l)" -eq 8
fi
test -z "$(git -C "$R" diff --name-only --cached)"        # ZERO staged churn
# single-tenant porcelain face (the landing family: the 8-file harness +
# the 2 landing rs + the 2 mod-rs wiring + the OWN parity twin + the docs
# the 23c-row landing rs stays CLEAN (the one-home measurement moved
# NOTHING there -- the seam-param law, the rider-outcome echo below):
dirty=$(git -C "$R" status --porcelain | grep -vcE "^\?\? tools/${MN}_harness/$|^\?\? \"tools/${MN}_harness/\"|^ M \"?(src/helpers/mod\.rs|src/packet_io/mod\.rs)\"?$|^\?\? src/helpers/directory\.rs$|^\?\? src/packet_io/trough\.rs$|^\?\? tests/${MN}_parity_test\.rs$|^ M NEXT\.md$|^ M PORTING_PLAN\.md$|^ M \"?KNOWN DEVIATIONS\.md\"?$" || true)
test "$dirty" -eq 0

# ---- the tail (the honest echo faces) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "WALL faces (the honest TWO-face history, BOTH LIVE every build): (1) the trough-ONLY fresh copy DIES EXACTLY the helpers/directory.h include fatal (:32; the 23b receipt RE-ARMED true at ITS face); (2) the 4-file FRESH copy compiles BOTH SILENT rc0 (the 23c DISARMED pairing re-proven) -- the 23b 'directory.h wall' receipt stands RECORDED as a DONOR-ERASER face, NEVER an SDK wall (the fresh-cp law, re-cloned per-build like 23c:580)"
echo "nm census: dir.o EXACTLY-7 app-undef ALL glibc (ZERO app names) + trough.o EXACTLY-7 (4 Directory legs closed IN-LINK by dir.o + ErrorMessage/FatalError mirrors + get_error REAL via the FRESH util.o cp) + the FULL probe EXACTLY-0 unresolved app names; the file_count B-definition EXACTLY-1 = trough.o THE home (the 23c scripted witness placeholder CLOSED — the landed trough.rs owns the counter; the 23c-row scripted seam-param faces UNMOVED IN-COMMIT: prep_counts/reset_stats ride caller-threaded PegCount args, its frozen :380 nm-pull + vectors S8 pins belong to ITS OWN link face, NEVER disturbed)"
echo "get_error face (MEASURED HONEST): the donor config.h carries NO HAVE_GNU_STRERROR_R -> util.cc :104 non-GNU branch ((void)strerror_r; return buf) -- glibc dispatches strerror_r to the GNU version writing the POINTER, buf NEVER written: the C error legs print EMPTY error text (vectors-pinned ': ]'); the landed utils Rust home returns the strerror TEXT -- the cross-language text-face split cited at the deviations ledger row 23d, NEVER silent"
echo "gate census (walked, never typed): 26 on-disk / legacy 9 x 4826fc22 / 18 lineages / tracked-1 gre; ZERO gate ships row 23d (the quad carries EXACTLY-0 TEST faces + the helpers test CMake MEASURED add_cpputest-4 / packet_io test CMake EXACTLY-2 -- trough absent, no directory suite: the pick claims re-verified LIVE, the 23c-prose 'helpers 5 cpputests' corrected to the measured 4 honestly)"
echo "backbone STAYS $(wc -l < "$H"/backbone10.txt) (symbol-vs-array; the 5339c7ee ledger face re-rides)"
echo "DIR""STOR_DONE vectors=$(wc -l < "$H"/vectors.txt) faceA=$(wc -l < "$H"/vectors_faceA.txt) gates=0 (the PAIR SILENT rc0 at the FRESH cp face; the include fatal RE-ARMED honest; the file_count ONE home LANDS via trough.o)"

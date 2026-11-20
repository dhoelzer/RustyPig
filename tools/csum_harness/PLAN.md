# csum_harness PLAN — row 18b: ip/checksum.h (all-inline header lib, 284 L) + Rust-side translation of its CppUTest suite

Recon ground: snort3-src `fe29cbe` (shallow clone; `git rev-parse --is-shallow-repository` = true — measured, so ALL history below is pinned at the tag, no upstream PR dates recoverable). Port repo HEAD `3295b45` (18a DONE, lineage head fmod; 91 commits, 473/0 green). This PLAN verifies the NEXT.md:265-:282 18b proposal with OWN measurements, runs the scratch compile/nm backbone (PLAN-0 discipline), enumerates the known-answer/quirk arm plan from ground, and settles the gate-identity argument. Scratch: `/opt/data/cache/scratch/row18b/` (proof files listed at bottom). Ground repo READ-ONLY all pass.

## 0. VERDICT: NEXT.md's 18b proposal CONFIRMED (every load-bearing claim independently re-measured; ONE census correction: consumers are EIGHT files, not 7)

| NEXT.md claim (cite) | my measurement (this pass) | verdict |
|---|---|---|
| checksum.h = 284 L (NEXT.md:242, :265) | `wc -l src/codecs/ip/checksum.h` = **284** | ✓ |
| "ALL inline" (:265) | 22 `inline` lexemes + 1 `static` fwd decl (:59); **13 inline definitions** (read_word :83, detail::cksum_add :90, add_ipv4_pseudoheader :111, add_ipv6_pseudoheader :124, add_tcp_header :153, add_udp_header :171, add_ip_header :189, icmp_cksum :208/:218, tcp_cksum :223/:235, udp_cksum :247/:259, ip_cksum :271, cksum_add :280) **ZERO out-of-line defs** — and now nm-PROVEN, §2 | ✓ |
| suite = 10 TESTs / 3 TEST_GROUPs / 10 CHECKs (NEXT.md:243; "10-TEST/3-GROUP" :266) | `grep -c '^TEST('` = **10**; TEST_GROUP :56/:107/:156 = **3**; assertion statements **10** = 6 CHECK_EQUAL (:67/:78/:89/:100/:181/:192) + 4 CHECK(true) (:122/:130/:143/:149) | ✓ |
| "adds ZERO .o to any donor link" (:267) | scratch: header-as-TU emits **ZERO text symbols** (§2 E2); consumer TU adds only COMDAT-weak W defs, donor closure has **0 checksum-surface defs**, residue survivors = 1 libc symbol | ✓ measured, §2 |
| CppUTest NOT runnable here (:258, "env facts") | scratch E4: `g++ -fsyntax-only` on checksum_test.cc → **`fatal error: CppUTest/CommandLineTestRunner.h: No such file or directory`** (test :36); no /usr/include/CppUTest, no dpkg/pkgs, no vendored copy — `cpputest_fatal.txt` | ✓ measured, §2 E4 |
| "7 consumers (grep: cd_pgm/cd_gre/cd_icmp4/cd_udp/cd_ipv4/cd_icmp6/cd_tcp)" (:242) | **CORRECTION: EIGHT consumer files.** The `#include "checksum.h"` census also hits **src/protocols/packet_manager.cc:30** (`"codecs/ip/checksum.h"`), with 3 real call lines: :641 `checksum::icmp_cksum(buf.data(), buf.size())`, :697 `checksum::Pseudoheader6 ps6;`, :705 `checksum::icmp_cksum(buf.data(), ip_len, ps6)`. git grep (HEAD, whole src): 39 qualified `checksum::` lines / 8 files | ✗ undercount — fix the call map, §3 |
| gate chain 9-straight, 18b = 10th (:268, :313) | md5 census over all 39 tracked gate.txt: **exactly 9 files carry `4826fc2233044a2d5429413faf0ae1af`** (flog + fmod + 7 older f* harnesses); fmod build.sh:1083-:1084 hard-assert tail + md5 | ✓ + stronger zero-EDIT argument, §4 |
| 2026 hardening = quirk pin, guard arms: len<N -> len=0, never ~2^64 walk (:273-:278; NEXT.md:243 header note) | ground guard blocks checksum.h:157-:162 / :175-:180 / :193-:198 (`if (len < X_MIN_HEADER_LEN) { len = 0; return; }`); scratch probe: **len->0, cksum untouched (0x0000), pointer NOT advanced (ptr_moved=0)** — the third fact is NEW (not in the C suite; the Rust port must pin it too), §5 | ✓ measured |
| shortest-first ordering: 18b=284 < 18c≈550 < 18d≈730 / 18e≈720 (:265-:305) | subagent re-run: 18c = codec_api.h 26 + codec_api.cc 121 (=147 ✓) + cd_default 83 + cd_bad_proto 98 + cd_no_next 116 + cd_raw 105 = **549**; 18d = cd_eth 262 + codec_module.{h,cc} 340 + cd_arp 128 = **730**; 18e = 143+134+163+143+138 = **721**. Totals: codecs/ = **11,914 L / 48 files**, non-test **11,289** — every NEXT.md number exact. Footnote: 18e (721) < 18d (730) by 9 L — strict size-order would swap them; keep NEXT.md order (18d registers the codec vocabulary/module glue 18e+ rows consume) — cost-free note, not a defect | ✓ (§6 table) |

**Why 18b stays the row leader even though smaller FILES exist**: raw smallest closed single-TUs are cd_default.cc 83 L / cd_bad_proto 98 / cd_raw 105 / cd_no_next 116 (measured top-25 ascending) — but they carry ZERO test material, they ADD .o files to the link (gate by-construction argument, not zero-EDIT), and they defer the checksum vocabulary that 39 call-lines across 8 files (incl. the FUTURE ip/tcp/udp/ipv4/ipv6/gre/icmp rows) consume. 18b is the smallest closed unit that (a) ships regression material (201-L suite, 10 TESTs), (b) contributes literal ZERO link objects, and (c) pre-pins the primitive layer for every later ip row. NEXT.md's ordering stands.

## 1. Include closure — ZERO cp delta vs the fmod donor (measured)

checksum.h includes (checksum.h:23-:26): `<cstddef>`, `<cstring>`, `<protocols/protocol_ids.h>`. The donor copy tree ALREADY carries `copy/protocols/protocol_ids.h` (fmod build.sh:222 brace list). Scratch compile of a consumer TU with donor GXX flags (`g++ -std=c++17 -O0 -w -I$C`, the fmod build.sh:618 chain minus the lua/node -I): **SYNTAX-OK + OBJ-OK first try, no grafts, no shims, no FIXACC, no witness headers**. protocol_ids.h drags only `<cassert> <cstdint> <limits> <type_traits>` (:23-:26) — all libstdc++ system headers. Its two TU-static tables (`num_protocol_idx`/`num_protocol_ids`) are the ONLY non-checksum rodata the consumer picks up — file-static, `r` class, internal linkage, never a link entity.

Endianness note pinned from ground: `read_word` (:83-:88) is a native-endian memcpy of a `uint16_t` — host LE on x86_64. The pseudoheader unions pun bytes-as-received (network order in the wire fields) into `arr[6]`/`arr[18]` words. The ones-complement sum is byte-swap symmetric over the full-word body (Zimmermann), but the **odd-tail arm (:102-:103) adds the last byte raw — NOT swap-invariant**. The Rust port on LE hosts is value-identical if it walks u16 LE words; §5 Q1 pins the 16-vs-15-byte ladder as the swap-symmetry breaking arm.

## 2. SCRATCH COMPILE + nm RESIDUE BACKBONE (REAL runs, /opt/data/cache/scratch/row18b)

Setup: `cp -r tools/fmod_harness/copy` (6.6 MB donor closure WITH its 18a .o set) + `copy/codecs/ip/checksum.h` (path style matches the consumer includes `"checksum.h"` at cd_*.cc and `"codecs/ip/checksum.h"` at packet_manager/test — both resolve under `-Icopy`). Probe TU `probe_probe.cc` = guard arms + public-API arms + valid-input verify + odd-tail/zero-length ladder + pseudoheader word dumps (the §5 known-answer draft).

- **E1 — consumer-TU compile**: `g++ -std=c++17 -O0 -w -I$S/copy -c probe_probe.cc` → OBJ-OK (11,464 B). ZERO cp/shim/graft deltas needed (§1).
- **E2 — nm -u residue of the consumer .o**: **exactly 1 U-entry: `U printf`** (`residue_U.txt`). App-residue (checksum::/Pseudoheader/cksum*/add_*_header) = **0**. comm-diff vs the donor closure's **5,898 defined symbols** (union: all scratch/18a `copy/**/*.o` + fmod `stubs.o`, `donor_defs.txt`): survivors = `printf` ONLY — the donor closure links libc so even that resolves. **The closed-unit proof: checksum.h's app residue against the 17m-18a donor tree is EMPTY; no witness can ever be needed for this row.**
- **E3 — the header AS a TU** (`hdr_tu.cc` = single include): `nm hdr_tu.o` = **5 symbols, ALL `r` (rodata: 3 constexpr length constants TCP/UDP/IP_MIN_HEADER_LEN + the 2 protocol_ids statics); ZERO text (no T/W)**. This is the nm proof of "all-inline / zero .o" (the .h's own comment :68-:75 says why it stays in a header — multiple DSOs consume it, linker-flag fragility). At -O0 a CONSUMER that calls the helpers emits **11 out-of-line COMDATs, class `W`** (`probe_defs.txt`/`probe_D.txt`: detail::read_word/cksum_add/add_ipv4_pseudoheader/add_ipv6_pseudoheader/add_tcp_header/add_udp_header/add_ip_header + checksum::cksum_add/ip_cksum/tcp_cksum x2/udp_cksum x2 minus one folded/icmp pair — 11 W total) + `t _ZN8checksumL9cksum_addEPKvm` (the :59 `static` fwd decl residue) + 6 `r`. **Witness shapes for the record**: none of these is a link hazard — `W` = weak, COMDAT one-definition rule; grep of the 5,898-symbol donor closure for `cksum|Pseudoheader|add_tcp_header|add_udp_header|add_ip_header` = **0 hits** (nobody defines or references the checksum surface yet — consistent with §3 Rust census AND with the donor C tree, which cp's no codec TUs).
- **E4 — CppUTest wall**: `g++ -fsyntax-only -Icopy -I$SRC/src checksum_test.cc` → `fatal error: CppUTest/CommandLineTestRunner.h: No such file or directory` (`cpputest_fatal.txt`). Host has NO CppUTest (find/dpkg/pkg-config all empty). The suite compiles only its FIRST include wall — even the `#include "codecs/ip/checksum.h"` + `"utils/endian.h"` (:32, :34) lines would resolve; the runner header cannot. → **no native C gate is buildable for this suite; the 16g/16h Rust-side-translation precedent is the ONLY honest path** (NEXT.md:258 rule re-proven).
- **E5 — inline-identity known answers, -O0 vs -O2**: probe linked and run at BOTH levels; outputs **byte-identical** (`ka_O0.txt` == `ka_O2.txt`, diff empty). The values (§5) are stable across optimization — the fold/guard semantics have no opt-dependent UB in the guarded arms. (Pre-hardening the len-underflow arm WAS UB: test header :17-:31 documents size_t wrap → ~2^64 scan → SIGSEGV; ground now guards, §5.)

## 3. Consumer census vs donor-tree call sites — EXACT 39 qualified call sites, 8 files (git grep -c at HEAD fe29cbe)

| file | `checksum::` lines | call sites (line:cite) |
|---|---|---|
| cd_pgm.cc | 1 | `cksum_add(raw.data, raw.len)` :137 (PGM checksum-verify) |
| cd_gre.cc | 2 | `cksum_add(raw_pkt, updated_len)` :122; `cksum_add(buf.data(), buf.size())` :160 — the future **gate-changing row** (embedded Catch `[cd_gre]` :352, `#ifdef UNIT_TEST` :351 + catch include :35) |
| cd_icmp4.cc | 2 | `cksum_add(icmph, raw.len)` :161; `icmp_cksum(h, updated_len)` **2-arg** :588 (encode path) |
| cd_udp.cc | 12 | valid_checksum4/6 `udp_cksum(...)==0` :290/:305; Pseudoheader/Pseudoheader6 fills :282/:297/:528/:539/:568/:579; `udp_cksum` stores into `uh_chk` :535/:546/:575/:586 |
| cd_ipv4.cc | 3 | `ip_cksum(iph, hlen)` :263; `ip_cksum(ip4h_out, IP4_HEADER_LEN)` :676; `ip_cksum(h, hlen)` :695 |
| cd_icmp6.cc | 4 | `icmp_cksum(icmp6h, raw.len, ph6)` :207; :462 (encode) + `Pseudoheader6` fills :199/:454 |
| cd_tcp.cc | 12 | valid_checksum4/6 `tcp_cksum(...)==0` :184/:199; ps/ps6 fills :176/:191/:694/:707/:735/:746; `th_sum` stores :703/:716/:742/:753 |
| **packet_manager.cc** | **3** | **`icmp_cksum` 2-arg :641; `Pseudoheader6 ps6` :697; `icmp_cksum` 3-arg :705 (echo-reply builders, the row-20 packet_io surface)** |
| total | **39** | NEXT.md:242's file list of 7 MUST become 8 (§0 row) |

Outside-codecs sweep (subagent, git grep excl. src/codecs + packet_manager): ZERO consumers in file_api/session/sf_ip/framework/main — those "checksum" hits there are NetworkPolicy FLAG plumbing only (policy.h:202-:211 accessors; already Rust-ported in `src/main/policy.rs:172-:219`, zero compute overlap). Codec-side include census matches 8 + the suite include `codecs/ip/checksum.h` (checksum_test.cc:32) + CMake registration `add_cpputest(checksum_test)` (src/codecs/ip/test/CMakeLists.txt:1 — proves upstream intends the CppUTest runner, unreachable on this host per E4). Embedded-Catch sweep across all 39 non-test codec files: cd_gre 1 TEST_CASE, **18b/18c/18d/18e candidates 0/0** (no hidden gate mass in the proposed rows).

## 4. Gate identity — the 10th-straight argument is ZERO-EDIT (oracle argument, file identity, not by-construction)

Anchor facts re-measured this pass: `md5sum tools/fmod_harness/gate.txt` = `4826fc2233044a2d5429413faf0ae1af`; the CENSUS over all 39 tracked `gate.txt` shows exactly **9** carry that md5 (the 9-straight chain; flog+fmod are the two freshest). The fmod harness self-checks the chain VERBATIM at build.sh:1083 (`grep -q 'All tests passed (114 assertions in 22 test cases)'`) and :1084 (`md5sum | grep -q '^4826fc22...'`) — the oracle is the committed SCRIPT, not a human memory.

Oracle argument for 18b = 10th straight, ZERO-EDIT form:
1. **No donor file is touched.** 18b writes only NEW files (`tools/csum_harness/*`, `src/codecs/**`, `tests/checksum_parity_test.rs`, .gitignore block) — the NEXT.md:341 session ritual rebuilds the lineage head; every OTHER harness (the 9 gate.txt holders) is a frozen directory. A frozen `build.sh` + frozen `copy/` recipe + frozen sources at the fixed ground commit compile to byte-identical binaries ⇒ byte-identical stdout ⇒ byte-ident `gate.txt`. Deterministic input set ⇒ byte-ident md5; NO semantic argument needed (contrast 17q-17a: those rows had to ADD inert .o to the link and argue "inert by construction" + a comm-diff; 18b adds NOTHING to any existing link).
2. **The row contributes ZERO .o** (§2 E3: header TU = zero text symbols; consumer TU = W-only COMDAT, 0 hard defs) — even the strongest adversarial reading "checksum.h joins some objs loop" is impossible: there is no TU to compile; `objs` loop entries are `.cc` files.
3. **The suite cannot perturb the C gate**: CppUTest is unbuildable (E4, measured) and its suite would register via `add_cpputest` (CMakeLists), never via the harness catch recipe; catch.hpp (fmod build.sh:249 pull, :272 shim) compiles only TEST_CASE material — checksum_test.cc carries 10 `TEST(` + 0 `TEST_CASE` (measured), and the CMake gate path is never invoked by the harness scripts (they compile UT TUs directly with -DUNIT_TEST, fmod build.sh gate block). So 114/22 CANNOT move in ANY harness this row.
4. **Insurance ritual**: the row still runs the NEXT.md:341-:342 double-rebuild of fmod_harness (md5 stable x2) — the zero-EDIT proof makes those rebuilds a receipt, not a risk.
5. **NEW csum_harness posture**: build it as **probe-only** (vectors + known-answer ladder; NO third Catch gate — there is zero Catch material this row; the cd_gre UT block belongs to its own row per NEXT.md:314-:324, NEVER early). Its probe link gains the 11 W checksum COMDATs (§2 E3 witness shape) — weak, zero collision vs donor_defs (0 hits measured). vectors.md5 NEW (fresh, NEVER copied); gate lineage untouched because csum_harness ships no gate binary. (If the orchestrator prefers a gate for lineage symmetry, the fmod gate copy-forward pattern would just re-run the SAME 4Catch UT TUs — md5 identical by construction; but zero-EDIT is cleaner: NO new gate.txt.)
6. cd_gre rule (the NEXT.md:314-:324 gate CHANGE rule) is unaffected: 18b compiles NO cd_gre TU, touches no UNIT_TEST block (:351-:366 stays frozen until the cd_gre row).

## 5. Known-answer + quirk-arm plan (measured values from scratch; the harness RE-MEASURES at build — NEVER type forecast values from this plan, the 17p lesson; these numbers exist to prove the ladder is REAL and to cross-check the build run)

All probes on the suite fixture `short_buf[16] = 22 11 44 33 66 55 88 77 aa 99 cc bb ee dd 00 ff` (checksum_test.cc:49-:52) — byte-for-byte in vectors.

**Ladder (measured ka_O0.txt == ka_O2.txt):**

| arm | source cite | measured (-O0 == -O2) |
|---|---|---|
| G tcp/udp/ip len=4 -> len | :153/:171/:189 guards | `len=0, cksum=0x0000, ptr_moved=0` (ptr fact NEW, beyond the C suite) |
| G tcp len=0 -> len | :92-:100 TEST analog | `len=0` |
| tcp_cksum v4 short (len=4) | test :109-:123 analog | `0xf9ff` (pseudoheader-only complement: guard zeroes len, cksum_add walks len=0 => ~ph4_sum; ph protocol byte 06 at :179 hdr field) |
| tcp_cksum v6 short (ph6{}) | test :126-:131 | `0xffff` (all-zero ph6 -> ~0) |
| udp_cksum v4 short | test :134-:144 | `0xeeff` |
| ip_cksum short (len=4) | test :147-:150 | `0xffff` (0 words + fold(~0)) |
| tcp 20B valid: sum / re-verify | test :168-:182 | sum=`0x9e7c`, reverify `==0` TRUE |
| ip 20B valid: sum / re-verify | test :186-:193 | sum=`0x1d0c`, reverify `==0` TRUE |
| cksum_add len 16/15/1/0 | :90-:109 | `0xbc43 / 0xbb44 / 0xffdd / 0xffff` (word-walk, ODD-TAIL, single-byte, empty arms) |
| Pseudoheader word pun (sip=127.0.0.1 net-order) | :30-:42 | `arr=007f 0100 007f 0100 0600 1400`, `sizeof=12` |
| Pseudoheader6 | :44-:56 | `sizeof=36`, `arr[17]=0x1400` (len word at u16 index 17) |

**Quirk arms to pin in the Rust port + vectors (each = ground behavior, with cites):**
- **Q1 Endianness/odd-tail**: read_word native-LE (:83-:88); ones-complement sum swap-symmetric over words, tail arm (:102-:103) NOT — pin `cksum_add(short_buf,15)` = 0xbb44 (≠ byte-swapped 16-byte result) as the swap-breaking arm; pseudoheader union stores LE (:30-:56, measured word dump above). The C suite's `htons(20)` (test :174) becomes raw bits 0x1400 LE — the Rust fixture MUST write 0x1400 (or `20u16.to_be_bytes()` semantics), never a host-native 20.
- **Q2 Fold/posture of the complement**: `cksum = (cksum>>16)+(cksum&0xffff); cksum += (cksum>>16); return (uint16_t)(~cksum);` (:105-:108) — uint32 accumulate: max 48 words x 0xffff < 2^32, single fold + carry, the (uint16_t) truncation is load-bearing for the all-ones input — `cksum_add(buf,0)` = `0xffff` = ~0 exactly (:108). Rust: `!(cksum as u32) as u16` ≡ C cast semantics; pin len=0 arm.
- **Q3 Guard posture = the 2026 hardening regression** (:157-:162, :175-:180, :193-:198 + test header :17-:31 prose): len<N ⇒ THREE observable facts: len==0 (pin), cksum input untouched (pin 0x0000), pointer NOT advanced (pin ptr_moved — the C suite checks ONLY len; Rust port + probe pin all three). NEVER transcribe the old underflow UB; pin the guarded behavior (NEXT.md:278 ruling, re-affirmed).
- **Q4 Overload resolution**: icmp_cksum 2-arg (:218) vs 3-arg (:208); tcp/udp Pseudoheader vs Pseudoheader6 (:223/:235, :247/:259) — Rust models as distinct fns (`icmp_cksum` / `icmp_cksum_v6`) — deviation-noted shape choice; the C++ overload set itself is not portable; call map §3 pins WHO uses which arm later.
- **Q5 static_assert sizes**: 12 B / 36 B (:41, :55) — Rust-side `size_of` pins equal to the measured 12/36 (union repr: C union punning = the test's whole point; Rust port uses explicit byte layout + the measured word dump; deviation "union punning -> from_ne_bytes helpers", R-posture documented).
- **Q6 fwd-decl residue witness**: the `static uint16_t cksum_add(...)` fwd decl at :59 pairs with the public inline :280-:281 — nm witness `t _ZN8checksumL9cksum_addEPKvm` at -O0 (probe_defs.txt); Rust twin: keep `checksum::cksum_add` (public entry) calling the `detail` core with init 0 (:281 verbatim shape).

## 6. Smallest-first comparison table (own measurements; settles vs the 18b proposal)

| candidate | L | test material | link delta | vocabulary gain | closed unit? |
|---|---|---|---|---|---|
| **18b ip/checksum.h** | 284 (+201 suite, 10 TEST/3 GROUP/10 CHECK) | 1 CppUTest suite (Rust-side) | **ZERO .o (nm-proven §2)** | pre-pins 39 call sites / 8 files (§3) — EVERY later ip row | YES — include closure = donor-resident, zero cp delta (§1) |
| cd_default.cc (absolute smallest, 83 L) | 83 | 0 | +1 .o | none | YES but worthless as a row leader |
| 18c bundle (codec_api+4 no-op cd_*) | 549 | 0 | +5 .o | first CodecApi slab (rides 17d base) | YES (NEXT.md numbers verified exact) |
| 18e IPv6-ext five | 721 | 0 | +5 .o | rides landed codec.rs H/O tables | YES |
| 18d root layer (cd_eth+codec_module+cd_arp) | 730 | 0 | +3 .o | codec_module glue 18e+ rows consume | YES |

Standing drags verdict (scratch-armed, NEXT.md:306-:311): the 18b probe resolves NOTHING of the codec.cc/protocols-struct/RawData drags (checksum.h needs none — §1 proves the closure is protocol_ids + cstring + cstddef, ALL resident), so the 17d-deferred seams stay deferred; the codec_base witness-vs-REAL decision defers to 18c as NEXT.md wants. protocols/*.h struct cps: NOT needed by 18b (checksum.h consumes protocol_ids.h only). IpProtocol in Rust: landed `src/framework/codec.rs:87-:96` (`pub type IpProtocol = u8`, TCP=6 :93, UDP=17 :94) — checksum.rs RIDES it (17d ride rule), parity-test against protocol_ids.h:54-:77 values (measured match).

## 7. Rust home (NEXT.md:269 "src/codecs/checksum.rs") — grep census confirms the landing pad is EMPTY

- `src/codecs/` does not exist yet (measured `ls`), `lib.rs:12-:25` has 14 pub mods, no codecs — NEW dir + `pub mod codecs;` (alphabetical insertion into lib.rs per the file_api/mod.rs precedent: dir-name sort, mod.rs inside keeps C-alpha order — codecs C dir sorts after main, before parser: lib.rs slots it accordingly).
- Checksum-compute identifiers `cksum_add|tcp_cksum|udp_cksum|ip_cksum|icmp_cksum|Pseudoheader` in the WHOLE Rust repo (src+tools, git grep at HEAD): **ZERO hits** (only NEXT.md prose :242/:243/:273). tools/*/stubs.cc: 0. The 25 loose "checksum" hits in tools are ALL conf_harness NetPol-flag material (conf build.sh :96-:103 `ChecksumFlag` shim enum etc.) + conf vectors :21-:28 — config plumbing, ZERO compute. In src: policy.rs:172-:219 flags, config files — no compute home exists → NO re-port/dup risk; checksum.rs is a FRESH canonical home.
- CMake order for module layout inside `src/codecs/`: ground dir order root→ip→link→misc→(test); the row lands `src/codecs/checksum.rs` flat (matches `src/codecs/ip/checksum.h` -> pick ONE convention at 18c when dirs multiply: NEXT.md:269 says mod.rs keeps C-alpha — pin then).

## 8. Risks (cites)

- **R1 CppUTest wall (measured, E4)**: NEVER pretend a native checksum C gate; suite lands Rust-side ONLY (16g/16h precedent, NEXT.md:258). The CppUTest suite's `main()` (:196-:199 CommandLineTestRunner) is framework, not material — port the 10 TESTs/3 GROUPs as 10 Rust fns + fixture + the extra Q-arms.
- **R2 Shallow clone**: hardening provenance unrecoverable (`git log -1 -- src/codecs/ip/checksum.h` = the single tag commit fe29cbe, 2026-11-05; `is-shallow-repository` = true, history depth 1). Ground TRUTH = the guard text itself (:157-:198) + suite header comment (:17-:31). Plan cites ground lines, not upstream PR numbers (none exist locally).
- **R3 consumer-census drift (measured, §0/§3)**: NEXT.md:242 says 7 consumers; ground has 8 (+packet_manager.cc:30/:641/:697/:705). This PLAN is the correction receipt; the 18b commit should carry the corrected number; packet_manager's 3 arms are the row-20 seam pre-pin.
- **R4 Gate temptation**: no Catch gate material exists this row (checksum_test = CppUTest dialect; cd_gre UT frozen at :351-:366 until its row, NEXT.md:314-:324); shipping a fake third gate = the 17p anti-pattern. csum_harness = probe-only.
- **R5 union punning posture**: checksum_test :44 `Pseudoheader6 ph6{}` zero-init + the arr/struct union (:40, :54) are C-layout semantics; Rust port pins exact u16 words (measured word dump §5) + documented deviation (repr-by-bytes, `from_ne_bytes`) — do NOT model C++ unions with Rust unions; `std::memcpy` word load :86 also means NO alignment requirement (probe reads odd offsets implicitly through the walk — Rust `u16::from_le_bytes([d[0],d[1]])` equivalent for any alignment).
- **R6 hygiene carry**: vectors stay pointer-free (fmod build.sh:1101 `! grep -E '0x[0-9a-f]{6,}'` recipe carried verbatim into csum build.sh; §5 values are <=4 hex digits, safe).

## 9. Scratch receipt files (/opt/data/cache/scratch/row18b/) — proof trail

`probe_probe.cc` (the §5 ladder source), `probe_probe.o` (11,464 B, E1), `hdr_tu.{cc,o}` (zero-text proof, E3), `residue_U.txt` (U=printf only), `probe_U.txt`/`probe_D.txt`/`probe_defs.txt` (witness shapes), `donor_defs.txt` (5,898-sym closure union incl. fmod stubs.o; checksum-def grep = 0), `ka_O0.txt` == `ka_O2.txt` (E5 identity), `cpputest_fatal.txt` (E4 wall), `copy/` (fmod donor copy + codecs/ip/checksum.h), `checksum_test.cc` (ground copy). Next-pass build.sh lifts the fmod donor cp/objs/shim blocks VERBATIM minus the LuaJIT third-party tail (unused by this row), objs+gate loops gain NO checksum .o (zero-.o row), probe-only link.

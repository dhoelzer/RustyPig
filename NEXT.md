# NEXT.md — snort3 → Rust port handoff (2026-11-15)

Repo: `/opt/data/snort3-rust` (branch `master`, pushed to `github.com/dhoelzer/RustyPig`)
Ground truth: `/opt/data/snort3-src` @ fe29cbe7403a
Authoritative plan: `PORTING_PLAN.md` (status table) — this file is the snapshot of *how far we got and what is in the air right now*.

## Method (non-negotiable)

Faithful port, quirks and all. Every milestone is pinned by a **C++ harness** that
compiles the ORIGINAL sources and emits a labeled transcript (`vectors.txt`); the
Rust port is validated by a whole-transcript replay test (`tests/*_parity_test.rs`),
byte-for-byte. Never rely only on upstream unit tests — many subsystems have none.
Where upstream ships embedded Catch2 `UNIT_TEST` tables, also build a `-DUNIT_TEST`
gate binary from the pristine TU so upstream cases run as a semantic gate
(see tools/sorule_harness, tools/rules_harness).

`ParseAbort` longjmp is modeled as `Err(ParseAbort)` / `Fatal::Quitting`, but
observable state left behind by aborts must match (resolving flags stuck, weak
lists not cleared, is_resolved burned). See `KNOWN DEVIATIONS.md` per subsystem.

Verify loop: `cargo test` (expect running total), `cargo clippy --all-targets`
(must be 0 warnings), rebuild the harness and diff `vectors.txt` (HARNESS_STABLE).
Commit + **push** at every milestone.

## Done (pushed; 36 commits, last = `114b6ec`)

Bottom-up per `PORTING_PLAN.md` rows 1–17a, DONE in the table (each with the
harness + replay citation): bitop, boyer_moore, base64, ring/ring2, utf,
util_cstring, full sfip, grouped_list, parse_ip, sf_ipvar/sf_vartable,
ports+parse_ports, literal_search, lockless_ring, json_stream, ber+cursor,
obfuscator, util_unfold, streambuf, util.cc, value/parameter/bits,
hash_key_operations+ghash+primetable, ips_option+pdu_section, lru caches
(local/shared/segmented), fnv, range, sflsq, parse_utils, arg_list,
ips_action+policy action-variables, xhash/zhash/hash_lru_cache/memcap layer,
**parser/vars+var_dependency+ParseIpVar** (143-line transcript, `d051958`),
**log/messages+log_errors+utils/cfmt** (132-line transcript + glibc printf oracle,
`1b7e71a`), **parser/parse_conf core + config_file** (161-line transcript,
`24cf06e`), **log/text_log + main/thread.cc naming** (87-line transcript,
`93f58a7`), **parser/parse_so_rule FSM** (upstream Catch2 tables gate + 152-line
transcript, `114b6ec`).

Suite at last clean push: **320 tests, clippy 0, tree clean.** Full layer table in
`PORTING_PLAN.md`.

## DONE this session (pushed): rule-tree core, plan row 17 keystone

Harness (`tools/rules_harness/`, pushed earlier as `fabe543`): build.sh compiles
the ORIGINAL TUs (parse_conf.cc, config_file.cc, parse_rule.cc full, parser.cc
lifecycle slice, rules.cc, sfrim.cc, signature.cc, treenodes.cc, fp_utils.cc,
log_stats.cc, ips_option.cc, util.cc half, fp_config copy w/ ctor surgery) +
probe + pristine `-DUNIT_TEST` Catch gate. Gate: **11/11, 36 assertions**
([ParseRule] 5, [RuleStateMap] 2, [RuleIndexMap] 1, [util] bonus). Deterministic
225-line `vectors.txt` (two-build DETERMINISTIC + repeated-probe md5), incl. the
two FATAL_DEMO subprocess blocks (undefined $port -> ParseAbort; raw-literal
port error -> ParseAbort) and the parse_rules_string STREAM seam.

Rust port (this commit): `src/detection/{rules,sfrim,treenodes,signature,
parse_rule,parser,fp_config,fp_utils}.rs`, `src/ports/port_table.rs`,
`src/ports/port_var_table.rs` (identity handles), `src/log/log_stats.rs`,
`src/target_based/snort_protocols.rs`, `src/main/policy.rs` (IpsPolicy toward
C shape; ctor defaults var_id=1/obfuscate_pii/configured_action(1)), patched
`ips_option.rs` base cursor/PDU. `tests/rules_parity_test.rs` replays the full
transcript byte-for-byte (in-process body + both fatal blocks).

Quirks pinned by the transcript (do not "fix" them):
- make_rule guard prints "PE=0 after type": get_parse_errors() CONSUMES the
  counter; the guard call eats it, the printed second call is 0.
- num_detection_opts bumps even when the option keyword MISSES (ROT starts
  OPT_TYPE_MAX which != OPT_TYPE_META); a two-option rule has ndo=2.
- ONLY parse_rule_type (action errors) latches s_ignore; net/port/proto
  errors ParseError but flow on; parse_rule_close clears the latch in its
  guard before any otn deref.
- get_policy_loaded/shared_rule_count are DESTRUCTIVE diffs; printf arg order
  right-to-left (shared before loaded before r).
- ProcessIP on an undefined var calloc-keeps the empty var (dip=~) even when
  the error path returns -1.
- RuleTreeCache: reduce_rtns NEVER re-shares through find_rtn in the pinned
  scope ("shared p1=0 p2=0") -- chain-order semantics unpinable, pointer-
  identity lookup (see KNOWN DEVIATIONS rule-tree section).
- ACTSTR prints "alert alert" (static single-buffer probe helper aliasing).

Deferred with later rows: rtn_checks.cc (rule_func CHECK arms all abort-
witnessed), parse_stream end-to-end (row 18), port compile/merge (row 19+),
GHash traversal order (OtnMap Vec stands in; every in-scope observation is
order-insensitive).

## Task queue after this milestone

1. `parser/parse_stream.{h,cc}` + end-to-end `parse_rules_string` with real
   rules (the seam currently test-doubles it; conf milestone only pinned the seam).
1a. `detection/rtn_checks.cc` arms (every CHECK now an abort-witness; small)
    + real `RuleTreeCache` bucket semantics if a future vectors block pins
    find_rtn chain order.
3. ips_options meta modules (flowbits/sid/rev/msg/gid/metadata subset) to grow
   past the option-begin/set/end seam; `IpsManager` real semantics.
4. `framework/codec.{h,cc}` (231 lines, 4 upstream Catch cases) — next light
   target.
5. `detection/detection_options` + option tree (big), `filters/` (rate/threshold),
   `managers/` (detection/event/module), `main/policy.cc` full shell wiring.
6. codecs row 18 (IP/TCP/UDP), detection engines row 19 (subset), DAQ/packet_io
   row 20 (AF_PACKET via libc), CLI + end-to-end `snort -q -c` parity row 21.

## Push recipe (token never on the command line)

```bash
TOK=$(grep GITHUB_TOKEN /opt/data/.env | grep -v '^#' | head -1 | cut -d= -f2-)
git -c credential.helper=*** '{ echo username=dhoelzer; echo password=$TOK; }; f' push origin HEAD
```

## Gotchas this repo already paid for

- write_file tool is jailed to /opt/data (`HERMES_SAFE_ROOT`); `cargo` is at
  ~/.cargo/bin (add to PATH before cargo commands in fresh shells).
- Never `export $(grep TOKEN ...)` — .env has comment lines; extract into a var.
- Harness heredocs: inner python blocks must not contain nested EOF-ish markers;
  prefer unique heredoc tags per block (FIXPOLICY/FIXH/EOFMGR/EOFCFG/STUBEOF).
- C++ `#include <sstream>`/`<cassert>` gaps in copied TUs are expected; fix with
  sed post-copy (vars.cc, port_table.cc, messages.cc all needed it).
- Witness headers must mirror upstream header semantics: keep real headers when
  their deps are satisfiable (policy.h, thread.h, log.h, fp_utils.h, mpls.h,
  search_common.h, base_api.h real); witness only monolith deps (data_bus,
  batched_logger, detection_options, trace/trace_api, protocols/packet.h with
  `snort::MAX_PORTS = 65536` constexpr, filterz/sfthd.h = filterz dir vs
  upstream filters/sfthd.h path rename in copy tree).
- `PortTablesFinish` in parser.cc calls
  `PortTablePrintInputEx(pt, rule_index_map_print_index)`:
  rule_index_map_print_index MUST come from real sfrim/parser code, not stub.



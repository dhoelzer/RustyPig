# Orchestrator prompt — Snort3→Rust port, next milestone (row 17p)

Paste everything below the line as the new agent's first message.

---

You are the ORCHESTRATOR for the Snort3 C++→Rust parity port. You never do
the heavy work yourself: you delegate each phase to a sub-agent
(delegate_task), one phase at a time, and you verify every child's claims
with your own read-only checks before dispatching the next phase. Keep
YOUR context slim — big outputs (transcripts, diffs, build logs) belong in
files under `/opt/data/snort3-rust/` or `/opt/data/cache/scratch/`; you
pass file paths between children, never pasted content.

MANDATORY FIRST ACTION: read `/opt/data/snort3-rust/NEXT.md` IN FULL and
follow it exactly — it is the authoritative resume point (ground rules,
environment facts, donor harnesses, row-17p scoping, session ritual).
Also have your first child confirm `PORTING_PLAN.md` (rows 1–17o DONE)
and `KNOWN DEVIATIONS.md` are authoritative references. Ground truth:
`/opt/data/snort3-src` @ fe29cbe7403a (READ-ONLY, never edit). Port repo:
`/opt/data/snort3-rust` (branch master).

Run this SEQUENTIAL pipeline for plan row 17p
(`file_api/file_cache.{h,cc}`), in this order — each step's output feeds
the next:

1. RECON — one child: measure the target (wc -l, TEST_CASE inventory,
   include closure), diff it against the `tools/filib_harness` donor
   closure, and write `tools/fcache_harness/PLAN.md` (in the repo) listing
   which upstream TUs compile verbatim, which symbols get witnesses, and
   every graft needed. No code yet. Verify: PLAN.md exists and cites real
   line numbers (spot-check two with your own grep).

2. HARNESS — one child, context includes PLAN.md path: author
   `tools/fcache_harness/` (build.sh + probe.cc + stubs.cc) by lifting the
   filib donor recipe; gate = the TU's own [file_cache] UNIT_TEST block
   compiled -DUNIT_TEST verbatim; probe compiles file_cache.cc verbatim
   with the UNIT_TEST block excised. Deliverable: `bash build.sh` exits 0,
   deterministic `vectors.txt` + `gate.txt`, md5 identical across 2 clean
   rebuilds, and the child reports the md5s + transcript line count +
   gate case/assertion counts. Verify YOURSELF: run zero-arg checks —
   recompute md5s yourself (one rebuild), assert gate "All tests passed",
   grep the transcript for WITNESS lines. If md5 disagrees with the
   child's claim, re-steer or redo; never proceed on self-report.

3. PORT — one child: literal Rust transcription to
   `src/file_api/file_cache.rs` (+ mod.rs wiring), reading the ACTUAL C
   sources and the harness transcript, not summaries. Rules from NEXT.md
   apply verbatim (Vec<u8> for byte-carrying strings, deviations only when
   structurally forced, never special-case to match output). Deliverable:
   `cargo build` clean + `cargo clippy --all-targets` 0 warnings on the
   lib. Verify: run both yourself.

4. PARITY TEST + FULL GATES — one child: write
   `tests/fcache_parity_test.rs` as a whole-transcript line-for-line
   replay (donor: `tests/filib_parity_test.rs`) + faithful translations of
   gate-only semantics; then full `cargo test` (>= 389 + new, all green —
   the replay must pass against the REAL committed transcript) and
   `cargo clippy --all-targets` ZERO warnings; add the harness
   `.gitignore` block mirroring siblings and run `git check-ignore` on
   every generated artifact BEFORE staging. Verify: re-run cargo test +
   clippy yourself; check `git status --short` lists exactly the expected
   files.

5. COMMIT + PUSH — dispatch as a STEER to the SAME child (or a fresh one
   with explicit instructions): commit the milestone, push with
   `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push
   origin master`. Token = last GITHUB_TOKEN line of /opt/data/.env —
   NEVER echo, print, or paste it anywhere. Verify: your own
   `git log --oneline -1` + `git status` clean.

6. DOCS — one child (fresh): (a) insert the plan row into
   PORTING_PLAN.md with a grep-guard (already-present check FIRST —
   double-inserts caused a force-push in this repo's history); (b) append
   the deviations section to `KNOWN DEVIATIONS.md` (one grep-guarded
   append); (c) rewrite the row-17p section of NEXT.md for the following
   milestone (measure file_capture.cc/file_service.cc/file_flows.cc —
   wc -l + TEST_CASE counts — to scope 17q); commit + push docs. Verify:
   grep counts == 1 for the new row/section in each file.

7. WIKI — one child: clone/pull `/tmp/RustyPig.wiki` (remote
   RustyPig.wiki.git), add the Porting-status.md row, the
   Deviations-from-Snort-3.md section, refresh the stats line
   (tracked files / rust lines / test files / commits / test count — the
   child must compute these from git + cargo, not guess), commit and push
   via the same credential helper. Wiki files live OUTSIDE /opt/data:
   edits ONLY via python scripts saved under /opt/data/cache/scratch/ and
   run through the terminal, plus `git -C /tmp/RustyPig.wiki ...`.
   Verify: your own fetch of the wiki HEAD hash.

ORCHESTRATION RULES
- One phase at a time; a phase starts only after the previous is
  verified. Sub-agents cannot talk to the user — anything ambiguous, YOU
  ask the user before dispatching.
- Every child's goal/context must be fully self-contained (children see
  nothing of this conversation): include exact paths, the ground rules
  from NEXT.md that apply to that phase, the "transcript is truth, never
  fabricate" rule, the "never echo secrets" rule, and for build/commit
  phases the exact commands.
- Child claims of external side effects (push succeeded, test green,
  file written) are self-reports until YOU re-check them with a cheap
  command. A failed gate = steer the running child, not re-dispatch from
  scratch (action='steer'), unless its approach is structurally wrong.
- If a phase's build flakes: the child must fix determinism, not lock a
  flaky transcript. If row 17p stalls twice on the same blocker, take the
  NEXT.md alternative quick win (main/thread_config.cc) and record the
  blocker in the plan row instead of thrashing.
- After step 7, write your final report: commit hash, test count, wiki
  head, transcript md5s, and next resume pointer (NEXT.md row 17q).

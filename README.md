# RustyPig — a Rust port of Snort 3

Rust port of [Snort 3](https://github.com/snort3/snort3), built layer by layer from the
C++ original (`snort3 @ fe29cbe7403a`). Each commit ports one subsystem with its own
ground-truth tests: a C++ harness under `tools/` that compiles the **original**
sources, and a Rust test that replays the harness transcript byte-for-byte.

**Full documentation: [wiki](https://github.com/dhoelzer/RustyPig/wiki)**

| Wiki page | Covers |
|---|---|
| [Home](https://github.com/dhoelzer/RustyPig/wiki) | what this project is |
| [Porting status](https://github.com/dhoelzer/RustyPig/wiki/Porting-status) | what is ported (and what isn't) |
| [Porting strategy](https://github.com/dhoelzer/RustyPig/wiki/Porting-strategy) | harness → port → replay method |
| [Deviations from Snort 3](https://github.com/dhoelzer/RustyPig/wiki/Deviations-from-Snort-3) | how and why it differs from the original C++ |
| [Building and testing](https://github.com/dhoelzer/RustyPig/wiki/Building-and-testing) | `cargo test`/`clippy` + harness regeneration |

In-repo canonical records, kept current at every commit:

- `PORTING_PLAN.md` — the layer-by-layer status table
- `KNOWN DEVIATIONS.md` — every deliberate departure, source-cited (the wiki mirrors it)

```
cargo test                  # 320 tests, all green
cargo clippy --all-targets  # gate: zero warnings
```

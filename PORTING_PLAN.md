# PORTING_PLAN — snort3 → snort3-rust

Strategy (from the porting-legacy-codebases skill): bottom-up by dependency layer,
one subsystem per commit, each with unit tests ported 1:1 from the original
Catch/CppUTest suites. Authority = /opt/data/snort3-src @ fe29cbe7403a (2026-11-05).

Original size: 1141 .cc + 992 .h files, ~550k lines under src/. A "fully
compatible" port of the whole engine is a multi-month program; this repo tracks
the plan honestly with a status table rather than claiming more than is built.

## Layer queue (status)

| # | subsystem | lines* | status |
|---|-----------|--------|--------|
| 1 | helpers/bitop | ~90 | DONE (tests ported) |
| 2 | helpers/boyer_moore | ~140 | DONE (tests ported) |
| 3 | helpers/base64_encoder | ~190 | DONE (tests ported) |
| 4 | helpers/ring + ring_logic | ~340 | DONE (tests ported) |
| 5 | helpers/utf | ~470 | DONE (iconv bridge pending) |
| 6 | utils/util_cstring | ~490 | DONE |
| 7 | sfip (SfIp/SfCidr/returns + inet_pton/ntop) | ~3.4k | DONE: full sf_ip_test.cc table (114 rows) passing |
| 8 | helpers/grouped_list.h | ~600 | DONE: 16 grouped_list_test.cc sections parity |
| 8d | parser/parse_ip (sfip_var_from_string) | ~100 | DONE: engine shared with sf_ipvar; code-mapping tests incl. C quirk ']'/'[]' -> SUCCESS and InetParseErr propagation |
| 8c | sfip/sf_ipvar + sf_vartable | ~1.7k | DONE: all 6 embedded UNIT_TEST Catch2 sections (merge, contained/negated, no-table, copy/compare, any, kitchen-sink) ported 1:1 |
| 8b | ports + parser/parse_ports | ~1.5k | DONE: 52-case ground-truth vector parity (no upstream unit suite; tools/cpp_harness) |
| 9 | helpers/literal_search + boyer_moore_search | ~360 | DONE: all 14 boyer_moore_search_test.cc CppUTest cases parity; hyperscan backend intentionally out of scope |
| 10a | helpers/lockless_ring | ~395 | DONE: all 5 Catch sections incl. 4-producer/4-consumer thread tests |
| 10 | helpers/ring2 (2025 lock-free FIFO) | ~300 | TODO |
| 11 | helpers/json_stream | ~400 | TODO |
| 12 | helpers/streambuf | ~2.1k tests | TODO |
| 13 | main/snort_types.h + framework/log levels, Option/OptionTree | ~4k | TODO |
| 14 | parsers: config_file, parse_ip, parse_ports, parse_rule | ~4k | TODO |
| 15 | codecs (IP/TCP/UDP normalization) | ~15k | TODO |
| 16 | detection option engines | ~30k+ | TODO (subset) |
| 17 | packet_io / DAQ | platform | TODO (AF_PACKET via libc crate) |
| 18 | main CLI + `snort -q -c` end-to-end parity test | - | TODO |

\* rough combined .h+.cc+test size.

## Compatibility contract goals
1. Same public option names / rule syntax as original parser tests expect.
2. Same log/alert output formats (fast, unified, JSON) byte-for-byte where feasible.
3. `KNOWN DEVIATIONS.md` lists every deliberate departure, each source-cited.
4. CI = `cargo test` + end-to-end PCAP-vs-reference-alert diff (once layer 14+ done).

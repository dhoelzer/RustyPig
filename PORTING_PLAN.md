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
| 10 | helpers/ring2 (2024 SPSC byte ring) | ~520 | DONE: all 30 Catch sections parity; Miri-clean (strict provenance) |
| 11 | helpers/json_stream | ~820 | DONE: 43 sections parity (json_stream_test.cc basic + 6 embedded escape) |
| 12 | helpers/ber + framework/cursor core | ~520 | DONE: all 5 ber_test.cc TEST_CASEs incl. length-overflow cap quirks; Cursor Packet*/CursorData side-table omitted |
| 13 | log/obfuscator | ~340 | DONE: all 10 obfuscator_test.cc CppUTest cases parity |
| 14 | utils/util_unfold | ~235 | DONE: 2 embedded Catch2 cases + 20-case ground-truth vector parity for sf_strip_CRLF/LWS (tools/unfold_harness) |
| 15 | helpers/streambuf | ~2.4k | DONE: all 17 streambuf_test.cc TEST_CASEs (97 sections) ported; C++ ground truth = upstream suite passed verbatim (17/17, 832 assertions, tools/streambuf_harness) |
| 16 | utils/util.cc (pure members + ts_print via TimeCfg) | ~490 | DONE: 3/3 embedded Catch2 cases + stoul/memrchr/ts_print pinning; rotate_file_for_max_size deferred (FILE*/errno layer) |
| 16c | framework/value + parameter subset + utils/bits bitsets | ~1k | DONE: 15/15 value.cc Catch2 cases (incl. get_addr over-size quirk, set_first_token ss-recreation quirk); strtol/strtoul C-base-0 pinned via glibc probe (octal LONG_MAX clamp, dec ULONG_MAX); Parameter::index/find; validate() deferred to option layer |
| 16d | hash: hash_key_operations + ghash + primetable (IpsOption::hash deps) | ~1.4k | DONE: 170-line ground-truth vector parity (static-hash do_hash/mix_str/finalize/nearest_prime) + 3/3 ghash_test.cc CppUTest cases; prime tables extracted verbatim |
| 16e | framework/ips_option core + pdu_section | ~800 | DONE: 4/4 embedded Catch2 sections re-expressed as 6 Rust tests + hash() values pinned to hash_harness MS vectors; IPSAPI_VERSION pin (BASE_API_VERSION=29); instantiator set_* statics deferred until IpsInfo/detection exists |
| 16g | hash/lru_cache_local (LruCacheLocal template) | ~200 | DONE: both lru_cache_local_test.cc CppUTest cases ported; entry_size quirk (clamp sz<entry_size), last-entry-never-pruned guard, prune-after-max-stat ordering all preserved |
| 16f | hash cache layer: memcap_allocator + hash_lru_cache + xhash + zhash + hash_defs + value.cc row-distribution tests | ~1.9k | DONE: all 6 xhash_test.cc + 3 hash_lru_cache_test.cc + 4 zhash_test.cc CppUTest cases ported (16 tests) + 5 hash_row_distribution pins + memcap pins (no upstream suite); XHASH_MAX_RECOVERY_WALK=64 ANR walk bound preserved; SIZEOF_HASH_NODE=56 probed from C++ |
| 16b | main/snort_types.h + framework/log levels, Option/OptionTree | ~4k | TODO |
| 17 | parsers: config_file, parse_rule, parse_so_rule (parse_ip/parse_ports DONE) | ~4k | TODO |
| 18 | codecs (IP/TCP/UDP normalization) | ~15k | TODO |
| 19 | detection option engines | ~30k+ | TODO (subset) |
| 20 | packet_io / DAQ | platform | TODO (AF_PACKET via libc crate) |
| 21 | main CLI + `snort -q -c` end-to-end parity test | - | TODO |

\* rough combined .h+.cc+test size.

## Compatibility contract goals
1. Same public option names / rule syntax as original parser tests expect.
2. Same log/alert output formats (fast, unified, JSON) byte-for-byte where feasible.
3. `KNOWN DEVIATIONS.md` lists every deliberate departure, each source-cited.
4. CI = `cargo test` + end-to-end PCAP-vs-reference-alert diff (once layer 14+ done).

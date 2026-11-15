# KNOWN DEVIATIONS

Deliberate, audited departures from the C++ original (snort3 @ fe29cbe7, 2026-11-05).
Each entry cites the original source so parity stays measurable and auditable.

## API shape (mechanical, no behavior change)

- `helpers/bitop.rs` (bitop.h): `set(unsigned int)` takes `usize`; original never
  type-checked larger widths either. Buffer ops identical.
- `helpers/base64_encoder.rs` (base64_encoder.cc): C `encode(data,len,buf)` pointer
  pair becomes `&[u8]` + caller-provided `&mut [u8]`. `nullptr,0` call in the
  original's "null data" SECTION is just `&[]` here. Step machine is line-for-line.
- `helpers/ring.rs` (ring.h/ring_logic.h): the C++ atomics in RingLogic exist only
  because snort used them across threads with relaxed discipline; the port is
  single-threaded `&mut` (Rust enforces it). Index arithmetic (rx=0, wx=1,
  usable=size-2, `full()` never true because it tests count()==sz) preserved
  verbatim including the C++ quirk.
- `helpers/ring.rs::Ring::new` requires `T: Clone + Default` in place of
  C++ `new T[size]` default-construction.
- `helpers/utf.rs` (utf.cc): C `decode_utf(..., int* bytes_copied)` out-param
  becomes `(ok, copied)` tuple return. `convert_character_encoding` (iconv bridge)
  NOT ported yet — depends on libc iconv; returns no equivalent in this layer.
  CharsetCode/CharsetSrc discriminants kept numerically identical (HTTP
  inspectors compare these values).
- `helpers/boyer_moore.rs` (boyer_moore.cc): C `toupper()` (C locale, uint8_t)
  reimplemented as ASCII-only mapping — same as the original's behavior since the
  original relies on locale "C" in unit tests. `search` returns `i64` with -1 for
  miss, mirroring C `int`. Skipping tables index bytes 0-255 exactly.

## Not yet ported (see PORTING_PLAN.md for status)

Everything outside `helpers/` — codecs/, detection/, framework/, main/, etc.
`helpers/{hyper_search, literal_search, json_stream, markup, streambuf, ring2,
lockless_ring, grouped_list, ber, ...}` are next on the queue.

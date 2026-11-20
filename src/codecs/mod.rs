//! `src/codecs` — the ported C `src/codecs` tree (row 18b opens it).
//!
//! C-dir -> Rust-file mapping (row 18c+ will grow this list; the 18b
//! scoping, csum PLAN §7, defers the flat-vs-dir convention call until
//! dirs multiply at 18c):
//!   src/codecs/ip/checksum.h (284 L all-inline) -> checksum.rs
//! No `mod.rs` partner: the C `codecs/` root has no umbrella TU this row
//! (codec_module.{h,cc} is row 18d turf).

pub mod checksum;

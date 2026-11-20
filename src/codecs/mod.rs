//! `src/codecs` — the ported C `src/codecs` tree (row 18b opened it;
//! row 18c grew it to 5 files).
//!
//! FLAT-vs-DIR call lands HERE (csum PLAN §7 deferred it to this row;
//! NEXT.md 18c note): **stay FLAT with C-name spellings.** The C tree
//! is root/ + ip/ + misc/ subdirs, but 18c's five TUs keep their C
//! base names verbatim (`codec_api`, `cd_default`, `cd_bad_proto`,
//! `cd_no_next`, `cd_raw`); the `cd_` prefix already disambiguates
//! against the later umbrella/module TUs (`codec_module` at 18d), and
//! the C base names are identical across dirs except by prefix — the
//! vectors, probes, and plan rows all key on those names. Dir
//! submodules would rename nothing and fork every later row's import
//! path. Per-TU C-dir provenance rides each file's header comment
//! (the NEXT.md path correction: cd_default is `misc/`,
//! cd_bad_proto + cd_no_next are `ip/`, cd_raw + codec_api are the
//! `codecs/` root).
//!
//! C-dir -> Rust-file mapping (row 18d+ will grow this list):
//!   src/codecs/ip/checksum.h   (284 L all-inline)  -> checksum.rs   [18b]
//!   src/codecs/codec_api.{h,cc} (26+121)           -> codec_api.rs  [18c]
//!   src/codecs/misc/cd_default.cc (83)             -> cd_default.rs [18c]
//!   src/codecs/ip/cd_bad_proto.cc (98)             -> cd_bad_proto.rs [18c]
//!   src/codecs/ip/cd_no_next.cc (116)              -> cd_no_next.rs [18c]
//!   src/codecs/root/cd_raw.cc (105)                -> cd_raw.rs     [18c]
//! No `mod.rs` partner TUs: the C `codecs/` root has no umbrella TU
//! landed here (codec_module.{h,cc} is row 18d turf).

pub mod cd_bad_proto;
pub mod cd_default;
pub mod cd_no_next;
pub mod cd_raw;
pub mod checksum;
pub mod codec_api;

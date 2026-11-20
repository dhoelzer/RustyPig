pub mod circular_buffer;
// row 17v: the file_api.{h,cc} umbrella TU — the canonical vocabulary +
// FilePolicyBase home; file_lib.rs / file_cache.rs interim homes are now
// pub-use re-points to it (17u const-home recipe). Alphabetical head of
// the file_api_* block (matches the C underscore sort in mod.rs order).
// module_inception allowed: the file name is PINNED by the C TU pairing
// (src/file_api/file_api.{h,cc} -> src/file_api/file_api.rs) and by this
// task; renaming to dodge the lint would break the TU-name mapping the
// whole queue follows (file_lib.rs, file_cache.rs, ... all match their
// C TUs one-for-one).
#[allow(clippy::module_inception)]
pub mod file_api;
pub mod file_cache;
// donor CMakeLists.txt:18-:19 order (file_cache then file_cache_share;
// the C underscore sort lands before file_capture).
pub mod file_cache_share;
pub mod file_capture;
// row 17u: the file_config.{h,cc} constants' canonical home (the
// file_cache.rs:104-:109 / file_lib.rs:801-:812 mirrors became pub
// re-exports of this table).
pub mod file_config;
pub mod file_flows;
pub mod file_identifier;
// row 17w: the file_inspect.{h,cc} inspector TU (h:36 closure + the
// REAL get_file_adv_pub_id getter -- file_lib's publish seam is
// re-pointed to it). Alphabetical slot holds (file_identifier <
// file_inspect < file_lib in the C underscore sort).
pub mod file_inspect;
pub mod file_lib;
// row 17z: the file_log.cc Inspector TU (329 L, NO file_log.h exists —
// the single-TU row: every class TU-local, reached through the sin_file[]
// export pin). The LogHandler FILE_VERDICT -> file.log renderer + the
// sanitizer %02X-run quirk land per flog PLAN §3; the TextLog/show/ts_-
// print/sha/VerdictName/get_UTF8_fname/file_type_name arms ride the
// landed twins (REAL-in-17z parity witnesses, zero twin edits); the
// DataBus subscribe + clocks + file_log_event consumers stay seams
// (W1/C counter witness mirrors below). Alphabetical slot holds
// (file_lib < file_log < file_mempool in the C underscore sort).
pub mod file_log;
pub mod file_mempool;
// row 17x: the file_policy.{h,cc} FilePolicy TU (FileRule table + the
// enable-flag pairs + the type/signature lookup ladder) — the real
// FilePolicy sits on the 17v FilePolicyApi/FilePolicyHandle seam
// (file_api.rs:229/:273) and the NetworkPolicySeam witness swaps to
// this file's real arm (NetworkPolicySeam trait file_lib.rs:1097-
// :1098 + FileEnvLite::network_policy slot :1165, both UNTOUCHED
// pub-name-stable; post-edit positions).
// Alphabetical slot holds (file_mempool < file_policy < file_segment
// in the C underscore sort).
pub mod file_policy;
pub mod file_segment;
pub mod file_stats;

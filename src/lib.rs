//! snort3-rust: a functional, behavior-compatible Rust port of Snort 3
//! (https://github.com/snort3/snort3, C++).
//!
//! The module tree mirrors the original `src/` layout. Currently ported:
//!   helpers::{bitop, boyer_moore, base64_encoder, ring (RingLogic/Ring), utf}
//! See KNOWN DEVIATIONS.md for audited departures from the C++ original.

// The crate mirrors the original src/ layout, which includes a `main/` module
// (policy, config); rustc reserves that name for binary crates.
#![allow(special_module_name)]

pub mod file_api;
pub mod framework;
pub mod hash;
pub mod helpers;
pub mod log;
pub mod lua;
pub mod parser;
pub mod ports;
pub mod sfip;
pub mod utils;
pub mod main;
pub mod detection;
pub mod target_based;
pub mod time;

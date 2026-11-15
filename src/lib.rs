//! snort3-rust: a functional, behavior-compatible Rust port of Snort 3
//! (https://github.com/snort3/snort3, C++).
//!
//! The module tree mirrors the original `src/` layout. Currently ported:
//!   helpers::{bitop, boyer_moore, base64_encoder, ring (RingLogic/Ring), utf}
//! See KNOWN DEVIATIONS.md for audited departures from the C++ original.

pub mod framework;
pub mod hash;
pub mod helpers;
pub mod log;
pub mod parser;
pub mod ports;
pub mod sfip;
pub mod utils;

//! `src/packet_io` — the ported C `src/packet_io` tree (row 23a opened it
//! with the SFDAQ config/wrapper pair).
//!
//! C-dir -> Rust-file mapping (rows 23b+ will grow this list; the C tree also
//! carries active.{h,cc}, the packet_tracer family, packet_constraints,
//! sfdaq_instance/sfdaq_module and trough — ALL still open books):
//!   src/packet_io/sfdaq_config.{h,cc} (85+131)  -> sfdaq_config.rs  [23a]
//!   src/packet_io/sfdaq.{h,cc} (72+420)          -> sfdaq.rs         [23a]
//!
//! FLAT-vs-DIR call lands HERE: the Rust dir mirrors the C dir name (first
//! chapter after codecs/framework etc. that has its own home — `ls src/`
//! pre-23a had NO packet_io (measured); the flat file-name law holds: C base
//! names verbatim, NO subdirs (the C tree is already flat).

pub mod sfdaq;
pub mod sfdaq_config;

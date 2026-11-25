//! `src/packet_io` — the ported C `src/packet_io` tree (row 23a opened it
//! with the SFDAQ config/wrapper pair; row 23b landed the REAL instance
//! pair — 436+105 — and THE 23a SEAM CLOSE).
//!
//! C-dir -> Rust-file mapping:
//!   src/packet_io/sfdaq_config.{h,cc} (85+131)  -> sfdaq_config.rs  [23a]
//!   src/packet_io/sfdaq.{h,cc} (72+420)          -> sfdaq.rs         [23a]
//!   src/packet_io/sfdaq_instance.{h,cc} (105+436) -> sfdaq_instance.rs [23b]
//!   (the C tree also carries active.{h,cc}, the packet_tracer family,
//!    packet_constraints, sfdaq_module.{h,cc} — its 89 L DECL rider rides
//!    inside sfdaq_instance.rs at 23b, the 298 L class body open — and
//!    trough, whose 265+88 died on the NOT-landed helpers/directory seam
//!    (the wall re-measured at 23b = the row-pick arm): ALL still open
//!    books)
//!
//! THE 23b SEAM CLOSE rides INSIDE sfdaq_instance.rs: `impl
//! crate::packet_io::sfdaq::DaqInstanceSeam for SFDAQInstance` (both
//! types crate-local — lawful; the trait stays 23a-FROZEN), pairing the
//! 23a facade legs (init_instance/get_input_spec/get_base_protocol/
//! can_*/get_tunnel_bypass/inject/get_stats) with the REAL ported
//! bodies — the 23a scripted SeamHandle stand-ins stay in the 23a
//! parity twin test file (their legs scripted faces, NEVER bodies; the
//! rider annotation there cites the landing).
//!
//! FLAT-vs-DIR call lands HERE: the Rust dir mirrors the C dir name (first
//! chapter after codecs/framework etc. that has its own home — `ls src/`
//! pre-23a had NO packet_io (measured); the flat file-name law holds: C base
//! names verbatim, NO subdirs (the C tree is already flat).

pub mod sfdaq;
pub mod sfdaq_config;
pub mod sfdaq_instance;
pub mod sfdaq_module;
// row 23d: the Trough pcap-source expander — THE file_count ONE home that
// the 23c sfdaq_module seam params (trough_file_count) producer-side closes;
// it rides the SAME flat dir (the Trough C home is packet_io).
pub mod trough;
// row 23e: the PacketConstraints value pair (76+331) — THE SECOND REAL GATE
// ROW: the cc's own in-TU Catch block (EXACTLY-3 TEST_CASE "[framework]"
// faces) host-green at THE row's harness; the row body lands flat, ZERO allows.
pub mod packet_constraints;
// row 23f: the PacketTracer per-thread tracing singleton (166+739) — THE
// THIRD REAL GATE ROW: the cc's own in-TU Catch block (EXACTLY-10
// TEST_CASE faces x 49 CHECK legs) host-green at THE row's harness; the
// four NOT-landed walls (ips_context/batched_logger/stream_log/active)
// ride the harness DECL-mirror riders + the Rust-side seam traits; THE
// cross-row REUSE: h :115 types the member with the 23e Landed
// PacketConstraints home (one home, NEVER re-forked).
pub mod packet_tracer;
// row 23g: the packet_tracer MODULE shell pair (59+262) — the ZERO-gate
// row (the in-TU TEST census MEASURED 0 by the harness EVERY build) that
// REUSES the landed 23e constraints + 23f PacketTrace/TraceThreadWorld
// homes through the one-home use-paths (the 16->17 pc twin face + the
// 17->18 pt twin face sanctioned AT the row, the strict-cp count law).
pub mod packet_tracer_module;
// the 23b seam-close re-export hub (the token-free wiring path — the
// frozen sd-token census law, cited at seam.rs):
pub mod seam;

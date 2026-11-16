//! Faithful Rust port of `framework/counts.h` (ground truth @
//! fe29cbe7403a): the basic peg/stats vocabulary the snapshot data model
//! and renderers share.
//!
//! Fidelity notes:
//! - C `typedef uint64_t PegCount` and the UNSCOPED `enum CountType`
//!   (enumerators END/SUM/NOW/MAX live in the global namespace). Rust
//!   cannot replicate "unscoped enumerators" as such; the enum keeps the
//!   declaration ORDER (explicit discriminants equal the C ones) and the
//!   module re-exports nothing global. Nothing in the pinned vectors
//!   relies on unqualified global names.
//! - `PegInfo` C initializers are just aggregates; ported as a plain
//!   struct. `simple_pegs[]` is a definition emitted by the peg
//!   subsystem (`SO_PUBLIC extern`), not by this header: deferred with
//!   that layer. `array_size` is a macro, not ported. C header comment
//!   kept: "where these are used, the number of elements in stats must
//!   be the same as the number of elements in the peg info (and in the
//!   same sequence)".

pub type PegCount = u64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum CountType {
    // END,   // sentinel value
    End = 0,
    /// SUM: running total: tracks cumulative total number of items
    /// seen (eg #events)
    Sum = 1,
    /// NOW: current level: gives snapshot of current number of items
    /// (eg current #sessions)
    Now = 2,
    /// MAX: maximum level: tracks maximum value seen (eg max #sessions)
    Max = 3,
}

/// C `struct SimpleStats { PegCount total_packets; }`
#[derive(Default, Clone, Copy)]
pub struct SimpleStats {
    pub total_packets: PegCount,
}

/// C `struct PegInfo { CountType type; const char* name; const char* help; }`
pub struct PegInfo {
    pub peg_type: CountType,
    pub name: &'static str,
    pub help: &'static str,
}

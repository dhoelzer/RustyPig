//! Literal port of `main/numa.{h,cc}` (NumaMemPolicy <-> string).
//!
//! C models `NumaMemPolicy` as `enum : uint8_t` whose enumerator
//! values are the *kernel ABI* `MPOL_*` (numbers grounded by the real
//! `/usr/include/linux/mempolicy.h` UAPI enum: DEFAULT=0, PREFERRED=1,
//! BIND=2, LOCAL=4 — note MPOL_INTERLEAVE=3 is skipped; UNKNOWN=255 is
//! a private outlier). C also implicitly casts arbitrary integers into
//! the enum type (`stringify`'s default arm runs on e.g. 3 and 5), so
//! Rust models the type as its underlying `u8` with named constants:
//! every raw value is representable exactly like C.

/// kernel MPOL_DEFAULT
pub const NUMA_POLICY_DEFAULT: u8 = 0;
/// kernel MPOL_PREFERRED
pub const NUMA_POLICY_PREFERRED: u8 = 1;
/// kernel MPOL_BIND
pub const NUMA_POLICY_BIND: u8 = 2;
/// kernel MPOL_LOCAL (kernel MPOL_INTERLEAVE == 3 is NOT an enumerator)
pub const NUMA_POLICY_LOCAL: u8 = 4;
/// private sentinel, not a kernel value
pub const NUMA_POLICY_UNKNOWN: u8 = 255;

/// `convert_string_to_numa_mempolicy`: exact-match lookup in the
/// 4-entry table; misses (including "" and any case variant) map to
/// UNKNOWN. No trimming: `"bind "` misses.
pub fn convert_string_to_numa_mempolicy(policy: &str) -> u8 {
    match policy {
        "default" => NUMA_POLICY_DEFAULT,
        "preferred" => NUMA_POLICY_PREFERRED,
        "bind" => NUMA_POLICY_BIND,
        "local" => NUMA_POLICY_LOCAL,
        _ => NUMA_POLICY_UNKNOWN,
    }
}

/// `stringify_numa_mempolicy`: switch on the enumerator; every value
/// outside {0,1,2,4} — including 3 (kernel MPOL_INTERLEAVE) — hits the
/// default arm and stringifies as "unknown".
pub fn stringify_numa_mempolicy(policy: u8) -> &'static str {
    match policy {
        NUMA_POLICY_DEFAULT => "default",
        NUMA_POLICY_PREFERRED => "preferred",
        NUMA_POLICY_BIND => "bind",
        NUMA_POLICY_LOCAL => "local",
        _ => "unknown",
    }
}

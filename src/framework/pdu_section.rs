// Port of snort3 framework/pdu_section.h
#![allow(dead_code)]

/// PduSection: PS_NONE = 0, PS_HEADER, PS_HEADER_BODY, PS_BODY,
/// PS_TRAILER, PS_MAX = PS_TRAILER, PS_ERROR (=> 5, sequence continues).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum PduSection {
    PsNone = 0,
    PsHeader = 1,
    PsHeaderBody = 2,
    PsBody = 3,
    PsTrailer = 4,
    PsError = 5,
}

pub const PS_MAX: u32 = 4; // PS_MAX = PS_TRAILER

pub type SectionFlags = u16;

/// inline section_flags section_to_flag(PduSection sect) { return 1<<sect; }
/// (C UB for sect >= 16; real values are <= 5, so plain shift is exact.)
pub fn section_to_flag(sect: PduSection) -> SectionFlags {
    1u16 << (sect as u32)
}

/// detection/fp_utils.cc: const char* section_to_str[]
pub const SECTION_TO_STR: [&str; 5] = ["NONE", "HEADER", "HEADER_BODY", "BODY", "TRAILER"];

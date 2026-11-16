//! Table half of the `utils/util_jsnorm.cc` port (row 17i): C enums
//! (as u8 discriminants pinned in C's declaration order), the byte
//! tables, and the four FSM tables with C's #define-indexed layout
//! kept literal. See jsnorm.rs for the engine.


pub const INVALID_HEX_VAL: i32 = -1;
pub const MAX_BUF: usize = 8;
pub const NON_ASCII_CHAR: i32 = 0xff;

pub const RET_OK: i32 = 0;
pub const RET_QUIT: i32 = -1;
pub const RET_INV: i32 = -2;

pub const IS_OCT: u16 = 0x1;
pub const IS_DEC: u16 = 0x2;
pub const IS_HEX: u16 = 0x4;
pub const IS_PERCENT: u16 = 0x8;
pub const IS_UPERCENT: u16 = 0x10;
pub const IS_BACKSLASH: u16 = 0x20;
pub const IS_UBACKSLASH: u16 = 0x40;

pub const ALERT_SPACES_EXCEEDED: u16 = 0x1;
pub const ALERT_LEVELS_EXCEEDED: u16 = 0x2;
pub const ALERT_MIXED_ENCODINGS: u16 = 0x4;

pub const MAX_ALLOWED_OBFUSCATION: i32 = 1;

/// C hex_lookup[256] (identical digit/a-f values; verified against the
/// upstream 16-row literal by the harness transcripts).
pub static HEX_LOOKUP: [i32; 256] = build_hex_lookup();

const fn build_hex_lookup() -> [i32; 256] {
    let mut t = [INVALID_HEX_VAL; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as i32;
        i += 1;
    }
    i = 0;
    while i < 6 {
        t[b'A' as usize + i] = 10 + i as i32;
        t[b'a' as usize + i] = 10 + i as i32;
        i += 1;
    }
    t
}

/// C valid_chars[256] as the bit-mask function it literally encodes
/// (IS_OCT|IS_DEC|IS_HEX for 0-7, IS_DEC|IS_HEX for 8-9, IS_HEX for
/// a-f/A-F; uppercased input, so lowercase rows are unreachable via
/// the scan FSMs which index with toupper).
pub const fn valid_chars(uc: u8) -> u16 {
    match uc {
        b'0'..=b'7' => IS_OCT | IS_DEC | IS_HEX,
        b'8' | b'9' => IS_DEC | IS_HEX,
        b'A'..=b'F' => IS_HEX,
        _ => 0,
    }
}

pub const fn is_space_c(c: u8) -> bool {
    // C isspace((uint8_t)c), "C" locale
    matches!(c, b' ' | 0x09..=0x0d)
}

pub const fn toupper_c(c: u8) -> u8 {
    if c.is_ascii_lowercase() {
        c - 32
    } else {
        c
    }
}

/// C `struct JSNorm`.
pub struct JsNormRow {
    pub event: u8, // C's ANY == 0
    pub r#match: usize,
    pub other: usize,
    pub action: u8, // C enum discriminant, C declaration order
}

// ActionSFCC order: COMMA,DEC,HEX,INV,NOP,OCT,QUIT,SPACE
pub const SF_COMMA: u8 = 0;
pub const SF_DEC: u8 = 1;
pub const SF_HEX: u8 = 2;
pub const SF_INV: u8 = 3;
pub const SF_NOP: u8 = 4;
pub const SF_OCT: u8 = 5;
pub const SF_QUIT: u8 = 6;
pub const SF_SPACE: u8 = 7;

// ActionUnsc order: BACKSLASH,CONV,NOP,PAREN,PERCENT,QUIT,SAVE,
// SAVE_NOP,SPACE,UBACKSLASH,UPERCENT,UNESCAPE
pub const UN_BACKSLASH: u8 = 0;
pub const UN_CONV: u8 = 1;
pub const UN_NOP: u8 = 2;
pub const UN_PAREN: u8 = 3;
pub const UN_PERCENT: u8 = 4;
pub const UN_QUIT: u8 = 5;
pub const UN_SAVE: u8 = 6;
pub const UN_SAVE_NOP: u8 = 7;
pub const UN_SPACE: u8 = 8;
pub const UN_UBACKSLASH: u8 = 9;
pub const UN_UPERCENT: u8 = 10;
pub const UN_UNESCAPE: u8 = 11;

// ActionPNorm order: DQUOTES,NOP,PLUS,SPACE,SQUOTES,WITHIN_QUOTES
pub const PN_DQUOTES: u8 = 0;
pub const PN_NOP: u8 = 1;
pub const PN_PLUS: u8 = 2;
pub const PN_SPACE: u8 = 3;
pub const PN_SQUOTES: u8 = 4;
pub const PN_WITHIN: u8 = 5;

// ActionJSNorm order: NOP,QUIT,SAVE,SFCC,SPACE,UNESCAPE
pub const JN_NOP: u8 = 0;
pub const JN_QUIT: u8 = 1;
pub const JN_SAVE: u8 = 2;
pub const JN_SFCC: u8 = 3;
pub const JN_SPACE: u8 = 4;
pub const JN_UNESCAPE: u8 = 5;

// marker bytes for the IS_* class rows in the C tables (table event
// fields hold the CLASS bits; scan matches (event & value) == event):
pub const EV_IS_OCT: u8 = IS_OCT as u8;
pub const EV_IS_DEC: u8 = IS_DEC as u8;
pub const EV_IS_HEX: u8 = IS_HEX as u8;

macro_rules! R {
    ($event:expr, $match:expr, $other:expr, $action:expr) => {
        JsNormRow { event: $event, r#match: $match, other: $other, action: $action }
    };
}

// static const JSNorm sfcc_norm[] — C: S0=0 S1=S0+3 S2=S1+1 S3=S2+1
// S4=S3+1
pub fn sfcc_norm() -> Vec<JsNormRow> {
    let s0 = 0usize;
    let s1 = s0 + 3;
    let s2 = s1 + 1;
    let s3 = s2 + 1;
    let s4 = s3 + 1;
    vec![
        R!(b'(', s0 + 1, s0 + 1, SF_NOP),
        R!(b'0', s0 + 2, s1, SF_NOP),
        R!(b'X', s3, s2, SF_NOP),
        // decimal
        R!(EV_IS_DEC, s1, s4, SF_DEC),
        // Octal
        R!(EV_IS_OCT, s2, s1, SF_OCT),
        // Hex
        R!(EV_IS_HEX, s3, s4, SF_HEX),
        R!(b',', s0 + 1, s4 + 1, SF_COMMA),
        R!(b')', s0 + 1, s4 + 2, SF_QUIT),
        R!(0, s4 + 1, s0 + 1, SF_INV),
    ]
}

// static const JSNorm unescape_norm[] — C: U0=0 U1=+1 U2=+8 U3=+9
// U4=+8 U5=+19 U6=+18 U7=+1
pub fn unescape_norm() -> Vec<JsNormRow> {
    let u0 = 0usize;
    let u1 = u0 + 1;
    let u2 = u1 + 8;
    let u3 = u2 + 9;
    let u4 = u3 + 8;
    let u5 = u4 + 19;
    let u6 = u5 + 18;
    let u7 = u6 + 1;
    vec![
        R!(b'(', u1, u1, UN_PAREN),
        R!(b'%', u1 + 1, u2, UN_SAVE),
        R!(EV_IS_HEX, u1 + 2, u1 + 3, UN_CONV),
        R!(EV_IS_HEX, u0, u0, UN_PERCENT),
        R!(b'U', u1 + 4, u0, UN_SAVE_NOP),
        R!(EV_IS_HEX, u1 + 5, u0, UN_CONV),
        R!(EV_IS_HEX, u1 + 6, u0, UN_CONV),
        R!(EV_IS_HEX, u1 + 7, u0, UN_CONV),
        R!(EV_IS_HEX, u0, u0, UN_UPERCENT),
        R!(b'\\', u2 + 1, u3, UN_SAVE),
        R!(b'X', u2 + 2, u2 + 4, UN_SAVE_NOP),
        R!(EV_IS_HEX, u2 + 3, u0, UN_CONV),
        R!(EV_IS_HEX, u0, u0, UN_BACKSLASH),
        R!(b'U', u2 + 5, u0, UN_CONV),
        R!(EV_IS_HEX, u2 + 6, u0, UN_CONV),
        R!(EV_IS_HEX, u2 + 7, u0, UN_CONV),
        R!(EV_IS_HEX, u2 + 8, u0, UN_CONV),
        R!(EV_IS_HEX, u0, u0, UN_UBACKSLASH),
        // "UNESCAPE" ladder
        R!(b'U', u3 + 1, u4, UN_NOP),
        R!(b'N', u3 + 2, u0, UN_NOP),
        R!(b'E', u3 + 3, u0, UN_NOP),
        R!(b'S', u3 + 4, u0, UN_NOP),
        R!(b'C', u3 + 5, u0, UN_NOP),
        R!(b'A', u3 + 6, u0, UN_NOP),
        R!(b'P', u3 + 7, u0, UN_NOP),
        R!(b'E', u0, u0, UN_UNESCAPE),
        // "STRINGFROMCHARGCODE" ladder (sic: as tabled)
        R!(b'S', u4 + 1, u5, UN_NOP),
        R!(b'T', u4 + 2, u0, UN_NOP),
        R!(b'R', u4 + 3, u0, UN_NOP),
        R!(b'I', u4 + 4, u0, UN_NOP),
        R!(b'N', u4 + 5, u0, UN_NOP),
        R!(b'G', u4 + 6, u0, UN_NOP),
        R!(b'.', u4 + 7, u0, UN_NOP),
        R!(b'F', u4 + 8, u0, UN_NOP),
        R!(b'R', u4 + 9, u0, UN_NOP),
        R!(b'O', u4 + 10, u0, UN_NOP),
        R!(b'M', u4 + 11, u0, UN_NOP),
        R!(b'C', u4 + 12, u0, UN_NOP),
        R!(b'H', u4 + 13, u0, UN_NOP),
        R!(b'A', u4 + 14, u0, UN_NOP),
        R!(b'R', u4 + 15, u0, UN_NOP),
        R!(b'C', u4 + 16, u0, UN_NOP),
        R!(b'O', u4 + 17, u0, UN_NOP),
        R!(b'D', u4 + 18, u0, UN_NOP),
        R!(b'E', u0, u0, UN_UNESCAPE),
        // "DECODER_unicode" ladder
        R!(b'D', u5 + 1, u6, UN_NOP),
        R!(b'E', u5 + 2, u0, UN_NOP),
        R!(b'C', u5 + 3, u0, UN_NOP),
        R!(b'O', u5 + 4, u0, UN_NOP),
        R!(b'D', u5 + 5, u0, UN_NOP),
        R!(b'E', u5 + 6, u0, UN_NOP),
        R!(b'U', u5 + 7, u0, UN_NOP),
        R!(b'R', u5 + 8, u0, UN_NOP),
        R!(b'I', u5 + 9, u0, UN_UNESCAPE),
        R!(b'C', u5 + 10, u0, UN_NOP),
        R!(b'O', u5 + 11, u0, UN_NOP),
        R!(b'M', u5 + 12, u0, UN_NOP),
        R!(b'P', u5 + 13, u0, UN_NOP),
        R!(b'O', u5 + 14, u0, UN_NOP),
        R!(b'N', u5 + 15, u0, UN_NOP),
        R!(b'E', u5 + 16, u0, UN_NOP),
        R!(b'N', u5 + 17, u0, UN_NOP),
        R!(b'T', u0, u0, UN_UNESCAPE),
        R!(b')', u0, u7, UN_QUIT),
        R!(0, u0, u0, UN_NOP),
    ]
}

// static const JSNorm plus_norm[] — C: P0=0 P1=+3 P2=+2 P3=+2 P4=+1
pub fn plus_norm() -> Vec<JsNormRow> {
    let p0 = 0usize;
    let p1 = p0 + 3;
    let p2 = p1 + 2;
    let p3 = p2 + 2;
    let p4 = p3 + 1;
    vec![
        R!(b' ', p0, p0 + 1, PN_SPACE),
        R!(b'"', p1, p0 + 2, PN_DQUOTES),
        R!(b'\'', p2, p3, PN_SQUOTES),
        R!(b'"', p0, p1 + 1, PN_DQUOTES),
        R!(0, p1, p1, PN_WITHIN),
        R!(b'\'', p0, p2 + 1, PN_SQUOTES),
        R!(0, p2, p2, PN_WITHIN),
        R!(b'+', p0, p4, PN_PLUS),
        R!(0, p0, p0, PN_NOP),
    ]
}

// static const JSNorm javascript_norm[] — C: Z0=0 Z1=+9 Z2=+20 Z3=+19
// Z6=+10
pub fn javascript_norm() -> Vec<JsNormRow> {
    let z0 = 0usize;
    let z1 = z0 + 9;
    let z2 = z1 + 20;
    let z3 = z2 + 19;
    let z6 = z3 + 10;
    vec![
        R!(b'U', z0 + 1, z1, JN_SAVE),
        R!(b'N', z0 + 2, z0, JN_NOP),
        R!(b'E', z0 + 3, z0, JN_NOP),
        R!(b'S', z0 + 4, z0, JN_NOP),
        R!(b'C', z0 + 5, z0, JN_NOP),
        R!(b'A', z0 + 6, z0, JN_NOP),
        R!(b'P', z0 + 7, z0, JN_NOP),
        R!(b'E', z0 + 8, z0, JN_NOP),
        R!(b'(', z0, z0, JN_UNESCAPE),
        R!(b'S', z1 + 1, z2, JN_SAVE),
        R!(b'T', z1 + 2, z0, JN_NOP),
        R!(b'R', z1 + 3, z0, JN_NOP),
        R!(b'I', z1 + 4, z0, JN_NOP),
        R!(b'N', z1 + 5, z0, JN_NOP),
        R!(b'G', z1 + 6, z0, JN_NOP),
        R!(b'.', z1 + 7, z0, JN_NOP),
        R!(b'F', z1 + 8, z0, JN_NOP),
        R!(b'R', z1 + 9, z0, JN_NOP),
        R!(b'O', z1 + 10, z0, JN_NOP),
        R!(b'M', z1 + 11, z0, JN_NOP),
        R!(b'C', z1 + 12, z0, JN_NOP),
        R!(b'H', z1 + 13, z0, JN_NOP),
        R!(b'A', z1 + 14, z0, JN_NOP),
        R!(b'R', z1 + 15, z0, JN_NOP),
        R!(b'C', z1 + 16, z0, JN_NOP),
        R!(b'O', z1 + 17, z0, JN_NOP),
        R!(b'D', z1 + 18, z0, JN_NOP),
        R!(b'E', z1 + 19, z0, JN_NOP),
        R!(b'(', z0, z0, JN_SFCC),
        R!(b'D', z2 + 1, z3, JN_SAVE),
        R!(b'E', z2 + 2, z0, JN_NOP),
        R!(b'C', z2 + 3, z0, JN_NOP),
        R!(b'O', z2 + 4, z0, JN_NOP),
        R!(b'D', z2 + 5, z0, JN_NOP),
        R!(b'E', z2 + 6, z0, JN_NOP),
        R!(b'U', z2 + 7, z0, JN_NOP),
        R!(b'R', z2 + 8, z0, JN_NOP),
        R!(b'I', z2 + 9, z0, JN_NOP),
        R!(b'C', z2 + 10, z2 + 18, JN_NOP),
        R!(b'O', z2 + 11, z0, JN_NOP),
        R!(b'M', z2 + 12, z0, JN_NOP),
        R!(b'P', z2 + 13, z0, JN_NOP),
        R!(b'O', z2 + 14, z0, JN_NOP),
        R!(b'N', z2 + 15, z0, JN_NOP),
        R!(b'E', z2 + 16, z0, JN_NOP),
        R!(b'N', z2 + 17, z0, JN_NOP),
        R!(b'T', z2 + 18, z0, JN_NOP),
        R!(b'(', z0, z0, JN_UNESCAPE),
        // "</SCRIPT" tail (ACT_QUIT on '>', Z3+9 ANY keeps Z3+8 sticky)
        R!(b'<', z3 + 1, z6, JN_NOP),
        R!(b'/', z3 + 2, z0, JN_NOP),
        R!(b'S', z3 + 3, z0, JN_NOP),
        R!(b'C', z3 + 4, z0, JN_NOP),
        R!(b'R', z3 + 5, z0, JN_NOP),
        R!(b'I', z3 + 6, z0, JN_NOP),
        R!(b'P', z3 + 7, z0, JN_NOP),
        R!(b'T', z3 + 8, z0, JN_NOP),
        R!(b'>', z3, z3 + 9, JN_QUIT),
        R!(0, z3 + 8, z3 + 8, JN_NOP),
        R!(0, z0, z0, JN_NOP),
    ]
}

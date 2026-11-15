// Port of snort3 src/sfip/sf_returns.h (SfIpRet enum; discriminants preserved).
#![allow(dead_code)]

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SfIpRet {
    Success = 0,
    Failure = 1,
    Lesser = 2,
    Greater = 3,
    Equal = 4,
    ArgErr = 5,
    CidrErr = 6,
    InetParseErr = 7,
    InvalidMask = 8,
    AllocErr = 9,
    Contains = 10,
    NotContains = 11,
    Duplicate = 12,
    LookupFailure = 13,
    UnmatchedBracket = 14,
    NotAny = 15,
    Conflict = 16,
    LookupUnavailable = 17,
}

// Linux <bits/socket.h> address families used by the original.
pub const AF_UNSPEC: i16 = 0;
pub const AF_INET: i16 = 2;
pub const AF_INET6: i16 = 10;

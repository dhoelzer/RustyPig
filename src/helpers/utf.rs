// Port of snort3 src/helpers/utf.{h,cc} (UtfDecodeSession: UTF-{16,32}{le,be} decoding).
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//           Copyright (C) 2010-2013 Sourcefire, Inc.
// Charset codes/values kept numerically identical to the C enum (HTTP inspectors
// depend on these values; see original header comment).

#[repr(usize)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CharsetCode {
    Default = 0,
    Other = 1,
    Utf7 = 2,
    Irrelevant = 3,
    Utf16Le = 4,
    Utf16Be = 5,
    Utf32Le = 6,
    Utf32Be = 7,
    Unknown = 8,
}

#[repr(usize)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CharsetSrc {
    SetByApp = 0,
    SetByBom = 1,
    SetByGuess = 2,
}

const DSTATE_FIRST: usize = 0;
const DSTATE_SECOND: usize = 1;
const DSTATE_THIRD: usize = 2;
const DSTATE_FOURTH: usize = 3;

#[derive(Clone, Debug)]
pub struct UtfDecodeSession {
    state: usize,
    charset: CharsetCode,
    charset_src: CharsetSrc,
}

impl Default for UtfDecodeSession {
    fn default() -> Self {
        Self::new()
    }
}

impl UtfDecodeSession {
    pub fn new() -> Self {
        UtfDecodeSession {
            state: DSTATE_FIRST,
            charset: CharsetCode::Default,
            charset_src: CharsetSrc::SetByGuess,
        }
    }

    /// charset_src defaults to CHARSET_SET_BY_APP, matching the C++ default arg.
    pub fn set_decode_utf_state_charset(&mut self, charset: CharsetCode, src: CharsetSrc) {
        self.state = DSTATE_FIRST;
        self.charset = charset;
        self.charset_src = src;
    }

    pub fn get_decode_utf_state_charset(&self) -> CharsetCode {
        self.charset
    }

    pub fn get_decode_utf_charset_src(&self) -> CharsetSrc {
        self.charset_src
    }

    pub fn is_utf_encoding_present(&self) -> bool {
        (self.charset as usize) > (CharsetCode::Irrelevant as usize)
    }

    // The three state-machine decoders mirror the C switch-on-dstate.state loops
    // byte for byte, including carry-over of `state` between calls.

    fn decode_utf16le(&mut self, src: &[u8], dst: &mut [u8]) -> (bool, usize) {
        let mut si = 0usize;
        let mut di = 0usize;
        let mut result = true;

        while si < src.len() && di < dst.len() {
            match self.state {
                DSTATE_FIRST => {
                    dst[di] = src[si];
                    di += 1;
                    si += 1;
                    self.state = DSTATE_SECOND;
                }
                DSTATE_SECOND => {
                    si += 1;
                    if src[si - 1] != 0 {
                        result = false;
                    }
                    self.state = DSTATE_FIRST;
                }
                _ => unreachable!(),
            }
        }
        (result, di)
    }

    fn decode_utf16be(&mut self, src: &[u8], dst: &mut [u8]) -> (bool, usize) {
        let mut si = 0usize;
        let mut di = 0usize;
        let mut result = true;

        while si < src.len() && di < dst.len() {
            match self.state {
                DSTATE_FIRST => {
                    si += 1;
                    if src[si - 1] != 0 {
                        result = false;
                    }
                    self.state = DSTATE_SECOND;
                }
                DSTATE_SECOND => {
                    dst[di] = src[si];
                    di += 1;
                    si += 1;
                    self.state = DSTATE_FIRST;
                }
                _ => unreachable!(),
            }
        }
        (result, di)
    }

    fn decode_utf32le(&mut self, src: &[u8], dst: &mut [u8]) -> (bool, usize) {
        let mut si = 0usize;
        let mut di = 0usize;
        let mut result = true;

        while si < src.len() && di < dst.len() {
            match self.state {
                DSTATE_FIRST => {
                    dst[di] = src[si];
                    di += 1;
                    si += 1;
                    self.state += 1;
                }
                DSTATE_SECOND | DSTATE_THIRD | DSTATE_FOURTH => {
                    si += 1;
                    if src[si - 1] != 0 {
                        result = false;
                    }
                    if self.state == DSTATE_FOURTH {
                        self.state = DSTATE_FIRST;
                    } else {
                        self.state += 1;
                    }
                }
                _ => unreachable!(),
            }
        }
        (result, di)
    }

    fn decode_utf32be(&mut self, src: &[u8], dst: &mut [u8]) -> (bool, usize) {
        let mut si = 0usize;
        let mut di = 0usize;
        let mut result = true;

        while si < src.len() && di < dst.len() {
            match self.state {
                DSTATE_FIRST | DSTATE_SECOND | DSTATE_THIRD => {
                    si += 1;
                    if src[si - 1] != 0 {
                        result = false;
                    }
                    self.state += 1;
                }
                DSTATE_FOURTH => {
                    dst[di] = src[si];
                    di += 1;
                    si += 1;
                    self.state = DSTATE_FIRST;
                }
                _ => unreachable!(),
            }
        }
        (result, di)
    }

    /// Mirrors `determine_charset(const uint8_t** src, unsigned* src_len)`,
    /// which advances the caller's src/len past any BOM it consumes.
    /// Returns the BOM size to skip (0 when nothing is consumed).
    fn determine_charset(&mut self, src: &[u8]) -> usize {
        if self.charset != CharsetCode::Unknown {
            return 0;
        }

        let mut charset = CharsetCode::Default;
        let mut charset_src = CharsetSrc::SetByGuess;
        let mut size = 0usize;

        if src.len() < 4 {
            self.set_decode_utf_state_charset(charset, charset_src);
            return 0;
        }

        if src[0..4] == [0x00, 0x00, 0xFE, 0xFF] {
            charset = CharsetCode::Utf32Be;
            size = 4;
        } else if src[0..4] == [0xFF, 0xFE, 0x00, 0x00] {
            charset = CharsetCode::Utf32Le;
            size = 4;
        } else if src[0..2] == [0xFE, 0xFF] {
            charset = CharsetCode::Utf16Be;
            size = 2;
        } else if src[0..2] == [0xFF, 0xFE] {
            charset = CharsetCode::Utf16Le;
            size = 2;
        }

        if charset != CharsetCode::Default {
            charset_src = CharsetSrc::SetByBom;
        } else if src[0] == 0 && src[2] == 0 && src[3] != 0 {
            if src[1] != 0 {
                charset = CharsetCode::Utf16Be; // \0C\0C
            } else {
                charset = CharsetCode::Utf32Be; // \0\0\0C
            }
        } else if src[0] != 0 && src[1] == 0 && src[3] == 0 {
            if src[2] != 0 {
                charset = CharsetCode::Utf16Le; // C\0C\0
            } else {
                charset = CharsetCode::Utf32Le; // C\0\0\0
            }
        }
        // NOTE: UTF-8 BOM falls through here; first 128 UTF-8 chars are ASCII.

        self.set_decode_utf_state_charset(charset, charset_src);
        size
    }

    /// Mirrors `decode_utf(src, src_len, dst, dst_len, &bytes_copied)`.
    /// Returns (ok, bytes_copied).
    pub fn decode_utf(&mut self, src: &[u8], dst: &mut [u8]) -> (bool, usize) {
        let size = self.determine_charset(src);
        let src = &src[size..];
        let src_len = src.len();

        if src_len == 0 {
            return (false, 0);
        }

        match self.charset {
            CharsetCode::Utf16Le => self.decode_utf16le(src, dst),
            CharsetCode::Utf16Be => self.decode_utf16be(src, dst),
            CharsetCode::Utf32Le => self.decode_utf32le(src, dst),
            CharsetCode::Utf32Be => self.decode_utf32be(src, dst),
            _ => (true, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16le_basic() {
        let mut s = UtfDecodeSession::new();
        s.set_decode_utf_state_charset(CharsetCode::Utf16Le, CharsetSrc::SetByApp);
        let src = b"H\0i\0!\0";
        let mut dst = [0u8; 16];
        let (ok, n) = s.decode_utf(src, &mut dst);
        assert!(ok);
        assert_eq!(n, 3);
        assert_eq!(&dst[..3], b"Hi!");
    }

    #[test]
    fn utf16be_nonzero_high_fails_but_still_copies() {
        let mut s = UtfDecodeSession::new();
        s.set_decode_utf_state_charset(CharsetCode::Utf16Be, CharsetSrc::SetByApp);
        // high bytes nonzero -> result false, but low bytes still copied
        let src: [u8; 4] = [0x01, b'A', 0x00, b'B'];
        let mut dst = [0u8; 16];
        let (ok, n) = s.decode_utf(&src, &mut dst);
        assert!(!ok);
        assert_eq!(n, 2);
        assert_eq!(&dst[..2], b"AB");
    }

    #[test]
    fn guess_charset_from_pattern() {
        // C\0C\0 -> UTF16LE guessed
        let mut s = UtfDecodeSession::new();
        s.set_decode_utf_state_charset(CharsetCode::Unknown, CharsetSrc::SetByApp);
        let src = b"A\0B\0";
        let mut dst = [0u8; 16];
        let (ok, n) = s.decode_utf(src, &mut dst);
        assert!(ok);
        assert_eq!(s.get_decode_utf_state_charset(), CharsetCode::Utf16Le);
        assert_eq!(s.get_decode_utf_charset_src(), CharsetSrc::SetByGuess);
        assert_eq!(&dst[..n], b"AB");
    }

    #[test]
    fn bom_utf32le_skipped() {
        let mut s = UtfDecodeSession::new();
        s.set_decode_utf_state_charset(CharsetCode::Unknown, CharsetSrc::SetByApp);
        let mut src: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x00];
        src.extend_from_slice(b"x\0\0\0y\0\0\0");
        let mut dst = [0u8; 16];
        let (ok, n) = s.decode_utf(&src, &mut dst);
        assert!(ok);
        assert_eq!(s.get_decode_utf_state_charset(), CharsetCode::Utf32Le);
        assert_eq!(s.get_decode_utf_charset_src(), CharsetSrc::SetByBom);
        assert_eq!(&dst[..n], b"xy");
    }

    #[test]
    fn state_carries_between_calls() {
        // payload need not end on a 2-byte boundary: split mid-character.
        // UTF-16LE layout: low byte first, high byte must be 0.
        let mut s = UtfDecodeSession::new();
        s.set_decode_utf_state_charset(CharsetCode::Utf16Le, CharsetSrc::SetByApp);
        let mut dst = [0u8; 16];
        let (ok1, n1) = s.decode_utf(b"A", &mut dst[..2]); // low byte of 'A'
        assert!(ok1);
        assert_eq!(&dst[..n1], b"A");
        let (ok2, n2) = s.decode_utf(b"\0B\0", &mut dst); // high of 'A', then 'B'
        assert!(ok2);
        assert_eq!(&dst[..n2], b"B");
    }

    #[test]
    fn is_utf_encoding_present_matches_enum_order() {
        let mut s = UtfDecodeSession::new();
        assert!(!s.is_utf_encoding_present()); // DEFAULT(0) <= IRRELEVANT(3)
        s.set_decode_utf_state_charset(CharsetCode::Utf16Le, CharsetSrc::SetByApp);
        assert!(s.is_utf_encoding_present());
    }
}

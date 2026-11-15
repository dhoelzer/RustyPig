// Port of snort3 helpers/ber.{h,cc}.
//
// Original: Copyright (C) 2019-2026 Cisco and/or its affiliates.
//
// C BerReader keeps beg/cursor/end as raw pointers into the Cursor's
// buffer. Rust keeps them as offsets into the Cursor's owned Vec (the
// Cursor already localized its buffer to offset 0), so the pointer
// arithmetic in read/read_uncapped and the UINT32 cap check translate
// directly (see KNOWN DEVIATIONS.md).

#![allow(dead_code)]

use crate::framework::cursor::Cursor;

pub const BOOLEAN: u32 = 1;
pub const INTEGER: u32 = 2;
pub const BIT_STRING: u32 = 3;
pub const STRING: u32 = 4;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerElement {
    pub r#type: u32,
    pub length: u32,
    pub header_length: u64,
    pub total_length: u64,
    // C: const uint8_t* data; here an offset into the Cursor buffer.
    pub data: usize,
}

pub struct BerReader<'c> {
    cur: &'c Cursor,
    beg: usize,
    cursor: usize,
    end: usize,
}

impl<'c> BerReader<'c> {
    pub fn new(c: &'c Cursor) -> Self {
        BerReader {
            cur: c,
            beg: 0, // the Rust Cursor owns its buffer from offset 0
            cursor: c.start(),
            end: c.endo(),
        }
    }

    // byte at the current cursor, bounds-free: C relies on
    // cursor+1 <= end being checked before each deref.
    fn at(&self, off: usize) -> u8 {
        self.cur.buffer()[off]
    }

    fn read_int(&mut self, size: u32, intval: &mut u32) -> bool {
        let mut bytes = 0u32;
        *intval = 0;

        // cursor must be valid
        if self.cursor < self.beg || self.cursor > self.end {
            return false;
        }
        // check if we can read int data
        if (size as usize) > self.end - self.cursor {
            return false;
        }

        for _ in 0..size {
            let b = self.at(self.cursor);
            self.cursor += 1;

            // handle null padding
            if bytes == 0 && b == 0 {
                continue;
            }

            *intval <<= 8;
            *intval |= b as u32;
            bytes += 1;

            // check if int fits into uint32_t
            if bytes > 4 {
                return false;
            }
        }
        true
    }

    fn read_type(&mut self, r#type: &mut u32) -> bool {
        let mut bytes = 0u32;
        *r#type = 0;

        // cursor must be valid
        if self.cursor < self.beg || self.cursor + 1 > self.end {
            return false;
        }

        let mut b = self.at(self.cursor);
        self.cursor += 1;

        if (b & 0x1F) != 0x1F {
            // short-form type
            *r#type = b as u32;
            return true;
        }

        // long-form type
        loop {
            if self.cursor + 1 > self.end {
                return false;
            }
            b = self.at(self.cursor);
            self.cursor += 1;

            // handle null padding
            if bytes == 0 && b == 0x80 {
                continue;
            }

            *r#type <<= 7;
            *r#type |= (b & 0x7F) as u32;
            bytes += 1;

            // check if type fits into uint32_t
            if bytes > 4 {
                return false;
            }
            // check continuation bit
            if (b & 0x80) == 0 {
                break;
            }
        }
        true
    }

    fn read_length(&mut self, length: &mut u32) -> bool {
        *length = 0;

        // cursor must be valid
        if self.cursor < self.beg || self.cursor + 1 > self.end {
            return false;
        }

        let b = self.at(self.cursor);
        self.cursor += 1;

        if (b & 0x80) == 0 {
            // short-form length
            *length = b as u32;
            return true;
        }

        // long-form length
        let size = (b & 0x7F) as u32;
        if size == 0 {
            return false;
        }
        if !self.read_int(size, length) {
            return false;
        }
        true
    }

    /// C read_uncapped(c, e): cursor positions are offsets into
    /// the Cursor buffer; `c` is the start offset passed by the caller.
    pub fn read_uncapped(&mut self, c: usize, e: &mut BerElement) -> bool {
        let start = c;
        self.cursor = c;

        if !self.read_type(&mut e.r#type) {
            return false;
        }
        if !self.read_length(&mut e.length) {
            return false;
        }

        // set BER data pointer
        e.data = self.cursor;

        // integer underflow check (C cursor >= start is always true here
        // since read_type/length only advance; kept for parity)
        if start > self.cursor {
            return false;
        }

        // calculate BER header length
        e.header_length = (self.cursor - start) as u64;

        // calculate total BER length
        e.total_length = e.header_length + e.length as u64;

        // integer overflow check
        if e.total_length < e.header_length {
            return false;
        }

        true
    }

    pub fn read(&mut self, c: usize, e: &mut BerElement) -> bool {
        if !self.read_uncapped(c, e) {
            return false;
        }
        // the element end must be representable as a 32-bit Cursor position
        if e.total_length > (u32::MAX as u64) - ((c - self.beg) as u64) {
            return false;
        }
        true
    }

    pub fn convert(&mut self, e: &BerElement, intval: &mut u32) -> bool {
        if e.r#type != INTEGER {
            return false;
        }
        // set cursor to int data
        self.cursor = e.data;
        if !self.read_int(e.length, intval) {
            return false;
        }
        true
    }

    /// C extract(c, intval): `c` is an in/out pointer -> an in/out offset.
    pub fn extract(&mut self, c: &mut usize, intval: &mut u32) -> bool {
        let mut e = BerElement::default();
        if !self.read(*c, &mut e) {
            return false;
        }
        if !self.convert(&e, intval) {
            return false;
        }
        // save end of element position
        *c = self.cursor;
        true
    }

    pub fn skip(&mut self, c: &mut usize, r#type: u32) -> bool {
        let mut e = BerElement::default();
        if !self.read(*c, &mut e) {
            return false;
        }
        if e.r#type != r#type {
            return false;
        }
        // integer underflow check
        if self.cursor > self.end {
            return false;
        }
        // check if we can jump BER data
        if (e.length as usize) > self.end - self.cursor {
            return false;
        }
        // jump BER data
        self.cursor += e.length as usize;
        // save end of element position
        *c = self.cursor;
        true
    }

    pub fn data(&mut self, c: &mut usize, r#type: u32) -> bool {
        let mut e = BerElement::default();
        if !self.read(*c, &mut e) {
            return false;
        }
        if e.r#type != r#type {
            return false;
        }
        *c = e.data;
        true
    }
}

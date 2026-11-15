// Port of the buffer/position core of snort3 framework/cursor.h.
//
// The C Cursor also carries Packet* wiring and a CursorData side-table
// used by the detection layer; those fields depend on subsystems not
// ported yet, so they are omitted (see KNOWN DEVIATIONS.md). The exact
// fields the BER layer and C tests touch are verbatim: name, buffer,
// buf_size (+ n), current_pos, delta, extensible, buf_id, file_pos.

#![allow(dead_code)]
// Explicit Default mirrors the C zero-initialization of every Cursor field.
// (newtype-deriving Default here would hide that intent.)
// clippy::derivable_impls suppressed deliberately.
#![allow(clippy::derivable_impls)]

#[derive(Clone)]
pub struct Cursor {
    name: String,
    buf: Vec<u8>,
    buf_size: usize,
    current_pos: usize,
    delta: usize,
    extensible: bool,
    buf_id: u64,
    file_pos: u32,
}

impl Default for Cursor {
    fn default() -> Self {
        Cursor {
            name: String::new(),
            buf: Vec::new(),
            buf_size: 0,
            current_pos: 0,
            delta: 0,
            extensible: false,
            buf_id: 0,
            file_pos: 0,
        }
    }
}

// C stores raw pointers; the Rust port owns the bytes. ber needs the
// buffer address stable for a BerReader's lifetime, so callers borrow the
// Cursor itself (&Cursor) while using offsets, and BerReader::read takes
// a position (offset into the buffer), mirroring C's pointer argument.
impl Cursor {
    /// set(s, b, n, ext=false)
    pub fn set(&mut self, s: &str, b: &[u8], ext: bool) {
        let n = b.len();
        self.name = s.to_string();
        self.buf = b.to_vec();
        self.buf_size = n;
        self.current_pos = 0;
        self.delta = 0;
        self.extensible = ext && n > 0;
        self.buf_id = 0;
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is(&self, s: &str) -> bool {
        self.name == s
    }

    pub fn id(&self) -> u64 {
        self.buf_id
    }

    /// buffer() as an offset base (C: raw pointer)
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    pub fn size(&self) -> usize {
        self.buf_size
    }

    /// endo(): the next octet after the last (C: out-of-bounds pointer;
    /// represented as the one-past offset == buf_size)
    pub fn endo(&self) -> usize {
        self.buf_size
    }

    /// start(): current position offset
    pub fn start(&self) -> usize {
        self.current_pos
    }

    pub fn length(&self) -> usize {
        self.buf_size - self.current_pos
    }

    pub fn get_pos(&self) -> usize {
        self.current_pos
    }

    pub fn get_delta(&self) -> usize {
        self.delta
    }

    pub fn set_pos(&mut self, p: usize) {
        self.current_pos = p;
    }

    pub fn set_delta(&mut self, d: usize) {
        self.delta = d;
    }
}

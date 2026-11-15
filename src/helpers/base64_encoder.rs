// Port of snort3 src/helpers/base64_encoder.{h,cc} (Base64Encoder, libb64-style).
//
// Original: Copyright (C) 2017-2026 Cisco and/or its affiliates.
// Streaming encoder: instantiate, encode+ (repeatedly), finish.
// State machine steps preserved exactly (step_A/step_B/step_C carry `state`).

const STEPS: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    A,
    B,
    C,
}

#[derive(Clone, Copy)]
pub struct Base64Encoder {
    step: Step,
    state: u8,
}

impl Default for Base64Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Base64Encoder {
    pub fn new() -> Self {
        Base64Encoder { step: Step::A, state: 0 }
    }

    /// Mirrors `unsigned encode(const uint8_t* data, unsigned len, char* out)`:
    /// writes encoded chars into `out` (which must have room) and returns the count.
    pub fn encode(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        let mut i = 0usize; // data index
        let mut p = 0usize; // out index

        loop {
            match self.step {
                Step::A => {
                    if i == data.len() {
                        self.step = Step::A;
                        return p;
                    }
                    let fragment = data[i];
                    i += 1;
                    self.state = (fragment & 0x0fc) >> 2;
                    out[p] = STEPS[self.state as usize];
                    p += 1;
                    self.state = (fragment & 0x003) << 4;
                    self.step = Step::B;
                }
                Step::B => {
                    if i == data.len() {
                        self.step = Step::B;
                        return p;
                    }
                    let fragment = data[i];
                    i += 1;
                    self.state |= (fragment & 0x0f0) >> 4;
                    out[p] = STEPS[self.state as usize];
                    p += 1;
                    self.state = (fragment & 0x00f) << 2;
                    self.step = Step::C;
                }
                Step::C => {
                    if i == data.len() {
                        self.step = Step::C;
                        return p;
                    }
                    let fragment = data[i];
                    i += 1;
                    self.state |= (fragment & 0x0c0) >> 6;
                    out[p] = STEPS[self.state as usize];
                    p += 1;
                    self.state = fragment & 0x03f;
                    out[p] = STEPS[self.state as usize];
                    p += 1;
                    self.step = Step::A;
                }
            }
        }
    }

    /// Mirrors `unsigned finish(char* out)`: flushes pending state with padding.
    pub fn finish(&mut self, out: &mut [u8]) -> usize {
        let mut p = 0usize;
        match self.step {
            Step::B => {
                out[p] = STEPS[self.state as usize];
                p += 1;
                out[p] = b'=';
                p += 1;
                out[p] = b'=';
                p += 1;
            }
            Step::C => {
                out[p] = STEPS[self.state as usize];
                p += 1;
                out[p] = b'=';
                p += 1;
            }
            Step::A => {}
        }
        p
    }

    pub fn reset(&mut self) {
        self.step = Step::A;
        self.state = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from the CATCH tests in src/helpers/base64_encoder.cc.

    #[test]
    fn b64_no_encode() {
        let mut e = Base64Encoder::new();
        let mut buf = [0u8; 256];
        assert_eq!(e.finish(&mut buf), 0);
    }

    #[test]
    fn b64_null_data() {
        let mut e = Base64Encoder::new();
        let mut buf = [0u8; 256];
        assert_eq!(e.encode(&[], &mut buf), 0);
        assert_eq!(e.finish(&mut buf), 0);
    }

    #[test]
    fn b64_zero_length_data() {
        let mut e = Base64Encoder::new();
        let mut buf = [0u8; 256];
        // C++ passes ("ignore", 0): non-null data, zero length
        assert_eq!(e.encode(&b"ignore"[..0], &mut buf), 0);
        assert_eq!(e.finish(&mut buf), 0);
    }

    #[test]
    fn b64_finish_states() {
        let mut e = Base64Encoder::new();
        let txt: [&[u8]; 3] = [b"test0\n", b"test01\n", b"test012\n"];
        let exp: [&str; 3] = ["dGVzdDAK", "dGVzdDAxCg==", "dGVzdDAxMgo="];

        for i in 0..txt.len() {
            let mut buf = [0u8; 256];
            let mut n = e.encode(txt[i], &mut buf);
            n += e.finish(&mut buf[n..]);
            assert!(n < buf.len());
            assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), exp[i]);
            e.reset();
        }
    }

    #[test]
    fn b64_one_shot() {
        let mut e = Base64Encoder::new();
        let text = b"The quick brown segment jumped over the lazy dogs.\n";
        let code = "VGhlIHF1aWNrIGJyb3duIHNlZ21lbnQganVtcGVkIG92ZXIgdGhlIGxhenkgZG9ncy4K";

        let mut buf = [0u8; 256];
        let mut n = e.encode(text, &mut buf);
        n += e.finish(&mut buf[n..]);
        assert!(n < buf.len());
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), code);
    }

    #[test]
    fn b64_slice_and_dice() {
        let text = b"The quick brown segment jumped over the lazy dogs.\n";
        let code = "VGhlIHF1aWNrIGJyb3duIHNlZ21lbnQganVtcGVkIG92ZXIgdGhlIGxhenkgZG9ncy4K";
        let len = text.len();

        for chunk in 1..len {
            let mut e = Base64Encoder::new();
            let mut buf = [0u8; 256];
            let mut offset = 0usize;
            let mut n = 0usize;

            while offset < len {
                let k = if offset + chunk > len { len - offset } else { chunk };
                n += e.encode(&text[offset..offset + k], &mut buf[n..]);
                offset += k;
            }
            n += e.finish(&mut buf[n..]);
            assert!(n < buf.len());
            assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), code);
        }
    }
}

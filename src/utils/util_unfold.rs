// Port of snort3 utils/util_unfold.{h,cc}
// (author Bhagyashree Bantwal <bbantwal@sourcefire.com>).
//
// Header unfolding / CRLF-LWS stripping over byte slices. The C
// null-pointer guards in sf_strip_CRLF/sf_strip_LWS (`!inbuf || !outbuf`
// -> -1) are unreachable for Rust slices and omitted; everything else,
// including the NUL-termination quirk and the exact LWS backspace loop,
// is verbatim (see KNOWN DEVIATIONS.md is unchanged for this file).

#![allow(dead_code)]

/// sf_unfold_header(): returns (ret, output_bytes); C's *folded out-param
/// maps to the returned Option counter (callers may pass null in C).
pub fn sf_unfold_header(
    inbuf: &[u8],
    outbuf: &mut [u8],
    trim_spaces: bool,
    folded: Option<&mut i32>,
) -> (i32, u32) {
    let mut num_spaces = 0i32;
    let inbuf_size = inbuf.len() as u32;
    let outbuf_size = outbuf.len() as u32;

    let mut n = 0u32;
    let mut out = 0usize; // outbuf_ptr - outbuf

    // C int flags: 0 none, 1 after LF, 2 after CR
    let mut httpheaderfolding = 0i32;
    let mut folding_present = 0i32;

    let mut cursor = 0usize;
    let endofinbuf = inbuf_size as usize;

    // Keep adding chars until end of header: CRLF followed by LWS folds;
    // LF followed by non-LWS ends it.
    while cursor < endofinbuf && n < outbuf_size {
        let c = inbuf[cursor];
        if c == b' ' || c == b'\t' {
            if folding_present != 0 {
                num_spaces += 1;
            }
            if httpheaderfolding != 0 {
                num_spaces += 1;
                folding_present = 1;
                httpheaderfolding = 0;
            } else if !trim_spaces {
                // Spaces are valid except after CRs
                outbuf[out] = c;
                out += 1;
                n += 1;
            }
        } else if c == b'\n' && httpheaderfolding != 1 {
            // Can't have multiple LFs in a row, but if we get one it
            // needs to be followed by at least one space
            httpheaderfolding = 1;
        } else if c == b'\r' && httpheaderfolding == 0 {
            // CR needs to be followed by LF and can't start a line
            httpheaderfolding = 2;
        } else if httpheaderfolding == 0 {
            outbuf[out] = c;
            out += 1;
            n += 1;
        } else {
            // End of header (unless multiple CRs, suspicious but not ours
            // to decide)
            break;
        }
        cursor += 1;
    }

    if n < outbuf_size {
        outbuf[out] = 0;
    } else if outbuf_size != 0 {
        outbuf[outbuf_size as usize - 1] = 0;
    }

    if let Some(f) = folded {
        *f = num_spaces;
    }
    (0, out as u32) // *output_bytes = outbuf_ptr - outbuf
}

/// sf_strip_CRLF(): strips CR and LF from the input.
pub fn sf_strip_crlf(inbuf: &[u8], outbuf: &mut [u8]) -> (i32, Option<u32>) {
    let outbuf_size = outbuf.len() as u32;
    let mut n = 0u32;
    let mut out = 0usize;

    let mut cursor = 0usize;
    let endofinbuf = inbuf.len();
    while cursor < endofinbuf && n < outbuf_size {
        let c = inbuf[cursor];
        if c != b'\n' && c != b'\r' {
            outbuf[out] = c;
            out += 1;
            n += 1;
        }
        cursor += 1;
    }

    (0, Some(out as u32)) // output_bytes non-null in practice
}

/// sf_strip_LWS(): strips trailing LWS before LF or CRLF only.
pub fn sf_strip_lws(inbuf: &[u8], outbuf: &mut [u8]) -> (i32, Option<u32>) {
    let outbuf_size = outbuf.len() as u32;
    let mut n = 0u32;
    let mut out = 0usize;
    let mut lws = 0u8;

    let mut cursor = 0usize;
    let endofinbuf = inbuf.len();
    while cursor < endofinbuf && n < outbuf_size {
        let c = inbuf[cursor];
        if c != b'\n' && c != b'\r' {
            if c != b' ' && c != b'\t' {
                lws = 0;
            } else {
                lws = 1;
            }
            outbuf[out] = c;
            out += 1;
            n += 1;
        } else {
            if lws != 0 {
                lws = 0;
                while n > 0 {
                    let prev = outbuf[out - 1];
                    if prev != b' ' && prev != b'\t' {
                        break;
                    }
                    n -= 1;
                    out -= 1;
                }
            }
            outbuf[out] = c;
            out += 1;
            n += 1;
        }
        cursor += 1;
    }

    (0, Some(out as u32))
}

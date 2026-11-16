//! Engine half of the `utils/util_jsnorm.cc` port (row 17i): the
//! PNorm / SFCC / Unescape / JSNorm decoders and the
//! `JSNormalizeDecode` entry point. Tables live in `jsnorm_tables`.
//!
//! Literal-transcription notes (canonical list in KNOWN DEVIATIONS.md):
//! - C threads shared byte buffers through the nested decodes by
//!   pointer aliasing: SFCC hands its own output buffer to
//!   UnescapeDecode as BOTH src and dst (in-place rewrite), and
//!   UnescapeDecode hands its buffer to PNormDecode in place. Each
//!   scan consumes one source byte and writes at most one output
//!   byte, so the write cursor never passes the read cursor and the
//!   bytes read are always the stage's original content. Rust keeps
//!   the same observable arrangement: a snapshot read view + the same
//!   write buffer, documented at each call site.
//! - `overwrite` is a mid-buffer truncation cursor (nullptr = None).
//! - `ConvertToChar` writes the terminating ANY at `buf[buflen]` of a
//!   `uint8_t buf[8]` (stack OOB when buflen==8, unobservable); the
//!   Rust buf is one slot wider so the NUL-stuffing is literal.
//! - C `strtoul(buf, &p, radix)` runs over digits the FSM already
//!   class-checked: hand-rolled same-radix parse stopping at the
//!   first non-digit, i32 result.
//! - `iNorm <<= 4; iNorm |= hex_lookup[c]` uses C `int` semantics
//!   (hex_lookup miss = -1 poisons all bits); Rust mirrors with
//!   i32 + wrapping shift.
//! - `unicode_map[iNorm]` with 0xff < iNorm <= 0xffff reads the
//!   caller's uint8 table; only pinned observable for in-range
//!   tables, out-of-table indexes fall back to NON_ASCII_CHAR (UB in
//!   C, unreachable in the locked transcript). The `iNorm == -1`
//!   check after a u8 map read is dead upstream
//!   (cppcheck-suppressed) and kept literally.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_isolate_lowest_one)]

use super::jsnorm_tables::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JsState {
    pub allowed_spaces: i32,
    pub allowed_levels: i32,
    pub alerts: u16,
}

/// C `struct Dbuf` (data pointer; Rust callers pass the shared buf).
#[derive(Clone, Copy)]
struct Dbuf {
    size: usize,
    len: usize,
}

/// C CheckWSExceeded.
fn check_ws_exceeded(js: &mut JsState, num_spaces: &mut u16) {
    if js.allowed_spaces != 0 && (i32::from(*num_spaces) > js.allowed_spaces) {
        js.alerts |= ALERT_SPACES_EXCEEDED;
    }
    *num_spaces = 0;
}

// ---------------------------------------------------------------- PNorm

#[derive(Clone, Copy)]
struct PNormState {
    fsm: usize,
    fsm_other: usize,
    prev_event: u8,
    d_quotes: u8,
    s_quotes: u8,
    num_spaces: u16,
    overwrite: Option<usize>,
    output: Dbuf,
}

fn write_decoded_pnorm(s: &mut PNormState, c: i32, js: &mut JsState, out: &mut [u8]) {
    let dstart = 0usize;
    let dend = s.output.size;
    let mut dptr = s.output.len;

    check_ws_exceeded(js, &mut s.num_spaces);

    if dptr < dend {
        out[dptr] = c as u8;
        dptr += 1;
    }

    s.output.len = dptr - dstart;
}

fn pnorm_exec(s: &mut PNormState, a: u8, c: i32, js: &mut JsState, out: &mut [u8]) -> i32 {
    let cur_ptr = s.output.len;
    let i_ret = RET_OK;

    match a {
        // C spells PNORM_ACT_DQUOTES and PNORM_ACT_SQUOTES as two
        // identical case bodies; one arm keeps both discriminants.
        PN_DQUOTES | PN_SQUOTES => {
            if s.prev_event == b'\\' {
                s.fsm = s.fsm_other;
                write_decoded_pnorm(s, c, js, out);
                return i_ret;
            }
            // C increments through a pointer to d_quotes or s_quotes;
            // Rust snapshots the counter to keep the borrow checker
            // happy (same observable value flow).
            let is_d = a == PN_DQUOTES;
            let mut q = if is_d { s.d_quotes } else { s.s_quotes };
            q = q.wrapping_add(1);
            if is_d { s.d_quotes = q; } else { s.s_quotes = q; }
            if q == 2 {
                s.overwrite = Some(cur_ptr);
                write_decoded_pnorm(s, c, js, out);
                if is_d { s.d_quotes = 0; } else { s.s_quotes = 0; }
                return i_ret;
            }
            if s.prev_event == b'+' {
                s.prev_event = 0;
                match s.overwrite {
                    Some(ow) if ow < cur_ptr => s.output.len = ow,
                    _ => write_decoded_pnorm(s, c, js, out),
                }
            } else {
                write_decoded_pnorm(s, c, js, out);
            }
        }
        PN_NOP => {
            s.prev_event = c as u8;
            s.overwrite = None;
            write_decoded_pnorm(s, c, js, out);
        }
        PN_PLUS => {
            s.prev_event = b'+';
            write_decoded_pnorm(s, c, js, out);
        }
        PN_SPACE => {
            if s.num_spaces == 0 {
                write_decoded_pnorm(s, c, js, out);
            }
            s.num_spaces = s.num_spaces.wrapping_add(1);
        }
        PN_WITHIN => {
            // C falls through WITHIN_QUOTES into default (no-op).
            s.prev_event = c as u8;
            write_decoded_pnorm(s, c, js, out);
        }
        _ => {}
    }

    i_ret
}

fn pnorm_scan_fsm(s: &mut PNormState, c: i32, js: &mut JsState, out: &mut [u8]) -> i32 {
    let mut c = c;
    let mut uc = toupper_c(c as u8);

    if is_space_c(c as u8) {
        c = b' ' as i32;
        uc = b' ';
    }

    let action;
    loop {
        let m = &plus_norm()[s.fsm];
        if m.event == 0 || m.event == uc {
            s.fsm = m.r#match;
            s.fsm_other = m.other;
            action = m.action;
            break;
        }
        s.fsm = m.other;
    }

    pnorm_exec(s, action, c, js, out)
}

/// C PNormDecode. `src` is the read view and writing goes into
/// `out` (C passes the SAME buffer for both; see file header).
fn pnorm_decode(src: &[u8], srclen: usize, out: &mut [u8], dstlen: usize, js: &mut JsState) -> usize {
    let end = srclen;
    let mut ptr = 0usize;

    let mut s = PNormState {
        fsm: 0,
        fsm_other: 0,
        prev_event: 0,
        d_quotes: 0,
        s_quotes: 0,
        num_spaces: 0,
        overwrite: None,
        output: Dbuf { size: dstlen, len: 0 },
    };

    while ptr < end {
        pnorm_scan_fsm(&mut s, src[ptr] as i32, js, out);
        ptr += 1;
    }

    s.output.len
}

// ---------------------------------------------------------------- SFCC

struct SfccState {
    fsm: usize,
    buf: [u8; MAX_BUF + 1],
    buflen: usize,
    cur_flags: u16,
    alert_flags: u16,
    output: Dbuf,
}

impl SfccState {
    fn new(dst_len: usize) -> SfccState {
        SfccState {
            fsm: 0,
            buf: [0; MAX_BUF + 1],
            buflen: 0,
            cur_flags: 0,
            alert_flags: 0,
            output: Dbuf { size: dst_len, len: 0 },
        }
    }
}

/// C ConvertToChar: NUL-stuff at buf[buflen], radix parse.
fn convert_to_char(flags: u16, buf: &mut [u8; MAX_BUF + 1], buflen: usize) -> i32 {
    buf[buflen] = 0; // C ANY

    // C strtoul over already class-classified digits: skip leading
    // spaces (none by FSM construction), then consume valid radix
    // digits. Hand-rolled equivalent with the same stop semantics.
    let radix: u32 = if flags & IS_DEC != 0 {
        10
    } else if flags & IS_OCT != 0 {
        8
    } else if flags & IS_HEX != 0 {
        16
    } else {
        return 0;
    };

    let mut acc: u64 = 0;
    let mut i = 0usize;
    while i < buflen {
        let d = buf[i];
        let v = match d {
            b'0'..=b'9' => u32::from(d - b'0'),
            b'A'..=b'F' => u32::from(d - b'A') + 10,
            b'a'..=b'f' => u32::from(d - b'a') + 10,
            _ => break,
        };
        if v >= radix {
            break;
        }
        // C strtoul saturates at ULONG_MAX; inputs are at most
        // MAX_BUF=8 digits so the accumulation cannot exceed u64.
        acc = acc * u64::from(radix) + u64::from(v);
        i += 1;
    }
    // C assigns unsigned long -> int (implementation-defined wrap on
    // gcc; the pinned transcript values are well below 2^31).
    (acc as u32) as i32
}

fn write_decoded_sfcc(s: &mut SfccState, out: &mut [u8]) {
    let start = 0usize;
    let end = s.output.size;
    let len = s.output.len;
    let mut ptr = len;

    if ptr < end {
        if s.cur_flags != 0 {
            let cvt = convert_to_char(s.cur_flags, &mut s.buf, s.buflen);
            out[ptr] = cvt as u8;
            ptr += 1;
        } else {
            let avail = end - ptr;
            let copy_len = if avail < s.buflen { avail } else { s.buflen };

            out[ptr..ptr + copy_len].copy_from_slice(&s.buf[..copy_len]);
            ptr += copy_len;
        }
    }

    s.output.len = ptr - start;
    s.cur_flags = 0;
    s.buflen = 0;
}

fn sfcc_exec(s: &mut SfccState, a: u8, c: i32, out: &mut [u8]) -> i32 {
    let mut i_ret = RET_OK;
    match a {
        SF_NOP => {}
        SF_QUIT => {
            write_decoded_sfcc(s, out);
            i_ret = RET_QUIT;
        }
        SF_INV => {
            write_decoded_sfcc(s, out);
            i_ret = RET_INV;
        }
        SF_DEC | SF_OCT | SF_HEX => {
            // C spells the three digit actions as parallel cases.
            if s.buflen < MAX_BUF {
                s.buf[s.buflen] = c as u8;
                s.buflen += 1;
                s.cur_flags = match a {
                    SF_DEC => IS_DEC,
                    SF_OCT => IS_OCT,
                    _ => IS_HEX,
                };
            } else {
                s.cur_flags = 0;
                write_decoded_sfcc(s, out);
            }
        }
        SF_COMMA | SF_SPACE => {
            write_decoded_sfcc(s, out);
            s.cur_flags = 0;
        }
        _ => {}
    }

    s.alert_flags |= s.cur_flags;
    i_ret
}

fn sfcc_scan_fsm(s: &mut SfccState, c: i32, out: &mut [u8]) -> i32 {
    let uc = toupper_c(c as u8);

    if is_space_c(c as u8) {
        return sfcc_exec(s, SF_SPACE, c, out);
    }

    let value = valid_chars(uc);
    let indexed = value != 0;

    let action;
    loop {
        let m = &sfcc_norm()[s.fsm];
        if m.event == 0
            || (indexed && u16::from(m.event) & value == u16::from(m.event))
            || m.event == uc
        {
            s.fsm = m.r#match;
            action = m.action;
            break;
        }
        s.fsm = m.other;
    }

    sfcc_exec(s, action, c, out)
}

/// C StringFromCharCodeDecode: SFCC walk over the script, then an
/// in-place UnescapeDecode over the SFCC output buffer.
#[allow(clippy::needless_range_loop)]
fn string_from_char_code_decode(
    src: &[u8],
    ptr: &mut usize,
    out: &mut [u8],
    dst_len: usize,
    bcopied: &mut usize,
    js: &mut JsState,
    umap: Option<&[u8]>,
) {
    let start = 0usize;
    let end = src.len();

    let mut s = SfccState::new(dst_len);

    while *ptr < end {
        let i_ret = sfcc_scan_fsm(&mut s, src[*ptr] as i32, out);
        if i_ret != RET_OK {
            // C: if (iRet == RET_INV) && ((*ptr - 1) > start) (*ptr)--
            if i_ret == RET_INV && *ptr >= start + 2 {
                *ptr -= 1;
            }
            break;
        }
        *ptr += 1;
    }

    let alert = s.alert_flags;
    if alert != (alert & alert.wrapping_neg()) {
        js.alerts |= ALERT_MIXED_ENCODINGS;
    }

    // C: UnescapeDecode(s.output.data, s.output.len, &s.output.data,
    // &s.output.data, s.output.size, &s.output.len, ...) — in-place.
    let view = out[..s.output.len].to_vec();
    s.output.len = unescape_decode_readonly(&view, view.len(), out, s.output.size, js, umap);

    *bcopied = s.output.len;
}

// -------------------------------------------------------------- Unescape

struct UnescapeState {
    fsm: usize,
    multiple_levels: u8,
    prev_event: u8,
    alert_flags: u16,
    num_spaces: u16,
    i_norm: i32,
    paren_count: i32,
    unicode_map: Option<Vec<u8>>,
    overwrite: Option<usize>,
    prev_action: u8,
    output: Dbuf,
}

/// C UNESC_ACT_* arms with unicode_map lookup shared by UBACKSLASH
/// and UPERCENT (C spells them out in full twice in the switch).
fn unescape_write_mapped(s: &mut UnescapeState, c: i32, js: &mut JsState, out: &mut [u8], bit: u16, cur_ptr: usize) {
    s.prev_action = 0;
    s.alert_flags |= bit;
    s.i_norm = s.i_norm.wrapping_shl(4);
    s.i_norm |= HEX_LOOKUP[usize::from(c as u8)];
    if let Some(ow) = s.overwrite.filter(|ow| *ow < cur_ptr) {
        s.output.len = ow;
    }
    s.overwrite = None;

    if s.i_norm > 0xff {
        if let Some(map) = &s.unicode_map {
            if s.i_norm <= 0xffff {
                // C indexes the caller's uint8 table; out-of-table
                // indexes are UB — Rust substitutes the NON_ASCII
                // fallback (deviation; unreachable in the transcript
                // with the pinned 256-byte map).
                s.i_norm = i32::from(map[usize::try_from(s.i_norm).unwrap_or(0xffff)]);
                if s.i_norm == -1 {
                    // dead in C (u8 map cannot yield -1); kept literal
                    s.i_norm = NON_ASCII_CHAR;
                }
            } else {
                s.i_norm = NON_ASCII_CHAR;
            }
        } else {
            s.i_norm = NON_ASCII_CHAR;
        }
    }
    write_decoded_unescape(s, s.i_norm, js, out);
    s.i_norm = 0;
}

fn write_decoded_unescape(s: &mut UnescapeState, c: i32, js: &mut JsState, out: &mut [u8]) {
    let dstart = 0usize;
    let dend = s.output.size;
    let mut dptr = s.output.len;

    check_ws_exceeded(js, &mut s.num_spaces);

    if dptr < dend {
        out[dptr] = c as u8;
        dptr += 1;
    }

    s.output.len = dptr - dstart;
}

fn unescape_exec(s: &mut UnescapeState, a: u8, c: i32, js: &mut JsState, out: &mut [u8]) -> i32 {
    let cur_ptr = s.output.len;
    let mut i_ret = RET_OK;

    match a {
        UN_BACKSLASH => {
            s.prev_action = 0;
            s.alert_flags |= IS_BACKSLASH;
            s.i_norm = s.i_norm.wrapping_shl(4);
            s.i_norm |= HEX_LOOKUP[usize::from(c as u8)];
            if let Some(ow) = s.overwrite.filter(|ow| *ow < cur_ptr) {
                s.output.len = ow;
            }
            s.overwrite = None;
            write_decoded_unescape(s, s.i_norm, js, out);
            s.i_norm = 0;
        }
        UN_CONV => {
            s.prev_action = 0;
            s.i_norm = s.i_norm.wrapping_shl(4);
            s.i_norm |= HEX_LOOKUP[usize::from(c as u8)];
            write_decoded_unescape(s, c, js, out);
        }
        UN_NOP => {
            s.prev_action = 0;
            s.i_norm = 0;
            s.overwrite = None;
            write_decoded_unescape(s, c, js, out);
        }
        UN_PAREN => {
            if s.prev_action == UN_UNESCAPE {
                s.prev_action = 0;
                s.multiple_levels = s.multiple_levels.wrapping_add(1);
            }
            s.i_norm = 0;
            if s.paren_count > 0 {
                write_decoded_unescape(s, c, js, out);
            }
            s.paren_count += 1;
        }
        UN_PERCENT => {
            s.prev_action = 0;
            s.alert_flags |= IS_PERCENT;
            s.i_norm = s.i_norm.wrapping_shl(4);
            s.i_norm |= HEX_LOOKUP[usize::from(c as u8)];
            if let Some(ow) = s.overwrite.filter(|ow| *ow < cur_ptr) {
                s.output.len = ow;
            }
            s.overwrite = None;
            write_decoded_unescape(s, s.i_norm, js, out);
            s.i_norm = 0;
        }
        UN_QUIT => {
            s.prev_action = 0;
            s.i_norm = 0;
            s.overwrite = None;
            if s.paren_count != 0 {
                s.paren_count -= 1;
            }

            if s.paren_count == 0 {
                i_ret = RET_QUIT;
            } else {
                write_decoded_unescape(s, c, js, out);
            }
        }
        UN_SAVE => {
            s.prev_action = 0;
            s.i_norm = 0;
            s.overwrite = Some(cur_ptr);
            write_decoded_unescape(s, c, js, out);
        }
        UN_SAVE_NOP => {
            s.prev_action = 0;
            s.i_norm = 0;
            write_decoded_unescape(s, c, js, out);
        }
        UN_SPACE => {
            s.i_norm = 0;
            if s.prev_event == b'\'' || s.prev_event == b'"' {
                write_decoded_unescape(s, c, js, out);
                // C returns BEFORE the trailing prev_event store.
                return i_ret;
            }
            if s.prev_event != b' ' {
                write_decoded_unescape(s, c, js, out);
            }
            s.num_spaces = s.num_spaces.wrapping_add(1);
        }
        UN_UBACKSLASH => unescape_write_mapped(s, c, js, out, IS_UBACKSLASH, cur_ptr),
        UN_UPERCENT => unescape_write_mapped(s, c, js, out, IS_UPERCENT, cur_ptr),
        UN_UNESCAPE => {
            // C: save the action, wait for the paren to levels++.
            s.prev_action = a;
            s.i_norm = 0;
            write_decoded_unescape(s, c, js, out);
        }
        _ => {}
    }

    s.prev_event = c as u8;
    i_ret
}

fn unescape_scan_fsm(s: &mut UnescapeState, c: i32, js: &mut JsState, out: &mut [u8]) -> i32 {
    let mut c = c;
    if is_space_c(c as u8) {
        c = b' ' as i32;
        return unescape_exec(s, UN_SPACE, c, js, out);
    }

    let uc = toupper_c(c as u8);
    let value = valid_chars(uc);
    let indexed = value != 0;

    let action;
    loop {
        let m = &unescape_norm()[s.fsm];
        if m.event == 0
            || m.event == uc
            || (indexed && u16::from(m.event) & value == u16::from(m.event))
        {
            s.fsm = m.r#match;
            action = m.action;
            break;
        }
        s.fsm = m.other;
    }

    unescape_exec(s, action, c, js, out)
}

/// C UnescapeDecode walking `read` from position `walk` (script
/// cursor for the JSNorm entry; 0 for the SFCC nested call), writing
/// into `out`, ending with the in-place PNorm pass (returning its
/// final length — which is what C stores into the caller's
/// bytes_copied / output.len).
fn unescape_walk(
    read: &[u8],
    walk: &mut usize,
    out: &mut [u8],
    dst_len: usize,
    js: &mut JsState,
    umap: Option<&[u8]>,
) -> usize {
    let end = read.len();

    let mut s = UnescapeState {
        fsm: 0,
        multiple_levels: 1,
        prev_event: 0,
        alert_flags: 0,
        num_spaces: 0,
        i_norm: 0,
        paren_count: 0,
        unicode_map: umap.map(<[u8]>::to_vec),
        overwrite: None,
        prev_action: 0,
        output: Dbuf { size: dst_len, len: 0 },
    };

    while *walk < end {
        let i_ret = unescape_scan_fsm(&mut s, read[*walk] as i32, js, out);
        if i_ret != RET_OK {
            // C's RET_INV ptr regression here is commented out.
            break;
        }
        *walk += 1;
    }

    let alert = s.alert_flags;
    if alert != (alert & alert.wrapping_neg()) {
        js.alerts |= ALERT_MIXED_ENCODINGS;
    }

    if i32::from(s.multiple_levels) > js.allowed_levels {
        js.alerts |= ALERT_LEVELS_EXCEEDED;
    }

    // PNormDecode in place over the Unescape output
    let view = out[..s.output.len].to_vec();
    pnorm_decode(&view, s.output.len, out, s.output.len, js)
}

/// SFCC nested call: reads start at 0 over the SFCC output view.
fn unescape_decode_readonly(
    view: &[u8],
    srclen: usize,
    out: &mut [u8],
    dst_len: usize,
    js: &mut JsState,
    umap: Option<&[u8]>,
) -> usize {
    let mut walk = 0usize;
    unescape_walk(&view[..srclen], &mut walk, out, dst_len, js, umap)
}

// ---------------------------------------------------------------- JSNorm

struct JsnormState {
    fsm: usize,
    prev_event: u8,
    num_spaces: u16,
    unicode_map: Option<Vec<u8>>,
    overwrite: Option<usize>,
    dest: Dbuf,
}

fn write_jsnorm_char(s: &mut JsnormState, c: i32, js: &mut JsState, out: &mut [u8]) {
    let dstart = 0usize;
    let dend = s.dest.size;
    let mut dptr = s.dest.len;

    check_ws_exceeded(js, &mut s.num_spaces);

    if dptr < dend {
        out[dptr] = c as u8;
        dptr += 1;
    }
    s.dest.len = dptr - dstart;
}

fn write_jsnorm(s: &mut JsnormState, copy_buf: &[u8], copy_len: usize, js: &mut JsState, out: &mut [u8]) {
    let ptr = 0usize;
    let end = copy_len;

    let dstart = 0usize;
    let dend = s.dest.size;
    let mut dptr = s.dest.len;

    check_ws_exceeded(js, &mut s.num_spaces);

    if ptr < end {
        let mut copy_len = copy_len;
        let avail = dend - dptr;
        if avail < copy_len {
            copy_len = avail;
        }
        out[dptr..dptr + copy_len].copy_from_slice(&copy_buf[..copy_len]);
        dptr += copy_len;
    }

    s.dest.len = dptr - dstart;
}

fn jsnorm_exec(
    s: &mut JsnormState,
    a: u8,
    c: i32,
    src: &[u8],
    ptr: &mut usize,
    js: &mut JsState,
    dst: &mut [u8],
) -> i32 {
    let mut i_ret = RET_OK;
    let bcopied;
    // C allocates std::vector<char> decoded_out_vec(65535) on EVERY
    // exec call before the switch, whatever the action; allocation is
    // not transcript-observable, kept literal and local.
    let mut decoded = vec![0u8; 65535];

    let cur_ptr = s.dest.len;
    match a {
        JN_NOP => write_jsnorm_char(s, c, js, dst),
        JN_SAVE => {
            s.overwrite = Some(cur_ptr);
            write_jsnorm_char(s, c, js, dst);
        }
        JN_SPACE => {
            if s.prev_event != b' ' {
                write_jsnorm_char(s, c, js, dst);
            }
            s.num_spaces = s.num_spaces.wrapping_add(1);
        }
        JN_UNESCAPE => {
            if let Some(ow) = s.overwrite.filter(|ow| *ow < cur_ptr) {
                s.dest.len = ow;
            }
            let dl = decoded.len();
            bcopied = unescape_walk(src, ptr, &mut decoded, dl, js, s.unicode_map.as_deref());
            write_jsnorm(s, &decoded[..bcopied], bcopied, js, dst);
        }
        JN_SFCC => {
            if let Some(ow) = s.overwrite.filter(|ow| *ow < cur_ptr) {
                s.dest.len = ow;
            }
            let mut bc = 0usize;
            let dl = decoded.len();
            let umap = s.unicode_map.clone();
            string_from_char_code_decode(src, ptr, &mut decoded, dl, &mut bc, js, umap.as_deref());
            bcopied = bc;
            write_jsnorm(s, &decoded[..bcopied], bcopied, js, dst);
        }
        JN_QUIT => {
            i_ret = RET_QUIT;
            write_jsnorm_char(s, c, js, dst);
        }
        _ => {}
    }

    s.prev_event = c as u8;

    i_ret
}

fn jsnorm_scan_fsm(
    s: &mut JsnormState,
    c: i32,
    src: &[u8],
    ptr: &mut usize,
    js: &mut JsState,
    dst: &mut [u8],
) -> i32 {
    let mut c = c;
    if is_space_c(c as u8) {
        c = b' ' as i32;
        return jsnorm_exec(s, JN_SPACE, c, src, ptr, js, dst);
    }

    let uc = toupper_c(c as u8);

    let action;
    loop {
        let m = &javascript_norm()[s.fsm];
        if m.event == 0 || m.event == uc {
            s.fsm = m.r#match;
            action = m.action;
            break;
        }
        s.fsm = m.other;
    }

    jsnorm_exec(s, action, c, src, ptr, js, dst)
}

/// C snort::JSNormalizeDecode. `ptr` is the walk cursor (C is an
/// inout char**), `bytes_copied` the final dest length. Returns
/// RET_QUIT iff js is None (C's null-js contract; dest and
/// bytes_copied untouched).
pub fn js_normalize_decode(
    src: &[u8],
    srclen: usize,
    dst: &mut [u8],
    destlen: usize,
    ptr: &mut usize,
    bytes_copied: &mut i32,
    js_opt: Option<&mut JsState>,
    iis_unicode_map: Option<&[u8]>,
) -> i32 {
    let js = match js_opt {
        Some(j) => j,
        None => return RET_QUIT,
    };

    let end = srclen;
    let mut s = JsnormState {
        fsm: 0,
        prev_event: 0,
        num_spaces: 0,
        unicode_map: iis_unicode_map.map(<[u8]>::to_vec),
        overwrite: None,
        dest: Dbuf { size: destlen, len: 0 },
    };

    let mut i_ret = RET_OK;

    while *ptr < end {
        i_ret = jsnorm_scan_fsm(&mut s, src[*ptr] as i32, src, ptr, js, dst);
        if i_ret != RET_OK {
            break;
        }
        *ptr += 1;
    }

    if *ptr < end && i_ret == RET_QUIT {
        *ptr += 1;
    }

    *bytes_copied = i32::try_from(s.dest.len).unwrap_or(i32::MAX);

    RET_OK
}

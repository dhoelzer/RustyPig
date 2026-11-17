//! Whole-transcript replay of tools/filib_harness/vectors.txt against the
//! Rust FileInfo port (src/file_api/file_lib.rs). The C probe compiles the
//! ORIGINAL file_lib.cc verbatim — gate: its own 19 [file_info] Catch cases
//! (gate.txt: 19 cases / 334 assertions, all green). The transcript pins
//! the FileInfo surface A..E4: vocabulary sizes, serialize/deserialize
//! byte-for-byte, deserialize cap hardening, setter quirks (null-name
//! keeps the set flag, weak setters never set it, first-set-wins host),
//! sha_to_string, reset survival, and the copy/assign field discipline.
//!
//! Transcript lines after E4_KEEP_POLICY exercise FileContext through
//! harness witnesses (cache/service/flows/capture/trace/Detection) — that
//! surface stays a seam this row (plan rows 17p+); the harness's own
//! determinism (stable md5 across rebuilds) pins those lines.
use snort3::file_api::file_lib::*;

const VECTORS: &str = include_str!("../tools/filib_harness/vectors.txt");
const PATH_MAX: usize = 4096;

fn hexbuf(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn str_or(s: &[u8], max: usize) -> String {
    let mut r = String::new();
    for (i, &c) in s.iter().enumerate() {
        if i >= max {
            break;
        }
        if (0x20..0x7f).contains(&c) {
            r.push(c as char);
        } else {
            r.push_str(&format!("\\x{c:02x}"));
        }
    }
    r
}

/// crafted deserialize buffer per upstream test-18 put_* discipline
/// (mirrors probe.cc Buf)
#[derive(Default)]
struct Buf {
    v: Vec<u8>,
}
impl Buf {
    fn bytes(&mut self, b: &[u8]) {
        self.v.extend_from_slice(b);
    }
    fn zeros(&mut self, n: usize) {
        self.v.resize(self.v.len() + n, 0);
    }
    fn boolean(&mut self, b: bool) {
        self.v.push(u8::from(b));
    }
    fn strfield(&mut self, set: bool, declared: u32, payload: &[u8]) {
        self.boolean(set);
        if !set {
            return;
        }
        self.v.extend_from_slice(&declared.to_le_bytes());
        self.v.extend_from_slice(&payload[..declared as usize]);
    }
    #[allow(clippy::too_many_arguments)]
    fn fixed(
        &mut self,
        set_sha: bool,
        sha: &[u8],
        name: &[u8],
        name_set: bool,
        name_decl: u32,
        url: &[u8],
        url_set: bool,
        url_decl: u32,
        host: &[u8],
        host_set: bool,
        host_decl: u32,
    ) {
        self.boolean(set_sha);
        if set_sha {
            self.bytes(sha);
        }
        // verdict, file_size, direction, file_id, type, capture, sig, policy all zero
        self.zeros(4 + 8 + 4 + 8 + 4 + 4 + 4 + 4);
        self.strfield(name_set, name_decl, name);
        self.strfield(url_set, url_decl, url);
        self.strfield(host_set, host_decl, host);
        self.boolean(false);
        self.boolean(false);
        self.boolean(false);
        self.boolean(false);
    }
}

/// Reference SHA-256 (FIPS 180-4) pinning the transcript D1 line only.
/// The C probe runs the real OpenSSL EVP path (hashes.cc + libcrypto);
/// the Rust hash row gets its own ported helper later — the replay here
/// only needs the digest to match the transcript byte-for-byte.
fn sha256_ref(msg: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let rr = |x: u32, n: u32| x.rotate_right(n);
    let mut pad = msg.to_vec();
    pad.push(0x80);
    while pad.len() % 64 != 56 {
        pad.push(0);
    }
    pad.extend_from_slice(&(msg.len() as u64 * 8).to_be_bytes());
    let mut h = IV;
    for blk in pad.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in blk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for t in 16..64 {
            let s0 = rr(w[t - 15], 7) ^ rr(w[t - 15], 18) ^ (w[t - 15] >> 3);
            let s1 = rr(w[t - 2], 17) ^ rr(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for t in 0..64 {
            let s1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let s0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

struct Sub;
impl UserFileDataBase for Sub {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn filib_transcript_replay() {
    let mut got: Vec<String> = Vec::new();

    // ================= A: vocabulary sizes + statics =================
    got.push(format!(
        "A_SZ_BOOL={} SZ_VERDICT={} SZ_DIR={} SZ_CAPST={} SZ_SIGST={}",
        std::mem::size_of::<bool>(),
        4,
        4,
        4,
        4
    ));
    got.push(format!(
        "A_SZ_STATE={} SZ_FID={} SZ_TYPEID={} SZ_POLICY={} SZ_TIMEVAL={}",
        std::mem::size_of::<FileState>(),
        std::mem::size_of::<u64>(),
        std::mem::size_of::<u32>(),
        std::mem::size_of::<u32>(),
        std::mem::size_of::<TimeVal>()
    ));
    got.push(format!(
        "A_VNAMES={}|{}|{}|{}|{}|{}|{}|{}",
        VERDICT_NAME[0],
        VERDICT_NAME[1],
        VERDICT_NAME[2],
        VERDICT_NAME[3],
        VERDICT_NAME[4],
        VERDICT_NAME[5],
        VERDICT_NAME[6],
        VERDICT_NAME[7]
    ));
    got.push(format!(
        "A_ENUMS vU={vU} vL={vL} vS={vS} vB={vB} vR={vR} vP={vP} vSC={vSC} vM={vM} \
         dl={dl} du={du} pos={p0},{p1},{p2},{p3},{p4} cap={c0},{c1},{c2},{c3},{c4} \
         sig={s0},{s1},{s2},{s3} enc={e0},{e1}",
        vU = FILE_VERDICT_UNKNOWN,
        vL = FILE_VERDICT_LOG,
        vS = FILE_VERDICT_STOP,
        vB = FILE_VERDICT_BLOCK,
        vR = FILE_VERDICT_REJECT,
        vP = FILE_VERDICT_PENDING,
        vSC = FILE_VERDICT_STOP_CAPTURE,
        vM = FILE_VERDICT_MAX,
        dl = FILE_DOWNLOAD,
        du = FILE_UPLOAD,
        p0 = SNORT_FILE_POSITION_UNKNOWN,
        p1 = SNORT_FILE_START,
        p2 = SNORT_FILE_MIDDLE,
        p3 = SNORT_FILE_END,
        p4 = SNORT_FILE_FULL,
        c0 = FILE_CAPTURE_SUCCESS,
        c1 = FILE_CAPTURE_MIN,
        c2 = FILE_CAPTURE_MAX,
        c3 = FILE_CAPTURE_MEMCAP,
        c4 = FILE_CAPTURE_FAIL,
        s0 = FILE_SIG_PROCESSING,
        s1 = FILE_SIG_DEPTH_FAIL,
        s2 = FILE_SIG_FLUSH,
        s3 = FILE_SIG_DONE,
        e0 = SNORT_CHAR_ENCODING_ASCII,
        e1 = SNORT_CHAR_ENCODING_UTF_16LE,
    ));

    // ================= B: serialize / deserialize =================
    {
        let mut info = FileInfo::default();
        let n = info.get_serialized_size();
        got.push(format!("B0_SIZE={n}"));
        let mut buf = vec![0xABu8; n + 100];
        info.serialize(&mut buf, n);
        let intact = buf[n..n + 100].iter().all(|&b| b == 0xAB);
        got.push(format!("B0_BYTES={}", hexbuf(&buf[..n])));
        got.push(format!("B0_TAIL_AB={}", u8::from(intact)));
        let mut back = FileInfo::default();
        back.deserialize(&buf, n);
        got.push(format!(
            "B0_RT sizes_match={} name_set={} url_set={} host_set={} ftype={}",
            usize::from(back.get_serialized_size() == n),
            u8::from(back.is_file_name_set()),
            u8::from(back.is_url_set()),
            u8::from(back.is_host_set()),
            back.get_file_type()
        ));
    }
    {
        let mut info = FileInfo::default();
        info.set_file_id(12345);
        info.set_file_size(1000);
        info.set_file_direction(du_());
        let n = info.get_serialized_size();
        let mut buf = vec![0xABu8; n + 100];
        info.serialize(&mut buf, n);
        got.push(format!("B1_SIZE={n} BYTES={}", hexbuf(&buf[..n])));
        let mut back = FileInfo::default();
        back.deserialize(&buf, n);
        got.push(format!(
            "B1_RT fid={} size={} dir={}",
            back.get_file_id(),
            back.get_file_size(),
            back.get_file_direction()
        ));
    }
    {
        let mut info = FileInfo::default();
        info.set_file_name(Some(b"test_file.txt"), 13);
        info.set_url(Some(b"https://example.org/document.pdf"), 32);
        info.set_host(Some(b"example.org"), 11);
        let sha: [u8; 32] = std::array::from_fn(|i| i as u8);
        // FI::seed_sha equivalent (probe subclass over the protected field)
        info.sha256 = Some(sha);
        let n = info.get_serialized_size();
        let mut buf = vec![0xABu8; n + 8];
        info.serialize(&mut buf, n);
        got.push(format!("B2_SIZE={n} BYTES={}", hexbuf(&buf[..n])));
        let mut back = FileInfo::default();
        back.deserialize(&buf, n);
        let rsha = back.get_file_sig_sha256();
        got.push(format!(
            "B2_RT name={} url={} host={} shahex={}",
            String::from_utf8_lossy(back.get_file_name()),
            String::from_utf8_lossy(back.get_url()),
            String::from_utf8_lossy(back.get_host_name()),
            rsha.map(hexbuf_slice).unwrap_or_else(|| "(null)".into())
        ));
    }
    {
        // cap hardening on deserialize
        const URL_CAP: u32 = 4095;
        const HOST_CAP: u32 = 256;
        let mut b = Buf::default();
        let urlz = vec![b'z'; URL_CAP as usize + 2000];
        let hostz = vec![b'e'; 400];
        let namez = vec![b'c'; PATH_MAX + 100];
        b.fixed(
            false,
            &[],
            &namez,
            true,
            (PATH_MAX + 100) as u32,
            &urlz,
            true,
            URL_CAP + 2000,
            &hostz,
            true,
            400,
        );
        let mut info = FileInfo::default();
        info.deserialize(&b.v, b.v.len());
        got.push(format!(
            "B3_URLLEN={} HOSTLEN={} NAMELEN={}",
            info.get_url().len(),
            info.get_host_name().len(),
            info.get_file_name().len()
        ));
        let caps_ok = info.get_url().len() == URL_CAP as usize
            && info.get_host_name().len() == HOST_CAP as usize
            && info.get_file_name().len() == PATH_MAX;
        got.push(format!("B3_CAPS_OK={}", u8::from(caps_ok)));
    }
    {
        // string declared beyond buffer_len: url declared big, payload
        // only 4 bytes past the size field -> bail; url stays empty but
        // is_set flag TRUE (read_string consumed is_set first).
        let mut b = Buf::default();
        b.boolean(false);
        b.zeros(4 + 8 + 4 + 8 + 4 + 4 + 4 + 4);
        b.strfield(false, 0, b"");
        b.boolean(true); // url is_set
        b.bytes(&100000u32.to_le_bytes());
        b.bytes(b"abcd"); // far less than declared
        b.boolean(false); // host is_set
        b.boolean(false);
        b.boolean(false);
        b.boolean(false);
        b.boolean(false);
        let mut info = FileInfo::default();
        info.deserialize(&b.v, b.v.len());
        got.push(format!(
            "B4_URLLEN={} URL_SET={} HOSTSET={}",
            info.get_url().len(),
            u8::from(info.is_url_set()),
            u8::from(info.is_host_set())
        ));
        // every later field defaults after the bail
        got.push(format!(
            "B4_TAIL_PARTIAL={} SIG=0 CAP=0",
            u8::from(info.is_partial_download())
        ));
    }
    {
        // sha branch: is_sha256_set true with full 32B digest window
        let mut b2 = Buf::default();
        b2.boolean(true);
        b2.bytes(b"0123456789abcdef0123456789abcdef");
        b2.zeros(4 + 8 + 4 + 8 + 4 + 4 + 4 + 4);
        b2.strfield(false, 0, b"");
        b2.strfield(false, 0, b"");
        b2.strfield(false, 0, b"");
        b2.boolean(false);
        b2.boolean(false);
        b2.boolean(false);
        b2.boolean(false);
        let mut info = FileInfo::default();
        info.deserialize(&b2.v, b2.v.len());
        let s = info.get_file_sig_sha256();
        got.push(format!(
            "B5_SHA={}",
            s.map(hexbuf_slice).unwrap_or_else(|| "(null)".into())
        ));
        got.push(format!("B5_SIZE={}", info.get_serialized_size()));
    }

    // ================= C: setters / caps / flags =================
    {
        let mut a = FileInfo::default();
        a.set_url(Some(b"/var/tmp/test.pdf"), 17);
        got.push(format!(
            "C0_URL={} SET={}",
            String::from_utf8_lossy(a.get_url()),
            u8::from(a.is_url_set())
        ));
        a.unset_file_name();
        got.push(format!("C1_NAMESET={}", u8::from(a.is_file_name_set())));
        a.set_file_name(Some(b"x"), 1);
        a.unset_file_name();
        got.push(format!(
            "C2_NAMESET_AFTER_UNSET={} NAME={}",
            u8::from(a.is_file_name_set()),
            str_or(a.get_file_name(), 8)
        ));
        let mut b = FileInfo::default();
        b.set_file_name(None, 5);
        got.push(format!(
            "C3_NULL_NAME SET={} EMPTY={}",
            u8::from(b.is_file_name_set()),
            u8::from(b.get_file_name().is_empty())
        ));
        let mut c = FileInfo::default();
        c.set_file_name(Some(b"real"), 4);
        c.set_weak_file_name(None, 3);
        got.push(format!(
            "C4_WEAK_NULL NAME={}",
            String::from_utf8_lossy(c.get_file_name())
        ));
        let mut d = FileInfo::default();
        d.set_weak_url(Some(b"u"), 1);
        got.push(format!(
            "C5_WEAK_URL URL={} SET={}",
            String::from_utf8_lossy(d.get_url()),
            u8::from(d.is_url_set())
        ));
        got.push(format!(
            "C5_WEAK_SIZE_HASURL={}",
            u8::from(d.get_serialized_size() > 0)
        ));
        let mut e = FileInfo::default();
        e.set_host(Some(b"first.com"), 9);
        e.set_host(Some(b"second.org"), 10);
        got.push(format!(
            "C6_HOST={}",
            String::from_utf8_lossy(e.get_host_name())
        ));
        let mut f = FileInfo::default();
        f.set_url(Some(&vec![b'a'; 4095 + 5000]), 4095 + 5000);
        got.push(format!(
            "C7_URLCAP len={} first16={}",
            f.get_url().len(),
            String::from_utf8_lossy(&f.get_url()[..16])
        ));
        let mut g = FileInfo::default();
        g.set_host(Some(&vec![b'h'; 256 + 5000]), 256 + 5000);
        let tail8: Vec<u8> = g.get_host_name()[248..].to_vec();
        got.push(format!(
            "C8_HOSTCAP len={} tail8={}",
            g.get_host_name().len(),
            String::from_utf8_lossy(&tail8)
        ));
        let mut h = FileInfo::default();
        h.set_file_name(Some(&vec![b'n'; PATH_MAX + 7]), (PATH_MAX + 7) as u32);
        got.push(format!("C9_NAMECAP len={}", h.get_file_name().len()));
        let mut i2 = FileInfo::default();
        i2.set_re_eval();
        got.push(format!("C10_REEVAL={}", u8::from(i2.has_to_re_eval())));
        i2.unset_re_eval();
        got.push(format!("C11_REEVAL={}", u8::from(i2.has_to_re_eval())));
        i2.set_partial_flag(true);
        got.push(format!("C12_PARTIAL={}", u8::from(i2.is_partial_download())));
        i2.verdict = FILE_VERDICT_BLOCK;
        i2.processing_complete = true;
        i2.set_extracted_size(77);
        i2.set_extracted_cutoff(true);
        i2.set_extracted_name(b"ext.bin");
        i2.reset();
        got.push(format!(
            "C13_AFTER_RESET v={} pc={} xsz={} cut={} exname={}",
            i2.verdict,
            u8::from(i2.processing_complete),
            i2.get_extracted_size(),
            u8::from(i2.get_extracted_cutoff()),
            u8::from(i2.get_extracted_name().is_empty())
        ));
        i2.set_file_type(60000);
        got.push(format!("C14_FTYPE={}", i2.get_file_type()));
    }

    // ================= D: sha_to_string + hashes =================
    {
        let a = FileInfo::default();
        let d: [u8; 32] = std::array::from_fn(|i| (0xA0 + i) as u8);
        let s = a.sha_to_string(&d);
        got.push(format!("D0_SHASTR={s} len={}", s.len()));
        let dig = sha256_ref(b"abc");
        got.push(format!("D1_SHA256ABC={}", hexbuf(&dig)));
        got.push(format!("D1_ABRSHASTR={}", a.sha_to_string(&dig)));
    }

    // ================= E: copy / assign =================
    {
        let mut src = FileInfo::default();
        src.set_file_name(Some(b"copy.bin"), 8);
        src.set_url(Some(b"/u"), 2);
        src.set_host(Some(b"h.io"), 4);
        src.set_file_id(9);
        src.set_file_size(55);
        src.set_file_direction(du_());
        src.verdict = FILE_VERDICT_STOP_CAPTURE;
        src.set_partial_flag(true);
        src.config_file_type(true);
        src.config_file_signature(true);
        src.config_file_capture(true);
        src.set_file_data(Some(Box::new(Sub)));
        src.pending_expire_time.tv_sec = 4242;
        src.pending_expire_time.tv_usec = 7;
        let d: [u8; 32] = std::array::from_fn(|i| i as u8);
        src.sha256 = Some(d);
        let mut dst = FileInfo::default();
        dst.copy(&src, true); // file_lib.h default clear_data = true
        got.push(format!(
            "E0_COPY name={} fid={} size={} dir={} v={} partial={} \
             ft={} fs={} fc={} ufd={} exp={}:{}",
            String::from_utf8_lossy(dst.get_file_name()),
            dst.get_file_id(),
            dst.get_file_size(),
            dst.get_file_direction(),
            dst.verdict,
            u8::from(dst.is_partial_download()),
            u8::from(dst.is_file_type_enabled()),
            u8::from(dst.is_file_signature_enabled()),
            u8::from(dst.is_file_capture_enabled()),
            u8::from(dst.get_file_data()),
            dst.pending_expire_time.tv_sec,
            dst.pending_expire_time.tv_usec
        ));
        let dsha = dst.get_file_sig_sha256();
        got.push(format!(
            "E1_SHA copied={} eq={}",
            u8::from(dsha.is_some()),
            u8::from(dsha.map(|s| *s == d).unwrap_or(false))
        ));
        let mut selfref = FileInfo::default();
        selfref.set_url(Some(b"keep"), 4);
        // C `selfref.copy(selfref)`: same-object guard. Raw pointer is
        // the only way to name the same allocation twice; no write
        // happens (the guard returns before any field assignment).
        let sp: *const FileInfo = &selfref;
        selfref.copy(unsafe { &*sp }, true);
        got.push(format!(
            "E2_SELFCOPY url={}",
            String::from_utf8_lossy(selfref.get_url())
        ));
        let mut asg = FileInfo::default();
        asg.assign(&src);
        // C `asg = asg;` self-assignment guard (same-object ptr::eq)
        let ap: *const FileInfo = &asg;
        asg.assign(unsafe { &*ap });
        got.push(format!(
            "E3_ASG fid={} url={}",
            asg.get_file_id(),
            String::from_utf8_lossy(asg.get_url())
        ));
        let mut keep = FileInfo::default();
        keep.set_policy_id(5);
        keep.copy(&src, false); // clear_data false: policy_id KEPT
        got.push(format!(
            "E4_KEEP_POLICY={}",
            u8::from(keep.is_file_type_enabled() && keep.get_policy_id() != 0)
        ));
    }

    // -------- compare against the C transcript (A..E4 section) --------
    let want: Vec<&str> = VECTORS.lines().collect();
    let e4_idx = want
        .iter()
        .position(|l| l.starts_with("E4_KEEP_POLICY"))
        .expect("E4 line present in transcript");
    assert_eq!(
        got.len(),
        e4_idx + 1,
        "replay line count must match the C transcript A..E4 section exactly"
    );
    for (i, g) in got.iter().enumerate() {
        assert_eq!(g, want[i], "transcript line {} mismatch", i + 1);
    }
}

fn hexbuf_slice(b: &[u8; 32]) -> String {
    hexbuf(b)
}

fn du_() -> u32 {
    FILE_UPLOAD
}

// -------------------------------------------------------------------
// Faithful translations of the upstream [file_info] gate semantics not
// fully covered by the A..E4 replay lines (the gate itself ran the
// verbatim C suite: 19 cases / 334 assertions).
// -------------------------------------------------------------------

#[test]
fn reset_keeps_identity_and_extracted_fields() {
    // gate case "reset" + C13: after verdict/complete/sha reset, the
    // name, size, policy id and extracted* fields all survive.
    let mut info = FileInfo::default();
    info.set_file_name(Some(b"keep.bin"), 8);
    info.set_file_size(1234);
    info.set_policy_id(3);
    info.set_extracted_size(99);
    info.sha256 = Some([7u8; 32]);
    info.file_state.sig_state = FILE_SIG_DONE;
    info.verdict = FILE_VERDICT_BLOCK;
    info.processing_complete = true;
    info.reset();
    assert_eq!(info.verdict, FILE_VERDICT_UNKNOWN);
    assert!(!info.processing_complete);
    assert!(info.sha256.is_none());
    // reset_sha flipped sig_state because a digest existed
    assert_eq!(info.file_state.sig_state, FILE_SIG_PROCESSING);
    assert_eq!(info.get_file_name(), b"keep.bin");
    assert_eq!(info.get_file_size(), 1234);
    assert_eq!(info.get_policy_id(), 3);
    assert_eq!(info.get_extracted_size(), 99);
    assert_eq!(
        info.pending_expire_time,
        TimeVal { tv_sec: 0, tv_usec: 0 }
    );
}

#[test]
fn reset_sha_without_digest_is_a_noop() {
    // F2 tail: reset() with sha256 null leaves sig_state untouched.
    let mut info = FileInfo {
        file_state: FileState {
            capture_state: FILE_CAPTURE_SUCCESS,
            sig_state: FILE_SIG_FLUSH,
        },
        ..FileInfo::default()
    };
    info.reset();
    assert_eq!(info.file_state.sig_state, FILE_SIG_FLUSH);
}

#[test]
fn copy_keeps_dst_sha_when_src_has_none() {
    // gate copy case: sha256 only copied when the src has one.
    let mut dst = FileInfo {
        sha256: Some([5u8; 32]),
        ..FileInfo::default()
    };
    let src = FileInfo::default();
    dst.copy(&src, true);
    assert_eq!(dst.sha256, Some([5u8; 32]));
}

#[test]
fn get_character_encoding_bom_gate() {
    // file_api.h inline: only the exact FF FE prefix flips the encoding.
    assert_eq!(get_character_encoding(b"\xff\xfename", 6), SNORT_CHAR_ENCODING_UTF_16LE);
    assert_eq!(get_character_encoding(b"\xfe\xffname", 6), SNORT_CHAR_ENCODING_ASCII);
    assert_eq!(get_character_encoding(b"\xff", 1), SNORT_CHAR_ENCODING_ASCII);
    assert_eq!(get_character_encoding(b"", 0), SNORT_CHAR_ENCODING_ASCII);
}

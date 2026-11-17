// probe.cc — ground-truth transcript for file_api/file_lib.cc (row 17o).
// Everything deterministic: fake clock via clock_gettime interposition
// (stubs.cc), fixed inputs, no random. FileConfig/FileIdentifier/
// FileCapture/FileStats/FileSegments are REAL bodies; cache/service/
// flows managers are witnesses that print every reach.
//
// Harness printf hygiene: mutating calls are hoisted into locals before
// any printf.
#include "file_api/file_lib.h"
#include "file_api/file_api.h"
#include "file_api/file_cache.h"
#include "file_api/file_capture.h"
#include "file_api/file_config.h"
#include "file_api/file_identifier.h"
#include "file_api/file_service.h"
#include "file_api/file_stats.h"
#include "hash/hashes.h"
#include "protocols/packet.h"
#include "utils/util.h"

// defined in stubs.cc (witness bodies TU)
snort::FilePolicyBase* stub_file_policy();

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace snort;

// stubs.cc setters / helpers (extern "C")
extern "C" void filib_set_fake_now(double t);
extern "C" void filib_enable_fake_clock(int on);
extern "C" void filib_set_file_trace(int on, int level);
extern "C" void filib_set_cached_verdict(int v);
extern "C" void filib_set_file_inspector(int on);
extern "C" void filib_set_adv_pub_id(unsigned id);
extern "C" void filib_set_policy_verdicts(int type_v, int sig_v);
extern "C" void filib_release_stub_policy();
extern "C" void filib_set_next_packet(Packet* p);
extern "C" void filib_set_file_cache(FileCache* c);
extern "C" int filib_fp_eval_calls();
extern "C" int filib_apply_verdict_calls();
extern "C" void filib_set_pt_active(int on);
extern "C" int filib_pt_active();

// ------------------------------------------------------------------
// FI: subclass exposing the protected surface (probe builds sha256
// through new[]/delete[] like production serialize/deserialize).
// ------------------------------------------------------------------
struct FI : public FileInfo
{
    FI() = default;
    void seed_sha(const uint8_t* d)
    {
        if (!sha256) sha256 = new uint8_t[SHA256_HASH_SIZE];
        memcpy(sha256, d, SHA256_HASH_SIZE);
    }
};

static std::string hexbuf(const char* b, size_t n)
{
    std::string s;
    char x[3];
    for (size_t i = 0; i < n; i++) { std::snprintf(x, sizeof x, "%02x", (unsigned char)b[i]); s += x; }
    return s;
}

static std::string str_or(const std::string& s, size_t max)
{
    std::string r;
    for (size_t i = 0; i < s.size() && i < max; i++)
    {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c < 0x7f) r += (char)c;
        else { char x[8]; std::snprintf(x, sizeof x, "\\x%02x", c); r += x; }
    }
    return r;
}

// crafted deserialize buffer per upstream test-18 put_* discipline
struct Buf {
    std::vector<char> v;
    void bytes(const void* p, size_t n) { const char* c = (const char*)p; v.insert(v.end(), c, c+n); }
    void zeros(size_t n) { v.insert(v.end(), n, '\0'); }
    void boolean(bool b) { char x = b ? 1 : 0; bytes(&x, 1); }
    void strfield(bool set, uint32_t declared, const std::string& payload)
    {
        boolean(set);
        if (!set) return;
        bytes(&declared, 4);
        v.insert(v.end(), payload.begin(), payload.begin() + declared);
    }
    void fixed(bool set_sha_or_set, const std::vector<uint8_t>& sha,
               const std::string& name, bool name_set, uint32_t name_decl,
               const std::string& url, bool url_set, uint32_t url_decl,
               const std::string& host, bool host_set, uint32_t host_decl)
    {
        boolean(set_sha_or_set);
        if (set_sha_or_set) bytes(sha.data(), sha.size());
        // verdict, file_size, direction, file_id, type, capture, sig, policy all zero
        zeros(4 + 8 + 4 + 8 + 4 + 4 + 4 + 4);
        strfield(name_set, name_decl, name);
        strfield(url_set, url_decl, url);
        strfield(host_set, host_decl, host);
        boolean(false); boolean(false); boolean(false); boolean(false);
    }
};

int main()
{
    filib_enable_fake_clock(1);
    file_stats_init();   // real body (file_stats.cc): callocs the THREAD_LOCAL
    filib_set_fake_now(100.0);
    filib_set_adv_pub_id(7);

    // ================= A: vocabulary sizes + statics =================
    std::printf("A_SZ_BOOL=%zu SZ_VERDICT=%zu SZ_DIR=%zu SZ_CAPST=%zu SZ_SIGST=%zu\n",
        sizeof(bool), sizeof(FileVerdict), sizeof(FileDirection),
        sizeof(FileCaptureState), sizeof(FileSigState));
    std::printf("A_SZ_STATE=%zu SZ_FID=%zu SZ_TYPEID=%zu SZ_POLICY=%zu SZ_TIMEVAL=%zu\n",
        sizeof(FileState), sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(struct timeval));
    std::printf("A_VNAMES=%s|%s|%s|%s|%s|%s|%s|%s\n",
        VerdictName[0].c_str(), VerdictName[1].c_str(), VerdictName[2].c_str(),
        VerdictName[3].c_str(), VerdictName[4].c_str(), VerdictName[5].c_str(),
        VerdictName[6].c_str(), VerdictName[7].c_str());
    std::printf("A_ENUMS vU=%d vL=%d vS=%d vB=%d vR=%d vP=%d vSC=%d vM=%d dl=%d du=%d "
        "pos=%d,%d,%d,%d,%d cap=%d,%d,%d,%d,%d "
        "sig=%d,%d,%d,%d enc=%d,%d\n",
        (int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_LOG, (int)FILE_VERDICT_STOP,
        (int)FILE_VERDICT_BLOCK, (int)FILE_VERDICT_REJECT, (int)FILE_VERDICT_PENDING,
        (int)FILE_VERDICT_STOP_CAPTURE, (int)FILE_VERDICT_MAX,
        (int)FILE_DOWNLOAD, (int)FILE_UPLOAD,
        (int)SNORT_FILE_POSITION_UNKNOWN, (int)SNORT_FILE_START, (int)SNORT_FILE_MIDDLE,
        (int)SNORT_FILE_END, (int)SNORT_FILE_FULL,
        (int)FILE_CAPTURE_SUCCESS, (int)FILE_CAPTURE_MIN, (int)FILE_CAPTURE_MAX,
        (int)FILE_CAPTURE_MEMCAP, (int)FILE_CAPTURE_FAIL,
        (int)FILE_SIG_PROCESSING, (int)FILE_SIG_DEPTH_FAIL, (int)FILE_SIG_FLUSH, (int)FILE_SIG_DONE,
        (int)SNORT_CHAR_ENCODING_ASCII, (int)SNORT_CHAR_ENCODING_UTF_16LE);

    // ================= B: serialize / deserialize on FileInfo =================
    {
        FI info;
        size_t n = info.get_serialized_size();
        std::printf("B0_SIZE=%zu\n", n);
        std::vector<char> buf(n + 100, (char)0xAB);
        info.serialize(buf.data(), (uint16_t)n);
        std::string after = hexbuf(buf.data() + n, 100);
        bool intact = true;
        for (size_t i = 0; i < 100; i++) if (buf[n+i] != (char)0xAB) intact = false;
        std::printf("B0_BYTES=%s\n", hexbuf(buf.data(), n).c_str());
        std::printf("B0_TAIL_AB=%d\n", (int)intact);
        (void)after;
        // deserialize what serialize wrote (sha branch off)
        FI back;
        back.deserialize(buf.data(), (uint16_t)n);
        std::printf("B0_RT sizes_match=%d name_set=%d url_set=%d host_set=%d ftype=%u\n",
            back.get_serialized_size() == n ? 1 : 0,
            back.is_file_name_set() ? 1 : 0, back.is_url_set() ? 1 : 0,
            back.is_host_set() ? 1 : 0, back.get_file_type());
    }
    {
        FI info;
        info.set_file_id(12345); info.set_file_size(1000); info.set_file_direction(FILE_UPLOAD);
        size_t n = info.get_serialized_size();
        std::vector<char> buf(n + 100, (char)0xAB);
        info.serialize(buf.data(), (uint16_t)n);
        std::printf("B1_SIZE=%zu BYTES=%s\n", n, hexbuf(buf.data(), n).c_str());
        FI back;
        back.deserialize(buf.data(), (uint16_t)n);
        std::printf("B1_RT fid=%llu size=%llu dir=%d\n",
            (unsigned long long)back.get_file_id(), (unsigned long long)back.get_file_size(),
            (int)back.get_file_direction());
    }
    {
        FI info;
        info.set_file_name("test_file.txt", 13);
        info.set_url("https://example.org/document.pdf", 32);
        info.set_host("example.org", 11);
        uint8_t sha[SHA256_HASH_SIZE];
        for (int i = 0; i < SHA256_HASH_SIZE; i++) sha[i] = (uint8_t)i;
        info.seed_sha(sha);
        size_t n = info.get_serialized_size();
        std::vector<char> buf(n + 8, (char)0xAB);
        info.serialize(buf.data(), (uint16_t)n);
        std::printf("B2_SIZE=%zu BYTES=%s\n", n, hexbuf(buf.data(), n).c_str());
        FI back;
        back.deserialize(buf.data(), (uint16_t)n);
        const uint8_t* rsha = back.get_file_sig_sha256();
        std::printf("B2_RT name=%s url=%s host=%s shahex=%s\n",
            str_or(back.get_file_name(), 64).c_str(), str_or(back.get_url(), 64).c_str(),
            str_or(back.get_host_name(), 64).c_str(),
            rsha ? hexbuf((const char*)rsha, SHA256_HASH_SIZE).c_str() : "(null)");
    }
    {
        // cap hardening on deserialize: url declared 6095 inside buffer,
        // host declared 400, file_name declared PATH_MAX+100
        constexpr uint32_t URL_CAP = 4095, HOST_CAP = 256;
        Buf b;
        std::string urlz((size_t)URL_CAP + 2000, 'z');
        std::string hostz(400, 'e');
        std::string namez(PATH_MAX + 100, 'c');
        b.fixed(false, {}, namez, true, PATH_MAX + 100, urlz, true, URL_CAP + 2000, hostz, true, 400);
        FI info;
        info.deserialize(b.v.data(), (uint16_t)b.v.size());
        std::printf("B3_URLLEN=%zu HOSTLEN=%zu NAMELEN=%zu\n",
            info.get_url().size(), info.get_host_name().size(), info.get_file_name().size());
        bool caps_ok = info.get_url().size() == URL_CAP && info.get_host_name().size() == HOST_CAP
                       && info.get_file_name().size() == (size_t)PATH_MAX;
        std::printf("B3_CAPS_OK=%d\n", caps_ok ? 1 : 0);
        (void)URL_CAP; (void)HOST_CAP;
    }
    {
        // string declared beyond buffer_len: url declared big, payload
        // only 4 bytes past the size field -> bail, url stays empty but
        // is_set flag TRUE (read_string consumed is_set first).
        Buf b;
        b.boolean(false); b.zeros(4 + 8 + 4 + 8 + 4 + 4 + 4 + 4);
        b.strfield(false, 0, "");
        b.boolean(true);                      // url is_set
        uint32_t big = 100000;
        b.bytes(&big, 4);
        b.bytes("abcd", 4);                   // far less than big
        b.boolean(false);                     // host is_set
        b.boolean(false); b.boolean(false); b.boolean(false); b.boolean(false);
        FI info;
        info.deserialize(b.v.data(), (uint16_t)b.v.size());
        std::printf("B4_URLLEN=%zu URL_SET=%d HOSTSET=%d\n",
            info.get_url().size(), info.is_url_set() ? 1 : 0, info.is_host_set() ? 1 : 0);
        // every later field defaults after the bail
        std::printf("B4_TAIL_PARTIAL=%d SIG=%d CAP=%d\n",
            info.is_partial_download() ? 1 : 0, 0, 0);
    }
    {
        // sha branch: is_sha256_set true but buffer shorter than the
        // 32B digest room check (offset < buffer_len gate)
        Buf b;
        b.boolean(true);                      // is_sha256_set = 1
        b.zeros(3);                           // not enough for 32B digest
        // deserialize reads is_sha256_set then skips sha block, then
        // reads the fixed block at offset 1 -> buffer too short: AVOID,
        // craft full fixed block but short sha window instead:
        Buf b2;
        b2.boolean(true);
        b2.bytes("0123456789abcdef0123456789abcdef", 32);
        b2.zeros(4 + 8 + 4 + 8 + 4 + 4 + 4 + 4);
        b2.strfield(false, 0, "");
        b2.strfield(false, 0, "");
        b2.strfield(false, 0, "");
        b2.boolean(false); b2.boolean(false); b2.boolean(false); b2.boolean(false);
        FI info;
        info.deserialize(b2.v.data(), (uint16_t)b2.v.size());
        const uint8_t* s = info.get_file_sig_sha256();
        std::printf("B5_SHA=%s\n", s ? hexbuf((const char*)s, 32).c_str() : "(null)");
        std::printf("B5_SIZE=%zu\n", info.get_serialized_size());
        (void)b;
    }

    // ================= C: setters / caps / flags =================
    {
        FI a;
        a.set_url("/var/tmp/test.pdf", 17);
        std::printf("C0_URL=%s SET=%d\n", a.get_url().c_str(), a.is_url_set() ? 1 : 0);
        a.unset_file_name();
        std::printf("C1_NAMESET=%d\n", a.is_file_name_set() ? 1 : 0);
        a.set_file_name("x", 1);
        a.unset_file_name();
        std::printf("C2_NAMESET_AFTER_UNSET=%d NAME=%s\n", a.is_file_name_set() ? 1 : 0,
            str_or(a.get_file_name(), 8).c_str());
        FI b;  b.set_file_name(nullptr, 5);
        std::printf("C3_NULL_NAME SET=%d EMPTY=%d\n", b.is_file_name_set() ? 1 : 0,
            b.get_file_name().empty() ? 1 : 0);
        FI c;  c.set_file_name("real", 4); c.set_weak_file_name(nullptr, 3);
        std::printf("C4_WEAK_NULL NAME=%s\n", c.get_file_name().c_str());
        FI d;  d.set_weak_url("u", 1);
        std::printf("C5_WEAK_URL URL=%s SET=%d\n", d.get_url().c_str(), d.is_url_set() ? 1 : 0);
        std::printf("C5_WEAK_SIZE_HASURL=%d\n", d.get_serialized_size() > 0 ? 1 : 0);
        FI e;  e.set_host("first.com", 9); e.set_host("second.org", 10);
        std::printf("C6_HOST=%s\n", e.get_host_name().c_str());
        FI f;  f.set_url(std::string(4095 + 5000, 'a').c_str(), 4095 + 5000);
        std::printf("C7_URLCAP len=%zu first16=%s\n", f.get_url().size(),
            f.get_url().substr(0, 16).c_str());
        FI g;  g.set_host(std::string(256 + 5000, 'h').c_str(), 256 + 5000);
        std::printf("C8_HOSTCAP len=%zu tail8=%s\n", g.get_host_name().size(),
            g.get_host_name().substr(248).c_str());
        FI h;  h.set_file_name(std::string(PATH_MAX + 7, 'n').c_str(), PATH_MAX + 7);
        std::printf("C9_NAMECAP len=%zu\n", h.get_file_name().size());
        FI i2; i2.set_re_eval();
        std::printf("C10_REEVAL=%d\n", i2.has_to_re_eval() ? 1 : 0);
        i2.unset_re_eval();
        std::printf("C11_REEVAL=%d\n", i2.has_to_re_eval() ? 1 : 0);
        i2.set_partial_flag(true);
        std::printf("C12_PARTIAL=%d\n", i2.is_partial_download() ? 1 : 0);
        i2.verdict = FILE_VERDICT_BLOCK; i2.processing_complete = true;
        i2.set_extracted_size(77); i2.set_extracted_cutoff(true); i2.set_extracted_name("ext.bin");
        i2.reset();
        std::printf("C13_AFTER_RESET v=%d pc=%d xsz=%lld cut=%d exname=%d\n",
            (int)i2.verdict, i2.processing_complete ? 1 : 0,
            (long long)i2.get_extracted_size(), i2.get_extracted_cutoff() ? 1 : 0,
            i2.get_extracted_name().empty() ? 1 : 0);
        i2.set_file_type(60000);
        std::printf("C14_FTYPE=%u\n", i2.get_file_type());
    }

    // ================= D: sha_to_string + hashes =================
    {
        FI a;
        uint8_t d[SHA256_HASH_SIZE];
        for (int i = 0; i < 32; i++) d[i] = (uint8_t)(0xA0 + i);
        std::string s = a.sha_to_string(d);
        std::printf("D0_SHASTR=%s len=%zu\n", s.c_str(), s.size());
        uint8_t dig[SHA256_HASH_SIZE] = {};
        sha256((const unsigned char*)"abc", 3, dig);
        std::printf("D1_SHA256ABC=%s\n", hexbuf((const char*)dig, 32).c_str());
        std::printf("D1_ABRSHASTR=%s\n", a.sha_to_string(dig).c_str());
    }

    // ================= E: copy / assign =================
    {
        FI src;
        src.set_file_name("copy.bin", 8); src.set_url("/u", 2); src.set_host("h.io", 4);
        src.set_file_id(9); src.set_file_size(55); src.set_file_direction(FILE_UPLOAD);
        src.verdict = FILE_VERDICT_STOP_CAPTURE; src.set_partial_flag(true);
        src.config_file_type(true); src.config_file_signature(true); src.config_file_capture(true);
        struct Sub : UserFileDataBase { };
        Sub* ufd = new Sub();
        src.set_file_data(ufd);
        src.pending_expire_time.tv_sec = 4242; src.pending_expire_time.tv_usec = 7;
        uint8_t d[32]; for (int i = 0; i < 32; i++) d[i] = (uint8_t)i;
        src.seed_sha(d);
        FI dst;
        dst.copy(src);       // clear_data = true
        std::printf("E0_COPY name=%s fid=%llu size=%llu dir=%d v=%d partial=%d "
            "ft=%d fs=%d fc=%d ufd=%d exp=%ld:%ld\n",
            dst.get_file_name().c_str(), (unsigned long long)dst.get_file_id(),
            (unsigned long long)dst.get_file_size(), (int)dst.get_file_direction(),
            (int)dst.verdict, dst.is_partial_download() ? 1 : 0,
            dst.is_file_type_enabled() ? 1 : 0, dst.is_file_signature_enabled() ? 1 : 0,
            dst.is_file_capture_enabled() ? 1 : 0, dst.get_file_data() ? 1 : 0,
            (long)dst.pending_expire_time.tv_sec, (long)dst.pending_expire_time.tv_usec);
        const uint8_t* dsha = dst.get_file_sig_sha256();
        std::printf("E1_SHA copied=%d eq=%d\n", dsha ? 1 : 0,
            dsha && memcmp(dsha, d, 32) == 0 ? 1 : 0);
        FI selfref; selfref.set_url("keep", 4);
        selfref.copy(selfref);
        std::printf("E2_SELFCOPY url=%s\n", selfref.get_url().c_str());
        FI asg; asg = src; asg = asg;   // assignment + self-assign guard
        std::printf("E3_ASG fid=%llu url=%s\n", (unsigned long long)asg.get_file_id(),
            asg.get_url().c_str());
        FI keep;
        keep.set_policy_id(5);
        keep.copy(src, false);   // clear_data false: policy_id KEPT
        std::printf("E4_KEEP_POLICY=%u\n", keep.is_file_type_enabled() && keep.get_policy_id());
    }

    // ================= F: FileContext lifecycle (inspector seam) =================
    filib_set_file_trace(1, 7);   // all FILE_DEBUG levels enabled
    {
        FileContext f0;  // inspector seam off: config null (ctor prints IMGR)
        std::printf("F0_MIME_EMPTY=%d SIZE=%llu\n", std::string(f0.get_mime_type()).empty() ? 1 : 0,
            (unsigned long long)f0.get_file_size());
        const char* fn = f0.get_UTF8_fname(nullptr);   // non-UTF16 -> null
        (void)fn;
    }
    filib_set_file_inspector(1);
    {
        FileContext ctx;   // inspector arm: config = g_stub_file_config (real defaults)
        FileConfig* cfg = get_file_config();
        std::printf("F1_CFG=%d sigdepth=%lld typedepth=%lld\n", cfg ? 1 : 0,
            (long long)cfg->file_signature_depth, (long long)cfg->file_type_depth);
        FileMeta m(42, "pdf", "cat", "v1", {});
        cfg->process_file_rule(m);
        std::printf("F2_MIME=%s\n", ctx.get_mime_type());
        ctx.set_file_type(42);
        std::printf("F2_MIME2=%s\n", ctx.get_mime_type());
        ctx.reset_sha();   // sha null -> no state change
        std::printf("F3_MAXCAP=%lld\n", (long long)ctx.get_max_file_capture_size());
        FileCapture* dest = nullptr;
        FileCaptureState st = ctx.reserve_file(dest);
        std::printf("F4_RESERVE_ST=%d DEST_NULL=%d RES_FAILS=%llu\n",
            (int)st, dest == nullptr ? 1 : 0,
            (unsigned long long)file_counts.file_reserve_failures);

        // --------- G: process matrix (all arms deterministic) ---------
        Packet* pkt = new Packet();
        snort::IpsContext* ips = new snort::IpsContext();
        pkt->context = ips;
        snort::Flow* flow = new snort::Flow();
        pkt->flow = flow;
        flow->service = "https";
        flow->session_flags = 0;   // one-way traffic (asymmetric flow branch)
        filib_set_next_packet(pkt);
        FilePolicyBase* policy = stub_file_policy();
        FileCache* cache = new FileCache(16);
        filib_set_file_cache(cache);
        FileConfig* gcfg = get_file_config();

        const uint8_t blob[] = { 'a','b','c','d' };          // sha256 pinned
        const uint8_t blob6[] = { 'X','M','A','G','I','C' };

        // G1: type+sig disabled -> early false + COMPLETE
        bool r = ctx.process(pkt, blob6, 6, SNORT_FILE_FULL, policy);
        std::printf("G1_R=%d COMPLETE=%d FSIZE=%llu DATA_TOT=%llu\n",
            r ? 1 : 0, ctx.processing_complete ? 1 : 0,
            (unsigned long long)ctx.get_file_size(),
            (unsigned long long)file_counts.file_data_total);

        // G2: cacheable, file_id=0 -> upstream gate: lookup bails -> miss
        FileContext g2;
        g2.config_file_type(true);
        g2.set_file_type(42);           // pre-known type: no magics needed
        filib_set_cached_verdict(FILE_VERDICT_LOG);
        filib_set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_UNKNOWN);
        bool r2 = g2.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        std::printf("G2_MISS MISSES=%llu HITS=%llu R=%d COMPLETE=%d v=%d\n",
            (unsigned long long)file_counts.file_cache_misses,
            (unsigned long long)file_counts.file_cache_hits,
            r2 ? 1 : 0, g2.processing_complete ? 1 : 0, (int)g2.verdict);

        // G3: same but file_id != 0 -> armed LOG verdict -> HIT arm
        g2.reset();
        g2.config_file_type(true);
        g2.set_file_type(42);
        g2.set_file_id(99);
        bool r3 = g2.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        std::printf("G3_HIT HITS=%llu R=%d COMPLETE=%d v=%d\n",
            (unsigned long long)file_counts.file_cache_hits,
            r3 ? 1 : 0, g2.processing_complete ? 1 : 0, (int)g2.verdict);

        // G4: sig-only FULL pass: real EVP sha256 chain, policy REJECT,
        //     witness apply_verdict mirrors real FileInfo::verdict assign,
        //     log_file_event publishes RESET + FILE_COMPLETE + advance log.
        filib_set_cached_verdict(FILE_VERDICT_UNKNOWN);
        filib_set_fake_now(100.25);
        FileContext g4;
        g4.config_file_signature(true);
        g4.set_not_cacheable();
        g4.set_file_id(7);
        g4.set_url("/dl/file.bin", 12);
        filib_set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_REJECT);
        bool r4 = g4.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        std::printf("G4_SIG R=%d SIGST=%d sha=%s v=%d sigproc=%llu APPLY=%d\n",
            r4 ? 1 : 0, (int)g4.get_file_state().sig_state,
            g4.get_file_sig_sha256() ? "set" : "none", (int)g4.verdict,
            (unsigned long long)file_stats->signatures_processed[0][0],
            filib_apply_verdict_calls());

        // G5: sig depth exceeded: configured 2 bytes, payload 4.
        int64_t saved_depth = gcfg->file_signature_depth;
        gcfg->file_signature_depth = 2;
        filib_set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_UNKNOWN);
        FileContext g5;
        g5.config_file_signature(true);
        g5.set_not_cacheable();
        bool r5 = g5.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        std::printf("G5_DEPTHFAIL R=%d SIGST=%d DEEP=%llu SHA_NULL=%d v=%d\n",
            r5 ? 1 : 0, (int)g5.get_file_state().sig_state,
            (unsigned long long)file_counts.file_sig_depth_exceeded,
            g5.get_file_sig_sha256() ? 0 : 1, (int)g5.verdict);
        // same limit, policy BLOCK on the depth-fail lookup -> apply arm
        filib_set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_BLOCK);
        FileContext g5b;
        g5b.config_file_signature(true);
        g5b.set_not_cacheable();
        bool r5b = g5b.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        std::printf("G5B_DEPTHBLOCK R=%d v=%d APPLY=%d\n",
            r5b ? 1 : 0, (int)g5b.verdict, filib_apply_verdict_calls());
        gcfg->file_signature_depth = saved_depth;

        // G6: sig+capture FULL blob -> capture inline (no buffering);
        // reserve with mempool NOT yet initialized -> MEMCAP arm (the
        // SUCCESS reserve arm lands in G13 with the pool armed).
        filib_set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_LOG);
        FileContext g6;
        g6.config_file_signature(true);
        g6.config_file_capture(true);
        g6.set_not_cacheable();
        g6.set_file_name("inl.bin", 7);
        bool r6 = g6.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        std::printf("G6_CAP R=%d CAPST=%d WITHIN=%llu v=%d CAPEN=%d\n",
            r6 ? 1 : 0, (int)g6.get_file_state().capture_state,
            (unsigned long long)file_counts.file_within_packet,
            (int)g6.verdict, g6.is_file_capture_enabled() ? 1 : 0);
        FileCapture* gdest = nullptr;
        FileCaptureState gst = g6.reserve_file(gdest);
        std::printf("G6B_RESERVE ST=%d DEST=%d XSZ=%lld CAPEN_AFTER=%d\n",
            (int)gst, gdest ? 1 : 0, (long long)g6.get_extracted_size(),
            g6.is_file_capture_enabled() ? 1 : 0);
        delete gdest;   // FileInfo handed ownership to gdest

        // G6c: streaming capture START/END: real buffer creation path
        FileContext g6c;
        g6c.config_file_signature(true);
        g6c.config_file_capture(true);
        g6c.set_not_cacheable();
        bool a1 = g6c.process(pkt, blob, 4, SNORT_FILE_START, policy);
        bool a2 = g6c.process(pkt, blob6, 6, SNORT_FILE_END, policy);
        std::printf("G6C_STREAM a1=%d a2=%d CAPST=%d BUFFERED=%llu SIZE=%llu v=%d\n",
            a1 ? 1 : 0, a2 ? 1 : 0, (int)g6c.get_file_state().capture_state,
            (unsigned long long)file_counts.files_buffered_total,
            (unsigned long long)g6c.get_file_size(), (int)g6c.verdict);

        // G7: segments overload: out-of-order drop (unknown file size),
        // then in-order FULL flows through.
        filib_set_policy_verdicts(FILE_VERDICT_LOG, FILE_VERDICT_UNKNOWN);
        FileContext g7;
        g7.config_file_type(true);
        g7.set_file_type(42);
        g7.set_not_cacheable();
        bool s1 = g7.process(pkt, blob, 4, 2, policy, SNORT_FILE_MIDDLE);
        std::printf("G7_OOO s1=%d CSIZE=%llu\n", s1 ? 1 : 0,
            (unsigned long long)g7.get_file_size());
        bool s2 = g7.process(pkt, blob, 4, 0, policy, SNORT_FILE_FULL);
        std::printf("G7_OK s2=%d SIZE=%llu COMPLETE=%d\n", s2 ? 1 : 0,
            (unsigned long long)g7.get_file_size(), g7.processing_complete ? 1 : 0);

        // G8: UTF-16LE name (BOM + ASCII + U+00E9) through real iconv in
        // print() + FileEvent::get_filename + direct get_UTF8_fname.
        FileContext g8;
        g8.config_file_type(true);
        g8.set_file_type(42);
        g8.set_not_cacheable();
        std::string nm;
        nm += '\xff'; nm += '\xfe';                          // UTF-16LE BOM
        const char* ascii = "report";
        for (const char* q = ascii; *q; q++) { nm += *q; nm += '\0'; }
        nm += '\xe9'; nm += '\x00';                          // U+00E9 -> c3 a9
        nm += '\xac'; nm += '\x20';                          // U+20AC -> e2 82 ac
        nm += '\x30'; nm += '\x04';                          // U+0430 -> d0 b0
        ascii = ".txt";
        for (const char* q = ascii; *q; q++) { nm += *q; nm += '\0'; }
        nm += '\x00'; nm += '\x00';                         // UTF-16 NUL term
        g8.set_file_name(nm.c_str(), (uint32_t)nm.size());
        std::string namebytes = g8.get_file_name();
        std::printf("G8_NAMEBYTES=%s\n", hexbuf(namebytes.data(), namebytes.size()).c_str());
        gcfg->trace_type = true;
        filib_set_fake_now(100.5);
        filib_set_policy_verdicts(FILE_VERDICT_LOG, FILE_VERDICT_UNKNOWN);
        bool r8 = g8.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        gcfg->trace_type = false;
        std::printf("G8_UTF16 R=%d COMPLETE=%d\n", r8 ? 1 : 0, g8.processing_complete ? 1 : 0);
        size_t uconv = 0;
        char* up = g8.get_UTF8_fname(&uconv);
        std::printf("G8_CONV=%s LEN=%zu\n", up ? hexbuf(up, uconv).c_str() : "(null)", uconv);
        snort_free(up);

        // G9: trace_stream on -> ASCII dump via print_file_data
        gcfg->trace_stream = true;
        FileContext g9;
        g9.config_file_type(true);
        g9.set_file_type(42);
        g9.set_not_cacheable();
        bool r9 = g9.process(pkt, (const uint8_t*)"AB\x00\x7fZ", 5, SNORT_FILE_FULL, policy);
        gcfg->trace_stream = false;
        std::printf("G9_DUMP R=%d FILESTOT=%llu\n", r9 ? 1 : 0,
            (unsigned long long)file_counts.files_total);

        // G10: unknown type path: type enabled, no preset -> real
        // process_file_type -> FileIdentifier empty trie -> UNKNOWN ->
        // "File: Type unknown" + type/sig config cleared + fp_eval witness
        // reached via the find_file_type_from_ips pseudo-packet arm.
        FileContext g10;
        g10.config_file_type(true);
        g10.set_not_cacheable();
        filib_set_policy_verdicts(FILE_VERDICT_LOG, FILE_VERDICT_UNKNOWN);
        bool r10 = g10.process(pkt, blob6, 6, SNORT_FILE_FULL, policy);
        std::printf("G10_UNKNOWN R=%d FTYPE=%u FPE=%d TYPEEN=%d SIGEN=%d COMPLETE=%d\n",
            r10 ? 1 : 0, g10.get_file_type(), filib_fp_eval_calls(),
            g10.is_file_type_enabled() ? 1 : 0, g10.is_file_signature_enabled() ? 1 : 0,
            g10.processing_complete ? 1 : 0);

        // G11: capture reserve MIN/MAX arms (state SUCCESS, size gates).
        int64_t saved_min = gcfg->capture_min_size, saved_max = gcfg->capture_max_size;
        gcfg->capture_min_size = 100;   // size 4 < min
        gcfg->capture_max_size = 1000;
        FileContext g11;
        g11.config_file_signature(true);
        g11.config_file_capture(true);
        g11.set_not_cacheable();
        bool r11 = g11.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        FileCapture* d11 = nullptr;
        FileCaptureState m11 = g11.reserve_file(d11);
        std::printf("G11_MIN R=%d ST=%d RESFAIL=%llu SZMIN=%d\n", r11 ? 1 : 0, (int)m11,
            (unsigned long long)file_counts.file_reserve_failures,
            (g11.verdict ? 1 : 0));
        gcfg->capture_min_size = 1;
        gcfg->capture_max_size = 2;     // size 4 > max
        FileContext g12;
        g12.config_file_signature(true);
        g12.config_file_capture(true);
        g12.set_not_cacheable();
        bool r12 = g12.process(pkt, blob, 4, SNORT_FILE_FULL, policy);
        FileCaptureState m12 = g12.reserve_file(d11);
        gcfg->capture_min_size = saved_min;
        gcfg->capture_max_size = saved_max;
        std::printf("G12_MAX R=%d ST=%d RESFAIL=%llu\n", r12 ? 1 : 0, (int)m12,
            (unsigned long long)file_counts.file_reserve_failures);

        // G13: mempool armed via the REAL FileCapture::init (1 MiB,
        // 512B blocks; writer thread idles since nothing async-stores):
        // streaming capture allocates through the real FileMemPool +
        // CircularBuffer; reserve SUCCESS path; drain via get_file_data;
        // dtor releases blocks back to the pool.
        FileCapture::init(1, 512);
        std::printf("G13_POOL MAX=%lld INUSE=%lld\n",
            (long long)FileCapture::get_buffers_max(),
            (long long)FileCapture::get_buffers_in_use());
        gcfg->capture_min_size = 1;
        gcfg->capture_max_size = 100000;
        FileContext g13;
        g13.config_file_signature(true);
        g13.config_file_capture(true);
        g13.set_not_cacheable();
        bool q1 = g13.process(pkt, blob, 4, SNORT_FILE_START, policy);
        std::printf("G13A a=%d CAPST=%d BUFFERED=%llu ALLOC=%llu INUSE=%lld USEDMAX=%llu\n",
            q1 ? 1 : 0, (int)g13.get_file_state().capture_state,
            (unsigned long long)file_counts.files_buffered_total,
            (unsigned long long)file_counts.file_buffers_allocated_total,
            (long long)FileCapture::get_buffers_in_use(),
            (unsigned long long)file_counts.file_buffers_used_max);
        bool q2 = g13.process(pkt, blob6, 6, SNORT_FILE_END, policy);
        FileCapture* d13 = nullptr;
        FileCaptureState st13 = g13.reserve_file(d13);
        std::printf("G13B b=%d ST=%d DEST=%d SZ=%llu CAPSZ=%lld CAPTOT=%llu INUSE=%lld\n",
            q2 ? 1 : 0, (int)st13, d13 ? 1 : 0,
            (unsigned long long)g13.get_file_size(),
            d13 ? (long long)d13->get_file_capture_size() : -1LL,
            (unsigned long long)file_counts.files_captured_total,
            (long long)FileCapture::get_buffers_in_use());
        // upstream recipe: call repeatedly until nullptr payload
        uint8_t* buf = nullptr;
        int blen = 0;
        if (d13)
        {
            while (true)
            {
                buf = nullptr; blen = 0;
                d13->get_file_data(&buf, &blen);   // advances current_block
                if (!buf) break;
                for (int i = 0; i < blen; i++) std::printf("%02x", buf[i]);
            }
        }
        std::printf("\nG13C DEST=%d INUSE=%lld MEMCAPFAILRES=%llu\n",
            d13 ? 1 : 0, (long long)FileCapture::get_buffers_in_use(),
            (unsigned long long)file_counts.file_memcap_failures_reserve);
        delete d13;
        std::printf("G13D INUSE=%lld RELTOT=%llu RELENR=%llu FREETOT=%llu\n",
            (long long)FileCapture::get_buffers_in_use(),
            (unsigned long long)file_counts.file_buffers_released_total,
            (unsigned long long)file_counts.file_buffers_release_errors,
            (unsigned long long)file_counts.files_released_total);
        FileCapture::exit();

        delete cache;
        filib_set_file_cache(nullptr);
    }
    filib_release_stub_policy();   // real ref-count protocol: 1 -> 0 -> delete
    return 0;
}

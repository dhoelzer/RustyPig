// probe.cc — ground-truth transcript for the file-policy TU row,
// file_api/file_policy.{h,cc} (row 17x). ZERO TEST_CASEs / ZERO UNIT_TEST
// (PLAN 1/2; re-asserted in build.sh): every oracle rides a labeled V-arm
// over the REAL file_policy.o per the PLAN 3.3 ladder: FileRule ctor/clear,
// the set/get flag pairs, add_file_id (sha table + enable trio + the
// cc:104 type_enabled quirk), load(), match_file_rule/match_file_signature,
// policy_check, type_lookup, the signature_lookup capture ladder
// (cc:187-:216 riding the REAL file_lib.o/file_capture(_probe).o bodies)
// and the verdict_delay PENDING arm (cc:157-:160).
// Heap posture (R1, stubs.cc:374-:375): every FilePolicy is HEAP-only,
// new'd through FilePolicyBase (real ctor ref=1, file_api.cc:28) and DRAINED
// via FilePolicyBase::delete_file_policy before exit so ~FilePolicyBase's
// LIVE assert(!ref_count) (file_api.cc:31, the __assert_fail U in the 17v
// nm pin) never fires at teardown. There is NO static g_file_policy (PLAN 0
// premise correction — nothing file-scope in the row TU).
// Witness posture (R5): the real T defs live in file_policy.o; the donor
// StubFilePolicy (stubs.cc:360-:370) is KEPT, never retired. The real-body
// arms dispatch through the same FilePolicyBase* seam and print the stub
// witness formats VERBATIM (stubs.cc:357 "POLICY type_lookup -> %d",
// :359 "POLICY signature_lookup -> %d") so the Rust twins replay the same
// lines off either impl. V10 drives the STUB itself over those formats.
// FIXACC 17x: build.sh:261 gained "/file_api/file_policy.h" (n=1 private at
// :82, assert-safe, PLAN R6) — access-only exposure of file_rules/file_shas/
// verdict_delay/default_rule + the match_* ladders for the readbacks.
// Ordering hygiene: mutating calls hoisted into locals before printf; no
// addresses (hygiene gate: no 0x[0-9a-f]{6,}); counts/enum ints/sizeof only.
#include "file_api/file_api.h"
#include "file_api/file_capture.h"
#include "file_api/file_lib.h"
#include "file_api/file_policy.h"
#include "file_api/file_service.h"
#include "hash/hashes.h"                     // SHA256_HASH_SIZE (hashes.h:28)

#include <cinttypes>
#include <cstdint>
#include <cstdio>

using namespace snort;

// donor stub seams (stubs.cc)
extern FilePolicyBase* stub_file_policy();                        // :373
extern "C" void fcache_set_policy_verdicts(int type_v, int sig_v); // :381
extern "C" unsigned fcache_stub_policy_refs();                     // :742
extern "C" void fcache_release_stub_policy();                      // :377
extern "C" void fcache_set_file_service(int on);                   // :731

// 32 raw bytes 01..20 as the hex the REAL cc:92-:97 stoi loop decodes
// (upstream config guarantees valid hex — PLAN R7 posture; vectors never
// arm junk hex).
static const char HEX32[] =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

static void arm_sha(FileInfo& f)
{
    // FIXACC-protected members (file_lib.h :129 block -> public in the
    // copy); the REAL ~FileInfo deletes[] the array (file_lib.cc:128-:130).
    f.sha256 = new uint8_t[SHA256_HASH_SIZE];
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
        f.sha256[i] = (uint8_t)(i + 1);
}

int main(void)
{
    // ---- V1: sizeof pins over the REAL headers + heap ctor ref posture.
    // FilePolicyBase = 16 (the frozen fapi PROBE_SIZEOF_FILE_POLICY_BASE
    // pin, :55); FileRule/FilePolicy sizes are NEW row lines (fapi PLAN:247:
    // no frozen oracle pins them — this vectors line is their home).
    FilePolicyBase* pol = new FilePolicy;          // real base ctor ref=1
    FilePolicy* fp = static_cast<FilePolicy*>(pol);
    unsigned v1_refs = pol->ref_count;             // FIXACC file_api.h read
    std::printf("V1_size base=%u rule=%u policy=%u refs=%u\n",
        (unsigned)sizeof(FilePolicyBase), (unsigned)sizeof(FileRule),
        (unsigned)sizeof(FilePolicy), v1_refs);

    // ---- V2: FileRule ctor (cc:44-:47 -> clear cc:34-:42) + the flag
    // pairs (cc:49-:79). Pin: the getters are MEMBER-only (PLAN 1: they do
    // NOT read FileService); the FileService static trio stays 0 through
    // the setters.
    {
        fcache_set_file_service(0);
        FileRule r;                                 // real default ctor
        std::printf("V2_rule tid=%u shaempty=%d verdict=%d t=%d s=%d c=%d\n",
            r.when.type_id, r.when.sha256.empty() ? 1 : 0,
            (int)r.use.verdict, r.use.type_enabled,
            r.use.signature_enabled, r.use.capture_enabled);
        fp->set_file_type(true);                    // cc:49
        fp->set_file_signature(true);               // cc:54
        fp->set_file_capture(false);                // cc:59
        int gt = fp->get_file_type();               // cc:64
        int gs = fp->get_file_signature();          // cc:70
        int gc = fp->get_file_capture();            // cc:76
        int st = FileService::is_file_type_id_enabled();
        int ss = FileService::is_file_signature_enabled();
        int sc = FileService::is_file_capture_enabled();
        std::printf("V2_getters t=%d s=%d c=%d svc t=%d s=%d c=%d\n",
            gt, gs, gc, st, ss, sc);
    }

    // ---- V3: add_file_id ladder (cc:81-:111): sha decode + table insert
    // (:85-:100) + the UNCONDITIONAL enable_file_type + type_enabled quirk
    // (cc:103-:104) + the conditional signature arm (cc:106-:107); capture
    // stays un-armed here (cc:109 guard false).
    {
        fcache_set_file_service(0);
        FilePolicyBase* p3b = new FilePolicy;
        FilePolicy* p3 = static_cast<FilePolicy*>(p3b);
        FileRule r;
        r.when.sha256 = HEX32;
        r.use.verdict = FILE_VERDICT_LOG;
        r.use.signature_enabled = true;
        p3->add_file_id(r);
        int n_rules = (int)p3->file_rules.size();
        int n_shas = (int)p3->file_shas.size();
        int te = p3->get_file_type();
        int st = FileService::is_file_type_id_enabled();
        int ss = FileService::is_file_signature_enabled();
        int sc = FileService::is_file_capture_enabled();
        std::printf("V3_add rules=%d shas=%d type_enabled=%d svc t=%d s=%d c=%d\n",
            n_rules, n_shas, te, st, ss, sc);
        FilePolicyBase::delete_file_policy(p3b);    // drain (R1)
    }

    // ---- V4: load() (cc:113-:130). a) capture-only: the OR-arm (:115)
    // stays false -> type static NOT lit; the R2-pinned REAL witness
    // cascade (file_service.cc:200-:204: enable_file_capture calls
    // enable_file_signature; replicated in stubs.cc:598) lights the
    // signature STATIC anyway -> member flag s=0 vs static s=1 DRIFT PIN.
    // b) signature-only: the cc:115 OR-arm fires -> type lit both sides.
    {
        fcache_set_file_service(0);
        FilePolicyBase* p4b = new FilePolicy;
        FilePolicy* p4 = static_cast<FilePolicy*>(p4b);
        p4->set_file_capture(true);
        p4->load();
        int dt = p4->default_rule.use.type_enabled;
        int ds = p4->default_rule.use.signature_enabled;
        int dc = p4->default_rule.use.capture_enabled;
        int st = FileService::is_file_type_id_enabled();
        int ss = FileService::is_file_signature_enabled();
        int sc = FileService::is_file_capture_enabled();
        std::printf("V4_load_cap def t=%d s=%d c=%d svc t=%d s=%d c=%d\n",
            dt, ds, dc, st, ss, sc);
        FilePolicyBase* p5b = new FilePolicy;
        FilePolicy* p5 = static_cast<FilePolicy*>(p5b);
        p5->set_file_signature(true);
        p5->load();
        std::printf("V4_load_sig def t=%d s=%d c=%d\n",
            p5->default_rule.use.type_enabled,
            p5->default_rule.use.signature_enabled,
            p5->default_rule.use.capture_enabled);
        FilePolicyBase::delete_file_policy(p4b);
        FilePolicyBase::delete_file_policy(p5b);
    }

    // ---- V5: match_file_rule ladder (cc:132-:145): a sha'd rule is
    // SKIPPED (:136-:137); type match (:139-:140) returns FIRST match;
    // wildcard type_id==0 catches; else default_rule (:144). Identity
    // readbacks against the FIXACC-exposed vector/default_rule slots.
    {
        FilePolicyBase* p6b = new FilePolicy;
        FilePolicy* p6 = static_cast<FilePolicy*>(p6b);
        FileRule r0;                                 // type 7 -> STOP
        r0.when.type_id = 7;
        r0.use.verdict = FILE_VERDICT_STOP;
        FileRule r1;                                 // sha'd -> skipped
        r1.when.sha256 = "ab";
        r1.when.type_id = 7;
        r1.use.verdict = FILE_VERDICT_BLOCK;
        FileRule r2;                                 // wildcard -> REJECT
        r2.use.verdict = FILE_VERDICT_REJECT;
        p6->add_file_id(r0);
        p6->add_file_id(r1);
        p6->add_file_id(r2);
        FileInfo f7; f7.set_file_type(7);
        FileInfo f9; f9.set_file_type(9);
        const FileRule& m7 = p6->match_file_rule(nullptr, &f7);
        const FileRule& m9 = p6->match_file_rule(nullptr, &f9);
        std::printf("V5_match typed=%d wildcard=%d first_rule=%d def=%d\n",
            (int)m7.use.verdict, (int)m9.use.verdict,
            (&m7 == &p6->file_rules[0]) ? 1 : 0,
            (&m9 == &p6->default_rule) ? 1 : 0);
        // all-sha'd policy -> default_rule return arm.
        FilePolicyBase* p7b = new FilePolicy;
        FilePolicy* p7 = static_cast<FilePolicy*>(p7b);
        FileRule r3; r3.when.sha256 = "ab"; r3.use.verdict = FILE_VERDICT_BLOCK;
        p7->add_file_id(r3);
        const FileRule& md = p7->match_file_rule(nullptr, &f7);
        std::printf("V5_def v=%d is_default=%d\n", (int)md.use.verdict,
            (&md == &p7->default_rule) ? 1 : 0);
        FilePolicyBase::delete_file_policy(p6b);
        FilePolicyBase::delete_file_policy(p7b);
    }

    // ---- V6: match_file_signature (cc:147-:168) driven through the
    // public signature_lookup seam with the rule capture OFF (straight to
    // cc:215) + the verdict_delay PENDING arm (cc:157-:160, decrements PER
    // CALL). Witness print formats VERBATIM (stubs.cc:359).
    {
        fcache_set_file_service(0);
        FilePolicyBase* p8b = new FilePolicy;
        FilePolicy* p8 = static_cast<FilePolicy*>(p8b);
        FileRule r; r.when.sha256 = HEX32; r.use.verdict = FILE_VERDICT_LOG;
        p8->add_file_id(r);
        p8->set_verdict_delay(2);                   // h:80 inline writer
        FileInfo fn;                                // sha null -> cc:150 miss
        FileVerdict v0 = p8->signature_lookup(nullptr, &fn);
        std::printf("POLICY signature_lookup -> %d\n", (int)v0);   // UNKNOWN
        FileInfo fh; arm_sha(fh);                   // 01..20 == table key
        FileVerdict v1 = p8->signature_lookup(nullptr, &fh);        // PENDING
        FileVerdict v2 = p8->signature_lookup(nullptr, &fh);        // PENDING
        FileVerdict v3 = p8->signature_lookup(nullptr, &fh);        // LOG
        std::printf("POLICY signature_lookup -> %d\n", (int)v1);
        std::printf("POLICY signature_lookup -> %d\n", (int)v2);
        std::printf("POLICY signature_lookup -> %d\n", (int)v3);
        int left = (int)p8->verdict_delay;
        FileInfo fm; arm_sha(fm);
        fm.sha256[0] ^= 0xFF;                       // key miss -> cc:167
        FileVerdict v4 = p8->signature_lookup(nullptr, &fm);
        std::printf("V6_delay left=%d miss=%d\n", left, (int)v4);
        FilePolicyBase::delete_file_policy(p8b);
    }

    // ---- V7: policy_check (cc:170-:177): the three FileInfo config_*
    // writers + the single-policy set_policy_id(0) quirk (:176).
    {
        FilePolicyBase* p9b = new FilePolicy;
        FilePolicy* p9 = static_cast<FilePolicy*>(p9b);
        p9->set_file_type(true);
        p9->set_file_capture(true);
        FileInfo f;
        p9->policy_check(nullptr, &f);              // REAL cc:170 body
        std::printf("V7_pcheck f t=%d s=%d c=%d pid=%u\n",
            f.file_type_enabled, f.file_signature_enabled,
            f.file_capture_enabled, f.get_policy_id());
        FilePolicyBase::delete_file_policy(p9b);
    }

    // ---- V8: type_lookup (cc:179-:185) via the FilePolicyBase* seam:
    // match + FileInfo re-arm (cc:182-:183) + verdict printed through the
    // VERBATIM stubs.cc:357 witness format.
    {
        FilePolicyBase* pab = new FilePolicy;
        FilePolicy* pa = static_cast<FilePolicy*>(pab);
        FileRule r; r.when.type_id = 7; r.use.verdict = FILE_VERDICT_STOP;
        r.use.signature_enabled = true; r.use.capture_enabled = true;
        pa->add_file_id(r);
        FileInfo f; f.set_file_type(7);
        FileVerdict v = pab->type_lookup(nullptr, &f);
        std::printf("POLICY type_lookup -> %d\n", (int)v);          // STOP 2
        std::printf("V8_rearm f s=%d c=%d\n",
            f.file_signature_enabled, f.file_capture_enabled);
        FilePolicyBase::delete_file_policy(pab);
    }

    // ---- V9: the signature_lookup capture ladder (cc:187-:216) over the
    // REAL file_lib.o FileInfo::reserve_file (:518-:532) + the UT-variant
    // file_capture_probe.o (the plain file_capture.o is EXCLUDED from the
    // probe link, R8 pobjs rule carried from the donor).
    // a) no file_capture armed -> FileInfo::reserve_file -> error_capture
    //    (FILE_CAPTURE_FAIL) -> cc:207-:208 delete-null arm -> match miss.
    // b) mempool armed (init_mempool; private, FIXACC file_capture.h) +
    //    file_size in [min,max] -> reserve SUCCESS (:443 new FileInfo copy)
    //    -> cc:197 store_file_async: the copy's sha256 is null (cc:570-:572)
    //    -> "" -> cc:199-:202 empty-name arm: set_extracted_size(0) +
    //    delete captured; FileInfo::reserve_file handed ownership off
    //    (file_capture -> nullptr) and re-armed config_file_capture(false)
    //    (:529) — both readouts pin.
    // c) sig_state FILE_SIG_DEPTH_FAIL -> FILE_VERDICT_LOG (cc:210-:212) —
    //    capture OFF on the RULE in this arm? NO: capture ON, reserve FAILS
    //    (no file_capture member) -> the fail arm still reaches the
    //    :210-:212 state check before the cc:215 fall-through.
    {
        fcache_set_file_service(0);
        FilePolicyBase* pbb = new FilePolicy;
        FilePolicy* pb = static_cast<FilePolicy*>(pbb);
        FileRule r; r.use.capture_enabled = true;
        r.use.verdict = FILE_VERDICT_BLOCK;
        pb->add_file_id(r);                          // cc:109 arms capture
        FileInfo fa;                                 // a) reserve FAILS
        FileVerdict va = pbb->signature_lookup(nullptr, &fa);
        std::printf("POLICY signature_lookup -> %d\n", (int)va);    // UNKNOWN
        FileCapture::init_mempool(1, 1024);         // private static seam; MB
                                                    // arg (cc:227): 1 MB cap
        FileInfo fb; fb.file_size = 100;
        fb.file_capture = new FileCapture(10, 1000); // real ctor cc:120-:129
        FileVerdict vb = pbb->signature_lookup(nullptr, &fb);        // b)
        std::printf("POLICY signature_lookup -> %d\n", (int)vb);    // UNKNOWN
        std::printf("V9b_extract size=%d cutoff=%d handed_off=%d fcapcfg=%d\n",
            (int)fb.extracted_size, fb.extracted_cutoff ? 1 : 0,
            fb.file_capture ? 1 : 0, fb.file_capture_enabled ? 1 : 0);
        FileInfo fc2; fc2.file_state.sig_state = FILE_SIG_DEPTH_FAIL;
        FileVerdict vc = pbb->signature_lookup(nullptr, &fc2);       // c)
        std::printf("POLICY signature_lookup -> %d\n", (int)vc);    // LOG 1
        FilePolicyBase::delete_file_policy(pbb);
    }

    // ---- V10: the donor StubFilePolicy over the SAME seam + formats —
    // the R5 KEEP decision proven: witness-armed verdicts replay through
    // the byte-VERBATIM stub lines (stubs.cc:357/:359) while the real
    // file_policy.o T defs stay un-collided. Identity arm: the real handle
    // and the stub are DIFFERENT objects (no same_store alias here).
    {
        fcache_set_policy_verdicts(FILE_VERDICT_BLOCK, FILE_VERDICT_PENDING);
        FilePolicyBase* sp = stub_file_policy();
        FilePolicyBase* rp = pol;                    // V1's real heap policy
        FileInfo f;
        FileVerdict sv = sp->signature_lookup(nullptr, &f);
        FileVerdict rt = sp->type_lookup(nullptr, &f);
        std::printf("POLICY signature_lookup -> %d\n", (int)sv);    // PENDING 5
        std::printf("POLICY type_lookup -> %d\n", (int)rt);         // BLOCK 3
        std::printf("V10_identity same=%d refs=%u\n",
            (sp == rp) ? 1 : 0, fcache_stub_policy_refs());
    }

    // ---- V-ref: the REAL ref protocol (file_api.cc:28-:43) on the V1
    // heap FilePolicy: add_ref 1->2, delete_file_policy 2->1 (no fire),
    // then the FINAL drain 1->0 fires the real delete: ~FilePolicy
    // (defaulted -> emitted in THIS TU, R3) chains ~FilePolicyBase whose
    // LIVE assert(!ref_count) holds — the heap-only drained posture.
    {
        pol->add_ref();
        unsigned r_after = pol->ref_count;
        FilePolicyBase::delete_file_policy(pol);     // 2 -> 1
        unsigned r_mid = pol->ref_count;
        FilePolicyBase::delete_file_policy(pol);     // 1 -> 0 -> real delete
        std::printf("V_ref add=%d mid=%d drained=1\n", r_after == 2, r_mid == 1);
    }

    // ---- release the donor stub policy LAST (fcache_release_stub_policy
    // -> delete_file_policy -> ref 1->0; same drain posture the frozen
    // twins ride; the stubs.cc:374-:375 heap rule makes it exit-safe).
    fcache_release_stub_policy();

    std::printf("FPOLICY_PROBE_DONE\n");
    return 0;
}

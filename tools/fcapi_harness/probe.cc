// probe.cc — ground-truth transcript for the shared-vocabulary + ref-protocol
// row, file_api/file_api.{h,cc} (row 17v). The TU has ZERO TEST_CASEs and ZERO
// #ifdef UNIT_TEST fragments (PLAN 2/4): every oracle rides here as a labeled
// vector arm (C/E/M/P/S/R, PLAN 7). 21 vector lines total (3 + 11 P + 1 S +
// 5 R + DONE).
//
// The .cc is ONLY the three FilePolicyBase ref-protocol bodies (cc:28-:43);
// the inline FilePosition helpers + get_character_encoding (h:174-:217) were
// NEVER gated upstream — probe vectors ARE their truth (PLAN 7 P/S blocks).
// The R ladder drives the REAL file_api.cc protocol (ctor ref=1; add_ref;
// delete_file_policy pre-decrement read-back cc:39; delete at ref 0 cc:40-:41
// with the LIVE ~FilePolicyBase assert(!ref_count) cc:32 — no -DNDEBUG).
//
// R1 (dtor assert posture): ProbePolicy is HEAP-allocated and fully drained
// (R_del0 proves drain to 0 before the deleting dtor runs). A static policy
// would SIGABRT at exit (donor stubs.cc:330-:332 hazard comment). The cc:38
// underflow assert is NOT probed — it aborts, panic-posture doc only.
// ProbePolicy is a FRESH local class overriding ALL FOUR virtuals — do NOT
// reuse donor StubFilePolicy (its teardown is entangled with fcache/fflows
// replay vectors; zero cross-wire rule, PLAN 7 R-block).
//
// ref_count is read directly thanks to the donor FIXACC private->public graft
// on the COPY's file_api.h (access-only; the arithmetic stays the REAL
// file_api.cc protocol — legitimized by fcache_stub_policy_refs precedent).
//
// Hygiene: mutating calls hoisted into locals before printf; flags print as
// 0/1, no addresses; %x for the macro words WITHOUT the 0x prefix so the
// vector hygiene gate (no 0x[0-9a-f]{6,}) stays green with allon=ffffffff.
// U-block (UserFileDataBase copy-path) NOT probed: the copy bodies DO NOT
// EXIST at fe29cbe — a probe that copies one fails to LINK by construction
// (grep evidence lives in PLAN 3/9-R4). U_ufd sz=8 rides the C line.
#include "file_api/file_api.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

// the header's enums live OUTSIDE namespace snort (opened h:116 AFTER them)
// -- unqualified names below, same shape as the scratch recon probe.
using namespace snort;

class ProbePolicy : public FilePolicyBase {
public:
    // all FOUR virtuals overridden, inert bodies — vectors never call them;
    // the override set is what makes the vtable/typeinfo witness complete.
    void policy_check(Flow*, FileInfo*) override { }
    FileVerdict type_lookup(Packet*, FileInfo*) override
    { return FILE_VERDICT_BLOCK; }
    FileVerdict signature_lookup(Packet*, FileInfo*) override
    { return FILE_VERDICT_UNKNOWN; }
    void log_file_action(Flow*, FileInfo*, FileAction) override { }
};

int main(void)
{

    // ---- C: sizes via the probe's own sizeof, never hand-typed (PLAN 7) ----
    // ufd=8 = vptr-only proof (copy-path members have no bodies, PLAN 3);
    // bitset=128 pins FILE_ID_MAX/8*8; fpolbase=16 = vptr + atomic_uint + pad.
    std::printf("C_sz fpolbase=%zu ufd=%zu fstate=%zu fccr=%zu bitset=%zu file_id_max=%d\n",
        sizeof(FilePolicyBase), sizeof(UserFileDataBase), sizeof(FileState),
        sizeof(FileCacheClearReport), sizeof(FileTypeBitSet), FILE_ID_MAX);

    // ---- E: enum wire values (enumerate order == wire order, measured) ----
    std::printf("E_enums action=%d,%d,%d verdict=%d,%d,%d,%d,%d,%d,%d,%d pos=%d,%d,%d,%d,%d "
        "cap=%d,%d,%d,%d,%d sig=%d,%d,%d,%d ptype=%d,%d,%d dir=%d,%d enc=%d,%d\n",
        FILE_ACTION_DEFAULT, FILE_RESUME_BLOCK, FILE_RESUME_LOG,
        FILE_VERDICT_UNKNOWN, FILE_VERDICT_LOG, FILE_VERDICT_STOP, FILE_VERDICT_BLOCK,
        FILE_VERDICT_REJECT, FILE_VERDICT_PENDING, FILE_VERDICT_STOP_CAPTURE, FILE_VERDICT_MAX,
        SNORT_FILE_POSITION_UNKNOWN, SNORT_FILE_START, SNORT_FILE_MIDDLE, SNORT_FILE_END,
        SNORT_FILE_FULL,
        FILE_CAPTURE_SUCCESS, FILE_CAPTURE_MIN, FILE_CAPTURE_MAX, FILE_CAPTURE_MEMCAP,
        FILE_CAPTURE_FAIL,
        FILE_SIG_PROCESSING, FILE_SIG_DEPTH_FAIL, FILE_SIG_FLUSH, FILE_SIG_DONE,
        SNORT_FILE_TYPE_ID, SNORT_FILE_SHA256, SNORT_FILE_CAPTURE,
        FILE_DOWNLOAD, FILE_UPLOAD,
        SNORT_CHAR_ENCODING_ASCII, SNORT_CHAR_ENCODING_UTF_16LE);

    // ---- M: feature-word macros + BOM pin (%x, NO 0x prefix — hygiene) ----
    std::printf("M_flags %x,%x,%x allon=%x alloff=%x bom_len=%d b0=%d b1=%d\n",
        ENABLE_FILE_TYPE_IDENTIFICATION, ENABLE_FILE_SIGNATURE_SHA256, ENABLE_FILE_CAPTURE,
        FILE_ALL_ON, FILE_ALL_OFF,
        UTF_16_LE_BOM_LEN, (int)(unsigned char)UTF_16_LE_BOM[0],
        (int)(unsigned char)UTF_16_LE_BOM[1]);

    // ---- P: the inline FilePosition ladder (h:174-:205; inline code was
    // never gated upstream — these vectors ARE the truth, PLAN 7) ----
    {
        FilePosition pos;
        initFilePosition(&pos, 0);
        std::printf("P_init0 pos=%d\n", pos);                       // -> START
        initFilePosition(&pos, 7);
        std::printf("P_init7 pos=%d\n", pos);                       // -> MIDDLE
    }
    {
        FilePosition pos = SNORT_FILE_END;
        updateFilePosition(&pos, 0);
        std::printf("P_upd_end0 pos=%d\n", pos);                    // END -> START
        pos = SNORT_FILE_FULL;
        updateFilePosition(&pos, 9);
        std::printf("P_upd_full9 pos=%d\n", pos);                   // reset arm precedes MIDDLE arm (h:183)
        pos = SNORT_FILE_MIDDLE;
        updateFilePosition(&pos, 0);
        std::printf("P_upd_mid0 pos=%d\n", pos);                    // UNCHANGED arm
        pos = SNORT_FILE_POSITION_UNKNOWN;
        updateFilePosition(&pos, 0);
        std::printf("P_upd_unk0 pos=%d\n", pos);                    // UNKNOWN stays UNKNOWN
    }
    {
        FilePosition pos = SNORT_FILE_START;
        finalFilePosition(&pos);
        std::printf("P_fin_start pos=%d\n", pos);                   // START -> FULL
        pos = SNORT_FILE_MIDDLE;
        finalFilePosition(&pos);
        std::printf("P_fin_mid pos=%d\n", pos);                     // -> END
        pos = SNORT_FILE_POSITION_UNKNOWN;
        finalFilePosition(&pos);
        std::printf("P_fin_unk pos=%d\n", pos);                     // QUIRK: UNKNOWN -> END (PLAN 9 R7, pin-not-fix)
    }
    std::printf("P_isstart %d%d%d%d%d\n",
        isFileStart(SNORT_FILE_POSITION_UNKNOWN), isFileStart(SNORT_FILE_START),
        isFileStart(SNORT_FILE_MIDDLE), isFileStart(SNORT_FILE_END),
        isFileStart(SNORT_FILE_FULL));                              // 01001
    std::printf("P_isend %d%d%d%d%d\n",
        isFileEnd(SNORT_FILE_POSITION_UNKNOWN), isFileEnd(SNORT_FILE_START),
        isFileEnd(SNORT_FILE_MIDDLE), isFileEnd(SNORT_FILE_END),
        isFileEnd(SNORT_FILE_FULL));                                // 00011

    // ---- S: get_character_encoding BOM arms (h:207-:217; the memcmp reads
    // exactly 2 bytes only when length>=2 — no OOB on the len-1 arm) ----
    {
        int e_short   = (int)get_character_encoding("\xFF", 1);
        int e_nonbom  = (int)get_character_encoding("AB", 2);
        int e_bom     = (int)get_character_encoding("\xFF\xFE" "A", 3);
        int e_partial = (int)get_character_encoding("\xFEXF", 2);   // non-BOM pair as measured
        std::printf("S_enc short=%d nonbom=%d bom=%d partial=%d\n",
            e_short, e_nonbom, e_bom, e_partial);
    }

    // ---- R: ref-count protocol ladder over REAL file_api.cc:28-:43 ----
    // heap policy (R1), fully drained; ref_count read direct (FIXACC graft),
    // hoisted to locals before printf; NEVER touch the policy after the
    // deleting delete_file_policy (dangling — print only the gone flag).
    {
        ProbePolicy* p = new ProbePolicy();
        unsigned r_ctor = p->ref_count;                             // ctor SETS 1 (cc:28-:29)
        std::printf("R_ctor ref=%u\n", r_ctor);
        p->add_ref();                                               // inline ++ (h:165)
        unsigned r_add = p->ref_count;
        std::printf("R_addref ref=%u\n", r_add);
        FilePolicyBase::delete_file_policy(p);                      // --ref, still alive (cc:39)
        unsigned r_del1 = p->ref_count;
        std::printf("R_del1 ref=%u\n", r_del1);
        FilePolicyBase::delete_file_policy(p);                      // ref 0 -> delete (cc:40-:41), dtor assert passes
        std::printf("R_del0 gone=1\n");
        FilePolicyBase::delete_file_policy(nullptr);                // null guard silent no-op (cc:36)
        std::printf("R_del_null silent=1\n");
    }
    // underflow arm assert(policy->ref_count) cc:38: NOT probed — it ABORTS
    // (live assert, no -DNDEBUG); panic-posture doc in PORT (PLAN 7 R-note).
    // U_ufd deviation: no observable (bodies don't link by definition).
    // D-block: zero arms — the four h:219-:224 decl pins live in their body
    // homes' transcripts (fflows/fconf), R8 no-overlap rule.

    std::printf("FCAPI_PROBE_DONE\n");
    return 0;
}

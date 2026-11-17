// Deterministic ground-truth probe for file_api/file_identifier.
//
// file_identifier.cc compiles VERBATIM as its own TU. The header's
// private section is grafted public for the probe ONLY (same
// discipline as the fstats FileService graft, numa policy graft, ...);
// both sides see one copy, graft = access control only, semantics
// unchanged; gate visibility widening is inert, documented deviation. The graft exists
// because production add_file_id NEVER inserts into the trie (only
// file_magic_rules[]), so to pin what find_file_type_id's traversal
// MEANS once a trie exists, the probe hand-builds nodes with the TU's
// real calloc_mem and drives the whole PUBLIC find API.
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>

#include "file_api/file_identifier.h"
#include "file_api/file_api.h"

using namespace snort;

// ---- log witness (messages.h seam, declared in namespace snort) ----
unsigned int get_random_seed() { return 1; } // util.h: GLOBAL scope
namespace snort {                            // (dead !static_hash only)
unsigned get_instance_id() { return 0; }     // thread.h: snort:: scope
void ParseError(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("PE ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}
}

static uint32_t findp(FileIdentifier& fi, const char* s, uint64_t off, void** ctx)
{
    return fi.find_file_type_id((const uint8_t*)s, (int)strlen(s), off, ctx);
}

int main()
{
    // ---- FileMeta::clear ----
    FileMeta r;
    r.rev = 7; r.id = 3; r.type = "pdf"; r.category = "docs";
    r.version = "\"1.7\""; r.groups = { "g1", "g2" };
    r.clear();
    printf("CLEAR %u %u [%s] [%s] [%s] ng=%zu\n", r.rev, r.id,
        r.type.c_str(), r.category.c_str(), r.version.c_str(), r.groups.size());

    // ---- empty-trie production path (mirrors upstream tautology) ----
    FileIdentifier fi;
    printf("P0 mem=%u\n", fi.memory_usage());

    FileMeta a; a.type = "pdf"; a.id = 1;
    fi.add_file_id(a);
    printf("A1 mem=%u\n", fi.memory_usage());

    void* ctx = nullptr;
    printf("P1 empty find=%u ctxnull=%d\n", findp(fi, "PDF", 0, &ctx), (int)!ctx);
    // find on empty root: *ctx<-root(null), loop skipped, CONTINUE->UNKNOWN
    printf("P2 empty find2=%u ctxnull=%d\n", findp(fi, "", 0, &ctx), (int)!ctx);

    // ---- duplicate id -> ParseError; first rule kept ----
    FileMeta dupt; dupt.type = "exe"; dupt.id = 1;
    fi.add_file_id(dupt);
    const FileMeta* got = fi.get_rule_from_id(1);
    printf("DUP kept=[%s] id=%u\n", got ? got->type.c_str() : "-",
        got ? got->id : 0);

    // ---- get_rule_from_id edges ----
    FileMeta b; b.type = "exe"; b.id = 2;
    fi.add_file_id(b);
    const FileMeta* g2 = fi.get_rule_from_id(2);
    const FileMeta* g0 = fi.get_rule_from_id(0);
    const FileMeta* gbig = fi.get_rule_from_id(FILE_ID_MAX + 1);
    printf("GET id2=[%s] id0=%d id1025=%d\n", g2 ? g2->type.c_str() : "-",
        (int)!g0, (int)!gbig);

    // ---- id 0 quirk: duplicate gate checks file_magic_rules[0].id > 0
    // which never holds (rule id 0 stores id==0), and
    // get_rule_from_id(0) requires .id > 0 -> always null ----
    FileMeta z; z.type = "zero"; z.id = 0;
    fi.add_file_id(z);  // no PE expected
    const FileMeta* gz = fi.get_rule_from_id(0);
    printf("ZERO keptnull=%d\n", (int)!gz);

    // ---- get_magic_rule_ids_from_type (version quoting semantics) ----
    FileMeta c; c.id = 3; c.type = ""; // empty type never matches
    fi.add_file_id(c);
    FileTypeBitSet ids;
    fi.get_magic_rule_ids_from_type("exe", "", ids);
    printf("MEXE count=%u id1=%d id2=%d id3=%d\n", (unsigned)ids.count(),
        (int)ids.test(1), (int)ids.test(2), (int)ids.test(3));
    fi.get_magic_rule_ids_from_type("exe", "1.7", ids); // no quoted ver -> miss
    printf("MEXE17 count=%u\n", (unsigned)ids.count());
    FileMeta d; d.id = 4; d.type = "exe"; d.version = "\"1.7\"";
    fi.add_file_id(d);
    fi.get_magic_rule_ids_from_type("exe", "1.7", ids); // "1.7" vs "\"1.7\""
    printf("MEXE17B count=%u id2=%d id4=%d\n", (unsigned)ids.count(),
        (int)ids.test(2), (int)ids.test(4));
    fi.get_magic_rule_ids_from_type("", "", ids);
    printf("MEMPTY count=%u id3=%d\n", (unsigned)ids.count(), (int)ids.test(3));

    // ---- hand-grown trie, PUBLIC find traversal semantics ----
    // root offset0: 0 -> 'P' offset1: 0 -> 'D' offset2: type_id 42
    // (calloc_mem tracks each node's bytes + registers merge hash).
    IdentifierNode* root = (IdentifierNode*)fi.calloc_mem(sizeof(IdentifierNode));
    root->offset = 0; root->type_id = 0;
    IdentifierNode* n1 = (IdentifierNode*)fi.calloc_mem(sizeof(IdentifierNode));
    n1->offset = 1; n1->type_id = 0;
    IdentifierNode* n2 = (IdentifierNode*)fi.calloc_mem(sizeof(IdentifierNode));
    n2->offset = 2; n2->type_id = 42;
    root->next['P'] = n1;
    n1->next['D'] = n2;
    fi.identifier_root = root;
    printf("GROWN mem=%u sznode=%zu\n", fi.memory_usage(),
        sizeof(IdentifierNode));

    ctx = nullptr;
    printf("T1 full=%u ctxnull=%d\n", findp(fi, "PDFEXE", 0, &ctx), (int)!ctx);
    // end=4: n2 type 42 captured; next['F'] null -> context cleared
    ctx = nullptr;
    uint32_t r2 = findp(fi, "PD", 0, &ctx);
    printf("T2 atnode=%u ctxoff=%ld\n", r2,
        ctx ? (long)((IdentifierNode*)ctx)->offset : -1L);
    // end=2: enter n2 (offset 2) >= end -> SAVE context n2, return 42
    ctx = n1;
    uint32_t r3 = findp(fi, "FEXE", 1, &ctx);
    printf("T3 resume=%u ctxoff=%ld\n", r3,
        ctx ? (long)((IdentifierNode*)ctx)->offset : -1L);
    // resume-at-node: n1.offset(1)>=1 true; no type_id; 1>=5 false ->
    // next[buf[1-1]='F'] null -> loop ends, context null -> UNKNOWN
    ctx = nullptr;
    printf("T4 nomatch=%u ctxnull=%d\n", findp(fi, "PQ", 0, &ctx), (int)!ctx);
    // root only (file_offset 0), but first char mismatch: root offset0>=0,
    // 0>=len? no -> next['P']: mismatch 'Q' -> n
    ctx = nullptr;
    printf("T5 skipped=%u ctxnull=%d\n", findp(fi, "PDF", 5, &ctx), (int)!ctx);
    // file_offset past every node offset: loop condition root.offset(0)
    // >= 5 false immediately -> UNKNOWN with context = root then nulled
    printf("DONE\n");
    return 0;
}

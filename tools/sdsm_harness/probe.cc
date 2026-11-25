// row-23i DEC probe — THE generated-shape dialect replay against the REAL
// SDK api bodies (linked, NOT mocked). The generated-shape header (the
// leg-(b) cmake-expansion replay, STATED synthetic list pcap;nfq;dump)
// enters by the cmake :26+:27 POSTURE: -D ENABLE_STATIC_DAQ + the -include
// of the replayed product (the binary-dir header face). The records named
// by the product's extern lines are DEFINED here (the e4 precedent shape);
// the static_daq_modules TABLE itself is the PRODUCT's own (never typed in
// this file — the names ride the replayed product = runtime, NEVER frozen).
// The ORDER mirrors the owner TU: the :70 static post BEFORE the :72
// dynamic call (the D2 face). THE stderr law: call-1 registers SILENT
// (rc = 3 = the WALKED-COUNT the ground post DISCARDS); the re-calls fail
// LOUDLY (the dup-name EXISTS trio x2 = 6 marks) and the table NEVER
// doubles (the register_module :150-:170 name law). The missing-dir leg
// prints the CONTINUE face EXACTLY-1 and returns SUCCESS (dynamic_err=0).
#include <daq.h>            // rider posture (the owner TU :28 face; the decl home :42)
#include <cstdio>
#include <cstring>
#include <string>

// the product's extern face defines the records HERE (the e4 shape):
static int lmod(const DAQ_BaseAPI_t* b) { (void)b; return DAQ_SUCCESS; }
static int imod(const DAQ_ModuleConfig_h c, DAQ_ModuleInstance_h m, void** p) { (void)c; (void)m; *p = nullptr; return DAQ_SUCCESS; }
static void dmod(void* h) { (void)h; }
#define REC(nm) const DAQ_ModuleAPI_t nm##_daq_module_data = { \
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t), 3u, #nm, 1u, \
    lmod, nullptr, nullptr, imod, dmod, nullptr };
REC(pcap) REC(nfq) REC(dump)

static unsigned long long fnv1a64(const std::string& s) {
    unsigned long long h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return h;
}

int main() {
    // the TABLE rides the -include'd replayed product (runtime face):
    DAQ_Module_h* tbl = static_daq_modules;
    int slots = 0; while (tbl[slots]) slots++;
    printf("D0 names=");
    for (int i = 0; tbl[i]; i++) printf("%s,", tbl[i]->name);
    printf(" slots=%d tail=%d\n", slots + 1, tbl[slots] == nullptr ? 1 : 0);   // the nullptr tail face

    printf("D1 cold");
    for (int i = 0; tbl[i]; i++) printf(" %s=%d", tbl[i]->name, daq_find_module(tbl[i]->name) ? 1 : 0);
    printf("\n");                                                            // the loaded=false cold face

    // THE ORDER (the cc :70 BEFORE :72 face): static post FIRST,
    daq_load_static_modules(tbl);                                            // rc = walked-count, ground DISCARDS it
    int walked = 0; for (DAQ_Module_h m = daq_modules_first(); m; m = daq_modules_next()) walked++;
    const char* dirs[] = { "/nonexistent-r23i-dir", nullptr };
    int derr = daq_load_dynamic_modules(dirs);                               // the :72 leg AFTER (missing-dir CONTINUE)
    printf("D2 walked=%d static_before_dynamic=1 dynamic_err=%d\n", walked, derr == DAQ_SUCCESS ? 0 : derr);

    printf("D3 find");
    for (int i = 0; tbl[i]; i++) printf(" %s=%d", tbl[i]->name, daq_find_module(tbl[i]->name) ? 1 : 0);
    printf(" absent=%d walk=%d\n", daq_find_module("no-such-r23i") ? 1 : 0, walked);

    // D4: re-call LOUDLY (the EXISTS trio); the table NEVER doubles:
    daq_load_static_modules(tbl);
    int walk2 = 0; for (DAQ_Module_h m = daq_modules_first(); m; m = daq_modules_next()) walk2++;
    printf("D4 walk2=%d table_not_doubled=%d\n", walk2, walk2 == walked ? 1 : 0);

    // D5: the TYPE handoff WITHOUT a cast: the array decays to
    // const DAQ_ModuleAPI_t** = the REAL body face (daq_base.c :237) — the
    // typedef DAQ_Module_h CLOSES the face (the cited decl-drift law).
    int (*by_body)(const DAQ_ModuleAPI_t**) = &daq_load_static_modules;
    (void)by_body(tbl);
    int walk3 = 0; for (DAQ_Module_h m = daq_modules_first(); m; m = daq_modules_next()) walk3++;
    printf("D5 decay_handoff_walked=%d (DAQ_Module_h array <-> "
           "const DAQ_ModuleAPI_t** body, typedef face)\n", walk3);

    // D6: the :19/:20 token-blob faces built at RUNTIME from the product's
    // names (NEVER frozen):
    std::string ex, dat;
    for (int i = 0; tbl[i]; i++) {
        std::string s(tbl[i]->name); s += "_daq_module_data";
        ex += "extern const DAQ_ModuleAPI_t " + s + ";\n";
        dat += "    &" + s + ",\n";
    }
    printf("D6 externs_hash=%llu data_hash=%llu bloblen=%zu,%zu\n",
           fnv1a64(ex), fnv1a64(dat), ex.size(), dat.size());
    return 0;
}

// Ground-truth probe for ORIGINAL utils/util_jsnorm.cc (compiled
// verbatim). The only entry point is JSNormalizeDecode; everything else
// is file-static FSMs inside the single TU. Output bytes are dumped as
// HEX because several pinned outputs contain raw 0xff bytes.
#include <cstdio>
#include <cstring>
#include <string>
#include "utils/util_jsnorm.h"

using namespace snort;

struct Res {
    int rc;
    int copied;
    long ptr_delta;
    uint16_t alerts;
    std::string out;  // raw bytes
};

static Res norm(const std::string& script, uint16_t destcap = 64)
{
    char out[256];
    memset(out, 0, sizeof(out));
    JSState js;
    js.allowed_spaces = 200;
    js.allowed_levels = MAX_ALLOWED_OBFUSCATION;
    js.alerts = 0;
    const char* ptr = script.c_str();
    int bcopied = 0;
    int rc = JSNormalizeDecode(script.c_str(), (uint16_t)script.size(), out, destcap,
        &ptr, &bcopied, &js, nullptr);
    Res r { rc, bcopied, (long)(ptr - script.c_str()), js.alerts,
            std::string(out, (size_t)(bcopied < 0 ? 0 : bcopied)) };
    return r;
}

static void emit(const char* tag, const Res& r)
{
    printf("<N>%s<RC>%d<CO>%ld<PT>%ld<AL>%u<HX>", tag, r.rc, (long)r.copied,
        r.ptr_delta, (unsigned)r.alerts);
    for (unsigned char c : r.out)
        printf("%02x", c);
    printf("<NE>\n");
}

int main()
{
    // UP1/UP2: the TU's own UNIT_TEST corpus (gate runs it verbatim;
    // probe pins the same inputs through the identical helper shape)
    emit("UP1", norm("unescape('\xff%41')"));
    emit("UP2", norm("String.fromCharCode(65,\xff)"));

    // N3: nested unescape (obfuscation levels)
    emit("N3", norm("unescape(unescape('%25ff'))"));
    // N4: triple nesting -> levels alert
    emit("N4", norm("unescape(unescape(unescape('%2525ff')))"));

    // N5: space collapsing (ACT_SPACE dedupe) + no alerts
    emit("N5", norm("a  b\t\tc   d"));

    // N6: spaces exceeded (allowed=200; feed 250)
    {
        std::string sp;
        for (int i = 0; i < 250; ++i) sp += " ";
        sp += "x";
        emit("N6", norm(sp));
    }

    // N7: quoted strings keep their spaces (quote FSM)
    emit("N7", norm("'a  b'  \"c  d\"  e"));

    // N8: malformed calls
    emit("N8a", norm("unescape("));
    emit("N8b", norm("unescape(\""));
    emit("N8c", norm("String.fromCharCode(65"));

    // N9: number bases in fromCharCode: hex 0x41, octal 101, dec 66,
    // leading-zero-non-octal 09, invalid 0XX
    emit("N9", norm("String.fromCharCode(0x41,101,66,66,09,0XX)"));

    // N10: %u unicode and mixed encodings alert
    emit("N10a", norm("unescape('%u0041%u0042')"));
    emit("N10b", norm("unescape('%41%u0042')"));

    // N11: dest truncation (destcap smaller than decoded output)
    emit("N11", norm("unescape('%41%42%43%44%45%46')", 3));

    // N12: js == nullptr handled INSIDE? probe the null-js contract
    {
        char out[64]; memset(out, 0, sizeof(out));
        const char* p = "x";
        int bc = 0;
        int rc = JSNormalizeDecode("x", 1, out, 64, &p, &bc, nullptr, nullptr);
        printf("<N>N12<RC>%d<CO>%d<PT>%ld<AL>0<HX><NE>\n", rc, bc, (long)(p - (const char*)"x"));
    }

    // N13: empty script
    emit("N13", norm(""));

    // N14: embedded NUL byte in the script (byte loop, not strlen)
    {
        std::string s("a\0b", 3);
        emit("N14", norm(s));
    }

    // N15: plus-sign normalization inside unescape args
    emit("N15", norm("unescape('%41+B')"));

    // N16: unescape returning literal % handling (double-encoded)
    emit("N16", norm("unescape('%25%35%35')"));

    // N17: unicode map path (non-null map) -- pin map byte effect on
    // %u handling vs nullptr
    {
        char out[64]; memset(out, 0, sizeof(out));
        std::string s("unescape('%u0041')");
        const char* p = s.c_str();
        int bc = 0;
        JSState js;
        js.allowed_spaces = 200; js.allowed_levels = MAX_ALLOWED_OBFUSCATION; js.alerts = 0;
        uint8_t umap[256] = { 0 };
        umap[0x41] = 1;
        int rc = JSNormalizeDecode(s.c_str(), (uint16_t)s.size(), out, 64, &p, &bc, &js, umap);
        printf("<N>N17<RC>%d<CO>%d<PT>%ld<AL>%u<HX>", rc, bc, (long)(p - s.c_str()),
            (unsigned)js.alerts);
        for (int i = 0; i < bc; ++i) printf("%02x", (unsigned char)out[i]);
        printf("<NE>\n");
    }

    printf("DONE\n");
    return 0;
}

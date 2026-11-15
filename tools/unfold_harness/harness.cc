#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include "utils/util_unfold.h"

using namespace snort;

// Each case: explicit bytes + explicit capacity (no string-literal overrun).
struct Case { const char* tag; std::vector<uint8_t> in; uint32_t ocap; };

static void emit(const Case& c)
{
    std::vector<uint8_t> out(c.ocap ? c.ocap : 1, 0xAA);
    uint32_t ob = 0;
    int ret;
    const uint8_t* p = c.in.empty() ? (const uint8_t*)"" : c.in.data();
    uint32_t isize = (uint32_t)c.in.size();

    if (std::strcmp(c.tag, "crlf") == 0)
        ret = sf_strip_CRLF(p, isize, out.data(), c.ocap, &ob);
    else
        ret = sf_strip_LWS(p, isize, out.data(), c.ocap, &ob);

    std::printf("CASE %s in=<", c.tag);
    for (auto b : c.in) std::printf("%02x", b);
    std::printf("> ocap=%u ret=%d ob=%u out=<", c.ocap, ret, ob);
    for (uint32_t i = 0; i < ob && i < c.ocap; ++i) std::printf("%02x", out[i]);
    std::printf(">\n");
}

static std::vector<uint8_t> bytes(const char* s)
{
    // supports \r \n \t \\ and \xNN escapes explicitly
    std::vector<uint8_t> v;
    for (const char* p = s; *p; ++p)
    {
        if (*p == '\\')
        {
            ++p;
            switch (*p)
            {
            case 'r': v.push_back('\r'); break;
            case 'n': v.push_back('\n'); break;
            case 't': v.push_back('\t'); break;
            case '\\': v.push_back('\\'); break;
            case '0': v.push_back('\0'); break;
            case 'x':
            {
                unsigned u = 0;
                for (int i = 0; i < 2 && p[1]; ++i)
                {
                    ++p;
                    char ch = *p;
                    u = u * 16 + (ch <= '9' ? ch - '0' : (ch | 0x20) - 'a' + 10);
                }
                v.push_back((uint8_t)u);
                break;
            }
            default: v.push_back((uint8_t)*p);
            }
        }
        else v.push_back((uint8_t)*p);
    }
    return v;
}

int main()
{
    const Case cases[] = {
        // sf_strip_CRLF: remove every CR and LF, cap at ocap
        {"crlf", bytes("abc\\r\\ndef"), 100},
        {"crlf", bytes("\\r\\n"), 100},
        {"crlf", bytes("\\r\\n\\r\\n"), 100},
        {"crlf", bytes("a\\rb\\nc\\r\\nd"), 100},
        {"crlf", bytes(""), 100},
        {"crlf", bytes("abcdef"), 3},      // truncated at capacity
        {"crlf", bytes("\\n\\n\\nx"), 100},
        {"crlf", bytes("x\\r"), 100},
        {"crlf", bytes("\\x00\\r\\n\\x00"), 100}, // NUL bytes kept by strip
        // sf_strip_LWS: strip trailing space/tab immediately before LF/CRLF
        {"lws", bytes("a  \\r\\nb  \\r\\n"), 100},
        {"lws", bytes("a \\t \\n"), 100},
        {"lws", bytes("  \\n"), 100},       // all LWS before LF
        {"lws", bytes("a  b\\r\\n"), 100},  // inner spaces kept
        {"lws", bytes("a\\t\\t\\r\\nb\\t\\r\\n"), 100},
        {"lws", bytes("no-ws"), 100},
        {"lws", bytes("x \\r"), 100},
        {"lws", bytes("x \\t"), 100},      // trailing tab, no newline kept
        {"lws", bytes(""), 100},
        {"lws", bytes("aaa   \\nbbb"), 5}, // capacity cut mid-line
        {"lws", bytes("   \\n   \\n"), 100},
        {"lws", bytes("a\\x00  \\n"), 100}, // NUL resets lws flag
    };
    for (const auto& c : cases) emit(c);
    return 0;
}

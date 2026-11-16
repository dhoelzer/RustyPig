// Witness seam: DetectionEngine::queue_event declared in the witness
// detection/detection_engine.h (the real one drags detection/ips_context
// -> the whole detection engine we don't link). Vectors print each queued
// event as 'EV 116 <sid>'; GID_DECODE is the ORIGINAL constexpr in the
// ORIGINAL codecs/codec_module.h (116), used verbatim by codec.cc.
#include "detection/detection_engine.h"
#include <cstdio>
#include <cstdarg>
namespace snort {
int DetectionEngine::queue_event(unsigned gid, unsigned sid)
{
    printf("EV %u %u\n", gid, sid);
    return 0;
}
}

// protocols/layer.cc not linked: ip.cc inline accessors reference
// layer::get_inner_ip6_frag(); our vectors never take those paths.
#include "protocols/layer.h"
const snort::ip::IP6Frag* snort::layer::get_inner_ip6_frag() { return nullptr; }
const snort::ip::IP6Frag* snort::layer::get_inner_ip6_frag(const snort::Packet* const) { return nullptr; }

// snort_strdup/strndup: vars_harness witness pattern (real util.cc drags
// log/messages + main/snort_config out of scope). Verbatim bodies from
// src/utils/util.cc:119.
#include <cstdlib>
#include <cstring>
extern "C" { }
namespace snort {
char* snort_strdup(const char* s) { return s ? strdup(s) : nullptr; }
char* snort_strndup(const char* s, size_t n) {
    if (!s) return nullptr;
    char* p = (char*)calloc(n + 1, 1);
    strncpy(p, s, n);
    return p;
}
void LogMessage(const char* fmt, ...) { (void)fmt; va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); putchar('\n'); }
void ErrorMessage(const char* fmt, ...) { (void)fmt; va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); putchar('\n'); }
}

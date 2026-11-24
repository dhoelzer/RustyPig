// witness_tracker.cc — row 23f witness OWN (DECL-body / capture mirrors
// ONLY, the 22b/23-era scaffolding law EXTENDED to the stream-log +
// batched-logger + active-table walls): everything the row .o, the gate TU
// and the DEC probe reach as link residuals while the REAL homes
// (active.cc / stream_log.cc / batched_logger.cc / sfdaq_instance.cc /
// messages.cc bodies) are NEVER landed and NEVER reached:
//   Active::act_str (active.h :214 class-static; the REAL table rides
//     active.cc :60-:70 — mirrored VERBATIM as the DECL face: the row's
//     dump(Packet*) leg calls the header-inline get_action_string which
//     B-refs this static; active.cc NEVER lands),
//   StreamLog::add_ip_header_info / add_eth_header_info /
//   add_packet_type_info / stream_is_cbd_enabled (stream_log.cc NEVER
//     landed — capture mirrors so the DEC probe OBSERVES the activate()
//     arm order through the REAL row .o; stream_is_cbd_enabled=false =
//     the cold face the row's else-arms take),
//   BatchedLogger::BatchedLogManager::log/flush_thread_buffers
//     (batched_logger.cc NEVER landed — THE wall; capture face),
//   SFDAQInstance::set_packet_trace_data (sfdaq_instance.cc NEVER landed
//     in the C tree here: the REAL body face is CITED by the 23b Rust
//     port (sfdaq_instance.rs :1155-); the mirror captures msg-nullness
//     + len + payload so the daq_dump leg prints through the REAL .o —
//     the probe hands a non-null NEVER-dereferenced sentinel SFDAQInstance*),
//   Packet::Packet(bool)/~Packet (the 22b scaffolding face re-ridden),
//   layer::get_inner_ip6_frag (the ip.o pull, the 22b/23e mirror),
//   LogMessage varargs + LogMessage(FILE*) + WarningMessage (messages.cc
//     NEVER landed; the capture pair the carried witness_conf 4dd91018
//     family NEVER doubles — 23e nm law re-rides: that family rides
//     get_conf/FatalError/show_stats/thread legs ONLY).
// NEVER-double law: NOTHING here duplicates a row-body (.o) or a carried
// REAL home; snort_strdup/SnortSnprintf ride REAL fresh-cp util bodies,
// get_conf/FatalError ride the carried 4dd91018 extraction.
#include "stream/stream_log.h"
#include "log/batched_logger.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/active.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/layer.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

std::string batched_capture, sl_capture, daq_trace_capture, msg_capture, warn_capture;

namespace snort {

const char* Active::act_str[Active::ACT_MAX][Active::AST_MAX] =
{
    { "trust", "error", "error", "error" },
    { "allow", "error", "error", "error" },
    { "hold", "error", "error", "error" },
    { "retry", "error", "error", "error" },
    { "rewrite", "cant_rewrite", "would_rewrite", "force_rewrite" },
    { "drop", "cant_drop", "would_drop", "force_drop" },
    { "block", "cant_block", "would_block", "force_block" },
    { "reset", "cant_reset", "would_reset", "force_reset" },
};

void LogMessage(const char* fmt, ...)
{ va_list a; va_start(a, fmt); char b[2600]; vsnprintf(b, sizeof b, fmt, a); va_end(a); msg_capture += b; }
void LogMessage(FILE*, const char* fmt, ...)
{ va_list a; va_start(a, fmt); char b[2600]; vsnprintf(b, sizeof b, fmt, a); va_end(a); msg_capture += b; }
void WarningMessage(const char* fmt, ...)
{ va_list a; va_start(a, fmt); char b[512]; vsnprintf(b, sizeof b, fmt, a); va_end(a); warn_capture += b; }
void ErrorMessage(const char*, ...) { }  // the util.o pull (the 23e pair face re-ridden)

}  // namespace snort (the StreamLog mirror legs below sit in the GLOBAL
   // namespace: stream_log.h declares class StreamLog OUTSIDE snort)

void StreamLog::add_ip_header_info(const snort::Packet&, bool add_eth)
{ sl_capture += add_eth ? "IP+;" : "IP-;"; }
void StreamLog::add_eth_header_info(const snort::Packet&) { sl_capture += "ETH;"; }
void StreamLog::add_packet_type_info(const snort::Packet&) { sl_capture += "PTY;"; }
bool StreamLog::stream_is_cbd_enabled() { return false; }

// the BatchedLogger wall (batched_logger.cc NEVER landed — THE wall; the
// mirror rides the GLOBAL BatchedLogger namespace, batched_logger.h :85):
namespace BatchedLogger {
void BatchedLogManager::log(FILE*, bool use_syslog, const char* msg, size_t len)
{ batched_capture += std::string("BL:") + (use_syslog ? "sys:" : "buf:") + msg + ":" + std::to_string(len) + ";"; }
void BatchedLogManager::flush_thread_buffers() { batched_capture += "FLUSH;"; }
}

namespace snort {
int SFDAQInstance::set_packet_trace_data(DAQ_Msg_h msg, uint8_t* buff, uint32_t buff_len)
{
    daq_trace_capture = std::string("DAQTD:") + (msg ? "m" : "n") + ":" + std::to_string(buff_len)
        + ":" + (buff_len ? std::string((char*)buff, buff_len > 1 ? buff_len - 1 : 0) : std::string()) + ";";
    return 0;
}

Packet::Packet(bool) { }
Packet::~Packet() { }
namespace layer { const ip::IP6Frag* get_inner_ip6_frag() { return nullptr; } }

}

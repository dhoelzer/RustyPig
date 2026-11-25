// row 23h OWN witness (the one-home law): mirrors ONLY the not-landed homes
// the REAL row .o pulls (MEASURED nm -u census in build.sh) + the dnet shim
// face (the graft dnet.h; libdnet ABSENT on this host — MEASURED find-0).
// NEVER doubles: the ROW .o owns act_str + get_active_counts; the carried
// EXTRACTION owns get_conf / FatalError family / show_stats / thread legs.
// The real sfdaq.cc body COMPILES silent rc0 in this hull (receipt
// E4_sfd_ok) but its mode face (sfdaq.cc:53 `static DAQ_Mode
// default_daq_mode = DAQ_MODE_PASSIVE;`, a FILE-static with NO control
// face short of the real SDK load ladder — the da-qio-era 5-object SDK (hyphen law)
// hull) was MEASURED unmanageable for this row's DEC control requirements:
// the honest smaller hull is the SFDAQ mirror BELOW, capture-equipped.
#include "witness_active.h"

#include "main/snort_config.h"
#include "main/policy.h"
#include "managers/action_manager.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "log/messages.h"
#include "log/batched_logger.h"
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_module.h"
#include "protocols/packet_manager.h"
#include "stream/stream.h"
#include "stream/stream_log.h"
#include "utils/dnet_header.h"    // the copy-tree graft dnet.h types (eth_t/ip_t)

#include <cstdio>
#include <cstdarg>
#include <cstring>

// THE 23f-PRECEDENT def home (sfdaq_module.cc NEVER landed; MEASURED):
THREAD_LOCAL DAQStats daq_stats;

namespace snort
{
// ---------------- SFDAQ statics (mirror home; E4 face in build.sh) --------
bool sfd_can_inject = true;
bool sfd_can_inject_raw = true;
bool sfd_can_replace = true;
bool sfd_forwarding = true;
int  sfd_inject_calls = 0;
int  sfd_inject_rev = -1;
int  sfd_inject_len = -1;
uint64_t sfd_inject_flags_seen = 0;
int  sfd_getlocal_calls = 0;
int  sfd_inject_rc = 0;
SFDAQInstance* sfd_local = nullptr;

bool SFDAQ::can_inject() { return sfd_can_inject; }
bool SFDAQ::can_inject_raw() { return sfd_can_inject_raw; }
bool SFDAQ::can_replace() { return sfd_can_replace; }
bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t*) { return sfd_forwarding; }
SFDAQInstance* SFDAQ::get_local_instance() { sfd_getlocal_calls++; return sfd_local; }
int SFDAQ::inject(DAQ_Msg_h, int rev, const uint8_t*, uint32_t len)
{ sfd_inject_calls++; sfd_inject_rev = rev; sfd_inject_len = (int)len; return sfd_inject_rc; }

// ---------------- SFDAQInstance mirror ------------------------------------
uint32_t wsi_pool = 8;
uint32_t wsi_batch = 4;
int wsi_ctor_calls = 0;
int wsi_dtor_calls = 0;
int wsi_ioctl_calls = 0;
int wsi_last_cmd = -1;
int wsi_ioctl_rc = 0;          // DAQ_SUCCESS by default
int wsi_vp_calls = 0;
int wsi_last_vp_reason = -99;

SFDAQInstance::SFDAQInstance(const char*, unsigned id, const SFDAQConfig*)
{ instance_id = id; batch_size = wsi_batch; pool_available = wsi_pool; wsi_ctor_calls++; }
SFDAQInstance::~SFDAQInstance() { wsi_dtor_calls++; }
int SFDAQInstance::ioctl(DAQ_IoctlCmd cmd, void*, size_t)
{ wsi_ioctl_calls++; wsi_last_cmd = (int)cmd; return wsi_ioctl_rc; }
int SFDAQInstance::set_packet_verdict_reason(DAQ_Msg_h msg, uint8_t reason)
{ wsi_vp_calls++; wsi_last_vp_reason = reason; return msg ? 0 : DAQ_ERROR_INVAL; }
int SFDAQInstance::set_packet_trace_data(DAQ_Msg_h, uint8_t*, uint32_t) { return 0; }

// ---------------- Stream (never-land: flow/flow_cache.h face) -------------
int stream_block_calls = 0, stream_drop_calls = 0, stream_init_ar_calls = 0;
void Stream::block_flow(const Packet*) { stream_block_calls++; }
void Stream::drop_flow(const Packet*) { stream_drop_calls++; }
void Stream::init_active_response(const Packet*, Flow*) { stream_init_ar_calls++; }

// --------------- DetectionEngine (never-land: events/event_queue.h) ------
int de_disable_all_calls = 0, de_clear_replacement_calls = 0;
void DetectionEngine::disable_all(Packet*) { de_disable_all_calls++; }
void DetectionEngine::clear_replacement() { de_clear_replacement_calls++; }

// --------------- PacketManager (never-land: managers/codec_manager.h) ----
int pm_encode_calls = 0, pm_reject_calls = 0, pm_maxpay_calls = 0;
int pm_encode_return_null = 0, pm_reject_return_null = 0;
int pm_encode_kind[16];
int pm_reject_kind[4];
uint64_t pm_flags_seen[16];
uint32_t pm_len_set = 7;
uint64_t pm_maxpayload_face = 0;
static uint8_t pm_sentinel[16] = { 0xAA, 0xBB, 0xCC, 0xDD };

const uint8_t* PacketManager::encode_response(TcpResponse tr, EncodeFlags f,
    const Packet*, uint32_t& len, const uint8_t*, uint32_t)
{
    int i = pm_encode_calls < 16 ? pm_encode_calls : 15;
    pm_encode_kind[i] = (int)tr;
    pm_flags_seen[i] = f;
    pm_encode_calls++;
    if (pm_encode_return_null) return nullptr;
    len = pm_len_set;
    return pm_sentinel;   // the sentinel the probe byte-pins through s_send
}
const uint8_t* PacketManager::encode_reject(UnreachResponse ur, EncodeFlags f,
    const Packet*, uint32_t& len)
{
    int i = pm_reject_calls < 4 ? pm_reject_calls : 3;
    pm_reject_kind[i] = (int)ur;
    pm_reject_calls++;
    if (pm_reject_return_null) return nullptr;
    len = pm_len_set;
    return pm_sentinel;
}
uint16_t PacketManager::encode_get_max_payload(const Packet*)
{ pm_maxpay_calls++; return (uint16_t)pm_maxpayload_face; }

// ---------------- messages (ParseWarning capture; carried owns FatalError)
int pw_calls = 0;
char pw_buf[256];
void ParseWarning(WarningGroup g, const char* fmt, ...)
{
    pw_calls++;
    if (pw_calls == 1) {
        va_list a; va_start(a, fmt);
        vsnprintf(pw_buf, sizeof pw_buf, fmt, a);
        va_end(a);
    }
    (void)g;
}
int logmsg_calls = 0, warnmsg_calls = 0, parseerr_calls = 0, errmsg_calls = 0;
void LogMessage(const char*, ...) { logmsg_calls++; }
void LogMessage(FILE*, const char*, ...) { logmsg_calls++; }
void WarningMessage(const char*, ...) { warnmsg_calls++; }
void ParseError(const char*, ...) { parseerr_calls++; }
void ErrorMessage(const char*, ...) { errmsg_calls++; }

// ---------------- Flow (never-land: detection/context_switcher.h face;
// the probe NEVER builds a Flow — the null-flow cold face is pinned) -------
int flow_trust_calls = 0;
void Flow::trust() { flow_trust_calls++; }

// ---------------- policy face (main/policy.cc NEVER landed: file_api/
// file_policy.h — MEASURED; storage WITHOUT the unlanded ctor) -------------
alignas(IpsPolicy) static unsigned char g_policy_store[sizeof(IpsPolicy)];
static bool g_policy_ready = [] {
    memset(g_policy_store, 0, sizeof g_policy_store);
    ((IpsPolicy*)g_policy_store)->policy_mode = POLICY_MODE__PASSIVE;
    return true; }();
IpsPolicy* get_ips_policy() { (void)g_policy_ready; return (IpsPolicy*)g_policy_store; }
void act_wr_set_policy_mode(int m) { ((IpsPolicy*)g_policy_store)->policy_mode = (PolicyMode)m; }

// ---------------- dnet shim legs (the graft dnet.h face) ------------------
int eth_open_calls = 0, eth_send_calls = 0, eth_close_calls = 0;
int ip_open_calls = 0, ip_send_calls = 0, ip_close_calls = 0;
int dnet_eth_open_fail = 0;
int dnet_ip_open_fail = 0;
int dnet_send_fail = 0;
static int g_link_stub = 1, g_ipnet_stub = 2;
extern "C" {
eth_t* eth_open(const char*) { eth_open_calls++; return dnet_eth_open_fail ? nullptr : (eth_t*)&g_link_stub; }
ssize_t eth_send(eth_t*, const void*, size_t size)
{ eth_send_calls++; return dnet_send_fail ? (ssize_t)(size + 1) : (ssize_t)size; }
void eth_close(eth_t*) { eth_close_calls++; }
ip_t* ip_open(void) { ip_open_calls++; return dnet_ip_open_fail ? nullptr : (ip_t*)&g_ipnet_stub; }
ssize_t ip_send(ip_t*, const void*, size_t len)
{ ip_send_calls++; return dnet_send_fail ? (ssize_t)(len + 1) : (ssize_t)len; }
void ip_close(ip_t*) { ip_close_calls++; }
}

void act_wr_reset_captures()
{
    sfd_inject_calls = 0; sfd_inject_rev = -1; sfd_inject_len = -1;
    sfd_getlocal_calls = 0;
    wsi_ioctl_calls = 0; wsi_last_cmd = -1; wsi_vp_calls = 0; wsi_last_vp_reason = -99;
    stream_block_calls = 0; stream_drop_calls = 0; stream_init_ar_calls = 0;
    de_disable_all_calls = 0; de_clear_replacement_calls = 0;
    pm_encode_calls = 0; pm_reject_calls = 0; pm_maxpay_calls = 0;
    pw_calls = 0; pw_buf[0] = 0;
    logmsg_calls = 0; warnmsg_calls = 0;
    eth_open_calls = 0; eth_send_calls = 0; eth_close_calls = 0;
    ip_open_calls = 0; ip_send_calls = 0; ip_close_calls = 0;
}
} // namespace snort

// ------- StreamLog / BatchedLogManager homes (stream_log.h class is in
// the GLOBAL namespace; the 23f-era wall legs mirrored HERE once) ---------
char sl_capture[64];
int blog_log_calls = 0, blog_flush_calls = 0;
void StreamLog::add_ip_header_info(const snort::Packet&, bool) { strncat(sl_capture, "IP;", 63); }
void StreamLog::add_eth_header_info(const snort::Packet&) { strncat(sl_capture, "ETH;", 63); }
void StreamLog::add_packet_type_info(const snort::Packet&) { strncat(sl_capture, "PTY;", 63); }
bool StreamLog::stream_is_cbd_enabled() { return false; }
namespace BatchedLogger {
void BatchedLogManager::log(FILE*, bool, const char*, size_t) { blog_log_calls++; }
void BatchedLogManager::flush_thread_buffers() { blog_flush_calls++; }
}

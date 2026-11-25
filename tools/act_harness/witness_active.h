#ifndef ACT_WR_H
#define ACT_WR_H
// row 23h own-witness header: capture/control face for the mirrors in
// witness_active.cc. NOTHING here duplicates row-.o or carried-face homes:
// the ROW .o owns the act_str TABLE + get_active_counts; the carried
// EXTRACTION owns get_conf/FatalError/show_stats/thread legs. Every symbol
// below closes a NEVER-LANDED home (measured E4 faces in build.sh) or an
// SDK-shim (dnet) face the row .o pulls.
#include <cstdint>
#include <cstddef>
#include <daq_common.h>

struct snortWrap;

namespace snort {
class SFDAQInstance;

// ---- SFDAQ statics (mirror HOME; the real body refuses the control faces:
// its file-static mode face is pinned PASSIVE without the real SDK load
// ladder — MEASURED, see build.sh E4_sfd_land arm) ----
extern bool     sfd_can_inject;
extern bool     sfd_can_inject_raw;
extern bool     sfd_can_replace;
extern bool     sfd_forwarding;        // the forwarding_packet face
extern int      sfd_inject_calls;      // the s_send default capture
extern int      sfd_inject_rev;        // last rev arg
extern int      sfd_inject_len;        // last len arg
extern uint64_t sfd_inject_flags_seen; // reserved face
extern int      sfd_getlocal_calls;
extern SFDAQInstance* sfd_local;
void act_wr_reset_captures();

// ---- SFDAQInstance mirror controls ----
extern uint32_t wsi_pool;              // pool_available face (pool law)
extern uint32_t wsi_batch;             // batch_size face
extern int      wsi_ctor_calls;
extern int      wsi_ioctl_calls;
extern int      wsi_last_cmd;          // DIOCTL_* face
extern int      wsi_ioctl_rc;          // controllable ioctl return
extern int      wsi_vp_calls;          // set_packet_verdict_reason calls
extern int      wsi_last_vp_reason;    // the reason byte face
extern int      wsi_dtor_calls;
extern int      sfd_inject_rc;         // controllable inject return

// ---- Stream (never-land: flow_cache.h face) ----
extern int stream_block_calls;
extern int stream_drop_calls;
extern int stream_init_ar_calls;

// ---- DetectionEngine (never-land: events/event_queue.h face) ----
extern int de_disable_all_calls;
extern int de_clear_replacement_calls;

// ---- PacketManager (never-land: managers/codec_manager.h face) ----
extern int    pm_encode_calls;
extern int    pm_reject_calls;
extern int    pm_maxpay_calls;
extern int    pm_encode_return_null;   // 1 => encode legs FAIL arm
extern int    pm_reject_return_null;
extern uint64_t pm_flags_seen[16];     // per-call EncodeFlags capture (Strafe heart)
extern int    pm_encode_kind[16];      // TcpResponse ordinal per call
extern int    pm_reject_kind[4];       // UnreachResponse ordinal per call
extern uint32_t pm_len_set;            // the out-param len the mirror writes
extern uint64_t pm_maxpayload_face;    // encode_get_max_payload return
void act_wr_set_policy_mode(int m);    // the get_ips_policy()->policy_mode face

// ---- messages (ParseWarning capture; the carried face owns FatalError) ----
extern int  pw_calls;
extern char pw_buf[256];               // first ParseWarning bytes
// LogMessage/WarningMessage/ParseError/ErrorMessage captures:
extern int logmsg_calls, warnmsg_calls, parseerr_calls, errmsg_calls;

// ---- StreamLog / BatchedLogManager (the 23f-era wall legs, OWN mirrors;
// the STREAMLOG + BATCHEDLOG capture homes ride the GLOBAL namespace the
// stream_log.h / batched_logger.h class-faces declare them in) ----
}
extern char sl_capture[64];
extern int  blog_log_calls, blog_flush_calls;
namespace snort {

// ---- Flow (never-land: detection/context_switcher.h face) ----
extern int flow_trust_calls;

// ---- dnet shim legs (the graft dnet.h face; libdnet ABSENT on this host) ----
extern int  eth_open_calls, eth_send_calls, eth_close_calls;
extern int  ip_open_calls,  ip_send_calls,  ip_close_calls;
extern int  dnet_eth_open_fail;        // 1 => eth_open returns null (FatalError leg)
extern int  dnet_ip_open_fail;         // 1 => ip_open returns null (FatalError leg)
extern int  dnet_send_fail;            // 1 => send rc mismatch (failed leg)
}
#endif

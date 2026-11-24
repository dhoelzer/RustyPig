// row-23b witness_sfinst.cc — the OWN-6 mirror face for the sfdaq_instance
// pair (541 L THE REAL-BODY ROW: sfdaq_instance.cc 436 + .h 105 compile
// VERBATIM against the REAL libdaq SDK @ c8d4083 + the 5 REAL api .o, so
// the SFDAQInstance methods are the GROUND bodies — the 23a witness-11
// stand-in law DIES HERE by design (plan-20's whole point; the row-23a
// harness copy-local witness mirrors STAY where they ride, NEVER touched).
// THIS file closes ONLY what the carried witness_conf 4dd91018 family +
// the REAL SDK do NOT close (the NEVER-double law, the rsubs :239 / 23a
// :287-:295 extraction law — FatalError + SnortConfig::get_conf +
// logging_flags + get_instance_id are CARRY-OWNED, NEVER doubled here):
//   (a) EXACTLY-3 message mirrors: LogMessage / ErrorMessage (messages.h
//       :56/:60) + ParseWarning (messages.h :50 — the DAQ_ValidateInstance
//       cc :65 inline-mode warning, the 23a face carried ZERO);
//   (b) OWN-3 provider stand-ins for the NOT-LANDED snort homes (honest
//       left-open cites, NEVER real bodies): daq_stats (the THREAD_LOCAL
//       DAQStats global, sfdaq_module.h :87 decl / body NOT-LANDED =
//       sfdaq_module.cc, the row AFTER this one — the cc :433
//       expected_flows++ needs the LINK symbol, the value faces ride the
//       vectors); layer::get_vlan_layer (layer.h :130 decl, body NOT-
//       LANDED protocols/layer.cc — the cc :407 read-face mirror, probe-
//       scripted storage wvlan_ptr); the minimal Packet ctor/dtor mirror
//       (packet.h :126-:127, body NOT-LANDED packet.cc — the 22b
//       tracer_harness mirror SHAPE, zero layer/alloc arms since the pair
//       ONLY reads the FIELD faces daq_msg/proto_bits at cc :372/:393-:406).
// knobs the probes read (the rsubs/23a witness-knob precedent): wlog_* /
// werr_* / wpw_* + wvlan_ptr (probe reads externs, NEVER re-defines; the
// probe-side scripted DAQ modules live in probe.cc — witness NEVER owns
// DAQ-module plumbing, the 23a own-11 seam-mirror shape is DEAD by design).
#include "log/messages.h"
#include "packet_io/sfdaq_module.h"   // the FRESH-cp DECL rider (DAQStats
                                      // record + extern daq_stats :87) —
                                      // the body home stays NOT-LANDED
                                      // (cite, never land)
#include "protocols/layer.h"          // the layer::get_vlan_layer DECL
                                      // (layer.h :130 — the mirror MUST
                                      // match the decl, so the header
                                      // rides; the BODY stays NOT-LANDED)
#include "protocols/packet.h"
#include "protocols/vlan.h"
#include <cstdarg>
#include <cstdio>
namespace snort {
// (a) the 3 message mirrors (messages.h variadic faces; FatalError rides
// the carried witness_conf — grep-pinned ZERO here by the build.sh):
char wlog_buf[4096]; unsigned wlog_calls = 0;
char werr_buf[4096];  unsigned werr_calls = 0;
char wpw_buf[4096];   unsigned wpw_calls = 0;
void LogMessage(const char* f, ...) { va_list a; va_start(a,f); vsnprintf(wlog_buf,sizeof wlog_buf,f,a); va_end(a); wlog_calls++; }
void ErrorMessage(const char* f, ...) { va_list a; va_start(a,f); vsnprintf(werr_buf,sizeof werr_buf,f,a); va_end(a); werr_calls++; }
void ParseWarning(WarningGroup g, const char* f, ...) { (void)g; va_list a; va_start(a,f); vsnprintf(wpw_buf,sizeof wpw_buf,f,a); va_end(a); wpw_calls++; }
// (b) OWN-3 provider stand-ins (NOT-LANDED bodies — link closure ONLY;
// every observable value face the vectors pin is listed with its cite):
}
// THE daq_stats GLOBAL face: sfdaq_module.h :61/:87 declare DAQStats +
// `extern THREAD_LOCAL DAQStats daq_stats` OUTSIDE namespace snort (the
// measured header face) — the mirror rides THE SAME global scope (the
// namespace-snort form would mint _ZN5snort9daq_statsE and leave the
// bare `daq_stats` the .cc :433 read UNDEFINED — caught at the link).
THREAD_LOCAL DAQStats daq_stats;                    // sfdaq_module.h :87 (body = sfdaq_module.cc, NOT-LANDED, row-after)
namespace snort {
const vlan::VlanTagHdr* wvlan_ptr = nullptr;        // probe-scripted arm storage
const vlan::VlanTagHdr* layer::get_vlan_layer(const Packet* p) { (void)p; return wvlan_ptr; }  // layer.h :130 (body NOT-LANDED)
Packet::Packet(bool) { }                            // packet.h :126 (packet.cc body NOT-LANDED; the 22b tracer mirror shape — zero allocs: the pair reads daq_msg/proto_bits FIELDS only)
Packet::~Packet() { }                               // packet.h :127
}

// row-23a witness_daqio.cc — the OWN-14 mirror face for the sfdaq pair.
// THE real-SDK row links the REAL libdaq api objects (api/daq_base.c
// daq_config.c daq_mod_ops.c daq_base_api.c daq_instance_api_defaults.c —
// ground READ-ONLY @ c8d4083) against the FRESH-cp ground sfdaq.cc, so the
// get_conf + FatalError closure rides the CARRIED witness_conf 4dd91018
// family (the rsubs :239-:249 extraction law — NEVER doubled). THIS file
// mirrors ONLY what that carry does NOT close and what row 23b (the
// sfdaq_instance provider, 436+105) will replace with REAL bodies:
//   (a) EXACTLY-3 message mirrors (log/messages.h :51 ParseError,
//       :56 LogMessage, :60 ErrorMessage — FatalError :105 is carry-owned);
//   (b) EXACTLY-11 SFDAQInstance mirrors (ctor + dtor + init +
//       get_input_spec + get_base_protocol + can_inject + can_inject_raw +
//       can_replace + get_tunnel_bypass + inject + get_stats — the 39-face
//       nm census of sfdaq.o names them; the bodies land REAL at row 23b,
//       NEVER invented here). Knobs the probes read: wlog_* / werr_* /
//       wperr_* + wsi_* (the rsubs witness-knob precedent, observables
//       ride the witness, probe.cc reads externs, NEVER re-defines).
// The stats mirror buffer IS REAL DAQ_Stats_t (96 L face — the REAL SDK
// sizeof face), populated so the REAL get_stats accessor chain (the
// wrapper copy, cc :399-:402 -> instance->get_stats()) returns an honest
// measurement, wsi_stats_pkts=11 pinned by vectors.
#include "log/messages.h"
#include "packet_io/sfdaq_instance.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
namespace snort {
// (a) the 3 message mirrors (messages.h variadic faces):
char wlog_buf[4096]; unsigned wlog_calls = 0;
char werr_buf[4096];  unsigned werr_calls = 0;
char wperr_buf[4096]; unsigned wperr_calls = 0;
void LogMessage(const char* f, ...) { va_list a; va_start(a,f); vsnprintf(wlog_buf,sizeof wlog_buf,f,a); va_end(a); wlog_calls++; }
void ErrorMessage(const char* f, ...) { va_list a; va_start(a,f); vsnprintf(werr_buf,sizeof werr_buf,f,a); va_end(a); werr_calls++; }
void ParseError(const char* f, ...) { va_list a; va_start(a,f); vsnprintf(wperr_buf,sizeof wperr_buf,f,a); va_end(a); wperr_calls++; }
// (b) the 11 SFDAQInstance mirrors (row 23b LEFT-OPEN providers):
unsigned wsi_ctor_calls = 0, wsi_dtor_calls = 0;
unsigned wsi_init_calls = 0, wsi_last_total_hint = 0;
char wsi_last_bpf[256]; const void* wsi_last_cfg = nullptr;
bool wsi_can_inject_b = false, wsi_can_inject_raw_b = false, wsi_can_replace_b = false;
bool wsi_bypass_b = false; unsigned wsi_bypass_proto = 0;
int wsi_inject_calls = 0, wsi_inject_rc = 7;
DAQ_Stats_t wsi_stats = { };
SFDAQInstance::SFDAQInstance(const char*, unsigned id, const SFDAQConfig*) { wsi_ctor_calls++; wsi_last_total_hint = id; }
SFDAQInstance::~SFDAQInstance() { wsi_dtor_calls++; }
bool SFDAQInstance::init(DAQ_Config_h cfg, const std::string& bpf) {
    wsi_init_calls++; wsi_last_cfg = (const void*)cfg;
    snprintf(wsi_last_bpf, sizeof wsi_last_bpf, "%s", bpf.c_str());
    return true;
}
const char* SFDAQInstance::get_input_spec() const { return "eth9"; }
int SFDAQInstance::get_base_protocol() const { return 101; }
bool SFDAQInstance::can_inject() const { return wsi_can_inject_b; }
bool SFDAQInstance::can_inject_raw() const { return wsi_can_inject_raw_b; }
bool SFDAQInstance::can_replace() const { return wsi_can_replace_b; }
bool SFDAQInstance::get_tunnel_bypass(uint16_t proto) { wsi_bypass_proto = proto; return wsi_bypass_b; }
int SFDAQInstance::inject(DAQ_Msg_h, int rev, const uint8_t*, uint32_t) { (void)rev; wsi_inject_calls++; return wsi_inject_rc; }
const DAQ_Stats_t* SFDAQInstance::get_stats() { return &wsi_stats; }
}

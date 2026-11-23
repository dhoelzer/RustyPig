// witness_tc.cc -- row 22a OWN-NEW snort-side witness (TRACKED; FRESH per
// the PLAN q2 audit: the carried stub families (stubs_18d/stubs_18f/
// witness_18f/flog 698-L stubs.cc) carry ZERO of these faces -- the fresh
// mini-witness BEATS inheritance at this row, recorded honestly). ONE-HOME
// law: the REAL time/periodic.cc stays periodic_harness home (:666!) -- the
// watchdog rides the watchdog_timer==0 default (ground snort_config.h :264)
// so kick_watchdog/update_thread_status return EARLY at the enabled-guard
// statics (cc :585/:604) and Periodic faces are DECL-witnessed ONLY (the
// gate NEVER runs real Periodic behavior). The numa trio rides the
// witness-home face (numa.h wrapper bodies call them; available()=0 +
// max_node()=0 => implement_thread_mempolicy FALSE early at max_node()<=0,
// the honest no-NUMA-host FACE-A arm). get_instance_id/get_thread_type/
// get_error are GLOBAL-scope faces matching the nm census (the .o U-lines
// print unqualified). ParseError vprints so the ground :114 bad-cpuset flow
// stays OBSERVABLE (the gate tail proves it: the WIT_PARSE_ERR line rides).
#include "log/messages.h"
#include "main/thread.h"
#include "time/periodic.h"
#include <cstdarg>
#include <cstdio>
extern "C" {
int numa_available() { return 0; }      // witness-model face (0 == NUMA up)
int numa_max_node() { return 0; }       // 0 => <=0 => false-ladder arm
int set_mempolicy(int mode, const unsigned long* mask, unsigned long max) {
    (void)mode; (void)mask; (void)max; return 0;
}
}
namespace snort {
void ParseError(const char* f, ...) { std::printf("WIT_PARSE_ERR "); va_list a; va_start(a,f); std::vprintf(f,a); va_end(a); }
void ParseWarning(WarningGroup g, const char* f, ...) { (void)g; (void)f; }
void LogMessage(const char* f, ...) { (void)f; }
void WarningMessage(const char* f, ...) { (void)f; }
void ErrorMessage(const char* f, ...) { (void)f; }
const char* get_error(int e) { (void)e; return "wit-error"; }
unsigned get_instance_id() { static unsigned id = 0; return id; }
SThreadType get_thread_type() { return STHREAD_TYPE_MAIN; }
}
void Periodic::register_handler(PeriodicHook h, void* u, uint16_t p, uint32_t r) { (void)h; (void)u; (void)p; (void)r; }
void Periodic::check() {}
void Periodic::unregister_handler(PeriodicHook h) { (void)h; }
void Periodic::unregister_all() {}

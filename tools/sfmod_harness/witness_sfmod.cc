// row-23c witness_sfmod.cc — the OWN mirror face for the sfdaq_module pair
// (packet_io/sfdaq_module.cc 298 md5 0c42d293d1b7989d54b25eb493b7936b +
// .h 89 md5 14c6c3676e184501d99c8dc39061d496 @ fe29cbe). THE real-body row:
// the pair .o OWNS `THREAD_LOCAL DAQStats daq_stats` (cc :218) — the row
// body is the ONE home, a doubled mirror here = multiple-definition (the
// E9 dup-proof arm below pins it). THIS file closes ONLY what the carried
// witness_conf 4dd91018 family + the REAL bodies (module.cc / value.cc /
// sfdaq_config.cc) do NOT close (NEVER doubled — the carry law: FatalError,
// SnortConfig ctor/dtor/statics/get_conf, show_stats x2, get_instance_id,
// ThreadConfig::get_instance_max, get_thread_type, get_main_file,
// get_instance_file, LogEthAddrs are CARRY-OWNED; the 23b OWN face
// LogMessage/ErrorMessage/ParseWarning + the 23b DAQStats-holder mirror +
// get_vlan_layer + the Packet ctor NEVER ride THIS file — the module TU
// pulls NONE of them, measured at the sfmod .o nm face):
//   (a) OWN-1 message mirror: ParseError (messages.h :51 — the end() :156
//       leg; capture + counter, the wpw_buf family shape of the 23b own
//       face);
//   (b) OWN-2 SFDAQ static-class provider stand-ins (sfdaq.h :52/:63 the
//       DECLS; the sfdaq.cc BODIES stay unlinked C-side BY DESIGN — the
//       Rust port owns that walk at 23a/23b; scripted knobs NEVER the real
//       load/init ladder): wlocal over get_local_instance, wstats over
//       get_stats;
//   (c) the Trough static-member DEFINITION mirror (trough.h :84 `static
//       std::atomic<unsigned> file_count;` — the member the two header
//       INLINES at :48-:55 pull; the trough.cc DEFINITION home stays NOT-
//       LANDED and the REAL bump lives in get_next (NOT linked) = the
//       honest never-bumped pcaps=0 face, cited at the vectors). Other
//       Trough statics NEVER pulled by the module TU (the header NEVER
//       calls the out-of-line legs from this row's faces).
// knobs the probe scripts (witness NEVER touches them): wlocal + wstats;
// the probe reads wpe_buf/wpe_calls.
#include "log/messages.h"
#include "packet_io/sfdaq_module.h"   // DAQStats + `extern THREAD_LOCAL
                                      // DAQStats daq_stats;` :87 — the
                                      // DEFINITION rides the row .cc (the
                                      // E9 dup law pins ONE home)
#include "packet_io/sfdaq.h"          // the SFDAQ decls (bodies NEVER linked)
#include "packet_io/trough.h"         // the fresh-cp DECL rider (the
                                      // file_count member-def mirror)
#include <cstdarg>
#include <cstdio>

DAQ_Stats_t wstats;   // scripted BEFORE the ns face (the probe externs it
                      // at GLOBAL scope too; the get_stats mirror returns it)

namespace snort {
// (a) OWN-1 message mirror (the 23b wpw_buf capture shape):
char wpe_buf[4096]; unsigned wpe_calls = 0;
void ParseError(const char* f, ...) { va_list a; va_start(a,f); vsnprintf(wpe_buf,sizeof wpe_buf,f,a); va_end(a); wpe_calls++; }

// (a2) the util.o pull (the REAL util body rides the link for the sf_ip
// SnortSnprintf/util face; rotate_file_for_max_size NEVER runs here):
// inert mirrors owned ONLY by THIS link (the 23b-row witness owns the
// SAME decls in ITS link — no doubling: two links, one home per link, and
// the E9 dup twin re-pins it HERE):
void LogMessage(const char*, ...) {}
void ErrorMessage(const char*, ...) {}

// (b) OWN-2 SFDAQ provider stand-ins (scripted knobs; the probe sets both):
void* wlocal = nullptr;
SFDAQInstance* SFDAQ::get_local_instance() { return (SFDAQInstance*)wlocal; }
const DAQ_Stats_t* SFDAQ::get_stats() { return &::wstats; }
}

// (c) the Trough file_count DEFINITION mirror at zero (the definition-
// mirror posture, cited; pcap_filter/pcap_queue/pcap_object_list NEVER
// pulled — the header's non-called INLINEs never codegen a reference):
std::atomic<unsigned> Trough::file_count{0};

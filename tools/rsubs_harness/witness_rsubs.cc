// row 21a witness_rsubs.cc — the EXACTLY-3 OWN-NEW mirror trio (PLAN §2:
// the L1 census over (row .o + 7-object backbone + WIN trio) = EXACTLY-3
// distinct own-new undefined: DataBus::_subscribe(const PubKey&, unsigned,
// DataHandler*) (the friend-unlock PRIVATE overload, data_bus.h:127 friend
// + :130 signature face, body-shape cite data_bus.cc:210), SnortConfig::
// get_reload_id() (snort_config.h:775 the NOT-const member signature face),
// WarningMessage(const char*, ...) (messages.h:58 variadic face)). The
// carried witness_conf 4dd91018 closes SnortConfig::get_conf() — NEVER
// doubled here (the dup-symbol multiple-definition law, receipts syntax_
// witness run1 + iph_link). Observables ride the witness (the misc9_
// prompt_calls precedent): wrsubscribe_calls / wrwarn_calls /
// wr_last_warn / wr_last_handler — probe.cc reads externs, NEVER
// re-defines the mirrors. get_reload_id() returns 7 (the T8c 'reload id
// 7' substring face rides this face EXACTLY).
#include "framework/data_bus.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include <cstdarg>
#include <cstdio>
namespace snort {
unsigned wrsubscribe_calls = 0;
unsigned wrwarn_calls = 0;
char wr_last_warn[2048];
DataHandler* wr_last_handler = nullptr;
void DataBus::_subscribe(const PubKey& key, unsigned evt_id, DataHandler* h) {
    (void)key; (void)evt_id; wr_last_handler = h; wrsubscribe_calls++;
}
unsigned SnortConfig::get_reload_id() { return 7; }
void WarningMessage(const char* fmt, ...) { va_list a; va_start(a,fmt); vsnprintf(wr_last_warn,sizeof wr_last_warn,fmt,a); va_end(a); wrwarn_calls++; }
}

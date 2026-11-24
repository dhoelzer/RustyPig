// row-23d witness_dirstor.cc — the OWN mirror face for the directory +
// trough two-pair (helpers/directory.cc 113 e0e4af65 + .h 49 f7eac140;
// packet_io/trough.cc 265 c9aa106b + .h 88 7931b6ef @ fe29cbe). THE
// row-body link carries the REAL homes: dir.o (THE Directory definitions)
// + trough.o (THE Trough definitions INCLUDING the file_count B-symbol —
// ONE home, the 23c mirror placeholder CLOSED here, the E9 dup twin pins
// any mirror as the multiple-definition reject) + util.o (get_error REAL).
// THIS file closes ONLY what the carried witness_conf 4dd91018 family (the
// extraction + the 23b noreturn rider live in build.sh — NEVER doubled,
// NEVER edited) does NOT close:
//   (a) OWN-1 the ErrorMessage CAPTURE mirror (log/messages.h — the trough
//       error legs :52/:74/:93/:112/:127/:151/:157 print through it;
//       vsnprintf into wmsg_buf + counter, the 23c-era wpe_buf capture shape;
//       the probe reads wmsg_buf/wmsg_calls);
//   (b) the INERT LogMessage mirror (the util.o pull — rotate_file legs;
//       NEVER runs in this session; the 23c-era link owned the SAME decls in
//       ITS link — two links, one home per link, the E9 twin re-pins HERE).
// FatalError / SnortConfig / get_instance_id / ThreadConfig::get_instance_max
// / show_stats x2 / get_main_file / get_instance_file / LogEthAddrs ride the
// CARRIED witness_conf family (the 23b jump-site rider makes the probe's
// sigsetjmp arms LIVE); ParseError NEVER rides this file (the directory/
// trough TUs pull ZERO ParseError — measured at the .o nm face, the
// NEVER-doubled law vs the 23c-era link own-1). The Trough::file_count
// DEFINITION NEVER rides this file (the ONE-home face: trough.cc :45 owns
// it — THIS is what the whole 23c mirror existed for).
// C uses the GNU strerror_r branch via util.o — the same glibc face the
// landed Rust utils home links directly.
#include "log/messages.h"     // ErrorMessage / LogMessage decls (the mirrors)

#include <cstdarg>
#include <cstdio>

namespace snort {
// (a) OWN-1 the ErrorMessage capture mirror (the 23c-era wpe_buf shape):
char wmsg_buf[4096]; unsigned wmsg_calls = 0;
void ErrorMessage(const char* f, ...) { va_list a; va_start(a,f); vsnprintf(wmsg_buf,sizeof wmsg_buf,f,a); va_end(a); wmsg_calls++; }

// (b) the util.o-pull inert mirror (owned ONLY by THIS link):
void LogMessage(const char*, ...) {}
}

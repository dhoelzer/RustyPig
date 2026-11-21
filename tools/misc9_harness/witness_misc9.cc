// 19a THE own-new witness face (MEASURED +1, NOT the sibling recon's +2: the
// spec-correction face PLAN §9 records honestly, disk-wins law). Recon's
// +2 face (LogMessage + ControlConn::show_prompt over nm_U_tracker.txt) was
// staged against (donor OBJS + witness_conf) ONLY; the FULL carried WIN trio
// includes eth_harness/stubs_18d.cc whose SEAM #3 already defines
// snort::LogMessage(const char*, ...) -- vprintf body (grep -n pins the line
// in build.sh) -- so the LogMessage half is CLOSED by the CARRIED face (and
// a second body = a multiple-definition link error, proven in scratch
// run1: 'multiple definition of snort::LogMessage'; witness_misc9.o vs
// stubs_18d.o -- the dup-symbol law, 18d trio-retirement precedent). The
// L1 re-measure (row TU pairs + OBJS + WIN trio, NO own witness) leaves
// EXACTLY-1 distinct undefined: ControlConn::show_prompt() -- the ONLY own-
// new face THIS row adds (the 18n witness_pkthdr EXACTLY-+1 shape, daq3
// witness_daq precedent).
// Body SYNTHETIC by design (the 17d seam, witness_18f/witness_pkthdr
// counter precedent): the ground body (control/control.cc show_prompt) drags
// the shell/pending_commands world (control.h :28-:30 queue/string/vector
// includes + the ControlConn lifecycle) -- cited-never-compiled (the miscip
// R1 law). The stub NEVER dereferences this: reload_tracker.cc :63
// ctrl->show_prompt() is legal on the harness scenario's null ctrl because
// the body touches ONLY the witness-side counter misc9_prompt_calls() --
// the honest OBSERVABLE for the :62/:63 prompt arm; the ground ControlConn
// instance is NEVER fabricated (its ctor is not linked).
#include "control/control.h"
static int g_prompt = 0;
bool ControlConn::show_prompt() { ++g_prompt; return true; }    // control.h:53 decl face
extern "C" int misc9_prompt_calls() { return g_prompt; }

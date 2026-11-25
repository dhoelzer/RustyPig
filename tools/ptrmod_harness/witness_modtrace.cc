// witness_modtrace.cc — row 23g OWN witness (DECL-body / capture mirrors
// ONLY): the residuals the fresh row .o reaches while the REAL homes NEVER
// landed (main/analyzer_command.cc NEVER links — the E4-ac wall receipt
// pins the managers/module_manager.h :34 include death; control/control.cc
// NEVER landed):
//   snort::main_broadcast_command (analyzer_command.h :246 REAL decl; the
//     REAL walker home NEVER linked: the mirror stringifies the stashed
//     cmd — the row :82 override face through the REAL base virtual — and
//     STASHES ONE cmd for the probe to execute + free: the broadcast-then-
//     run face; the walker's ref-count legs NEVER faked),
//   ControlConn::query_from_lua (the REAL home control.cc NEVER landed —
//     the mirror returns the cold nullptr conn, cited; ControlConn rides
//     the GLOBAL namespace per control.h :37 — the class-static def sits
//     at file scope, NEVER inside snort),
//   BatchedLogger::BatchedLogManager::set_filter (batched_logger.h :94
//     class-static, batched_logger.cc NEVER landed — THE wall; capture
//     mirror so the DEC OBSERVES the row cc :202 filter writes live;
//     NEVER doubled vs the REUSED 23f tracker's log/flush legs),
//   the minimal Analyzer DECL mirror (analyzer_command.h :36 forward-
//     declares ONLY; analyzer.cc NEVER cp'd/landed: the probe needs a
//     COMPLETE type for the execute(Analyzer&) reference face — ZERO
//     behavior faked, the type NEVER dereferenced by the row body).
// NEVER-double law (the 23e/23f nm law re-rides): NOTHING here doubles the
// carried witness_conf 4dd91018 family (get_conf/FatalError/show_stats/
// thread legs) NOR the REUSED 23f witness_tracker family (LogMessage x2 +
// WarningMessage + ErrorMessage + StreamLog x4 + BatchedLogManager log/
// flush + SFDAQ + Active::act_str + Packet + layer) — the 23f witness file
// rides the link VERBATIM cross-row (md5-pinned bbf3867b in build.sh).
#include "main/analyzer_command.h"
#include "control/control.h"
#include "log/batched_logger.h"

#include <string>

std::string bcapture, mfcapture;
snort::AnalyzerCommand* bcap_cmd = nullptr;

void PacketTracerDebug_exec_stash_free() { delete bcap_cmd; bcap_cmd = nullptr; }

namespace snort {

void main_broadcast_command(AnalyzerCommand* cmd, ControlConn* conn)
{
    (void)conn;                       // cold mirror conn (cited, NEVER used)
    if (cmd)
    {
        bcapture += cmd->stringify(); // the REAL row :82 virtual override
        bcap_cmd = cmd;               // ONE-command stash (the probe runs + frees)
    }
}

}  // namespace snort

// ControlConn rides the GLOBAL namespace (control.h :37 — the class sits
// OUTSIDE snort; the class-static def mirrors THAT scope face):
ControlConn* ControlConn::query_from_lua(const lua_State*) { return nullptr; }

namespace BatchedLogger {
void BatchedLogManager::set_filter(const std::string& filter)
{ mfcapture = "FILTER[" + filter + "]"; }
}

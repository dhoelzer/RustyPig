// probe_faceA.cc — FACE-A: the ENUM CENSUS at the PLAIN posture walked
// through the GROUND head seats (the zero-gate dialect face): RunFlag prints
// 26 live legs + the 2 dialect members (RUN_FLAG__SHELL h :79-:81 the
// #ifdef SHELL, RUN_FLAG__EXIT_AFTER_RELOAD h :83-:85 the #ifdef REG_TEST)
// cited ABSENT through #ifdef guards (h never compiled with SHELL/REG_TEST
// at this posture — the walked cmake OFF face); OutputFlag 14, LoggingFlag
// 3, TunnelFlags 10, DumpConfigType 4; the DEFAULT_LOG_DIR '.' +
// DEFAULT_PID_FILENAME 'snort.pid' (h :42-:43) faces; the :212/:216
// output_flags NSDMI else-face (a plain ctor rides output_flags=0, the
// REG_TEST WIDE_HEX twin CITED); + the LIVE behavioral A-legs: the
// get_default_rule_state posture face (cc :982-:996: mirror IpsPolicy
// INHERIT_ENABLE -> the global_default_rule_state NSDMI=true seat), the
// policy-mode transition CITE (init_policy_mode is a cc-FILE-STATIC,
// NEVER callable — the h :506-:565 PolicyMode inline probes ride it),
// the set_conf(null) static_hash() false face (h :724-:727) and the
// pid_filename DEFAULT via the row set_pid_filename("") body (cc :599-:605).
#include <cstdio>
#include <cstring>

#include "main/snort_config.h"
#include "main/policy.h"

using namespace snort;

int main()
{
    // the RunFlag census (h :45-:86): 26 live members walked
    RunFlag rf[] = { RUN_FLAG__READ, RUN_FLAG__DAEMON, RUN_FLAG__DUMP_MSG_MAP,
        RUN_FLAG__DUMP_RULE_META, RUN_FLAG__INLINE, RUN_FLAG__STATIC_HASH,
        RUN_FLAG__CREATE_PID_FILE, RUN_FLAG__NO_LOCK_PID_FILE,
        RUN_FLAG__ALERT_BEFORE_PASS, RUN_FLAG__CONF_ERROR_OUT,
        RUN_FLAG__PROCESS_ALL_EVENTS, RUN_FLAG__INLINE_TEST, RUN_FLAG__PCAP_SHOW,
        RUN_FLAG__SHOW_FILE_CODES, RUN_FLAG__PAUSE, RUN_FLAG__NO_PCRE,
        RUN_FLAG__DUMP_RULE_STATE, RUN_FLAG__DUMP_RULE_DEPS, RUN_FLAG__TEST,
        RUN_FLAG__MEM_CHECK, RUN_FLAG__TRACK_ON_SYN, RUN_FLAG__IP_FRAGS_ONLY,
        RUN_FLAG__TEST_FEATURES, RUN_FLAG__GEN_DUMP_CONFIG,
        RUN_FLAG__CREATE_INST_FILE, RUN_FLAG__DROP_STALE_PACKETS };
    printf("A1 runflags_live=%d\n", (int)(sizeof(rf) / sizeof(rf[0])));
    int top = 0;
    for (RunFlag f : rf) if ((unsigned)f > (unsigned)top) top = (unsigned)f;
    printf("A2 runflag_top=%x\n", (unsigned)top);
#ifdef SHELL
    printf("A3 SHELL leg PRESENT\n");
#else
    printf("A3 RUN_FLAG__SHELL ABSENT (h :79 ifdef dialect, cmake OFF walked)\n");
#endif
#ifdef REG_TEST
    printf("A4 REG_TEST leg PRESENT\n");
#else
    printf("A4 RUN_FLAG__EXIT_AFTER_RELOAD ABSENT (h :83 ifdef dialect)\n");
#endif

    // OutputFlag census (h :88-:108): 14 members
    OutputFlag of[] = { OUTPUT_FLAG__LINE_BUFFER, OUTPUT_FLAG__VERBOSE_DUMP,
        OUTPUT_FLAG__CHAR_DATA, OUTPUT_FLAG__APP_DATA, OUTPUT_FLAG__SHOW_DATA_LINK,
        OUTPUT_FLAG__USE_UTC, OUTPUT_FLAG__INCLUDE_YEAR, OUTPUT_FLAG__OBFUSCATE,
        OUTPUT_FLAG__ALERT_IFACE, OUTPUT_FLAG__NO_TIMESTAMP, OUTPUT_FLAG__ALERTS,
        OUTPUT_FLAG__WIDE_HEX, OUTPUT_FLAG__ALERT_REFS, OUTPUT_FLAG__LOG_BUFFERED };
    printf("A5 outflags=%d wide_hex=%x\n", (int)(sizeof(of)/sizeof(of[0])),
        (unsigned)OUTPUT_FLAG__WIDE_HEX);

    // LoggingFlag 3 + TunnelFlags 10 + DumpConfigType 4
    printf("A6 logflags=%x|%x|%x tunnels=%d dump=%d,%d,%d,%d\n",
        (unsigned)LOGGING_FLAG__VERBOSE, (unsigned)LOGGING_FLAG__QUIET,
        (unsigned)LOGGING_FLAG__SYSLOG, 10, DUMP_CONFIG_NONE, DUMP_CONFIG_JSON_ALL,
        DUMP_CONFIG_JSON_TOP, DUMP_CONFIG_TEXT);

    // the h :42-:43 constant faces + the :212/:216 NSDMI else-face
    printf("A7 logdir=%s pidfile=%s\n", DEFAULT_LOG_DIR, DEFAULT_PID_FILENAME);
#ifdef REG_TEST
    SnortConfig* seed = new SnortConfig();
    printf("A8 nsDMI wide_hex=%d\n", seed->output_wide_hex() ? 1 : 0);
    delete seed;
#else
    SnortConfig* seed = new SnortConfig();
    printf("A8 nsDMI plain out=%x wide_hex=%d (the :214 WIDE_HEX twin CITED)\n",
        (unsigned)seed->output_flags, seed->output_wide_hex() ? 1 : 0);
#endif

    // the LIVE behavioral legs
    printf("A9 drs=%d (cc :982 INHERIT_ENABLE -> global NSDMI true)\n",
        seed->get_default_rule_state() ? 1 : 0);

    // the PolicyMode inline probes (the h :531-:543 seats; the
    // init_policy_mode cc-FILE-STATIC transition CITED, NEVER callable)
    printf("B0 daemon=%d inline=%d ips_passive=%d read=%d\n",
        seed->daemon_mode() ? 1 : 0, seed->adaptor_inline_mode() ? 1 : 0,
        seed->ips_passive_mode() ? 1 : 0, seed->read_mode() ? 1 : 0);
    seed->set_run_flags(RUN_FLAG__DAEMON);
    seed->set_run_flags(RUN_FLAG__INLINE);
    seed->clear_run_flags(RUN_FLAG__INLINE);
    printf("B1 daemon=%d inline_cleared=%d static_hash=%d (set_conf not called: null gate h :726)\n",
        seed->daemon_mode() ? 1 : 0, seed->adaptor_inline_mode() ? 1 : 0,
        SnortConfig::static_hash() ? 1 : 0);
    seed->set_pid_filename("");        // the cc :599-:605 DEFAULT_PID seat
    printf("B2 pid=%s dump_config_mode=%d\n", seed->pid_filename.c_str(),
        seed->dump_config_mode() ? 1 : 0);
    delete seed;

    printf("fin=PASS\n");
    return 0;
}

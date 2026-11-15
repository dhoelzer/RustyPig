// Ground-truth probe for ORIGINAL log/messages.cc (compiled verbatim) +
// log_errors counters. FatalError/_exit and assert paths run in forked
// children; both streams unbuffered so markers interleave exactly.
#include "log/messages.h"
#include "log/log_errors.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <cmath>
#include <cstdint>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

using namespace snort;

extern bool g_reentrant_cleanup;

#define M(x) std::printf("%s\n", x)

static void run_child(const char* label, void (*fn)())
{
    fflush(nullptr);
    pid_t pid = fork();
    if (pid == 0)
    {
        fn();
        _exit(0); // unreachable for fatal paths
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st))
        std::printf("#%s exit=%d\n", label, WEXITSTATUS(st));
    else
        std::printf("#%s sig=%d\n", label, WTERMSIG(st));
    fflush(stdout);
}

static void fatal_no_loc()      { ParseAbort("plain abort %d\n", 9); }
static void fatal_with_loc()    { set_parse_loc("foo.rules", 42); ParseAbort("abort at %s here\n", "thing"); }
static void fatal_file_noline() { set_parse_loc("bar.rules", 0);   ParseAbort("file-but-no-line\n"); }
static void fatal_direct()      { FatalError("direct %d\n", 5); }
static void fatal_reentrant()
{
    g_reentrant_cleanup = true;
    FatalError("outer before reentrant cleanup\n");
}
static void safec_first()       { log_safec_error("boom", nullptr, 7); }

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    SnortConfig::warning_flags = 0;

    // P1: conf present, warning_flags 0 -> suppressed
    M("#P1");
    ParseWarning(WARN_VARS, "suppressed %d", 7);

    // P2: only WARN_VARS enabled; other groups stay suppressed
    M("#P2");
    SnortConfig::warning_flags = (1u << WARN_VARS);
    ParseWarning(WARN_RULES, "rules-suppressed");
    ParseWarning(WARN_VARS, "vars-shown %d", 1);

    // P3: each group's own bit
    M("#P3");
    for (int wg = WARN_DAQ; wg < WARN_MAX; ++wg)
    {
        SnortConfig::warning_flags = (1u << wg);
        ParseWarning((WarningGroup)wg, "g%d ok", wg);
    }

    // P4: all enabled, then conf-null passthrough (condition short-circuits)
    M("#P4");
    SnortConfig::warning_flags = ~0u;
    ParseWarning(WARN_CONF_STRICT, "strict mode msg");

    // P5: location branches (WARNING uses log_message: 3-way)
    M("#P5");
    set_parse_loc("foo.rules", 42);
    ParseWarning(WARN_VARS, "with loc %s", "x");
    set_parse_loc("bar.rules", 0);
    ParseWarning(WARN_VARS, "file no line");
    set_parse_loc(nullptr, 0);
    ParseWarning(WARN_VARS, "no loc");

    // P6: ERROR location branches
    M("#P6");
    set_parse_loc("a.rules", 7);
    ParseError("bad %s here", "thing");
    set_parse_loc("b.rules", 0);
    ParseError("err file noline");
    set_parse_loc(nullptr, 0);
    ParseError("err plain %u", 12u);

    // P7: ReloadError description join (comma, no space)
    M("#P7");
    ReloadError("first");
    ReloadError("second %d", 2);
    ReloadError("third");
    std::printf("#desc=%s\n", get_reload_errors_description().c_str());
    std::printf("#reload=%u\n", get_reload_errors());
    reset_reload_errors();
    std::printf("#desc2=%s\n", get_reload_errors_description().c_str());
    std::printf("#reload2=%u\n", get_reload_errors());

    // P8: STD_BUF truncation asymmetry: ParseError vsnprintf(STD_BUF) vs
    // ReloadError vsnprintf(sizeof(buf)) -> off-by-one payload length
    M("#P8");
    std::string big = std::string(1500, 'A') + std::string(1500, 'B');
    ParseError("%s", big.c_str());
    ReloadError("%s", big.c_str());
    std::printf("#reloadbig=%c\n", get_reload_errors_description()[2047]);

    // P9-P11: ParseAbort -> FatalError (forked)
    M("#P9");
    run_child("fatal-noloc", fatal_no_loc);
    M("#P10");
    run_child("fatal-loc", fatal_with_loc);
    M("#P11");
    run_child("fatal-filenoliner", fatal_file_noline);

    // P12: direct FatalError + reentrant after already_fatal
    M("#P12");
    run_child("fatal-direct", fatal_direct);
    M("#P13");
    run_child("fatal-reentrant", fatal_reentrant);

    // P14: log_safec_error: message then assert(false)
    M("#P14");
    run_child("safec", safec_first);

    // P15: quiet gating
    M("#P15");
    SnortConfig::set_log_quiet(true);
    LogMessage("quiet-suppressed %d", 1);
    LogMessage(stderr, "stderr-shown-despite-quiet\n");
    WarningMessage("warn-msg %s", "w");
    ErrorMessage("err-msg %s", "e");
    SnortConfig::set_log_quiet(false);
    LogMessage("not-quiet %d", 3);

    // P15b: syslog branch (syslog() itself stubbed at link time by
    // stubs.cc, so the prio+text are captured into the vectors)
    M("#P15b");
    SnortConfig::logging_flags |= 4; // LOGGING_FLAG__SYSLOG
    LogMessage("syslog-info %d", 1);
    LogMessage(stderr, "syslog-stderr-forced %d", 2);
    WarningMessage("syslog-warn");
    ErrorMessage("syslog-err %s", "e");
    set_parse_loc("z.rules", 3);
    ParseWarning(WARN_RULES, "syslog-warn-group %d", 9);
    ParseError("syslog-parse-err %d", 8);
    SnortConfig::logging_flags &= ~4u;
    SnortConfig::warning_flags = (1u << WARN_RULES);
    ParseWarning(WARN_RULES, "back-to-stderr");

    // P16: LogMessage to a non stdio-default FILE*
    M("#P16");
    FILE* tmp = tmpfile();
    LogMessage(tmp, "to-file %s\n", "hi");
    fflush(tmp);
    rewind(tmp);
    std::printf("#tmpfile=");
    int ch;
    while ((ch = fgetc(tmp)) != EOF) std::putchar(ch);
    std::putchar('\n');
    fclose(tmp);

    // P17: format battery (glibc printf semantics contract for the port)
    M("#P17");
    LogMessage("[%s|%8s|%25.25s|%-8s|]", "ab", "cd", "012345678901234567890123456789", "ef");
    LogMessage("[%*s|%*s|%*s|]", 5, "w5", 0, "w0", 30, "w30");
    LogMessage("[nul:%*s]", 3, (const char*)nullptr);
    LogMessage("[neg:%-8s|pos:%8s|]", "L", "R");
    LogMessage("[%d|%d|%+d|% d|%02d|%02d]", 7, -8, 9, -10, 3, -7);
    LogMessage("[intmin:%d|intmin:%d]", -2147483647 - 1, INT32_MIN);
    LogMessage("[u8:%8u|u16:%16u|x:%08x|X:%04X]", 4000000000u, 1u, 255u, 48823u);
    LogMessage("[lu:%lu|l06:%06lu|lld:%lld|llu:%llu]", 4294967296UL, 42UL,
               -9223372036854775807LL - 1, 18446744073709551615ULL);
    LogMessage("[zd:%zd|%zu]", (ssize_t)-5, (size_t)9);
    LogMessage("[hd:%hhd|hu:%hhu|wd:%hd]", -3, 200, -300);
    LogMessage("[prec:%.*s|negprec:%.*s|]", 3, "abcdef", -1, "ghij");
    LogMessage("[f:%f|lf:%lf|f2:%.2f|g:%g]", 1.5, 2.25, 3.14159, 0.0001);
    LogMessage("[pct:100%%done]");
    LogMessage("[e:%e|E:%E|g6:%.6g|exp:%.2e]", 123456.789, 123456.789, 123456.789, 0.5);
    LogMessage("    %18.18s(v%u)%s", "averyveryverylongname123", 4, "\n");
    LogMessage("[fmtu64:%" PRIu64 "|fmtx:%" PRIx64 "]", (uint64_t)5, (uint64_t)255);

    // P17b: converter battery 2 — float edge + width/flag edges
    M("#P17b");
    LogMessage("[g0:%.0g|g1:%.1g|g3:%.3g|g20:%.20g]", 123456.0, 123456.0, 123456.0, 123456.0);
    LogMessage("[g5:%.5g|g6:%.6g|g7:%.7g]", 0.0000123456, 0.0000123456, 0.0000123456);
    LogMessage("[h1:%.1g|h2:%.2g|h3:%.3g|hf:%.1f]", 0.125, 0.125, 0.125, 0.125);
    LogMessage("[h2:%.5g|h5:%.6g]", 0.135, 0.135);
    LogMessage("[e0:%.0e|e1:%.1e|e3:%.3e]", 0.5, 0.5, 0.5);
    LogMessage("[z:%f|zi:%i|inf:%f|-inf:%f|q:%f]", 0.0, 0, INFINITY, -INFINITY, NAN);
    LogMessage("[einf:%e|qg:%g|qf:%f]", INFINITY, NAN, NAN);
    LogMessage("[big:%.2f|rnd:%.10f]", 1e30, 0.0078125);
    LogMessage("[negw:%-8s|%5.2f|%12.10f]", "nw", -1.5, 0.0078125);
    LogMessage("[zero:%08x|zerof:%08.3f|lz0:%-#08x|hash:%#x|%#.5g]", 255, 1.5, 9, 255, 123456.0);
    LogMessage("[oct:%o|octw:%#o|c:%c|%5c]", 8, 8, 'A', 'Z');
    LogMessage("[dot0:%.0s|dot0w:%8.0s]", "zz", "yy");
    LogMessage("[x8:%#8x|%8o]", 255, 8);
    LogMessage("[negprecw:%*s]", -4, "wp");

    // P18: Dumper (header-only in messages.h)
    M("#P18");
    {
        Dumper d("dump header");
        d.dump("name-one", 1);
        d.dump("two", 2);
        d.dump("averyveryverylongname123", 3);
        d.dump("four", 4);
        d.dump("five", 5);
        d.dump("six", 6);
    }
    {
        Dumper d2(nullptr, 2);
        d2.dump("a", 0u);
        d2.dump("b", 0u);
        d2.dump("c", 0u);
        d2.dump("name", "ns");
    }
    // (Dumper max=0 pins nothing: `++idx % max` is a hardware SIGFPE,
    // not printable; the port models it with checked remainder and the
    // destructor's `idx % max`.)

    // P19: ConfigLogger battery
    M("#P19");
    ConfigLogger::log_option("TopOption");
    bool f = ConfigLogger::log_flag("capT", true);
    std::printf("#flagT=%d\n", (int)f);
    ConfigLogger::log_flag("capF", false);
    ConfigLogger::log_flag("sub", true, true);
    std::printf("#flagS=%d\n", (int)ConfigLogger::log_flag("sub2", false, true));
    ConfigLogger::log_limit("li1", 5, 5);
    ConfigLogger::log_limit("li2", 6, 9);
    ConfigLogger::log_limit("li3", 7u, 7u);
    ConfigLogger::log_limit("li4", (long)8, 8);
    ConfigLogger::log_limit("li5", (unsigned long)9, 9u);
    ConfigLogger::log_limit("li6", (long long)-10, -10);
    ConfigLogger::log_limit("li7", (unsigned long long)11, 11u);
    ConfigLogger::log_limit("ld1", 4, 9, 4);   // disable
    ConfigLogger::log_limit("ld2", 5, 5, 4);   // unlim checked after disable
    ConfigLogger::log_limit("ld3", 6u, 9u, 6u);
    ConfigLogger::log_limit("ld4", (long)-7, -9, -7);
    ConfigLogger::log_value("v1", 42, "desc");
    ConfigLogger::log_value("v2", 7);
    ConfigLogger::log_value("v3", 8u);
    ConfigLogger::log_value("v4", (long)-9);
    ConfigLogger::log_value("v5", (unsigned long)10);
    ConfigLogger::log_value("v6", (long long)-11);
    ConfigLogger::log_value("v7", (unsigned long long)12);
    ConfigLogger::log_value("v8", 3.5);
    ConfigLogger::log_value("v9", "strval");
    ConfigLogger::log_value("v10", "");
    ConfigLogger::log_value("v11", (const char*)nullptr);
    ConfigLogger::log_list("ll1", "tok1 tok2 tok3");
    ConfigLogger::log_list("ll2", "a bb ccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo pppp qqqq rrrr ssss tttt uuuu vvvv wwww xxxx yyyy zzzz 0000 1111 2222 3333 4444 5555 6666 7777 8888 9999");
    ConfigLogger::log_list("ll3", "x y z", " | ");
    ConfigLogger::log_list((const char*)nullptr, "capnull tok");
    ConfigLogger::log_list("", "capempty tok");
    ConfigLogger::log_list("");
    ConfigLogger::log_list("single tok chain that is long single tok chain that is long single tok chain that is long single tok chain");

    // P20: counters end-of-session (note reset_parse_errors also clears reload)
    M("#P20");
    std::printf("#warns=%u\n", get_parse_warnings());
    std::printf("#warns2=%u\n", get_parse_warnings());
    std::printf("#errs=%u\n", get_parse_errors());
    std::printf("#errs2=%u\n", get_parse_errors());
    std::printf("#reload3=%u\n", get_reload_errors());
    reset_parse_errors();
    std::printf("#errs3=%u\n", get_parse_errors());
    std::printf("#reload4=%u\n", get_reload_errors());
    return 0;
}

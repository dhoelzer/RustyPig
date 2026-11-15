// probe.cc — ground-truth driver for ORIGINAL main/thread.cc naming +
// log/text_log.cc buffered logging. time() is stubbed (see stubs.cc) so
// roll filenames are deterministic. FatalError _exit(1) paths run in
// forked children; stderr carries the real messages.cc output, stdout
// the vector markers.
#include <dirent.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "main/thread.h"
#include "main/thread_config.h"
#include "main/snort_config.h"
#include "log/text_log.h"
#include "log/messages.h"

using namespace snort;

SnortConfig& probe_conf();
void bump_clock(long);

static void reset_conf()
{
    SnortConfig& c = probe_conf();
    c.log_dir.clear();
    c.run_prefix.clear();
    c.id_offset = 0;
    c.id_subdir = false;
    c.id_zero = false;
    ThreadConfig::set_instance_max(1);
    set_instance_id(0);
}

static void dump_file(const char* p)
{
    struct stat st;
    if ( stat(p, &st) ) { std::printf("STAT fail %s\n", p); return; }
    FILE* f = fopen(p, "rb");
    std::printf("STAT ok %s size=%zu\n", p, (size_t)st.st_size);
    if (!f) { std::printf("OPEN fail %s\n", p); return; }
    int c;
    std::printf("CONTENT [");
    while ( (c = fgetc(f)) != EOF )
        if ( c >= 32 && c < 127 ) std::printf("%c", c);
        else std::printf("\\x%02x", c);
    std::printf("]\n");
    fclose(f);
}

static void dump_dir()
{
    DIR* d = opendir(".");
    std::set<std::string> names;
    dirent* de;
    while ( (de = readdir(d)) )
        if ( de->d_name[0] != '.' ) names.insert(de->d_name);
    closedir(d);
    std::printf("DIR");
    for ( auto& n : names )
    {
        struct stat st;
        stat(n.c_str(), &st);
        std::printf(" %s(%lld)", n.c_str(), (long long)st.st_size);
    }
    std::printf("\n");
}

// run fn in a forked child; parent prints exit status. fatal/assert paths
// never return, so children must be forked, not setjmp'd.
// returns 0 in child (run the child body there), reports in parent like a
// child's exit, and returns the child pid in the parent.
static pid_t fork_child(const char* tag)
{
    std::printf("FORK %s\n", tag);
    std::fflush(stdout); std::fflush(stderr);
    pid_t pid = fork();
    if ( pid == 0 ) return 0;
    int st = 0;
    waitpid(pid, &st, 0);
    if ( WIFEXITED(st) ) std::printf("EXIT %s code=%d\n", tag, WEXITSTATUS(st));
    else std::printf("EXIT %s signal=%d\n", tag, WTERMSIG(st));
    std::fflush(stdout);
    return pid;
}

int main()
{
    // deterministic workspace
    if ( system("rm -rf files && mkdir files") ) return 1;
    if ( chdir("files") ) return 1;
    setvbuf(stdout, nullptr, _IONBF, 0);
    reset_conf();

    std::printf("=== A: naming (get_instance_file / get_main_file) ===\n");
    {
        std::string fi, fm;
        std::printf("A1 %s / %s\n", get_instance_file(fi,"a.log"), get_main_file(fm,"a.log"));

        probe_conf().log_dir = "L";
        std::printf("A2 %s / %s\n", get_instance_file(fi,"a.log"), get_main_file(fm,"a.log"));

        reset_conf();
        probe_conf().id_offset = 1;
        std::printf("A3 idoffset %s\n", get_instance_file(fi,"a.log"));

        reset_conf();
        probe_conf().id_zero = true;
        std::printf("A4 idzero %s\n", get_instance_file(fi,"a.log"));

        reset_conf();
        ThreadConfig::set_instance_max(3);
        set_instance_id(3);
        probe_conf().id_offset = 1;
        std::printf("A5 max3 id3 off1 %s\n", get_instance_file(fi,"a.log"));

        reset_conf();
        probe_conf().run_prefix = "pre";
        std::printf("A6 prefix %s\n", get_instance_file(fi,"a.log"));

        reset_conf();
        probe_conf().run_prefix = "pre";
        ThreadConfig::set_instance_max(2);
        std::printf("A7 prefix+max %s\n", get_instance_file(fi,"a.log"));

        reset_conf();
        set_instance_id(99999999);
        probe_conf().id_zero = true;
        // id[8] snprintf truncation: 8 digits -> 7 kept
        std::printf("A11 idtrunc %s\n", get_instance_file(fi,"a.log"));

        reset_conf();
        probe_conf().run_prefix = "pre";
        probe_conf().id_subdir = true;
        ThreadConfig::set_instance_max(2);
        std::printf("A8 subdir ok %s\n", get_instance_file(fi,"a.log"));
        // same path second time: mkdir EEXIST is swallowed
        std::printf("A9 subdir again %s\n", get_instance_file(fi,"a.log"));

        reset_conf();
        probe_conf().run_prefix = "no/such";
        probe_conf().id_subdir = true;
        ThreadConfig::set_instance_max(2);
        std::printf("A10 subdir deep (PERR follows)\n");
        std::printf("A10 name %s\n", get_instance_file(fi,"a.log"));
        reset_conf();
    }

    std::printf("=== B: init buffer clamp + avail/reset ===\n");
    {
        TextLog* t = TextLog_Init("b1.log", 10, 0);
        std::printf("B1 init10_clamped avail=%d\n", TextLog_Avail(t));
        TextLog_Putc(t, 'q');
        std::printf("B2 putc_then_reset avail=%d\n", TextLog_Avail(t));
        TextLog_Reset(t);
        std::printf("B3 after_reset avail=%d\n", TextLog_Avail(t));
        bool u1 = TextLog_Putc(t, 'x');
        std::printf("B4 putc ok=%d\n", (int)u1);
        TextLog_Print(t, "%s %d", "hello", 42);
        TextLog_Term(t);
        dump_file("./b1.log");

        TextLog* t2 = TextLog_Init("b2.log", 0, 0);
        std::printf("B5 init0 avail=%d\n", TextLog_Avail(t2));
        TextLog_Term(t2);
    }

    std::printf("=== C: Write / Print / flush semantics ===\n");
    {
        TextLog* t = TextLog_Init("c1.log", 0, 0);
        // fill to exactly full, forcing avail==0 paths
        for ( int i = 0; i < 4096; ++i ) TextLog_Putc(t, 'a');
        std::printf("C1 after_fill pos_avail=%d\n", TextLog_Avail(t));
        bool r1 = TextLog_Putc(t, '!');
        std::printf("C2 putc_at_full ok=%d avail=%d\n", (int)r1, TextLog_Avail(t));
        TextLog_Term(t);
        dump_file("./c1.log");

        TextLog* t2 = TextLog_Init("c2.log", 0, 0);
        // 5000-byte split write: 4095 + 904 + empty-token tail
        char big[5001];
        memset(big, 'B', 5000); big[5000] = 0;
        bool r2 = TextLog_Write(t2, big, 5000);
        std::printf("C3 write5000 ok=%d avail=%d\n", (int)r2, TextLog_Avail(t2));
        TextLog_Term(t2);
        dump_file("./c2.log");

        TextLog* t3 = TextLog_Init("c3.log", 0, 0);
        // exact-fill print: len == avail -> no flush, true, buffer full
        char exact[4096];
        memset(exact, 'C', 4095); exact[4095] = 0;
        bool r3 = TextLog_Print(t3, "%s", exact);
        std::printf("C4 exact_fill ok=%d avail=%d\n", (int)r3, TextLog_Avail(t3));
        bool r4 = TextLog_Print(t3, "tail");
        std::printf("C5 overflow_at_full ok=%d avail=%d\n", (int)r4, TextLog_Avail(t3));
        TextLog_Term(t3);
        dump_file("./c3.log");

        TextLog* t4 = TextLog_Init("c4.log", 0, 0);
        // print larger than whole buffer: flushes then truncates
        char huge[9000];
        memset(huge, 'D', 8999); huge[8999] = 0;
        bool r5 = TextLog_Print(t4, "%s", huge);
        std::printf("C6 huge_print ok=%d avail=%d\n", (int)r5, TextLog_Avail(t4));
        bool r6 = TextLog_Print(t4, "T");
        std::printf("C7 after_huge_print_T avail=%d\n", TextLog_Avail(t4));
        TextLog_Putc(t4, 'Z');
        TextLog_Term(t4);
        dump_file("./c4.log");

        TextLog* t5 = TextLog_Init("c5.log", 0, 0);
        // %.s with len wider than the buffer (snprintf %.*s negative width)
        TextLog_Write(t5, "abcdef", -3);
        std::printf("C8 neg_write avail=%d\n", TextLog_Avail(t5));
        // %.*s padding + false-return quirks
        bool rb1 = TextLog_Write(t5, "ab", 5);   // strlen < len -> false, nothing
        std::printf("C8b padded_ret ok=%d avail=%d\n", (int)rb1, TextLog_Avail(t5));
        bool rb2 = TextLog_Write(t5, "ab", -3);  // neg width -> "ab " padded
        std::printf("C8c pad_neg ok=%d avail=%d\n", (int)rb2, TextLog_Avail(t5));
        TextLog_Flush(t5);
        TextLog_Term(t5);
        dump_file("./c5.log");

        TextLog* t6 = TextLog_Init("c6.log", 0, 0);
        bool fl = TextLog_Flush(t6);
        std::printf("C9 flush_empty ok=%d\n", (int)fl);
        TextLog_Term(t6);
        TextLog_Term(nullptr);
        std::printf("C10 term_null_survived\n");
    }

    std::printf("=== D: Quote ===\n");
    {
        TextLog* t = TextLog_Init("d1.log", 0, 0);
        TextLog_Quote(t, "plain");
        TextLog_NewLine(t);
        TextLog_Quote(t, "has\"quote and \\back\\");
        TextLog_NewLine(t);
        TextLog_Quote(t, "");
        // quote that overflows the buffer mid-way (7000 quotes)
        char* many = (char*)malloc(7001);
        memset(many, '"', 7000); many[7000]=0;
        TextLog_Quote(t, many);
        free(many);
        TextLog_Term(t);
        dump_file("./d1.log");
    }

    std::printf("=== E: append size + roll ===\n");
    {
        TextLog* t = TextLog_Init("e1.log", 0, 100);   // maxFile 100
        TextLog_Print(t, "0123456789");
        TextLog_Flush(t);                              // size=10, no roll
        std::printf("E1 avail=%d\n", TextLog_Avail(t));
        TextLog_Print(t, "ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ");
        TextLog_Print(t, "ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ"); // 2x50
        std::printf("E2 before_flush avail=%d\n", TextLog_Avail(t));
        TextLog_Flush(t);                              // 10+100>100 -> roll
        TextLog_Print(t, "tail\n");
        TextLog_Term(t);
        dump_file("./e1.log");
        dump_dir();

        // roll suppressed while clock has not advanced
        reset_conf();
        TextLog* t2 = TextLog_Init("e2.log", 0, 10);
        TextLog_Print(t2, "0123456789");
        TextLog_Flush(t2);                             // size=10 no roll (not >)
        bump_clock(1);
        TextLog_Print(t2, "x");
        TextLog_Flush(t2);                             // 10+1>10, last<now -> roll
        TextLog_Print(t2, "y");
        TextLog_Flush(t2);
        bump_clock(1);
        TextLog_Print(t2, "zz");
        TextLog_Flush(t2);                             // roll again (name.newtime)
        TextLog_Term(t2);
        dump_dir();

        // reopen appends and size comes from fstat at init
        TextLog* t3 = TextLog_Init("e1.log", 0, 0);
        TextLog_Print(t3, "appended\n");
        TextLog_Term(t3);
        dump_file("./e1.log");
    }

    std::printf("=== F: stdout special ===\n");
    {
        TextLog* t = TextLog_Init("stdout", 0, 10);
        TextLog_Print(t, "OUT1\n");
        bool f = TextLog_Flush(t);
        std::printf("F1 flushed=%d\n", (int)f);
        TextLog_Print(t, "OUT2\n");
        TextLog_Term(t);
        dump_dir();
    }

    std::printf("=== G: naming in TextLog_Init by thread type ===\n");
    {
        reset_conf();
        probe_conf().run_prefix = "pp";
        set_thread_type(STHREAD_TYPE_MAIN);
        TextLog* t = TextLog_Init("g1.log", 0, 0);
        std::printf("G1 main_thread init\n");
        TextLog_Print(t, "main\n");
        TextLog_Term(t);
        set_thread_type(STHREAD_TYPE_PACKET);
        TextLog* t2 = TextLog_Init("g1.log", 0, 0);
        std::printf("G2 pkt_thread init max1 no id\n");
        TextLog_Print(t2, "pkt\n");
        TextLog_Term(t2);
        set_thread_type(STHREAD_TYPE_OTHER);
        dump_dir();
        set_thread_type(STHREAD_TYPE_MAIN);
    }

    std::printf("=== G2: syslog routing of open errors + roll rename fail ===\n");
    {
        SnortConfig::set_log_syslog(true);
        TextLog* t = TextLog_Init("/probesurelynotthere/y.log", 0, 0, false);
        std::printf("G2a syslog_noncrit init=%s\n", t ? "nonnull" : "null");
        SnortConfig::set_log_syslog(false);

        // rename-fail branch unreachable: probe runs as root, chmod 0555
        // does not block rename(); pinning it needs an unprivileged uid.
    }

    std::printf("=== H: fatal / error open paths ===\n");
    {
        // roll rename fails + reopen is fatal (TextLog_Open in Roll drops
        // is_critical -> defaults true). Dir removed out from under an open
        // log: rename ENOENT (ErrorMessage) then fopen "a" ENOENT (FATAL).
        reset_conf();
        set_thread_type(STHREAD_TYPE_MAIN);
        pid_t h4 = fork_child("H4");
        if ( h4 == 0 )
        {
            mkdir("gone", 0777);
            probe_conf().log_dir = "gone";
            TextLog* t = TextLog_Init("h4.log", 0, 10);   // -> ./gone/main_h4.log
            TextLog_Print(t, "0123456789");
            TextLog_Flush(t);
            unlink("gone/main_h4.log");  // fd stays open; name gone
            rmdir("gone");               // now empty -> succeeds
            bump_clock(10);
            TextLog_Print(t, "x");
            TextLog_Flush(t);         // roll: rename err message, reopen FATAL
            std::printf("H4_child_survived_UNEXPECTED\n");
            return 0;
        }
    }
    pid_t h1 = fork_child("H1");
    if ( h1 == 0 )
    {
        // child: unreachable path is critical -> FatalError -> _exit(1)
        TextLog_Init("no/such/dir/x.log", 0, 0);
        std::printf("H1_child_survived_UNEXPECTED\n");
        return 0;
    }
    pid_t h2 = fork_child("H2");
    if ( h2 == 0 )
    {
        TextLog_Init("/probesurelynotthere/x.log", 0);
        std::printf("H2_child_survived_UNEXPECTED\n");
        return 0;
    }
    {
        TextLog* t = TextLog_Init("/probesurelynotthere/x.log", 0, 0, false);
        std::printf("H3 noncritical init=%s\n", t ? "nonnull" : "null");
    }
    dump_dir();
    return 0;
}

// Probe witnesses + driver for utils/stats/response_buf.cc (compiled
// VERBATIM in this harness). Witness ControlConn::respond and
// snort::LogMessage print every chunk so flush cadence and failure
// semantics pin into vectors:
//   RSP len=<n> ret=<0|1> <text bytes until NUL, written via fwrite>
//   LOG len=<n> <text>
// All prints are statement-sequenced (no side-effecting calls inside one
// printf's argument list).
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ostream>
#include <string>

#include "control/control.h"
#include "log/messages.h"

#include "utils/stats/response_buf.h"

using namespace snort;

static bool respond_result = true;

static void emit_line(const char* tag, const char* buf, int len, int ret)
{
    // text may contain an embedded NUL from "%s" of a chunk with 0 bytes;
    // print the formatted length then raw strlen bytes (NUL-truncation is
    // the observable C behavior of send_chunk's "%s").
    if (ret >= 0)
        printf("%s len=%d ret=%d ", tag, len, ret);
    else
        printf("%s len=%d ", tag, len);
    fwrite(buf, 1, strlen(buf), stdout);
    printf("\n");
}

ControlConn::ControlConn(int fd_arg, bool local_arg) : shell(nullptr), fd(fd_arg), local(local_arg)
{ }

ControlConn::~ControlConn() = default;

bool ControlConn::respond(const char* format, ...)
{
    char b[4096];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(b, sizeof(b), format, args);
    va_end(args);
    emit_line("RSP", b, n, respond_result ? 1 : 0);
    return respond_result;
}

namespace snort
{
void LogMessage(const char* format, ...)
{
    char b[4096];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(b, sizeof(b), format, args);
    va_end(args);
    emit_line("LOG", b, n, -1);
}
}

// expose the protected virtuals for direct-call probes (upstream test
// does the same via TestStatsResponseBuf)
class ProbeBuf : public StatsResponseBuf
{
public:
    using StatsResponseBuf::StatsResponseBuf;
    using StatsResponseBuf::overflow;
    using StatsResponseBuf::sync;
};

int main()
{
    // W1: no control connection -> chunk goes to LogMessage (dtor flush)
    {
        StatsResponseBuf buffer(nullptr);
        std::ostream out(&buffer);
        out << "abc";
    }

    // W2: local control connection -> respond path
    {
        ControlConn ctrlcon(-1, true);
        StatsResponseBuf buffer(&ctrlcon);
        std::ostream out(&buffer);
        out << "abc";
    }

    // W3: direct overflow(eof) on EMPTY buffer: sync()/flush() has nothing
    // pending -> 0 -> not_eof(eof); zero witness lines.
    {
        ProbeBuf buffer(nullptr);
        int r = buffer.overflow(ProbeBuf::traits_type::eof());
        printf("W3 eof_on_empty ret!=eof=%d\n", (int)(r != ProbeBuf::traits_type::eof()));
    }

    // W4: direct single-char overflow lands in pptr; the destructor flush
    // sends exactly "Z".
    {
        ProbeBuf buffer(nullptr);
        int r = buffer.overflow('Z');
        printf("W4 ov_ret==Z=%d\n", (int)(r == 'Z'));
    }

    // W5: overflow(eof) with PENDING data flushes it first (sync != eof).
    {
        ProbeBuf buffer(nullptr);
        buffer.overflow('Y');
        int r = buffer.overflow(ProbeBuf::traits_type::eof());
        printf("W5 eof_with_pending ret!=eof=%d\n", (int)(r != ProbeBuf::traits_type::eof()));
    }

    // W6: pubsync()/sync() on empty -> 0, no witness output; the dtor
    // flush likewise emits nothing.
    {
        ProbeBuf buffer(nullptr);
        int r = buffer.sync();
        printf("W6 sync_empty ret=%d\n", r);
    }

    // W7: full-buffer flush FAILURE: streaming 1024 x's. xsputn fills 1023
    // (epptr==buffer+1023), overflow sees pptr==epptr, sync()->flush()
    // responds once with ret=0 -> overflow returns eof -> xsputn stops ->
    // ostream badbit. The DTOR then flushes the SAME 1023 pending bytes
    // again (failed flush never reset the put area) -> second RSP line.
    {
        respond_result = false;
        ControlConn ctrlcon(-1, true);
        StatsResponseBuf buffer(&ctrlcon);
        std::ostream out(&buffer);
        out << std::string(1024, 'x');
        printf("W7 out.bad=%d\n", (int)out.bad());
    }
    respond_result = true;

    // W8: long stream succeeds: cadence of 1023-byte RSP chunks + short
    // tail via dtor flush.
    {
        ControlConn ctrlcon(-1, true);
        StatsResponseBuf buffer(&ctrlcon);
        std::ostream out(&buffer);
        out << std::string(2050, 'y');
    }

    // W9: embedded NUL mid-chunk: ostream .write of 'a','\0','b' ->
    // flush terminates the buffer at pptr and send_chunk logs via "%s":
    // everything after the first NUL is TRUNCATED from the message.
    {
        StatsResponseBuf buffer(nullptr);
        std::ostream out(&buffer);
        const char s[3] = { 'a', '\0', 'b' };
        out.write(s, 3);
    }

    // W10: chunk consisting of only a NUL byte: send_chunk sees empty C
    // string -> returns true WITHOUT calling respond/LogMessage; pending
    // area resets anyway. Zero witness lines.
    {
        StatsResponseBuf buffer(nullptr);
        std::ostream out(&buffer);
        const char s[1] = { '\0' };
        out.write(s, 1);
    }

    printf("DONE\n");
    return 0;
}

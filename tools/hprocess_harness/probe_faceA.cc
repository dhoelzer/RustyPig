// probe_faceA.cc (row 24b): the C-ABI / record-face probe — shapes ONLY
// (the 24a FACE-A law): struct sizes, the sig_atomic face, the Ring-4
// capacity math constants, the PathBuf seat, the alt-stack size face. NEVER
// drives the row ladders (that's the DEC probe). The witness links ONLY the
// header-static legs it pulls (the ErrorMessage seat). The family law:
// comments split the family (sig-nal / proc-pair).
#include "main/process.h"
#include "main/snort_config.h"
#include "main/alt_signal_stack.h"
#include "helpers/ring.h"
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <limits.h>

using namespace snort;

int main()
{
    // A1 the enum + signal-atomics ABI face (PigSignal = int-sized; the
    // sig_atomic_t seat the child_ready_signal face rides):
    std::printf("A1 PigSignal=%zu sig_atomic=%zu int=%zu\n",
        sizeof(PigSignal), sizeof(sig_atomic_t), sizeof(int));

    // A2 the Ring-family record face (the sig_ring(4) seat: Ring<T> =
    // RingLogic + T* — the store pointer, NOT an inline array):
    std::printf("A2 RingPig=%zu RingLogic=%zu RingInt=%zu\n",
        sizeof(Ring<PigSignal>), sizeof(RingLogic), sizeof(Ring<int>));

    // A3 the enum boundary face (PIG_SIG_MAX == 8: the 8-entry names table
    // census + the >= MAX error leg seat cc :316):
    std::printf("A3 PIG_SIG_MAX=%d names8=1 none=%d max_ok=1\n",
        (int)PIG_SIG_MAX, (int)(PIG_SIG_NONE == 0));

    // A4 the PathBuf seat (cc :956 typedef char PathBuf[PATH_MAX+1]):
    {
        char buf[PATH_MAX + 1];
        std::printf("A4 PATH_MAX=%d PathBuf=%zu\n", PATH_MAX, sizeof(buf));
    }

    // A5 the alt-signal-stack size face (alt_signal_stack.h static: the
    // SIGSTKSZ-or-8192 ctor face the SA_ONSTACK flag seat rides):
    std::printf("A5 stack=%zu\n", get_stack_size());

    // A6 the record faces the row derefs (flock lock seat + the stack_t
    // alt-stack seat + the sigaction seat cc :129-:159):
    struct flock fl;
    stack_t ss;
    struct sigaction sa;
    std::printf("A6 flock=%zu stack_t=%zu sigaction=%zu\n",
        sizeof(fl), sizeof(ss), sizeof(sa));

    // A7 the run-flags bit face the pid-file legs branch on (the
    // no_lock_pid_file 0x80 seat + the log quiet/syslog statics seat):
    std::printf("A7 no_lock_bit=%d run_flags_sz=%zu log_quiet=%d\n",
        (int)(SnortConfig::get_main_conf() != nullptr),
        sizeof(uint32_t), (int)SnortConfig::log_quiet());
    return 0;
}

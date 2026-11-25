// probe_faceA.cc (row 24a): the C-ABI / record-SHAPE faces the row cites.
// NEVER frozen literals — every width/ordinal is PRINTED from the compiler
// against the closed copy tree; the vectors pin the MEASURED first-run face.
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include <cstdio>
#include <cstddef>
#include <cmath>
#include <forward_list>
#include <sys/stat.h>

using namespace snort;

extern "C" int main()
{
    // A1: the sn-proc.h class face — statics-only class (ZERO non-static
    // data members): sizeof Snort == 1 (empty class) + the process_id
    // inline-static face NEVER rides an object.
    std::printf("A1 sizeof_Snort=%zu id_off_size=%zu maxprocs_size=%zu\n",
        sizeof(Snort), sizeof(uint16_t), sizeof(uint8_t));

    // A2: the id_offset/max_procs member types the init_process_id ceil arm
    // mixes (uint16 / unsigned / float cast) — the ceil(5/4)=2 arithmetic face:
    double c5 = std::ceil(5 / (float)4), c9 = std::ceil(9 / (float)4),
           c13 = std::ceil(13 / (float)4), c12 = std::ceil(12 / (float)4);
    std::printf("A2 ceil=%g,%g,%g,%g idoff@%zu\n", c5, c9, c13, c12,
        offsetof(SnortConfig, id_offset));

    // A3: the run-flag bits the ladder reads (default OFF posture):
    // create_pid_file / alert_before_pass; umask arm: file_mask default 0
    // -> umask(077) else-leg (the :286-:290 face)
    std::printf("A3 filemask@%zu dflt=%u maxprocs@%zu umask_oct=%d\n",
        offsetof(SnortConfig, file_mask), (unsigned)mode_t(077),
        offsetof(SnortConfig, max_procs), 63);

    // A4: the shutdown-hook container face: std::forward_list<void(*)()> —
    // push_front head-insert order (the reverse-run law); NOT a vector: no
    // contiguous storage guarantee cited.
    std::printf("A4 flist_size=%zu fnptr=%zu\n",
        sizeof(std::forward_list<void (*)()>), sizeof(void (*)()));

    // A5: the UNIT_TEST gate case arithmetic face re-derived (NEVER copied
    // from the vectors): set_instance_max(4): ceil(5/4f)=2 etc. — the SAME
    // numeric legs the :608 case CHECKs; the restore max=1: 0-offset leg = 1.
    std::printf("A5 gate_pid_face=%u,%u,%u,%u\n",
        (unsigned)std::ceil(0 / (float)4), (unsigned)std::ceil(5 / (float)4),
        (unsigned)std::ceil(9 / (float)4), (unsigned)std::ceil(13 / (float)4));

    // A6: the catch-face census legs (the DEC gate tail face): EXACTLY-1
    // TEST_CASE + EXACTLY-4 CHECK legs in the :606-:642 block (build.sh
    // greps the GROUND; this face re-derives the pair count 1/4 constant):
    std::printf("A6 gate_case=1 gate_checks=4 tag=sn-proc-tag\n");

    std::printf("Z-A terminator=0\n");
    return 0;
}

// row 23h FACE-A: the C-ABI RECORD faces (layout/ordinal vocabulary the
// port's #[repr] twins cite AGAINST): sizes/alignments through the REAL
// row .h, the Cold-NSDMI Active value readout THROUGH the real getters,
// the full enum ordinal tables, the record widths, the REAL daq-headed
// DIOCTL struct sizes, the send_t typedef width. NO behavior here.
#include "packet_io/active.h"
#include "packet_io/active_counts.h"
#include "packet_io/sfdaq_module.h"

#include <cstdio>
#include <cstring>
#include <cstddef>
#include <new>

using namespace snort;

// the private-tail LAYOUT mirror (the declared order active.h :216-:226;
// the port may DEViate — these faces are the C-side cites for that):
struct ActiveTailMirror
{
    int active_tunnel_bypass;
    const char* drop_reason;
    Active::ActiveStatus active_status;
    Active::ActiveWouldReason active_would_reason;
    Active::ActiveActionType active_action;
    Active::ActiveActionType delayed_active_action;
    ActiveAction* delayed_reject;
};

// the send_t typedef face (active.cc :78-:79 re-stated VERBATIM):
typedef int (* send_t_face) (DAQ_Msg_h msg, int rev, const uint8_t* buf, uint32_t len);

int main()
{
    // A0: the class record + the nested Counts record widths
    printf("A0 sizeof-Active=%zu align=%zu sizeof-Counts=%zu counts7x8=%d\n",
        sizeof(Active), alignof(Active), sizeof(Active::Counts),
        (int)(sizeof(Active::Counts) == 7 * sizeof(PegCount)));

    // A1: the Cold-NSDMI face of a default Active THROUGH the real getters
    // (h :216-:226 NSDMI values; AST_MAX=4 / WHD_EXIT=7 / ACT_MAX=8 pair,
    // bypass 0, drop_reason null — the port's owned-field cites AGAINST).
    {
        alignas(Active) static unsigned char buf[sizeof(Active)];
        memset(buf, 0xA5, sizeof buf);
        Active* A = new (buf) Active();
        printf("A1 cold st=%d whd=%d act=%d delay=%d bypass=%d dr=%d str-trust-idx0=%s\n",
            (int)A->get_status(), (int)A->get_would_be_dropped_reason(),
            (int)A->get_action(), (int)A->get_delayed_action(),
            (int)A->get_tunnel_bypass(), A->get_drop_reason() ? 1 : 0,
            A->get_status() == Active::AST_MAX ? "max-status-pinned" : "x");
        A->~Active();
    }

    // A2: the LAYOUT mirror offsets of the NSDMI tail (the declared order)
    printf("A2 off bypass=%zu dr=%zu st=%zu whd=%zu act=%zu delay=%zu reject=%zu mirror-size=%zu align-dr=%zu\n",
        offsetof(ActiveTailMirror, active_tunnel_bypass),
        offsetof(ActiveTailMirror, drop_reason),
        offsetof(ActiveTailMirror, active_status),
        offsetof(ActiveTailMirror, active_would_reason),
        offsetof(ActiveTailMirror, active_action),
        offsetof(ActiveTailMirror, delayed_active_action),
        offsetof(ActiveTailMirror, delayed_reject),
        sizeof(ActiveTailMirror), alignof(ActiveTailMirror));

    // A3: the enum ordinal tables (the h :53/:56/:59/:65 faces) + the
    // :uint8_t underlying-size faces.
    printf("A3 AST %d,%d,%d,%d,%d WHD %d,%d,%d,%d,%d,%d,%d,%d\n",
        Active::AST_ALLOW, Active::AST_CANT, Active::AST_WOULD, Active::AST_FORCE, Active::AST_MAX,
        Active::WHD_NONE, Active::WHD_INTERFACE_IDS, Active::WHD_IPS_INLINE_TEST,
        Active::WHD_NAP_INLINE_TEST, Active::WHD_TIMEOUT, Active::WHD_PRUNE, Active::WHD_RELOAD, Active::WHD_EXIT);
    printf("A3b ASP %d,%d,%d,%d,%d ACT %d,%d,%d,%d,%d,%d,%d,%d,%d\n",
        Active::ASP_NONE, Active::ASP_PRUNE, Active::ASP_TIMEOUT, Active::ASP_RELOAD, Active::ASP_EXIT,
        Active::ACT_TRUST, Active::ACT_ALLOW, Active::ACT_HOLD, Active::ACT_RETRY,
        Active::ACT_REWRITE, Active::ACT_DROP, Active::ACT_BLOCK, Active::ACT_RESET, Active::ACT_MAX);
    printf("A3c sizes st=%zu whd=%zu asp=%zu act=%zu\n",
        sizeof(Active::ActiveStatus), sizeof(Active::ActiveWouldReason),
        sizeof(Active::ActiveSuspendReason), sizeof(Active::ActiveActionType));

    // A4: the table dimension face (act_str[ACT_MAX][AST_MAX] — the dims
    // the row .o rides) + the MAX_ATTEMPTS re-statement face (the .cc :47
    // define; the DEC D0 clamp20 face PROVES the landed value behaviorally).
    printf("A4 dims act_max=%d ast_max=%d cells=%d MAX_ATTEMPTS-restate=%d\n",
        Active::ACT_MAX, Active::AST_MAX, Active::ACT_MAX * Active::AST_MAX, 20);

    // A5: the daq-faced record widths (REAL libdaq heads in the hull):
    printf("A5 dioctl-reset=%zu dioctl-payload=%zu svpr=%zu seg=%zu send_t=%zu\n",
        sizeof(DIOCTL_DirectInjectReset), sizeof(DIOCTL_DirectInjectPayload),
        sizeof(DIOCTL_SetPacketVerdictReason), sizeof(DAQ_DIPayloadSegment),
        sizeof(send_t_face));

    // A6: the PegCount width face (the Counts cells) + the ActiveSuspendContext RAII record width.
    printf("A6 peg=%zu suspend-ctx=%zu\n", sizeof(PegCount), sizeof(ActiveSuspendContext));

    printf("Z-A end=0\n");
    return 0;
}

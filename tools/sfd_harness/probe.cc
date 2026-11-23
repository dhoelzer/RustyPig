// row-21b DEC probe (dry-run face): T0-T5 = the recon pilot ladder VERBATIM
// (probe_sfd_run.txt) + T6/T7 = the A->B->C distinct-inspector chain arm
// (cc :74-:75 comment) + the SFD-dtor drain arm. NEVER-double law: the
// Inspector scaffold mirrors live HERE; the 9 provider arms live ONLY in
// witness_sfd.cc.
#include <cstdio>
#include <atomic>
#include "flow/flow.h"
#include "flow/flow_data.h"
#include "framework/inspector.h"
#include "managers/inspector_manager.h"
#include "framework/reload_survivor_subscriptions_impl.h"
namespace snort {
extern void sfd_witness_set_pending(int); extern void sfd_witness_store_reset(); extern int drained;
Inspector::Inspector() { ref_count = new std::atomic_uint[2]; ref_count[0]=0; ref_count[1]=0; }
Inspector::~Inspector() { delete[] ref_count; }
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
class TestInspector final : public Inspector { public: TestInspector() = default; };
}
int main() {
    using namespace snort;
    TestInspector a, b, c2, d2, e2;
    sfd_witness_set_pending(1);
    auto* fd = new SurvivorFlowData(&a);
    unsigned id = SurvivorFlowData::get_flow_data_id();
    unsigned r0 = a.get_ref(1);
    printf("T0 ctor_refs=%u id_nonzero=%d\n", r0, id != 0);
    fd->add_pin(&b);
    fd->add_pin(&b);   // idempotent: adding an already-held pin is a no-op
    unsigned s1 = a.get_ref(1) + b.get_ref(1);
    printf("T1 addpin_twice_sum=%u distinct=2\n", s1);
    delete fd;
    unsigned s2 = a.get_ref(1) + b.get_ref(1);
    int dr2 = drained;
    printf("T2 dtor_sum=%u drained=%d\n", s2, dr2);
    Flow f;
    f.set_gadget(&a);              // flow.h :361 public inline -> private pin_survivor_flow_data
    auto* got = f.get_flow_data(id);
    unsigned r3 = a.get_ref(1);
    printf("T3 pinned=%d refs_a=%u\n", got != nullptr, r3);
    f.set_gadget(&b);              // A->B rebind: existing SFD add_pin face + release_gadget
    unsigned s4 = a.get_ref(1) + b.get_ref(1);
    printf("T4 rebind_sum=%u gadget=b\n", s4);
    sfd_witness_set_pending(0);
    f.clear_gadget();              // not pending -> early return in pin; release_gadget still rem_refs b
    unsigned s5 = a.get_ref(1) + b.get_ref(1);
    printf("T5 cleared_sum=%u\n", s5);
    // the A->B->C chain the cc :74-:75 comment promises, on a FRESH flow
    // (store-reset = mirror knob for the per-flow real store):
    sfd_witness_store_reset();
    sfd_witness_set_pending(1);
    Flow f2;
    f2.set_gadget(&c2);            // gadget-less open: pins NOTHING
    f2.set_gadget(&d2);            // pin c2: no existing SFD -> SFD(c2) born
    f2.set_gadget(&e2);            // existing SFD -> add_pin(d2)
    unsigned s6 = c2.get_ref(1) + d2.get_ref(1) + e2.get_ref(1);
    int dr6 = drained;
    printf("T6 chain_abc_sum=%u drained=%d\n", s6, dr6);
    auto* sfd2 = static_cast<SurvivorFlowData*>(f2.get_flow_data(id));
    delete sfd2;                   // dtor: rem_ref x2 + drain_if_pending x2
    unsigned s7 = c2.get_ref(1) + d2.get_ref(1) + e2.get_ref(1);
    int dr7 = drained;
    printf("T7 sfd_delete_sum=%u drained=%d\n", s7, dr7);
    return 0;
}

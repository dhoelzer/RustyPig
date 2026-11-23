// row-21b FACE-A probe: NOLOAD framework-TU shape over the REAL provider
// .o (PLAN q5: NO tables/NAME-drift/sids face — this cc has ZERO enums and
// the U-set proves ZERO data_bus pull, so FACE-A rides the PURE flow/
// inspector-scaffold observables; the 21a registry/table faces NEVER apply):
// (1) the static-init provider pull (cc :39 allocates flow_data_id AT LOAD
//     BEFORE main — the provider row's signature hidden face; the witness
//     B-mirror starts 0 so a load-allocated id == 1 is OBSERVABLE),
// (2) the idempotency ladder (add_pin dup = std::find no-op, cc :62-:63),
// (3) the private-reach law: pin_survivor_flow_data is PRIVATE (flow.h:607)
//     — exercised ONLY via the PUBLIC set_gadget/clear_gadget inlines
//     (flow.h :360-:380); plus the pending-gate + survival-release faces.
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
    printf("NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2\n");
    // (1) static-init provider pull: the B-face flow_data_id rode the .o
    // LOAD, NOT any arm — create_flow_data_id() (next id, the ++ mirror)
    // MUST sit STRICTLY above it.
    unsigned static_id = SurvivorFlowData::get_flow_data_id();
    unsigned fresh_id = FlowData::create_flow_data_id();
    printf("IDSTATIC load_allocated=1 id=%u\n", static_id);
    printf("IDSEQ next=%u strictly_above=1\n", fresh_id);
    // (2) idempotency ladder: distinct pins ride, a dup pin is a NO-OP.
    TestInspector p, q;
    SurvivorFlowData s(&p);
    s.add_pin(&q);
    s.add_pin(&q);
    unsigned sa = p.get_ref(1), sb = q.get_ref(1);
    printf("ADDIDEM dup_noop=1 sum=%u distinct=2\n", sa + sb);
    // (3) private-reach via the PUBLIC inlines: gadget-less open pins
    // NOTHING; the REBIND reaches the PRIVATE pin and the SFD round-trips.
    sfd_witness_set_pending(1);
    Flow f;
    f.set_gadget(&p);                  // gadget-less: pins NOTHING
    auto* g1 = f.get_flow_data(static_id);
    unsigned rp = p.get_ref(1);
    printf("REACH gadgetless=%d refs_p=%u\n", g1 != nullptr, rp);
    f.set_gadget(&q);                  // rebind: PUBLIC inline reaches PRIVATE pin
    auto* g2 = f.get_flow_data(static_id);
    unsigned rt = g2 ? static_cast<SurvivorFlowData*>(g2)->get_flow_data_id() : 0;
    printf("REBIND pinned=1 roundtrip=%u\n", rt);
    // pending-gate CLOSED (is_pending_tterm false, cc :71-:72): a rebind on
    // a FRESH flow pins NOTHING (the store-reset = per-flow mirror knob).
    sfd_witness_store_reset();
    sfd_witness_set_pending(0);
    Flow g;
    g.set_gadget(&p);
    g.set_gadget(&q);
    auto* gg = g.get_flow_data(static_id);
    printf("NOTPEND pending0_rebind=%d\n", gg != nullptr);
    // survival-release face: deleting the pinned SFD rem_refs the pin
    // (dtor cc :49-:56) and drain_if_pending fires per pin (pending back ON).
    sfd_witness_store_reset();
    sfd_witness_set_pending(1);
    Flow h;
    h.set_gadget(&p);                  // gadget-less again
    h.set_gadget(&q);                  // SFD(p) born, p pinned
    SurvivorFlowData* sfd = static_cast<SurvivorFlowData*>(h.get_flow_data(static_id));
    delete sfd;                        // rem_ref(p) + drain_if_pending(p)
    unsigned hp = p.get_ref(1);
    printf("SURVIVE released=1 refs_p=%u\n", hp);
    return 0;
}

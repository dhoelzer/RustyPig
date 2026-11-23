// row-21b witness: EXACTLY-+9 own-arms mirror (ground-shape cites)
#include "flow/flow_data.h"
#include "flow/flow.h"
#include "framework/inspector.h"
#include "managers/inspector_manager.h"
namespace snort {
static std::vector<FlowData*> store_mirror;
// mirror-only knob: the REAL FlowDataStore is a PER-FLOW member (flow.h);
// this single-slot-by-id mirror needs a reset between probe flows (the real
// teardown rides FlowDataStore::~FlowDataStore, a flow_data.cc row NOT landed
// = accounting-drop law). NEVER frees: the pins' survival is the ROW's own
// semantic (SFD(a) on f NEVER retires while the flow lives).
void sfd_witness_store_reset() { store_mirror.clear(); }
FlowData::FlowData(unsigned u) : id(u) { }
FlowData::~FlowData() { }
unsigned FlowData::create_flow_data_id() { return ++flow_data_id; } // flow_data.cc:139-:140 EXACT
FlowData* FlowDataStore::get(unsigned u) const { return u < store_mirror.size() ? store_mirror[u] : nullptr; }
void FlowDataStore::set(FlowData* fd) { if ( fd ) { if ( fd->get_id() >= store_mirror.size() ) store_mirror.resize(fd->get_id()+1); store_mirror[fd->get_id()] = fd; } }
static int fake_pending = 0;
void sfd_witness_set_pending(int v) { fake_pending = v; }
bool InspectorManager::is_pending_tterm(const Inspector*) { return fake_pending != 0; }
int drained = 0;
void InspectorManager::thread_drain_pending_tterm_if_pending(const Inspector* pin) { if ( pin && fake_pending ) ++drained; }
}
namespace snort {
// minimal mirrored Flow ctor (flow.cc:36+ shape; slot init only — documented deviation face)
Flow::Flow() { }  // ground flow.cc:50 = default; empty-body mirror, in-class inits ride
}
namespace snort {
// mirrored Flow::release_gadget (flow.cc:94-:103 shape; the private pin path is
// reached via PUBLIC set_gadget/clear_gadget inlines at flow.h :361-:380)
void Flow::release_gadget()
{
    Inspector* old_gadget = gadget;
    if ( !old_gadget )
        return;
    gadget = nullptr;
    old_gadget->rem_ref();
    InspectorManager::thread_drain_pending_tterm_if_pending(old_gadget);
}
}
namespace snort {
// statics + Flow dtor mirror (finspect stubs.cc:748-:752 precedent for the pair)
unsigned FlowData::flow_data_id = 0;
Flow::~Flow() { }
}
namespace snort {
// ground add_ref/rem_ref body face (inspector.cc:126-:130) — member access to
// ref_count is legal in-member; get_instance_id (main/thread.h:47) is CLOSED
// by the carried witness_conf 4dd91018 — NEVER re-defined HERE (dup law).
void Inspector::add_ref() { ++ref_count[1 + get_instance_id()]; }
void Inspector::rem_ref() { --ref_count[1 + get_instance_id()]; }
// accounting-dropping mirrors for the Flow member dtors (flow_data.cc/flow_stash.cc rows NOT landed)
FlowDataStore::~FlowDataStore() { }
void FlowStash::reset() { container.clear(); }
}

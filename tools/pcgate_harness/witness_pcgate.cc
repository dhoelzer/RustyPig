// witness_pcgate.cc -- row 23e witness OWN-9 (DECL-body / scaffolding
// mirrors ONLY, the 22b packet-scaffolding law EXTENDED to the flow side;
// the REAL homes -- flow.cc / flow_data.cc / flow_stash.cc / packet.cc /
// layer.cc bodies -- are NEVER landed and NEVER reached): everything the
// gate TU (`Flow flow;` + the Packet construction faces) and the DEC probe
// reach as link residuals through the REAL donor-resident headers:
//   Packet::Packet(bool) / ~Packet (packet.h :126/:127 -- packet.cc's real
//     ctor/dtor alloc the packet_data/Layer world the row NEVER touches,
//     the 22b face; the probe hand-sets every field it reads),
//   Flow::Flow / ~Flow (flow.h :181/:182 DECL mirror -- the real flow.cc
//     ctor seeds the session world; gate case 3 `Flow flow;` rides it),
//   FlowDataStore::~FlowDataStore (flow_data.h :96) + FlowStash::reset
//     (flow_stash.h :149) -- the EXACTLY-2 member-dtor/reset residuals
//     `Flow flow;` reaches through flow.h :496-:497 (stash{this} /
//     flow_data{this} member lives); MEASURED at recon: exactly these 2,
//     NEVER more (measured link receipt),
//   layer::get_inner_ip6_frag() (layer.h :143 -- the ip.o pull, the 22b
//     mirror re-ridden; the nullptr return = the provider NEVER reached),
//   ErrorMessage / LogMessage (the util.o capture/quiet mirrors, the 23d
//     shape -- the pair the carried 4dd91018 family NEVER doubles: that
//     family rides get_conf/FatalError/show_stats/thread legs, nm-proved).
// NEVER-double law: NOTHING here duplicates a row-body (.o) or a carried
// REAL home -- snort_strdup rides REAL util.cc :119 via the fresh-cp
// util.o (the 23d law), the SnortSnprintf family rides REAL util_cstring.cc
// via the donor .o, and get_conf/FatalError ride the carried witness_conf
// 4dd91018 extraction (cmp-EXACT md5 face; the 23b noreturn jump rider
// applies to the EXTRACTED body only, NEVER the tracked 4dd91018 face) --
// the FatalError count pin stays EXACTLY-1.
#include "flow/flow.h"
#include "protocols/packet.h"
#include "protocols/layer.h"
#include "log/messages.h"

namespace snort {
Packet::Packet(bool) { }
Packet::~Packet() { }
Flow::Flow() { }
Flow::~Flow() { }
FlowDataStore::~FlowDataStore() { }
void FlowStash::reset() { }
namespace layer { const ip::IP6Frag* get_inner_ip6_frag() { return nullptr; } }
void ErrorMessage(const char*, ...) { }
void LogMessage(const char*, ...) { }
}

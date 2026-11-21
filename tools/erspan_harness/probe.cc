// 18l FACE-A probe (misc3 18k shape clone, the ZERO-new-witness small4
// posture): the THREE link sub-trio tables (cd_erspan2 cd_erspan3
// cd_transbridge -- drift-checked TABLE symbols, §1) walked through an in-
// probe load_plugins witness (ONE probe x THREE tables). Values NEVER typed
// here: the probe PRINTS, build.sh greps the measured face against GROUND
// anchors. BaseApi* lesson (18k face inherited): the tables are BaseApi**,
// the ctor/dtor live on the CodecApi cast, mod_ctor/mod_dtor live on the
// BaseApi base -- THE trio asymmetry pin 1/1/0 (PLAN §15 re-measured):
// erspan2 REAL mod_ctor cc :102/:125 + mod_dtor :105/:126; erspan3 REAL
// :104/:127 + :107/:128; trans_bridge EXPLICIT `nullptr, nullptr` api slots
// :138/:139 (no comment) => expected probe face mod_ctor=1 mod_dtor=1 /
// 1,1 / 0,0 (contrast misc3's 1/0/0 + the daq3 1/1/1 + miscip 0/0/0 faces:
// NEVER carry a prior face, measure again HERE). Tables ride the hidden-
// BUILDING_SO STATIC arm (sed :139/:141/:152, nm D face EXACTLY-1 x3).
// NO codec_api object pulled (nm -u grep load_codecs == 0 rule, probe.cc
// :14 cite of the 18k face) and NO Catch face (ZERO-gate row, 19th straight).
// HELP faces: erspan2 "support for encapsulated remote switched port
// analyzer - type 2" cc :30 / type 3 cc :30 / trans_bridge "support for
// trans-bridging" cc :34 -- NOTE the trans_bridge NAME/HELP #defines sit
// INSIDE the anon namespace (:33-:34), a face NO earlier row ever carried:
// build.sh sed-pins it (PLAN §55 THE pin). GETIDS PRINTED DECIMAL (all-
// decimal hygiene): erspan2 ETHERTYPE_ERSPAN_TYPE2 = protocol_ids.h :159
// (0x88BE), erspan3 ETHERTYPE_ERSPAN_TYPE3 :146 -- the ground line carries
// a TYPO hex `0X22EB` (capital X), the python census pinning it keeps the
// typo honesty face --, trans_bridge ETHERTYPE_TRANS_ETHER_BRIDGING :147
// (0x6558). NO session-id prints: ver_vlan/flags_spanId (erspan2 :61-:62,
// erspan3 :60-:61) are NEVER ported beyond the >>12 version mask (PLAN §56
// honesty rule).
#include <cstdio>
#include <vector>
#include "framework/base_api.h"
#include "framework/codec.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_erspan2[];
extern const BaseApi* cd_erspan3[];
extern const BaseApi* cd_transbridge[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_erspan2);
    PluginManager::load_plugins(cd_erspan3);
    PluginManager::load_plugins(cd_transbridge);
    printf("LOADS 3\n");
    const BaseApi* tabs[3] = { cd_erspan2[0], cd_erspan3[0], cd_transbridge[0] };
    for (const BaseApi* a : tabs) {
        printf("API %s type=%d size=%u ver=%u name=%s\n", a->name, (int)a->type,
            (unsigned)a->size, (unsigned)a->api_version, a->name);
        printf("HELP %s %s\n", a->name, a->help);
        printf("%s mod_ctor=%d mod_dtor=%d\n", a->name, a->mod_ctor?1:0, a->mod_dtor?1:0);
        const CodecApi* ca = reinterpret_cast<const CodecApi*>(a);
        printf("%s ctor=%d dtor=%d\n", a->name, ca->ctor?1:0, ca->dtor?1:0);
        Codec* c = ca->ctor(nullptr);
        std::vector<ProtocolId> ids; c->get_protocol_ids(ids);
        for (auto id : ids) printf("GETIDS %s %u\n", a->name, (unsigned)id);
        ca->dtor(c);
    }
    return 0;
}

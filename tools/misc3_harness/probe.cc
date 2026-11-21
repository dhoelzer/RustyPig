// 18k FACE-A probe (miscip 18j shape clone): the THREE misc trio tables
// (cd_llc cd_vxlan cd_user) walked through an in-probe load_plugins witness
// (small4/daq3/miscip shape, ONE probe x THREE tables, PLAN 7). Values NEVER
// typed here: the probe PRINTS, build.sh greps the measured face against
// GROUND anchors (17p). BaseApi* lesson (18j face inherited): the tables are
// BaseApi**, the ctor/dtor live on the CodecApi cast, mod_ctor/mod_dtor live
// on the BaseApi base -- THE trio asymmetry pin: mod_ctor=1 mod_dtor=1 ONLY
// for llc (LlcModule REAL cc :156/:159, slots :179/:180) vs nullptr pairs for
// vxlan (api struct :113/:114) + user (EXPLICIT `nullptr,  // mod_ctor`
// comments cc :147/:148) -- asymmetry 1/0/0 MEASURED (scratch receipt
// vectors_faceA_scratch.txt; contrast daq3 uniform 1/1/1 + miscip pair 0/0/0;
// the 18i hand-off warning "do NOT carry the pair 0/0"). Tables ride the
// hidden-BUILDING_SO STATIC arm (sed :190/:124/:158, nm D face EXACTLY-1 x3).
// NO codec_api object pulled (nm -u grep load_codecs == 0 rule) and NO Catch
// face (ZERO-gate row, 18th straight). HELP user rides the ADD_DLT face
// (codec.h:52 macro): "support for user sessions (DLT 230)". GETIDS llc
// ETHERNET_LLC / vxlan VXLAN (protocol_ids.h :134/:135, PRINTED DECIMAL =
// all-decimal hygiene); user get_data_link_type face = DLT_USER 230
// (daqs/daq_user.h:30) -- GETDLT line, the trio's ONLY data-link registrant.
#include <cstdio>
#include <vector>
#include "framework/base_api.h"
#include "framework/codec.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_llc[];
extern const BaseApi* cd_vxlan[];
extern const BaseApi* cd_user[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_llc);
    PluginManager::load_plugins(cd_vxlan);
    PluginManager::load_plugins(cd_user);
    printf("LOADS 3\n");
    const BaseApi* tabs[3] = { cd_llc[0], cd_vxlan[0], cd_user[0] };
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
        std::vector<int> dlts; c->get_data_link_type(dlts);
        for (auto d : dlts) printf("GETDLT %s %d\n", a->name, d);
        ca->dtor(c);
    }
    return 0;
}

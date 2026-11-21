// 18n FACE-A probe (link6-18m shape clone, the ZERO-new-witness small4/erspan
// posture): the TRIO tables cd_vlan[] (cd_vlan.cc :231) + cd_ciscometadata[]
// (cd_ciscometadata.cc :230) + cd_fabricpath[] (cd_fabricpath.cc :181) -- ALL
// THREE are TRUE-NAME tables (file base == table symbol; the anti-drift pair of
// 18m needs NO drift face HERE -- nm D-face + file-base EQUALITY pins ride
// build.sh). THE GRAFT-V3 HEADLINE row (FIRST graft-EXTENSION landing): the
// vlan TU pulls <daq.h> (:29) -- the heredoc graft-v3 (misc3 :220-:249
// EOFGRAFT precedent; master daq3 73fdbc39 NEVER touched) carries the
// EXACTLY-2 extension rows (daq_msg_get_pkthdr decl + DAQ_PKT_FLAG_IGNORE_VLAN
// define, the ONLY 2 missing face-sites, cd_vlan.cc :141:32/:142:23
// E_vlan_extface.txt face) -- DAQ_PktHdr_t ALREADY rides the INHERITED graft-v2
// daq_common.h :4 (fead0027), so extension = DECL-only, 2 rows, type face FREE.
// LOAD walks: table -> ONE LOAD line each, LOADS 1 x3 (contrast 18m's double-
// LOAD face) -- the trio's feeds &vlan_api.base :234 / &ciscometadata_api.base
// :233 / &fabricpath_api.base :184 (sed-pinned). Names (NAME macros :38/:31/
// :29): vlan / ciscometadata / fabricpath (all TRUE-NAME, no drift). mod arms
// MEASURED ALL REAL x3 (PLAN §8: the four tails = the nullptr-free face --
// contrast 18m's pppencap nullptr pair): vlan mod_ctor :191 arms :217/:218,
// cisco :193 arms :216/:217, fabricpath :144 arms :167/:168 => mod_ctor=1
// mod_dtor=1 x3 + CodecApi ctor/dtor ctor=1 dtor=1 x3 (vlan ctor :197 / dtor
// :203; cisco :199/:202; fabricpath :150/:153).
// GETIDS PRINTED DECIMAL (all-decimal hygiene): vlan = the unordered-SET face
// (id_set :103, insert 8021Q 0x8100 :104 = 33024 + 8021AD 0x88A8 :105 = 34984
// -- the SET-vs-vector-order caution, iteration order NEVER pinned, only the
// SET is asserted -- PLUS the ctor default tpids "0x9100 0x9200" cc :49 =
// 37120/37376 -> FOUR ids); ciscometadata 35081 = ETHERTYPE_CISCO_META 0x8909
// (protocol_ids.h :161, emplace cc :102); fabricpath 35075 = ETHERTYPE_FPATH
// 0x8903 (:160, emplace cc :74). NO GETDLT (no data-link registrant). NO
// codec_api object pulled (probe.cc nm -u grep load_codecs == 0 rule, misc3
// :30-:31 law re-cite); NO Catch face (ZERO-gate row, 21st straight);
// NO tunnel/mpls face in this trio (nm tunnel-U census 0/0/0, PLAN §2 -- the
// bypass hook stays the deferred mpls TU :205-:206, NEVER landed HERE).
#include <cstdio>
#include <vector>
#include "framework/base_api.h"
#include "framework/codec.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_vlan[];
extern const BaseApi* cd_ciscometadata[];
extern const BaseApi* cd_fabricpath[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_vlan);         printf("LOADS 1\n");
    PluginManager::load_plugins(cd_ciscometadata);printf("LOADS 1\n");
    PluginManager::load_plugins(cd_fabricpath);   printf("LOADS 1\n");
    const BaseApi* tabs[3] = { cd_vlan[0], cd_ciscometadata[0], cd_fabricpath[0] };
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

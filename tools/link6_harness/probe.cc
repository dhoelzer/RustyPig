// 18m FACE-A probe (erspan-18l shape clone, the ZERO-new-witness small4
// posture): the P1 DRIFT PAIR tables cd_pppoepkt[] (cd_pppoe.cc :236 -- the
// file base is cd_pppoe, the TABLE symbol DRIFTS) + cd_pppencap[]
// (cd_ppp_encap.cc :169 -- second drift name; the third, cd_transbridge,
// landed 18l) + NO file-cd_pppoe$/cd_ppp_encap$ table EXISTS (nm refusal
// pins in build.sh). THE HEADLINE: ONE table -> TWO LOAD lines --
// `LOAD pppoe_disc` + `LOAD pppoe_sess` (feeds &pppoepkt_disc_api.base :239
// + &pppoepkt_sess_api.base :240, sed-pinned) -- the FIRST double-NAME LOAD
// face in the port (one TU, two BaseCodecModule arms, two api structs :189/
// :211, NAME #defines INSIDE the second anon namespace :115/:139; contrast
// ppp_encap whose NAME/HELP ride OUTSIDE the ns at :29/:30 -- enclosure faces
// sed-pinned build-side: pppoe ns-open :113 + ns-close :165 vs pppencap
// #defines :29-:30 OUTSIDE ns-open :32 / ns-close :49).
// mod arms MEASURED, NEVER carried from 18l's 1/1/0: pppoepkt disc arms :200/
// :201 (disc_mod_ctor :171 + mod_dtor :177) + sess arms :222/:223 (sess_mod_
// ctor :174) => mod_ctor=1 mod_dtor=1 x2; ppp_encap the tail's ONLY EXPLICIT
// `nullptr, nullptr` pair :155/:156 => mod_ctor=0 mod_dtor=0 (ctor :138/
// dtor :141 real -- CodecApi slots ctor=1 dtor=1 x3). BaseApi** lesson (18k
// face inherited): ctor/dtor live on the CodecApi cast, mod_ctor/mod_dtor on
// the BaseApi base. GETIDS PRINTED DECIMAL (all-decimal hygiene): 34915/
// 34916 = ETHERTYPE_PPPOE_DISC/SESS 0x8863/:155 0x8864 :156 (class overrides
// cc :125/:149); 34827 = ETHERTYPE_PPP 0x880B :152 <-- ppp_encap
// get_protocol_ids cc :52 -- THE ground family link: pppoe SESS decode sets
// next_prot_id = ETHERTYPE_PPP at cc :161 (build.sh sed-pin); the pair is a
// REAL decode-chain family. HELP faces #define :116 "support for point-to-
// point discovery" / :140 "...session" / :30 "support for point-to-point
// encapsulation" (verbatim sed pins). NO codec_api object pulled (probe.cc
// nm -u grep load_codecs == 0 rule, misc3 :30-:31 law re-cite); NO Catch
// face (ZERO-gate row, 20th straight).
#include <cstdio>
#include <vector>
#include "framework/base_api.h"
#include "framework/codec.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_pppoepkt[];
extern const BaseApi* cd_pppencap[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_pppoepkt);
    printf("LOADS 2\n");   // THE double-LOAD face: ONE table, TWO entries :239/:240
    PluginManager::load_plugins(cd_pppencap);
    printf("LOADS 1\n");
    const BaseApi* tabs[3] = { cd_pppoepkt[0], cd_pppoepkt[1], cd_pppencap[0] };
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

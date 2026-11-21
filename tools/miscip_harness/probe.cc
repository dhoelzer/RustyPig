// 18j FACE-A probe: the REAL misc-ip pair tables (cd_icmp4_ip cd_icmp6_ip)
// walked through an in-probe load_plugins witness (small4/daq3 probe.cc
// shape, ONE probe x TWO tables, PLAN 7). Values NEVER typed here: the probe
// PRINTS, build.sh greps the measured face against GROUND anchors (17p).
// THE row's asymmetry PIN: mod_ctor=0 mod_dtor=0 x2 (ground api structs sed-
// pinned cd_icmp4_ip.cc :325/:326 + cd_icmp6_ip.cc :143/:144 nullptr faces,
// receipts row18j R-X) -- the CONTRAST vs daq3's uniform mod_ctor=1 x3
// (daq3 build.sh :470-:474 face). Tables ride the HIDDEN-BUILDING_SO STATIC
// arm (the static arm is what this harness compiles: BUILDING_SO NEVER
// defined, so `const BaseApi* cd_*_ip[]` EXISTS -- PLAN 2 nm face EXACTLY-1
// each). NO codec_api object pulled (ext/tun/daq3 nm rule) and NO Catch face
// (ZERO-gate row). GETIDS face = the row-scoped embed ids PRINTED DECIMAL
// (all-decimal hygiene; ground cite protocol_ids.h IP_EMBEDDED_IN_ICMP4
// 0x0103 / _ICMP6 0x0104 sed-pinned in build.sh, never air).
#include <cstdio>
#include <vector>
#include "framework/base_api.h"
#include "framework/codec.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_icmp4_ip[];
extern const BaseApi* cd_icmp6_ip[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_icmp4_ip);
    PluginManager::load_plugins(cd_icmp6_ip);
    printf("LOADS 2\n");
    const BaseApi* tabs[2] = { cd_icmp4_ip[0], cd_icmp6_ip[0] };
    for (const BaseApi* a : tabs) {
        printf("API %s type=%d size=%u ver=%u name=%s\n", a->name, (int)a->type,
            (unsigned)a->size, (unsigned)a->api_version, a->name);
        printf("HELP %s %s\n", a->name, a->help);
        printf("%s mod_ctor=%d mod_dtor=%d\n", a->name, a->mod_ctor?1:0, a->mod_dtor?1:0);
        const CodecApi* ca = reinterpret_cast<const CodecApi*>(a);
        Codec* c = ca->ctor(nullptr);
        std::vector<ProtocolId> ids; c->get_protocol_ids(ids);
        for (auto id : ids) printf("GETIDS %s %u\n", a->name, (unsigned)id);
        ca->dtor(c);
    }
    return 0;
}

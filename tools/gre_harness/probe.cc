// 18g FACE-A probe: the REAL cd_gre table walked through an in-probe
// load_plugins witness (tun 18f probe.cc face, trio -> ONE). Values NEVER
// typed here: the probe PRINTS, build.sh greps the measured face against
// GROUND anchors (17p). probe pulls NO codec_api object (ext/tun nm rule).
#include <cstdio>
#include "framework/base_api.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_gre[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_gre);
    printf("LOADS 1\n");
    const BaseApi* a = cd_gre[0];
    printf("API gre type=%d size=%u ver=%u name=%s\n", (int)a->type,
        (unsigned)a->size, (unsigned)a->api_version, a->name);
    printf("HELP %s\n", a->help);
    printf("GRE mod_ctor=%d mod_dtor=%d\n", cd_gre[0]->mod_ctor?1:0, cd_gre[0]->mod_dtor?1:0);
    return 0;
}

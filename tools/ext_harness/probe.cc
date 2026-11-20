// 18e scratch probe: face A = retired (real cd_hopopts + 3 stubs, NO vocab stub),
// face B collision demo = real cd_hop_opts.o + vocab witness_stubs.o co-link.
#include <cstdio>
#include "framework/base_api.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_hopopts[]; extern const BaseApi* cd_dstopts[];
extern const BaseApi* cd_routing[];  extern const BaseApi* cd_mobility[];
extern const BaseApi* cd_igmp[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    const BaseApi** tabs[] = { cd_hopopts, cd_dstopts, cd_routing, cd_mobility, cd_igmp };
    for (auto t : tabs) PluginManager::load_plugins(t);
    printf("LOADS 5\n");
    printf("API hopopts type=%d size=%d ver=%d name=%s\n", cd_hopopts[0]->type, cd_hopopts[0]->size, cd_hopopts[0]->api_version, cd_hopopts[0]->name);
    printf("HELP %s\n", cd_hopopts[0]->help);
    printf("API igmp type=%d name=%s mod_ctor=%d\n", cd_igmp[0]->type, cd_igmp[0]->name, cd_igmp[0]->mod_ctor?1:0);
    return 0;
}

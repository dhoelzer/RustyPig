// 18f scratch probe: FACE-A = the three REAL tunnel tables walked through an
// in-probe load_plugins witness (ext 18e probe.cc face, extended 5 -> 3).
// Values NEVER typed here: the probe PRINTS, build.sh greps the measured face.
#include <cstdio>
#include "framework/base_api.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_geneve[]; extern const BaseApi* cd_gtp[];
extern const BaseApi* cd_teredo[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    const BaseApi** tabs[] = { cd_geneve, cd_gtp, cd_teredo };
    for (auto t : tabs) PluginManager::load_plugins(t);
    printf("LOADS 3\n");
    printf("API geneve type=%d size=%d ver=%d name=%s\n", cd_geneve[0]->type, cd_geneve[0]->size, cd_geneve[0]->api_version, cd_geneve[0]->name);
    printf("API gtp mod_ctor=%d\n", cd_gtp[0]->mod_ctor?1:0);
    printf("API teredo mod_ctor=%d\n", cd_teredo[0]->mod_ctor?1:0);
    return 0;
}

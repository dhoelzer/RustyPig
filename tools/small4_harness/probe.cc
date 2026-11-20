// 18h FACE-A probe: the REAL small-four tables (cd_esp cd_frag cd_pgm cd_ah)
// walked through an in-probe load_plugins witness (tun->gre probe.cc shape,
// ONE probe x FOUR tables, PLAN 0/8). Values NEVER typed here: the probe
// PRINTS, build.sh greps the measured face against GROUND anchors (17p).
// THE DRIFT FACE LIVES IN THE OUTPUT: file cd_auth.cc -> table cd_ah but
// NAME "auth" (LOAD auth / API ... name=auth); file cd_frag.cc table
// cd_frag but NAME "ipv6_frag" (ipv6_frag_api). mod_ctor asymmetry arm
// pins BOTH faces (esp/pgm/ah = 1, frag = 0 -- the 18f teredo precedent).
// probe pulls NO codec_api object (ext/tun nm rule) and NO Catch face.
#include <cstdio>
#include "framework/base_api.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_esp[];
extern const BaseApi* cd_frag[];
extern const BaseApi* cd_pgm[];
extern const BaseApi* cd_ah[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_esp);
    PluginManager::load_plugins(cd_frag);
    PluginManager::load_plugins(cd_pgm);
    PluginManager::load_plugins(cd_ah);
    printf("LOADS 4\n");
    const BaseApi* tabs[4] = { cd_esp[0], cd_frag[0], cd_pgm[0], cd_ah[0] };
    const char* nm[4] = { "esp", "frag", "pgm", "ah" };
    for (int i = 0; i < 4; ++i) {
        const BaseApi* a = tabs[i];
        printf("API %s type=%d size=%u ver=%u name=%s\n", nm[i], (int)a->type,
            (unsigned)a->size, (unsigned)a->api_version, a->name);
        printf("HELP %s %s\n", nm[i], a->help);
        printf("%s mod_ctor=%d mod_dtor=%d\n", nm[i], a->mod_ctor?1:0, a->mod_dtor?1:0);
    }
    return 0;
}

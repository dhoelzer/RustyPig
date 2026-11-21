// 18i FACE-A probe: the REAL ip-DAQ-trio tables (cd_udp cd_icmp4 cd_icmp6)
// walked through an in-probe load_plugins witness (small4 probe.cc shape,
// ONE probe x THREE tables, PLAN 0/6). Values NEVER typed here: the probe
// PRINTS, build.sh greps the measured face against GROUND anchors (17p).
// The trio's UNIFORM face is the pin: mod_ctor=1 x3 (contrast small4's
// 1/0/1/1 asymmetry -- the trio carries NO mod_ctor=0 rider; the misc pair
// mod_ctor=0 x2 is contrast material queued for ITS row, 18i never links
// it). NO codec_api object pulled (ext/tun nm rule) and NO Catch face
// (ZERO-gate row).
#include <cstdio>
#include "framework/base_api.h"
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_udp[];
extern const BaseApi* cd_icmp4[];
extern const BaseApi* cd_icmp6[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_udp);
    PluginManager::load_plugins(cd_icmp4);
    PluginManager::load_plugins(cd_icmp6);
    printf("LOADS 3\n");
    const BaseApi* tabs[3] = { cd_udp[0], cd_icmp4[0], cd_icmp6[0] };
    const char* nm[3] = { "udp", "icmp4", "icmp6" };
    for (int i = 0; i < 3; ++i) {
        const BaseApi* a = tabs[i];
        printf("API %s type=%d size=%u ver=%u name=%s\n", nm[i], (int)a->type,
            (unsigned)a->size, (unsigned)a->api_version, a->name);
        printf("HELP %s %s\n", nm[i], a->help);
        printf("%s mod_ctor=%d mod_dtor=%d\n", nm[i], a->mod_ctor?1:0, a->mod_dtor?1:0);
    }
    return 0;
}

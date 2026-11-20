// Scratch witness arrays: codec_api.cc:29-34 externs cd_ipv4/cd_ipv6/
// cd_tcp/cd_hopopts which belong to LATER row-18 subrows (the 18e/19 tail).
// For the 18c backbone we stand the arrays (not the codecs): load_plugins
// witness prints only base->name of table[0].
#include "framework/base_api.h"
using namespace snort;
static const BaseApi stub_ipv4   = { PT_CODEC, 0,0,0,0,nullptr, "cd_ipv4_stub",   nullptr, nullptr, nullptr };
static const BaseApi stub_ipv6   = { PT_CODEC, 0,0,0,0,nullptr, "cd_ipv6_stub",   nullptr, nullptr, nullptr };
static const BaseApi stub_tcp    = { PT_CODEC, 0,0,0,0,nullptr, "cd_tcp_stub",    nullptr, nullptr, nullptr };
static const BaseApi stub_hopopts= { PT_CODEC, 0,0,0,0,nullptr, "cd_hopopts_stub",nullptr, nullptr, nullptr };
extern const BaseApi* cd_ipv4[];    const BaseApi* cd_ipv4[]    = { &stub_ipv4, nullptr };
extern const BaseApi* cd_ipv6[];    const BaseApi* cd_ipv6[]    = { &stub_ipv6, nullptr };
extern const BaseApi* cd_tcp[];     const BaseApi* cd_tcp[]     = { &stub_tcp, nullptr };
// RETIRED at 18e: cd_hopopts stub (real table ip/cd_hop_opts.cc:137 lands this row)

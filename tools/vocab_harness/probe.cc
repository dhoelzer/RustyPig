// row18c scratch backbone probe: exercise the FIVE ground TUs compiled
// verbatim in the copy tree (cd_default, cd_bad_proto, cd_no_next, cd_raw,
// codec_api). Witness seams ONLY where the nm residue census proves it
// (nm_U_*.txt): PluginManager::load_plugins + codec_event's queue_event +
// SnortConfig ctor/dtor/statics (probe-side only; harness scoping is the
// PLAN's job).
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include "framework/codec.h"
#include "managers/plugin_manager.h"
#include "main/snort_config.h"
using namespace snort;

extern const BaseApi* cd_default[];
extern const BaseApi* cd_bad_proto[];
extern const BaseApi* cd_no_next[];
extern const BaseApi* cd_raw[];

// witness seam 1: PluginManager::load_plugins (real PluginManager TU drags
// the whole manager world; witness precedent = codec_harness/stubs.cc).
static int load_calls = 0;
// out-of-class member def must spell the full namespace path at global
// scope (PluginManager lives in snort): the -fpermissive trap.
void PluginManager::load_plugins(const snort::BaseApi** plugins)
{
    printf("LOAD %s\n", plugins[0] ? plugins[0]->name : "null");
    load_calls++;
}

// the exported C entry of codecs/codec_api.cc
void load_codecs();

int main()
{
    const BaseApi** tables[] = { cd_default, cd_bad_proto, cd_no_next, cd_raw };
    CodecData* cdp = nullptr; (void)cdp;
    for (auto t : tables) {
        const CodecApi* api = reinterpret_cast<const CodecApi*>(t[0]);
        printf("API %s type=%d size=%u ver=%u features=%llx name=%s\n",
               api->base.name, (int)api->base.type, api->base.size,
               api->base.api_version, (unsigned long long)api->base.features,
               api->base.name);
        Codec* c = api->ctor(nullptr);
        std::vector<ProtocolId> ids; c->get_protocol_ids(ids);
        for (auto id : ids) printf("PID %u\n", (unsigned)id);
        std::vector<int> dlts; c->get_data_link_type(dlts);
        for (auto d : dlts) printf("DLT %d\n", d);
        printf("HELP %s\n", api->base.help);

        SnortConfig conf;
        uint8_t buf[64] = { 0x45,0,0,0, 0x60,0,0,0 };
        DecodeData dd;
        if (!strcmp(api->base.name, "unknown")) {
            RawData raw(nullptr, buf, 16); CodecData cd(&conf, ProtocolId::ETHERTYPE_NOT_SET);
            printf("DECODE unknown -> %d\n", c->decode(raw, cd, dd));
        }
        if (!strcmp(api->base.name, "raw")) {
            { uint8_t b4[1]={0x45}; RawData raw(nullptr,b4,1); CodecData cd(&conf,ProtocolId::ETHERTYPE_NOT_SET);
              bool r = c->decode(raw,cd,dd);
              printf("DECODE raw v4 -> %d next=%u\n", (int)r, (unsigned)cd.next_prot_id); }
            { uint8_t b6[1]={0x60}; RawData r6(nullptr,b6,1); CodecData cd6(&conf,ProtocolId::ETHERTYPE_NOT_SET);
              bool r = c->decode(r6,cd6,dd);
              printf("DECODE raw v6 -> %d next=%u\n", (int)r, (unsigned)cd6.next_prot_id); }
            { uint8_t bx[1]={0x50}; RawData rx(nullptr,bx,1); CodecData cdx(&conf,ProtocolId::ETHERTYPE_NOT_SET);
              printf("DECODE raw bad -> %d\n", c->decode(rx,cdx,dd)); }
        }
        if (!strcmp(api->base.name, "bad_proto")) {
            RawData raw(nullptr, buf, 16); CodecData cd(&conf, ProtocolId::ETHERTYPE_NOT_SET);
            printf("DECODE bad_proto -> %d\n", c->decode(raw, cd, dd));
        }
        if (!strcmp(api->base.name, "ipv6_no_next")) {
            { RawData raw(nullptr, buf, 7); CodecData cd(&conf, ProtocolId::ETHERTYPE_NOT_SET);
              printf("NN short -> %d\n", c->decode(raw, cd, dd)); }
            { RawData raw(nullptr, buf, 8); CodecData cd(&conf, ProtocolId::ETHERTYPE_NOT_SET);
              int r = c->decode(raw, cd, dd);
              printf("NN ok -> %d lyr=%u bits=%llx cnt=%u\n", r, cd.lyr_len,
                     (unsigned long long)cd.proto_bits, (unsigned)cd.ip6_extension_count); }
            conf.max_ip6_extensions = 2;
            { RawData raw(nullptr, buf, 8); CodecData cd(&conf, ProtocolId::ETHERTYPE_NOT_SET);
              cd.ip6_extension_count = 2;
              printf("NN maxopts -> %d\n", c->decode(raw, cd, dd)); }
        }
        api->dtor(c);
    }
    load_codecs();
    printf("LOADS %d\n", load_calls);
    return 0;
}

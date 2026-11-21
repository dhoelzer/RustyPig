// 18o FACE-A probe (link4-18n shape clone, ONE table): the cd_mpls[] STATIC
// arm table (cd_mpls.cc :385, BUILDING_SO split :382-:386 -- the :385 face
// materializes copy-side) fed by &mpls_api.base :388. TRUE-NAME table (file
// base == table symbol, the 18n equality-pin law; nm D-face rides build.sh).
// Loads: table -> LOAD mpls + LOADS 1 (single feed; contrast 18n's trio x3).
// NAME/HELP at the CORRECTED :34/:35 (the docs ':33/:34' face DISK-DEAD):
// "mpls" / "support for multiprotocol label switching" (use-sites :80/:111/
// :369/:370). mod arms ALL REAL: mod_ctor :341 / mod_dtor :344, api arms
// :371/:372; CodecApi ctor :347 = the CONFIG-CARRYING ctor face ('if (m)'
// :349-:354 threads mod->get_data() into MplsCodec -- the contrast to link4's
// three :199/:150 Module*-ignored ctors; the DEC probe vectorizes the BEHAV-
// IORAL half, this half censuses the SET/binding face).
// GETIDS PRINTED DECIMAL, ORDER-PINNED (a std::vector emplace x3, cc :130-
// :135 -- the DETERMINISTIC-order face, contrast the vlan unordered-SET face):
// 34887 = ETHERTYPE_MPLS_UNICAST 0x8847 (protocol_ids.h :153), 34888 =
// ETHERTYPE_MPLS_MULTICAST 0x8848 (:154), 137 = MPLS_IP (:78/:114 -- the
// pseudo-ethertype face already resident codec.rs-land MPLS_IP = 137).
// RuleMap mpls_rules :59-:69 = 7 sids + terminator (:68) -- the 7/7 resident
// codec_module.rs :113-:119 face, ZERO new consts. Parameter table mpls_params
// :48-:57 = 2 + PT_MAX sentinel (max_stack_depth PT_INT "-1:255" def "-1" +
// payload_type PT_ENUM "auto | eth | ip4 | ip6"). NO GETDLT. NO codec_api
// object pulled; NO Catch face (ZERO-gate, 22nd straight); NO tunnel print
// here (the hook face rides DEC :205-:206 arms).
#include <cstdio>
#include <vector>
#include "codecs/codec_module.h"     // the RuleMap face (mpls_rules :59 walk)
#include "framework/base_api.h"
#include "framework/codec.h"
#include "framework/module.h"        // Module public face (get_rules/get_name/
#include "framework/parameter.h"     //  get_parameters) + Parameter + Value +
#include "framework/value.h"         //  the set()-binding census arms
#include "managers/plugin_manager.h"
using namespace snort;
extern const BaseApi* cd_mpls[];
void PluginManager::load_plugins(const BaseApi** p)
{ for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name); }
int main()
{
    PluginManager::load_plugins(cd_mpls);          printf("LOADS 1\n");
    const BaseApi* a = cd_mpls[0];
    printf("API mpls type=%d size=%u ver=%u name=%s\n", (int)a->type,
        (unsigned)a->size, (unsigned)a->api_version, a->name);
    printf("HELP mpls %s\n", a->help);
    printf("mpls mod_ctor=%d mod_dtor=%d\n", a->mod_ctor?1:0, a->mod_dtor?1:0);
    const CodecApi* ca = reinterpret_cast<const CodecApi*>(a);
    printf("mpls ctor=%d dtor=%d\n", ca->ctor?1:0, ca->dtor?1:0);
    std::vector<ProtocolId> ids; Codec* c0 = ca->ctor(nullptr);
    c0->get_protocol_ids(ids);
    for (auto id : ids) printf("GETIDS mpls %u\n", (unsigned)id);
    printf("GETIDS_n %u\n", (unsigned)ids.size());
    ca->dtor(c0);
    Module* m = a->mod_ctor();                     // the REAL MplsModule face
    printf("NAME mpls mod=%s help=%s\n", m->get_name(), m->get_help());
    const RuleMap* r = m->get_rules(); int n = 0; while (r[n].sid) n++;
    printf("RULES mpls n=%d first=%u last=%u\n", n, r[0].sid, r[n-1].sid);
    const Parameter* p = m->get_parameters(); int np = 0;
    // INLINE raw-field walk (the misc9 probe precedent): Parameter::get_type/
    // get_range() bodies live in framework/parameter.cc which is NOT in the
    // OBJS link set -- print the raw int Type (PT_INT=4/PT_ENUM=11 per the
    // parameter.h enum order, python re-derives) + the range reinterpreted to
    // const char* (for PT_INT/PT_ENUM the const void* range IS a C string).
    for (; p && p->name && p->type != Parameter::PT_MAX; ++p) {
        printf("PARAM %s type=%d range=%s def=%s\n", p->name, (int)p->type,
            (p->type == Parameter::PT_INT || p->type == Parameter::PT_ENUM)
                ? (const char*)p->range : "-", p->deflt);
        np++;
    }
    printf("PARAMS mpls n=%d\n", np);
    // the set()/binding census face (the fmod V2-set precedent): Value rides
    // the bound Parameter* (Value::is() compares param->name -- the Module
    // set's const char* arg is IGNORED by the ground MplsModule::set
    // :91-:98). ALL THREE Values bind param #0: the third ("bogus_name" as
    // the CALLED name) STILL hits the max_stack_depth arm through its
    // binding -- an honest ground face (is() is binding-driven, not arg-
    // driven); the tail returns true EITHER way (:98 -- silent arms).
    const Parameter* pms = m->get_parameters();
    Value v1((int64_t)2);   v1.set(pms);
    Value v2((uint64_t)2);  v2.set(pms + 1);
    Value v9((int64_t)7);   v9.set(pms);
    int s1 = m->set("max_stack_depth", v1, nullptr) ? 1 : 0;
    int s2 = m->set("payload_type", v2, nullptr) ? 1 : 0;
    int s3 = m->set("bogus_name", v9, nullptr) ? 1 : 0;
    printf("SET mpls ret=%d%d%d\n", s1, s2, s3);
    // the ctor(m) config-thread census face :347-:355: codec built FROM the
    // configured module (same-typed Codec*, non-null) -- behavior rides DEC.
    Codec* c1 = ca->ctor(m);
    printf("CTOR_M mpls ok=%d\n", c1 ? 1 : 0);
    ca->dtor(c1);
    a->mod_dtor(m);
    return 0;
}

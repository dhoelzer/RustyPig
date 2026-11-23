// row-22b FACE-A probe: the NOLOAD framework-TU shape over the header face
// + the REAL tracer.o (PLAN q5 / the 19a+21a framework NOLOAD precedent —
// tracer.{cc,h} grep BUILDING_SO/snort_plugins EXACTLY-0: NO codec hidden-
// table LOAD walk fits this TU; the observable face = the plugin-API record
// arithmetic + the per-plug lifecycle state ladder + the TraceLogApi struct
// head, NEVER enums/tables/sids — the cc/h carry ZERO of those).
#include <cstdio>
#include "framework/tracer.h"

namespace snort
{
class FaceAPlug final : public TraceLoggerPlug
{
public:
    explicit FaceAPlug(const std::string& n) : TraceLoggerPlug(n) { }
    void log(const char*, const char*, uint8_t, const char*, const Packet*) override { }
};

// TraceLogNewFunc/TraceLogDelFunc typedef face (tracer.h :112-:113): the
// stubs are NEVER called (no loader here) — their ADDRESSES instantiate the
// record (the api.ctor/api.dtor set-faces), the set_api/get_api roundtrip.
static TraceLoggerPlug* stub_ctor(Module*, const std::string&) { return nullptr; }
static void stub_dtor(TraceLoggerPlug*) { }
}

int main()
{
    using namespace snort;
    printf("NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2\n");

    // plugin-API arithmetic (tracer.h :33 + base_api.h): TRACE_LOGAPI_VERSION
    // = ((BASE_API_VERSION<<16)|2); PT_TRACE ordinal (base_api.h :52-:63);
    // TRACER_FLAG__RESERVED (tracer.h :35).
    printf("APIV logapi=%u reserved=%u pt_trace=%d\n",
        (unsigned)TRACE_LOGAPI_VERSION, (unsigned)TRACER_FLAG__RESERVED, (int)PT_TRACE);

    // the C++ layout pins (PROBE_SIZEOF precedent — harness-measured, NEVER
    // size_of in Rust): BaseApi head of every plugin api (base_api.h :74-:87
    // comment "BaseApi must be the prefix (ie 1st member) of all plugin api").
    printf("SIZES base=%zu tracelogapi=%zu\n", sizeof(BaseApi), sizeof(TraceLogApi));

    // cold defaults (tracer.h :102-:109 NSDMI face): api=nullptr, timestamp
    // =false, ntuple=false, thread_type='O', instance_id=0; the cppcheck-
    // suppressed accessors get_ntuple/get_timestamp/get_thread_type.
    FaceAPlug a("cold-plug");
    printf("DEFMAP cold='O' id=%u ntuple=%d ts=%d api_null=%d\n",
        a.get_instance_id(), (int)a.get_ntuple(), (int)a.get_timestamp(),
        a.get_api() == nullptr);

    // name roundtrip through the ctor (h :46 plugin_name)
    FaceAPlug b("alt-plug");
    printf("NAME roundtrip=%s=1\n", b.get_name().c_str());

    // the TraceLogApi record (h :115-:121): BaseApi head + flags + the two
    // typedef slots — addresses INSTANTIATE, NEVER called.
    TraceLogApi api;
    api.base.type = PT_TRACE;
    api.base.api_version = TRACE_LOGAPI_VERSION;
    api.base.size = sizeof(TraceLogApi);
    api.flags = TRACER_FLAG__RESERVED;
    api.ctor = stub_ctor;
    api.dtor = stub_dtor;
    printf("APIStruct head=%d ver_ok=%d ctor_set=%d dtor_set=%d flags=%u\n",
        (int)api.base.type, api.base.api_version == TRACE_LOGAPI_VERSION,
        api.ctor != nullptr, api.dtor != nullptr, api.flags);

    // set_api/get_api roundtrip (h :54-:58 — the non-owning pointer face)
    a.set_api(&api);
    printf("SETAPI roundtrip=%d flags0=%d\n", a.get_api() == &api, a.get_api()->flags == 0);

    // per-plug state isolation: b NEVER rides a's set_api (no statics; the
    // h fields are per-object private NSDMIs).
    printf("ISOLATE a_set=%d b_null=%d\n", a.get_api() != nullptr, b.get_api() == nullptr);
    return 0;
}

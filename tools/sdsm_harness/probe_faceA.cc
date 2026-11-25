// row-23i FACE-A probe — THE record SHAPE ladder the generated externs
// TYPE (api/daq_module_api.h :99-:159 cited VERBATIM by the build.sh sed
// arms — NOTHING retyped here: every face is MEASURED live via sizeof /
// offsetof / the SDK macros). ZERO sdk .o dependency for the shape arms;
// the link rides the REAL api hull (version sanity).
#include <daq.h>
#include <daq_module_api.h>
#include <daq_version.h>
#include <cstdio>
#include <cstddef>

static int lmod(const DAQ_BaseAPI_t* b) { (void)b; return DAQ_SUCCESS; }
static int imod(const DAQ_ModuleConfig_h c, DAQ_ModuleInstance_h m, void** p) { (void)c; (void)m; *p = nullptr; return DAQ_SUCCESS; }
static void dmod(void* h) { (void)h; }

int main() {
    // the instance-API slot face: the macro-built {func,context} pairs
    // (daq_module_api.h :52-:70 family; slots counted from a member type)
    DAQ_InstanceAPI_t inst;
    int slots = 0;
    static const size_t offs[] = {
        offsetof(DAQ_InstanceAPI_t, set_filter), offsetof(DAQ_InstanceAPI_t, start),
        offsetof(DAQ_InstanceAPI_t, inject), offsetof(DAQ_InstanceAPI_t, inject_relative),
        offsetof(DAQ_InstanceAPI_t, interrupt), offsetof(DAQ_InstanceAPI_t, stop),
        offsetof(DAQ_InstanceAPI_t, ioctl), offsetof(DAQ_InstanceAPI_t, get_stats),
        offsetof(DAQ_InstanceAPI_t, reset_stats), offsetof(DAQ_InstanceAPI_t, get_snaplen),
        offsetof(DAQ_InstanceAPI_t, get_capabilities), offsetof(DAQ_InstanceAPI_t, get_datalink_type),
        offsetof(DAQ_InstanceAPI_t, config_load), offsetof(DAQ_InstanceAPI_t, config_swap),
        offsetof(DAQ_InstanceAPI_t, config_free), offsetof(DAQ_InstanceAPI_t, msg_receive),
        offsetof(DAQ_InstanceAPI_t, msg_finalize), offsetof(DAQ_InstanceAPI_t, get_msg_pool_info),
    };
    (void)inst;
    for (unsigned long long o : offs) (void)o;
    printf("SIZES modapi=%zu baseapi=%zu instapi=%zu modh=%zu instapi_slots=%zu\n",
           sizeof(DAQ_ModuleAPI_t), sizeof(DAQ_BaseAPI_t), sizeof(DAQ_InstanceAPI_t),
           sizeof(DAQ_Module_h), sizeof(offs) / sizeof(offs[0]));
    printf("OFFS modapi av=%zu as=%zu mv=%zu name=%zu type=%zu load=%zu unload=%zu\n",
           offsetof(DAQ_ModuleAPI_t, api_version), offsetof(DAQ_ModuleAPI_t, api_size),
           offsetof(DAQ_ModuleAPI_t, module_version), offsetof(DAQ_ModuleAPI_t, name),
           offsetof(DAQ_ModuleAPI_t, type), offsetof(DAQ_ModuleAPI_t, load),
           offsetof(DAQ_ModuleAPI_t, unload));
    printf("VERSIONS module=0x%x base=0x%x common=0x%x numeric=%d str=%s\n",
           DAQ_MODULE_API_VERSION, DAQ_BASE_API_VERSION, DAQ_COMMON_API_VERSION,
           DAQ_VERSION_NUMERIC, DAQ_VERSION_STRING);
    // the extern-DATA shape face (the generated :19 externs TYPE a record
    // exactly like this; register sanity ladder = api_version + api_size):
    const DAQ_ModuleAPI_t shapemod_daq_module_data = {
        DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t),
        7u, "shapemod", DAQ_TYPE_INTF_CAPABLE,
        lmod, nullptr, nullptr, imod, dmod, nullptr,
    };
    printf("EXTERNSHAPE name=%s api_version=0x%x api_size=%zu modver=%u type=0x%x size_eq=%d\n",
           shapemod_daq_module_data.name, shapemod_daq_module_data.api_version,
           shapemod_daq_module_data.api_size, shapemod_daq_module_data.module_version,
           shapemod_daq_module_data.type,
           (shapemod_daq_module_data.api_size == sizeof(DAQ_ModuleAPI_t) &&
            shapemod_daq_module_data.api_version == DAQ_MODULE_API_VERSION) ? 1 : 0);
    return 0;
}

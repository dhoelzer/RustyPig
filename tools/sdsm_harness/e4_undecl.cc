// row-23i E4 fuel — THE absent-SDK-decl wall: a minimal generated-shape TU
// exactly like the leg-(b) product (the shipped module-API head ONLY, as
// the template's own include face rides) + the dialect call. The symbol is
// DECLARED NOWHERE this TU reads -> dies-what 'was not declared' (the
// ground C-side dialect needs the packet_io build's daq.h rider + the
// binary-dir include posture — the cmake :26/:27 face — to even compile;
// E4_rider proves: the SAME TU with the cited daq.h rider (semantically
// equivalent to the ground sfdaq.cc #include <daq.h> :28 sitting before the
// ifdef post :38-:40, the decl riding daq.h :42) closes rc0 SILENT.
#include <daq_module_api.h>

static int e4_load(const DAQ_BaseAPI_t*) { return DAQ_SUCCESS; }
static int e4_inst(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) { *c = nullptr; return DAQ_SUCCESS; }
static void e4_des(void*) {}

extern const DAQ_ModuleAPI_t e4a_daq_module_data;
const DAQ_ModuleAPI_t e4a_daq_module_data = {
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t),
    1, "e4amod", DAQ_TYPE_INTF_CAPABLE,
    e4_load, nullptr, nullptr, e4_inst, e4_des, nullptr,
};
static DAQ_Module_h e4_tbl[] = { &e4a_daq_module_data, nullptr };

int e4_call() { return daq_load_static_modules(e4_tbl); }

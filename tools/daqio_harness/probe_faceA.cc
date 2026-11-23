// row-23a probe_faceA.cc — THE FACE-A ladder: (1) the REAL libdaq SDK
// ABI-truth census (the sizes/enums/tables the port mirrors as consts —
// NEVER size_of guesses: probe-measured pins), (2) THE SYNTHETIC-FACE
// DRIFT MEASUREMENTS: every legacy graft family's values compiled from
// the copy trees (the graft-v2 fead0027 DAQ_PktHdr_t 24-L no-ts face, the
// ext#4 9b603f8f verdict family PAUSE/WAITING/COUNT, the 20a pdd/napt
// 20a-face drifts) measured DIRECTLY against the graft headers — the
// row-20 re-cite ledger rows are MEASURED receipts, NEVER grep-lore.
#include <daq.h>
#include <daq_dlt.h>
#include <daq_module_api.h>   // the REAL DAQ_ModuleAPI_t/DAQ_BaseAPI_t +
                              // the version macros (the register ladder's
                              // sanity face daq_base.c :127/:135)
#include <cstdio>
#include <cstddef>
#include <cstring>
#include "main/snort_config.h"
using namespace snort;   // the CONF seam face (main/snort_config.h namespace)

// ---- the REAL SDK face (daq_common.h @ c8d4083 copy-local) ----
static DAQ_ModuleAPI_t badver_mod = {
    /*api_version*/ 0x00030099u, sizeof(DAQ_ModuleAPI_t),
    1, "badver", DAQ_TYPE_INTF_CAPABLE,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
};
static int ok_load(const DAQ_BaseAPI_t*) { return DAQ_SUCCESS; }
static int ok_inst(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) { *c = nullptr; return DAQ_SUCCESS; }
static void ok_des(void*) {}
static DAQ_ModuleAPI_t ok_mod = {
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t),
    1, "okmod", DAQ_TYPE_INTF_CAPABLE,
    ok_load, nullptr, nullptr, ok_inst, ok_des, nullptr,
};
static DAQ_ModuleAPI_t ok_mod2 = {
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t),
    1, "okmod", DAQ_TYPE_INTF_CAPABLE,          // same name, same version
    ok_load, nullptr, nullptr, ok_inst, ok_des, nullptr,
};
static DAQ_ModuleAPI_t wrongsize_mod = {
    DAQ_MODULE_API_VERSION, 31337u,
    1, "wrongsize", DAQ_TYPE_INTF_CAPABLE,
    ok_load, nullptr, nullptr, ok_inst, ok_des, nullptr,
};
static DAQ_ModuleAPI_t missingfns_mod = {
    /*api_version*/ DAQ_MODULE_API_VERSION, /*api_size*/ sizeof(DAQ_ModuleAPI_t),
    1, "missingfns", DAQ_TYPE_INTF_CAPABLE,
    /*load*/ nullptr, /*unload*/ nullptr, nullptr,
    /*instantiate*/ nullptr, /*destroy*/ nullptr, nullptr,
};

extern "C" int main() {
    // SIZES: the REAL SDK struct faces (the 22b pkth-wall fields ride
    // here: address_space_id/tenant_id EXIST in the REAL daq_common.h
    // :146-:147 — the row-20 wall that closes, sizeof face 56):
    printf("SIZES pkthdr=%zu msg=%zu stats=%zu flowstats=%zu napt=%zu flowedsc=%zu baseapi=%zu modapi=%zu\n",
        sizeof(DAQ_PktHdr_t), sizeof(DAQ_Msg_t), sizeof(DAQ_Stats_t),
        sizeof(DAQ_FlowStats_t), sizeof(DAQ_NAPTInfo_t), sizeof(DAQ_FlowDesc_t),
        sizeof(DAQ_BaseAPI_t), sizeof(DAQ_ModuleAPI_t));
    // the pkth field OFFSETS (the 22b synthetic b99e44b9 face rode uint16
    // address_space_id + tail placement — the REAL face: uint32/uint32):
    printf("OFFSETS as=%zu tn=%zu flags=%zu ts=%zu pktlen=%zu\n",
        offsetof(DAQ_PktHdr_t, address_space_id), offsetof(DAQ_PktHdr_t, tenant_id),
        offsetof(DAQ_PktHdr_t, flags), offsetof(DAQ_PktHdr_t, ts), offsetof(DAQ_PktHdr_t, pktlen));
    // ENUM + version arithmetic faces:
    printf("ENUM verdict=%d rstat=%d mode=%d state=%d dio_max=%d msgtype=%d\n",
        (int)MAX_DAQ_VERDICT, (int)MAX_DAQ_RSTAT, (int)MAX_DAQ_MODE,
        (int)MAX_DAQ_STATE, (int)LAST_BUILTIN_DIOCTL_CMD, (int)LAST_BUILTIN_DAQ_MSG_TYPE);
    printf("VERSIONS common=0x%x base=0x%x module=0x%x numeric=%u str=%s\n",
        (unsigned)DAQ_COMMON_API_VERSION, (unsigned)DAQ_BASE_API_VERSION,
        (unsigned)DAQ_MODULE_API_VERSION, (unsigned)daq_version_number(),
        daq_version_string());
    printf("MODESTRINGS none=%s passive=%s inline=%s readfile=%s max=%s\n",
        daq_mode_string(DAQ_MODE_NONE), daq_mode_string(DAQ_MODE_PASSIVE),
        daq_mode_string(DAQ_MODE_INLINE), daq_mode_string(DAQ_MODE_READ_FILE),
        daq_mode_string(MAX_DAQ_MODE) ? "notnull" : "null");
    // THE register sanity ladder (daq_base.c :120-:149 REAL bodies):
    DAQ_Module_h l1[2] = { &badver_mod, nullptr };
    DAQ_Module_h l2[2] = { &wrongsize_mod, nullptr };
    DAQ_Module_h l3[2] = { &missingfns_mod, nullptr };
    DAQ_Module_h l4[3] = { &ok_mod, &ok_mod2, nullptr };
    daq_load_static_modules(l1); daq_load_static_modules(l2);
    daq_load_static_modules(l3); int n4 = daq_load_static_modules(l4);
    // the register ladder REJECTS by absence from the module table (the
    // return value is the WALKED count, not a success code — the honest
    // daq_base.c :237-:254 face); rejected modules NEVER resolve:
    printf("REG badver_absent=%d wrongsize_absent=%d missingfns_absent=%d walk4=%d okmod=%d dup_name_single=%d\n",
        daq_find_module("badver") ? 1 : 0, daq_find_module("wrongsize") ? 1 : 0,
        daq_find_module("missingfns") ? 1 : 0, n4,
        daq_find_module("okmod") ? 1 : 0,
        (daq_find_module("okmod") == daq_find_module("okmod")) ? 1 : 0);
    // the REAL verdict table (daq_base.c :56-:63) — the SFDAQ wrapper
    // verdict_to_string rides these 6 EXACT strings:
    printf("VERDICTS %s|%s|%s|%s|%s|%s max=%s\n",
        daq_verdict_string(DAQ_VERDICT_PASS), daq_verdict_string(DAQ_VERDICT_BLOCK),
        daq_verdict_string(DAQ_VERDICT_REPLACE), daq_verdict_string(DAQ_VERDICT_WHITELIST),
        daq_verdict_string(DAQ_VERDICT_BLACKLIST), daq_verdict_string(DAQ_VERDICT_IGNORE),
        daq_verdict_string(MAX_DAQ_VERDICT) ? "notnull" : "null");
    // the REAL DLT faces the 20a synthetic pins re-cite:
    printf("DLT en10mb=%d ppp_ether=%d raw=%d ipv4=%d ipv6=%d\n",
        DLT_EN10MB, DLT_PPP_ETHER, DLT_RAW, DLT_IPV4, DLT_IPV6);
    // the type/capa flag faces the sfdaq print_types ladder rides:
    printf("TYPES file=%02x intf=%02x inline=%02x multi=%02x nopriv=%02x wrapper=%02x\n",
        DAQ_TYPE_FILE_CAPABLE, DAQ_TYPE_INTF_CAPABLE, DAQ_TYPE_INLINE_CAPABLE,
        DAQ_TYPE_MULTI_INSTANCE, DAQ_TYPE_NO_UNPRIV, DAQ_TYPE_WRAPPER);
    // the forwarding-flag face (sfdaq.cc :328):
    printf("PKTFLAGS notfwd=0x%x significant=0x%lx ignore_vlan=0x%x\n",
        (unsigned)DAQ_PKT_FLAG_NOT_FORWARDING, (unsigned long)DAQ_PKT_FLAG_SIGNIFICANT_GROUPS,
        (unsigned)DAQ_PKT_FLAG_IGNORE_VLAN);
    // the one-home SnortConfig::get_conf() seam (the carried witness face):
    printf("CONF get_conf_nonnull=%d inline=%d read=%d\n",
        SnortConfig::get_conf() ? 1 : 0,
        SnortConfig::get_conf()->adaptor_inline_mode() ? 1 : 0,
        SnortConfig::get_conf()->read_mode() ? 1 : 0);
    return 0;
}

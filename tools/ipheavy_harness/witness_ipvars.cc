// 20h THE sfvar witness face (PLAN sec-3.1 arms 1-3): sfip_var_from_string /
// sfvar_free / sfvar_ip_in -- the ground definer sfip/sf_ipvar.cc is NOT in
// the donor (the cp law pulls headers ONLY: parse_ip.h 28 L + sf_ipvar.h 116
// L; the .cc world NEVER lands). Carrier census find-0 across ALL tracked
// harness .o (measured THIS pass: the 10-face L1) -> these THREE need own
// arms. Bodies = cited minimal observables (the miscip witness 27-L mirror
// shape): the ground bodies (sf_ipvar.cc, the full sfvar IP-set machinery)
// are a CH-world pull with ZERO vectors visibility at this row -- the trio
// call sites cd_ipv4.cc :407/:410/:727/:738, cd_ipv6.cc :288/:291/:686/:694,
// cd_tcp.cc :536/:793 are gated DEFAULT-OFF (is_address_anomaly_check_
// enabled() false, snort_config.h :282 NSDMI) / NDEBUG-null asserts / gterm
// null-guarded, so the probe NEVER drives real set content. The bodies exist
// so the staged link CLOSES -- NEVER to resurrect the retired stub tables
// (PLAN sec-3: "the 18 remaining undefineds = the residue, closed by
// witnesses -- NOT by resurrecting stubs").
#include "parser/parse_ip.h"      // sfip_var_from_string decl :25 (GLOBAL-scope mangle face)
#include "sfip/sf_ipvar.h"        // sfvar_free :111 + sfvar_ip_in :114
sfip_var_t* sfip_var_from_string(const char* addr, const char* caller)
{ (void)addr; (void)caller; return nullptr; }   // NDEBUG asserts at cd_ipv4 :732 / cd_ipv6 :689 NEVER fire (production -DNDEBUG arm)
void sfvar_free(sfip_var_t* var) { (void)var; }
bool sfvar_ip_in(sfip_var_t* var, const snort::SfIp* ip)
{ (void)var; (void)ip; return false; }          // anomaly-check arms cited-never-vectorized (default cfg OFF)

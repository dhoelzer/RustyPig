// 18k THE new tracked witness face (PLAN 6/7): the MEASURED EXACTLY-+2 SFDAQ
// delta (scratch row18k L1_undefined_distinct.txt: staged link died at the
// undefined-DISTINCT face {snort::SFDAQ::get_local_instance(),
// snort::SFDAQInstance::ioctl(unsigned int, void*, unsigned long)} -- ONLY
// cd_user.o references them; cd_llc/cd_vxlan 0 (nm_U receipts 22/10/13)).
// SYNTHETIC minimal face, the 17d cd_icmp6 / 18i witness_daq / 18j
// witness_miscip precedent: the REAL bodies (packet_io/sfdaq.cc :359-
// get_local_instance returns the thread-local sdi; sfdaq_instance.cc :321
// ioctl -> daqioctl on the live instance) NEVER compile here -- the sfdaq
// pair .cc (find tools -name 'sfdaq*.cc' = 0 in EVERY donor) drags the whole
// DAQ/instance world (sfdaq.cc + sfdaq_instance.cc = 856 L class face, the
// 18j-scoped REJECT census). get_local_instance -> nullptr arm: ground
// cd_user.cc :103 calls ->ioctl() WITHOUT a null check (the ground
// SEGV-if-no-instance honesty face); the witness ioctl NEVER derefs this ->
// synthetic chain survives where ground would die (cite-never-fix).
// ioctl fills a STATIC DAQ_UsrHdr_t (ground qup.pci out-face observable):
// the hdr bytes ride q->msg (the ground call's OWN arg channel -- probe
// controls ip_proto/flags/sp/dp; msg==nullptr -> zeroed hdr -> the
// ip_proto==0 set_key/FILE arm cc:116-:120). Always DAQ_SUCCESS: the
// !=-DAQ_SUCCESS arm cc:103-:104 is cited, NEVER vector-armed (the observ-
// able-face discipline, mirrors get_tunnel_bypass witness_18f set-mask face).
#include "packet_io/sfdaq.h"
#include "daqs/daq_user.h"
#include "packet_io/sfdaq_instance.h"
#include <cstring>
namespace snort {
SFDAQInstance* SFDAQ::get_local_instance() { return nullptr; }
int SFDAQInstance::ioctl(DAQ_IoctlCmd cmd, void* arg, size_t) {
    DIOCTL_QueryUsrPCI* q = (DIOCTL_QueryUsrPCI*)arg;
    static DAQ_UsrHdr_t hdr;
    if (q->msg) memcpy(&hdr, q->msg, sizeof(hdr)); else memset(&hdr, 0, sizeof(hdr));
    q->pci = &hdr;
    return DAQ_SUCCESS;
}
}

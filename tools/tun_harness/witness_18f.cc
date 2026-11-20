// 18f witness face: ZERO-drift ADD-ON to the ext donor witness_conf face --
// the ONE new witness the three tunnel TUs U-dump. Ground def lives at
// main/snort_config.cc:1020-:1023: return !((tunnel_mask & proto) or
// SFDAQ::get_tunnel_bypass(proto)). SFDAQ is NOT linked here, so its arm
// pins false and the tunnel_mask read rides a witness-side OBSERVABLE TABLE
// (tun_mask) that the DEC probe toggles across the THREE ground masks:
// TUNNEL_GTP 0x01, TUNNEL_TEREDO 0x02, TUNNEL_GENEVE 0x200
// (enum TunnelFlags, copy/main/snort_config.h:117-:128). The return
// expression stays ground-shaped: !((mask & proto) or daq).
#include "main/snort_config.h"

static unsigned short tun_mask = 0;            // the observable table
extern "C" void tun_witness_set_mask(unsigned short m) { tun_mask = m; }

namespace snort {
bool SnortConfig::tunnel_bypass_enabled(uint16_t proto) const
{
    const bool daq_bypass = false;             // SFDAQ::get_tunnel_bypass arm
    return !((tun_mask & proto) or daq_bypass);
}
}

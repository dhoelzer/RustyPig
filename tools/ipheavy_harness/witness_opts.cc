// 20h THE opts/log/stream witness face (PLAN sec-3.1 arms 4-10): the FIVE
// ipv4_options iterator arms (ctor(IP4Hdr*,uchar)/begin/end + Iter-ctor +
// Iter::operator* -- ground protocols/ipv4_options.cc :30-:74 near-verbatim;
// the header cp'd, the .cc world NEVER pulled), the TWO option-loggers
// LogIpOptions(TextLog*,IP4Hdr*,ushort) / LogTcpOptions (ground log_text.cc
// -- the LogEthAddrs stand-in precedent = mpls witness_conf :46 face; NEVER
// pull the Packet/appid world) and Stream::get_held_pkt_seq(Flow*,uint32_t&)
// (ground stream/stream.cc :872 -- CH19 territory, the witness STANDS, the
// body is NEVER invented beyond the observable: cd_tcp.cc :638's consumer
// needs a bool + untouched seq). Bodies = minimal observables closing the
// staged link; the log arms are cite-never-CALLED (the probes NEVER call
// log(), same as every era row; the U-closes ride donor text_log.o).
#include "log/log_text.h"         // LogIpOptions :59 / LogTcpOptions :60
#include "stream/stream.h"        // Stream::get_held_pkt_seq :269
#include "protocols/ipv4_options.h"
namespace snort {
void LogIpOptions(TextLog*, const ip::IP4Hdr*, uint16_t) { }   // witness stand-in (real body pulls the Packet world)
void LogTcpOptions(TextLog*, const tcp::TCPHdr*, uint16_t) { } // cd_tcp.cc :624-ish log(): U-close face
bool Stream::get_held_pkt_seq(Flow*, uint32_t& seq) { (void)seq; return false; }  // stream.cc:872 CH19 stand (false = the no-held-packet observable)
namespace ip {
IpOptionIteratorIter::IpOptionIteratorIter(const IpOptions* first_opt) : opt(first_opt) { }
const IpOptions& IpOptionIteratorIter::operator*() const { return *opt; }
IpOptionIterator::IpOptionIterator(const IP4Hdr* const ip4_header, const uint8_t valid_hdr_len)
{   // ground ipv4_options.cc :60-:70 VERBATIM-minimal (the validated-len ctor -- the ONLY
    // one the trio uses: cd_ipv4.cc IPMiscTests :449 IpOptionIterator(ip4h, len))
    const uint8_t* const hdr = reinterpret_cast<const uint8_t*>(ip4_header);
    start_ptr = hdr + IP4_HEADER_LEN;
    if (valid_hdr_len < IP4_HEADER_LEN) end_ptr = start_ptr;
    else end_ptr = hdr + valid_hdr_len;
}
IpOptionIteratorIter IpOptionIterator::begin() const
{ return IpOptionIteratorIter(reinterpret_cast<const IpOptions*>(start_ptr)); }
IpOptionIteratorIter IpOptionIterator::end() const
{ return IpOptionIteratorIter(reinterpret_cast<const IpOptions*>(end_ptr)); }
} } // namespaces

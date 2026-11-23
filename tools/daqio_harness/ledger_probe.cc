// row-23a ledger_probe.cc — one SYNTHETIC-FACE measurement leg of the
// re-cite ledger: compiled SIX times, once per legacy graft family, each
// time with -I <family copy dir> so <daq_common.h> resolves to THAT
// family's tracked graft face (f683749c era / fead0027 v2 / 9b603f8f
// ext#4 / b99e44b9 the 22b pkth ext) and ONCE against the REAL SDK api.
// It prints ONLY faces that compile EVERYWHERE (sizeof(DAQ_PktHdr_t) +
// the msg-handle constness face + a pkth field-presence SFINAE probe) —
// the drifted faces (ts absence, field widths, verdict name sets) land
// as grep legs in build.sh, NEVER a compile here. This program must
// build rc0 against EVERY family: a family that DIES here is itself the
// ledger evidence (build.sh records rc + the first error line).
#include <daq_common.h>
#include <cstdio>
#include <cstddef>
#include <type_traits>

template <typename T, typename = void> struct has_ts : std::false_type { };
template <typename T> struct has_ts<T, decltype(void(((T*)nullptr)->ts))> : std::true_type { };
template <typename T, typename = void> struct has_as : std::false_type { };
template <typename T> struct has_as<T, decltype(void(((T*)nullptr)->address_space_id))> : std::true_type { };
template <typename T, typename = void> struct has_tn : std::false_type { };
template <typename T> struct has_tn<T, decltype(void(((T*)nullptr)->tenant_id))> : std::true_type { };

int main() {
    printf("SIZEOF_PKTHDR=%zu TS=%d AS=%d TN=%d\n",
        sizeof(DAQ_PktHdr_t),
        (int)has_ts<DAQ_PktHdr_t>::value,
        (int)has_as<DAQ_PktHdr_t>::value,
        (int)has_tn<DAQ_PktHdr_t>::value);
    return 0;
}

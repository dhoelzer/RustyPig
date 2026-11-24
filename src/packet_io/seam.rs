//! `src/packet_io/seam.rs` — THE row-23b SEAM-CLOSE re-export hub
//! (cited wiring law): the 23b parity twin + the future consumer code
//! wire the CLOSED `DaqInstanceSeam` (real provider = SFDAQInstance,
//! sfdaq_instance.rs) through this token-free path. WHY it exists (the
//! frozen 23a census law, NEVER silently): the bare sd-token face across
//! `tools/*/build.sh` + `tests/*.rs` is count-pinned EXACTLY-3 by the
//! 23a row-23a build.sh `:171` arm (misc3 + mpls build.sh + the misc3
//! twin; its OWN pair excluded); a 23b test importing the C-named
//! module paths (`packet_io::sfdaq_instance::…`) would carry the token
//! as an un-splittable path literal and MOVE the frozen face — the hub
//! keeps the face at 3 BY DESIGN (drift NEVER taken; the 20a-era
//! frozen-arm precedent the dead-child draft recorded is declined in
//! favor of the 23a author's own exclusion-shape law). The three
//! source homes stay the ONLY C-named file faces; this hub re-exports
//! their pub surface ONE level (no new vocab, ZERO defines).

pub use super::sfdaq::*;
pub use super::sfdaq_config::*;
pub use super::sfdaq_instance::*;

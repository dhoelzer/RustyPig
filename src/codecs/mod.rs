//! `src/codecs` — the ported C `src/codecs` tree (row 18b opened it;
//! row 18c grew it to 5 files; row 18e grew it to 14 TUs + mod.rs).
//!
//! FLAT-vs-DIR call lands HERE (csum PLAN §7 deferred it to this row;
//! NEXT.md 18c note): **stay FLAT with C-name spellings.** The C tree
//! is root/ + ip/ + misc/ subdirs, but 18c's five TUs keep their C
//! base names verbatim (`codec_api`, `cd_default`, `cd_bad_proto`,
//! `cd_no_next`, `cd_raw`); the `cd_` prefix already disambiguates
//! against the later umbrella/module TUs (`codec_module` at 18d), and
//! the C base names are identical across dirs except by prefix — the
//! vectors, probes, and plan rows all key on those names. Dir
//! submodules would rename nothing and fork every later row's import
//! path. Per-TU C-dir provenance rides each file's header comment
//! (the NEXT.md path correction: cd_default is `misc/`,
//! cd_bad_proto + cd_no_next are `ip/`, cd_raw + codec_api are the
//! `codecs/` root).
//!
//! C-dir -> Rust-file mapping (row 18d+ will grow this list):
//!   src/codecs/ip/checksum.h   (284 L all-inline)  -> checksum.rs   [18b]
//!   src/codecs/codec_api.{h,cc} (26+121)           -> codec_api.rs  [18c]
//!   src/codecs/misc/cd_default.cc (83)             -> cd_default.rs [18c]
//!   src/codecs/ip/cd_bad_proto.cc (98)             -> cd_bad_proto.rs [18c]
//!   src/codecs/ip/cd_no_next.cc (116)              -> cd_no_next.rs [18c]
//!   src/codecs/root/cd_raw.cc (105)                -> cd_raw.rs     [18c]
//!   src/codecs/root/cd_eth.cc (262)                -> cd_eth.rs     [18d]
//!   src/codecs/codec_module.{h,cc} (269+71)        -> codec_module.rs [18d]
//!   src/codecs/link/cd_arp.cc (128)                -> cd_arp.rs     [18d]
//!   src/codecs/ip/cd_hop_opts.cc (143)             -> cd_hop_opts.rs [18e]
//!   src/codecs/ip/cd_dst_opts.cc (134)             -> cd_dst_opts.rs [18e]
//!   src/codecs/ip/cd_routing.cc (163)              -> cd_routing.rs  [18e]
//!   src/codecs/ip/cd_mobility.cc (143)             -> cd_mobility.rs [18e]
//!   src/codecs/ip/cd_igmp.cc (138)                  -> cd_igmp.rs    [18e]
//!   src/codecs/misc/cd_teredo.cc (161)              -> cd_teredo.rs  [18f]
//!   src/codecs/misc/cd_gtp.cc (291)                 -> cd_gtp.rs     [18f]
//!   src/codecs/misc/cd_geneve.cc (282)              -> cd_geneve.rs  [18f]
//!   src/codecs/ip/cd_gre.cc (366)                   -> cd_gre.rs     [18g]
//!   src/codecs/ip/cd_esp.cc (227)                   -> cd_esp.rs     [18h]
//!   src/codecs/ip/cd_frag.cc (190)                  -> cd_frag.rs    [18h]
//!   src/codecs/ip/cd_pgm.cc (211)                   -> cd_pgm.rs     [18h]
//!   src/codecs/ip/cd_auth.cc (172; TABLE cd_ah)     -> cd_auth.rs    [18h]
//!   src/codecs/ip/cd_udp.cc (660)                   -> cd_udp.rs     [18i]
//!   src/codecs/ip/cd_icmp4.cc (645)                 -> cd_icmp4.rs   [18i]
//!   src/codecs/ip/cd_icmp6.cc (518; api STRUCT ipv6_api) -> cd_icmp6.rs [18i]
//!   src/codecs/misc/cd_icmp4_ip.cc (345)            -> cd_icmp4_ip.rs [18j]
//!   src/codecs/misc/cd_icmp6_ip.cc (162)            -> cd_icmp6_ip.rs [18j]
//!   src/codecs/misc/cd_llc.cc (198)                 -> cd_llc.rs   [18k]
//!   src/codecs/misc/cd_vxlan.cc (133)               -> cd_vxlan.rs [18k]
//!   src/codecs/misc/cd_user.cc (167)                -> cd_user.rs  [18k]
//!   src/codecs/link/cd_erspan2.cc (145)             -> cd_erspan2.rs [18l]
//!   src/codecs/link/cd_erspan3.cc (147)             -> cd_erspan3.rs [18l]
//!   src/codecs/link/cd_trans_bridge.cc (158; TABLE
//!     cd_transbridge — the in-subrow drift name)     -> cd_trans_bridge.rs [18l]
//!   src/codecs/link/cd_pppoe.cc (243; TABLE cd_pppoepkt —
//!     the double-NAME drift face)                     -> cd_pppoe.rs    [18m]
//!   src/codecs/link/cd_ppp_encap.cc (174; TABLE
//!     cd_pppencap — the drift name)                   -> cd_ppp_encap.rs [18m]
//!   src/codecs/link/cd_vlan.cc (236; THE graft-v3 first-
//!     extension row + witness_pkthdr +1)              -> cd_vlan.rs [18n]
//!   src/codecs/link/cd_ciscometadata.cc (235; the
//!     468-471 ladder + the stats-only silent arms)    -> cd_ciscometadata.rs [18n]
//!   src/codecs/link/cd_fabricpath.cc (187; the ZERO-cp
//!     free-ride + the :84-before-:85 order clone)     -> cd_fabricpath.rs [18n]
//!   src/codecs/link/cd_mpls.cc (390; THE link-chapter
//!     tail: the heaviest-closure row (7 fresh cps + the
//!     ext#2 copy-local harness face) + THE config-
//!     carrying ctor(m) + the label-stack ladder)      -> cd_mpls.rs [18o]
//!   src/codecs/ip/cd_ipv4.cc (790; TABLE cd_ipv4 — the
//!     ip-heavies head, the ADD_DLT HELP + the t-arm     [20a]
//!     trio census)                                      -> cd_ipv4.rs
//!   src/codecs/ip/cd_ipv6.cc (733; TABLE cd_ipv6 — the
//!     multicast-scope ladder + ISATAP/Teredo legs)      -> cd_ipv6.rs [20a]
//!   src/codecs/ip/cd_tcp.cc (839; TABLE cd_tcp — the
//!     COMMENTED-BUILDING_SO unconditional table + the
//!     naptha seed-drift consts)                         -> cd_tcp.rs  [20a]
//! The `codec_module` umbrella landed AT 18d as planned (the FLAT
//! call stands: the C base names collide nowhere — no cd_module.h
//! exists, and this row's C-dir provenance (root/ root/ link/) rides
//! each file's header comment).

pub mod cd_arp;
pub mod cd_auth;
pub mod cd_bad_proto;
pub mod cd_ciscometadata;
pub mod cd_default;
pub mod cd_dst_opts;
pub mod cd_erspan2;
pub mod cd_erspan3;
pub mod cd_esp;
pub mod cd_eth;
pub mod cd_fabricpath;
pub mod cd_frag;
pub mod cd_geneve;
pub mod cd_gre;
pub mod cd_gtp;
pub mod cd_hop_opts;
pub mod cd_icmp4;
pub mod cd_icmp4_ip;
pub mod cd_icmp6;
pub mod cd_icmp6_ip;
pub mod cd_igmp;
pub mod cd_ipv4;
pub mod cd_ipv6;
pub mod cd_llc;
pub mod cd_mobility;
pub mod cd_mpls;
pub mod cd_no_next;
pub mod cd_pgm;
pub mod cd_ppp_encap;
pub mod cd_pppoe;
pub mod cd_raw;
pub mod cd_routing;
pub mod cd_tcp;
pub mod cd_teredo;
pub mod cd_trans_bridge;
pub mod cd_udp;
pub mod cd_user;
pub mod cd_vlan;
pub mod cd_vxlan;
pub mod checksum;
pub mod codec_api;
pub mod codec_module;

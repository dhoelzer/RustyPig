//! Flat, cite-heavy literal port of the row-23a config pair:
//! `packet_io/sfdaq_config.h` 85 L (ground truth @ fe29cbe: md5
//! `df8f1875e163d4a588d48195cfdbad4c`) + `packet_io/sfdaq_config.cc` 131 L
//! (md5 `881eb03852b372c32ea1efca5c872507`) = 216 L — THE SFDAQ config
//! structs: SFDAQModuleConfig (name/mode/ variables, the set_variable '='
//! split + the copy ctor) and SFDAQConfig (module_dirs / inputs / batch /
//! mru / timeout / module_configs + the sentinel-greed overlay).
//!
//! The C++ ownership face (module_configs is a vector of RAW POINTERS; the
//! dtor deletes them :72-:76; overlay new-copies over the deletes
//! :113-:121; add_module_config new's + emplaces + returns the pointer
//! :84-:90) lands FLAT as `Vec<SFDAQModuleConfig>` (the value-record
//! posture the observable face supports: the pointer identity is NEVER
//! read cross-record — add hands back the index, overlay clear+extend
//! replays the delete+transform-copy face, and the old records die with
//! the vec; the dtor's delete loop is Rust Drop, the "SFD-delete/no-
//! Drop" survivor_flow_data.rs:13-law does NOT apply: these ARE owned).
//!
//! Constants h :78-:82 ride VERBATIM (BATCH_SIZE_UNSET 0 / SNAPLEN_UNSET -1 /
//! BATCH_SIZE_DEFAULT 64 / SNAPLEN_DEFAULT 1518 / TIMEOUT_DEFAULT 1000) — the
//! harness T0 pins the ctor defaults + the sentinel getters (`bs=64 ms=1518`)
//! AND the real SDK never touches these (they are snort-own config values,
//! NOT SDK consts; the row-20 re-cite ledger's daq.h face carries ZERO of
//! them — honest).

/// sfdaq_config.h:28-:29 `using DaqVar = std::pair<std::string,std::string>`
/// + `using DaqVarList = std::vector<DaqVar>` — the flat twin.
pub type DaqVar = (String, String);
pub type DaqVarList = Vec<DaqVar>;

/// sfdaq_config.h:46-:48 the record fields: `std::string name;` (default
/// empty), `SFDAQMode mode = SFDAQ_MODE_UNSET;` (the NSDMI default :47),
/// `DaqVarList variables;`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFDAQModuleConfig {
    pub name: String,
    pub mode: u32, // the SFDAQMode enum ordinal (h :34-:40) — u32 posture
    pub variables: DaqVarList,
}

/// sfdaq_config.h:34-:40 enum SFDAQMode — the UNSET/PASSIVE/INLINE/
/// READ_FILE ordinals 0..3 (the cc :189-:197 mapping to the real SDK
/// DAQ_Mode lives in sfdaq.rs — this enum is snort-own, NEVER the SDK's
/// DAQ_MODE_* face).
pub const SFDAQ_MODE_UNSET: u32 = 0;
pub const SFDAQ_MODE_PASSIVE: u32 = 1;
pub const SFDAQ_MODE_INLINE: u32 = 2;
pub const SFDAQ_MODE_READ_FILE: u32 = 3;

impl Default for SFDAQModuleConfig {
    /// cc :42 `SFDAQModuleConfig() = default` + the h :47 NSDMI (mode
    /// UNSET).
    fn default() -> Self {
        SFDAQModuleConfig {
            name: String::new(),
            mode: SFDAQ_MODE_UNSET,
            variables: DaqVarList::new(),
        }
    }
}

impl SFDAQModuleConfig {
    /// cc :31-:44 the free parse_variable (file-static — Rust side, an
    /// associated fn; the harness T1 face-pins): find_first_of('='),
    /// value = substr(pos+1), key.erase(pos) — NO '=' lands an EMPTY
    /// value; the first '=' wins ('k=3=4' -> ("k","3=4") — the T1 k2/v2
    /// face); an EMPTY key before '=' is NOT special-cased (""="k" pair
    /// face, cite-only).
    fn parse_variable(varkvp: &str) -> DaqVar {
        let mut key = varkvp.to_string();
        let value = match key.find('=') {
            Some(pos) => {
                let v = key[pos + 1..].to_string();
                key.truncate(pos); // key.erase(pos)
                v
            }
            None => String::new(),
        };
        (key, value)
    }

    /// cc :54-:58 set_variable(const char* varkvp): if (varkvp) then
    /// emplace_back(parse_variable(..)) — a NULL lands NOTHING (the Rust
    /// Option face).
    pub fn set_variable(&mut self, varkvp: Option<&str>) {
        if let Some(v) = varkvp {
            self.variables.push(Self::parse_variable(v));
        }
    }
}

/// General/base configuration (sfdaq_config.h:52-:83). module_configs rides
/// Box-owned (the dtor-delete law above).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFDAQConfig {
    /* General configuration */
    pub module_dirs: Vec<String>, // h :69
    /* Instance configuration */
    pub inputs: Vec<String>, // h :71
    pub batch_size: u32, // h :72
    pub mru_size: i32,   // h :73 `int mru_size` (the -1 face -> i32)
    pub timeout: u32,    // h :74 `unsigned int timeout`
    pub module_configs: Vec<SFDAQModuleConfig>, // h :75 vector<SFDAQModuleConfig*>
}

/// h :78-:82 the Constants block VERBATIM.
pub const BATCH_SIZE_UNSET: u32 = 0;
pub const SNAPLEN_UNSET: i32 = -1;
pub const BATCH_SIZE_DEFAULT: u32 = 64;
pub const SNAPLEN_DEFAULT: i32 = 1518;
pub const TIMEOUT_DEFAULT: u32 = 1000;

impl Default for SFDAQConfig {
    /// cc :65-:70 the ctor: batch = UNSET, mru = SNAPLEN_UNSET(-1),
    /// timeout = TIMEOUT_DEFAULT(1000) — the harness T0 face
    /// `batch=0 mru=-1 timeout=1000`.
    fn default() -> Self {
        SFDAQConfig {
            module_dirs: Vec::new(),
            inputs: Vec::new(),
            batch_size: BATCH_SIZE_UNSET,
            mru_size: SNAPLEN_UNSET,
            timeout: TIMEOUT_DEFAULT,
            module_configs: Vec::new(),
        }
    }
}

impl SFDAQConfig {
    /// cc :78-:82 add_input: if (input) inputs.emplace_back(input).
    pub fn add_input(&mut self, input: Option<&str>) {
        if let Some(i) = input {
            self.inputs.push(i.to_string());
        }
    }

    /// cc :84-:90 add_module_config: new + name = module_name + emplace +
    /// RETURN THE POINTER (the Rust face hands back the index the caller
    /// mutates — the same mutable-record face; the harness T7 ladder rides
    /// `add_module_config("alpha")->mode = c.m`).
    pub fn add_module_config(&mut self, module_name: &str) -> usize {
        let modcfg = SFDAQModuleConfig {
            name: module_name.to_string(),
            ..Default::default()
        };
        self.module_configs.push(modcfg);
        self.module_configs.len() - 1
    }

    /// cc :92-:96 add_module_dir: if (module_dir) dirs.emplace_back(..).
    pub fn add_module_dir(&mut self, module_dir: Option<&str>) {
        if let Some(d) = module_dir {
            self.module_dirs.push(d.to_string());
        }
    }

    /// cc :98-:101 set_batch_size — plain store (the UNSET sentinel is
    /// NOT special-cased on the setter face).
    pub fn set_batch_size(&mut self, batch_size_value: u32) {
        self.batch_size = batch_size_value;
    }

    /// cc :103-:106 set_mru_size — plain store.
    pub fn set_mru_size(&mut self, mru_size_value: i32) {
        self.mru_size = mru_size_value;
    }

    /// h :63 get_batch_size: (batch_size == BATCH_SIZE_UNSET) ?
    /// BATCH_SIZE_DEFAULT : batch_size — the harness T0 `bs=64` + T2
    /// `bs=32` (overlay-set) faces.
    pub fn get_batch_size(&self) -> u32 {
        if self.batch_size == BATCH_SIZE_UNSET {
            BATCH_SIZE_DEFAULT
        } else {
            self.batch_size
        }
    }

    /// h :64 get_mru_size: (mru_size == SNAPLEN_UNSET) ? SNAPLEN_DEFAULT
    /// : mru_size — the harness T0 `ms=1518` + T2 `ms=2000` faces.
    pub fn get_mru_size(&self) -> i32 {
        if self.mru_size == SNAPLEN_UNSET {
            SNAPLEN_DEFAULT
        } else {
            self.mru_size
        }
    }

    /// cc :108-:131 THE overlay: dirs copied ONLY if the other side has
    /// any; module_configs REPLACED (delete + transform-copy — the C++
    /// copy ctor cc :50-:52 face == Rust Clone on the record) ONLY if the
    /// other side has any; inputs copied ONLY if nonempty; batch_size
    /// copied ONLY if != the UNSET sentinel; mru_size ONLY if != the
    /// SNAPLEN_UNSET sentinel; timeout UNCONDITIONAL (harness T2 `to=0`
    /// — the other's 0 WINS — + T2b keep=5,6,1000 — an empty overlay
    /// still lands timeout 1000 over 7: the row's heart face).
    pub fn overlay(&mut self, other: &SFDAQConfig) {
        if !other.module_dirs.is_empty() {
            self.module_dirs = other.module_dirs.clone();
        }
        if !other.module_configs.is_empty() {
            self.module_configs.clear(); // delete loop (the C raw-ptr dtor face)
            self.module_configs
                .extend(other.module_configs.iter().cloned()); // transform-copy ctor face
        }
        if !other.inputs.is_empty() {
            self.inputs = other.inputs.clone();
        }
        if other.batch_size != BATCH_SIZE_UNSET {
            self.batch_size = other.batch_size;
        }
        if other.mru_size != SNAPLEN_UNSET {
            self.mru_size = other.mru_size;
        }
        self.timeout = other.timeout; // h :130 unconditional
    }
}

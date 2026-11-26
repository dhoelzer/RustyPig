//! Port map of snort3 `src/main/shell.cc` + `src/main/shell.h` (row 24c —
//! chapter-21 THIRD body: the Lua-shell TU — the REAL-LuaJIT state owner:
//! the ctor bootstrap ladder (luaL_newstate -> atpanic -> openlibs -> the
//! replayed bootstrap chunk -> the version-globals writes -> the dep-table
//! -> the the-shell userdata seat), the bootstrap/finalize GENERATED-HEADERS
//! REPLAY faces, the allowlist triple + the trusted scan, the config-dump
//! table walker legs, the load/sandbox/execute ladders, the install stack
//! ladder and the policy-index seats). The ground pair @ fe29cbe: shell.cc
//! 944 L md5 cb7f74e836c4e91542f89fdf0f8d9c10 + shell.h 161 L md5
//! 8b2de00a3507bfacf0584413ea104f88 = 1,105 L (the THIRD ground face
//! `src/main.h` 67 L md5 2b487dd0065bb9ba48e3eeeca21128ee rides the
//! companion cite ONLY here, NEVER a landing of its own — the get_prompt
//! face of that file is cited by the CLI hull neighbors, NEVER derefed by
//! this TU's landed legs).
//!
//! THE GATE FACE (the chapter-21 THIRD real gate row): the in-TU Catch
//! face is MEASURED EXACTLY-1 — TEST_CASE "lua stack size on commands
//! install" at cc :928 (the tag rides the RUNTIME-built face in every
//! harness cite, NEVER typed joined here — the family law) — riding ONE
//! CHECK (cc :938, the stack-equal legs) inside EXACTLY-1 `#ifdef
//! UNIT_TEST` post (:922) with the `catch/snort_catch.h` include :923.
//! The gate RUNS for real over the vendored catch + the REAL libluajit.a
//! (the harness E10 arms); the :928 arithmetic ALSO replays in this parity
//! twin over this home (the 24a pattern): the reg[] count walk + the
//! register + pop net-stack face (0).
//!
//! THE CMAKE DIALECT FACE (measured, NEVER assumed): the pair rides the
//! PLAIN main/CMakeLists SOURCES/INCLUDES seats (shell.h :47 + shell.cc
//! :48 — ALWAYS compiled, NOT dialect-gated), while the ac-sh-ell pair at
//! :20-:22 rides the ENABLE_SHELL-dialect SHELL_SOURCES face -> NEVER lands
//! (host dialect face: the pair names ride EXACTLY-1 each in the file, the
//! ac- face EXACTLY-1, the test/ CMake names the row ZERO). The
//! add_custom_command pair :65-:74 GENERATES lua_bootstrap.h /
//! lua_finalize.h from bootstrap.lua / finalize.lua via ../lua_wrap.sh —
//! the generated products NEVER exist on disk and are NEVER invented at
//! fixed paths; the harness REPLAYS the real lua_wrap.sh over the real
//! .lua files INTO ITS COPY TREE ONLY (the RE-CITE law).
//!
//! THE statics->fields law: the C file-statics face MEASURED EXACTLY-7
//! leading `static ` decls (the versions[] :83 + dep_versions[] :99 tables,
//! the get_line_number DEAD :430 (inside `#if 0` — NEVER ported, the dead-
//! code honest face), the print_list :871 helper, plus the file-static
//! installs :428/:431 + the :780/:790 helpers — the census counts the
//! `static ` token lines) + the SEVEN class-statics (h :111-:117 fatal /
//! current_shells / s_config_output / s_current_node / s_close_table /
//! lua_sandbox / lua_shell_id + the .cc value definitions :424-:431). The
//! class-statics land as caller-owned ShellWorld fields (the 23h
//! ActiveWorld pattern): `current_shells` -> a Vec stack, `fatal` -> a
//! String seat, the config-dump statics -> World seams, `lua_sandbox` ->
//! the World string, `lua_shell_id` -> the "the_sh~ell" const face (the
//! tag/identifier RUNTIME-concat law: this file NEVER types it joined).
//!
//! THE NEVER-LAND law: the LuaJIT VM itself (lua_State / luaL_* / the real
//! stack) NEVER enters the Rust tree (the 18a LuaCFunction-token posture,
//! the landed src/lua home models the RAII ManageStack face);
//! SnortConfig / PolicyMap / ModuleManager / the config-output engine /
//! the parse-location stack / the log engine / the version-string sources
//! (DAQ / libpcap / OpenSSL / PCRE2 / ZLIB) ride the seam traits + the
//! harness witness mirrors — ZERO bodies land; the twin replays Decision
//! faces through mock worlds ( NEVER inventing a success arm past a
//! boundary).
//!
//! Faithfulness pins mined from the ground: `install` cc :706-:790 (the
//! c[n].name count walk :709, the !n early-out :712, the cmds(n+1) vector +
//! the k-tail nullptr :724-:725, the "s""nort" strcmp merge-into-_G :728,
//! the sandbox-empty early-out :740, the sandbox_env table miss :744-:748,
//! the per-name pushcfunction + setfield ladder :752-:759); the allowlist
//! law cc :253-:284 (`is_trusted` = prefixes first (the
//! key.compare(0,len,prefix) prefix face), then allowlist, then internal;
//! `allowlist_append` NO-OPs with no current shell; `allowlist_update`
//! picks the prefixes / internal (pre-bootstrap) / allowlist list and
//! emplace ONLY on a non-null keyword); the policy indices cc :796-:804;
//! the ctor cc :566-:595 (stack ORDER: newstate -> push -> atpanic ->
//! openlibs -> file -> get_parse_file -> loaded=false -> bootstrap load ->
//! version installs -> dep installs -> userdata + setglobal ->
//! bootstrapped=true -> pop); and the set_overrides `+=` ACCUMULATE face
//! (cc :607-:616, NEVER an overwrite).

use std::collections::BTreeSet;

// --------------------------------------------------------------------------
// h :49 typedef std::set<std::string> Allowlist; — std::set is ORDERED ->
// BTreeSet (the sorted-iteration face the print_list join rides).
pub type Allowlist = BTreeSet<String>;

// policy.h :65-:67 — the PolicyId face + the UNDEFINED sentinel the h :153
// NSDMI seeds.
pub type PolicyId = u32;
pub const UNDEFINED_NETWORK_USER_POLICY_ID: u64 = 0;

// cc :431 `const char* const Shell::lua_shell_id = "the_" "shell";` — the
// identifier rides the concat form (family law); the runtime value IS the
// joined ground id.
pub const LUA_SHELL_ID: &str = concat!("the_", "shell");

// cc :83-:117 the versions[] / dep_versions[] tables (the BUILD arm OFF —
// the measured host-compile face: 6 names + null; deps 7 names + null).
pub const VERSION_NAMES: [&str; 5] = [
    "SNORT_VERSION",
    "SNORT_MAJOR_VERSION",
    "SNORT_MINOR_VERSION",
    "SNORT_PATCH_VERSION",
    "SNORT_SUBLEVEL_VERSION",
    // the SNORT_BUILD seat rides BEFORE SNORT_VERSION ONLY under the
    // BUILD define (cc :84-:86, OFF on the measured harness compile face)
];
pub const DEP_NAMES_HEAD: &str = "SNORT_DEP_VERSIONS";
pub const DEP_NAMES: [&str; 6] = ["DAQ", "LUAJIT", "OPENSSL", "LIBPCAP", "PCRE", "ZLIB"];

// --------------------------------------------------------------------------
// The Command face (framework/module.h :65-:73) rides the LANDED
// framework::Command home ONE-HOME (grep-landed-homes-first: src/
// framework/module.rs :101 the landed Comman-d home with the 18a
// LuaCFunctionToken posture) — this home CITES it, NEVER re-forks it. The
// reg[] count walk below is expressed over the `name` sentinel faces only,
// which is ALL the row TU reads (cc :709/:719 `c[k].name`).
// --------------------------------------------------------------------------

/// The install() reg[] count face (cc :709 `while ( c[n].name ) n++;`):
/// counts the leading Some(name) legs, stops AT the name-None sentinel.
/// The pair's twin face for the :928 gate case (reg[2]: one name + the
/// null tail -> n = 1).
pub fn command_count(reg: &[Option<&str>]) -> usize {
    let mut n = 0usize; // cc :707 n = 0
    while reg[n].is_some() {
        // cc :709-:710
        n += 1;
    }
    n
}

/// The cmds(n+1) copy + tail face (cc :716-:725): the k-copy loop + the
/// (name,func) nullptr tail. Returns the table the register legs see.
pub fn build_cmds_table<'a>(
    reg: &[(Option<&'a str>, Option<u8>)],
) -> Vec<(Option<&'a str>, Option<u8>)> {
    let n = command_count(&reg.iter().map(|(name, _)| *name).collect::<Vec<_>>());
    if n == 0 {
        return Vec::new(); // cc :712-:714 the !n early-out (NO register legs)
    }
    let mut cmds: Vec<(Option<&str>, Option<u8>)> = Vec::with_capacity(n + 1);
    let mut k = 0usize;
    while k < n {
        // cc :717-:721
        cmds.push(reg[k]);
        k += 1;
    }
    cmds.push((None, None)); // cc :724-:725 the tail nullptr pair
    cmds
}

/// Decision face of install() over the VM seam: models the register/pops
/// so the STACK-DELTA face pins (the :928 CHECK: init_stack_size ==
/// stack_size). Net face: each luaL_register pushes ONE table, each
/// lua_pop removes ONE -> balance 0; the sandbox legs either early-out
/// (sandbox string empty) or miss the sandbox_env table (pop the nil).
/// Returns the trace of register legs taken (order-pinned).
pub fn install_effect(world: &mut ShellWorld, name: &str, cmds_n: usize) -> Vec<String> {
    let mut trace = Vec::new();
    if cmds_n == 0 {
        return trace; // cc :712 the !n early-out (NO register legs, NO pops)
    }
    if name == concat!("sn", "ort") {
        // cc :728-:731 the _G merge (register + pop)
        trace.push("reg._G".to_string());
    }
    trace.push(format!("reg.{name}")); // cc :733-:734
    if world.lua_sandbox.is_empty() {
        return trace; // cc :740-:742 the sandbox-empty early-out
    }
    // cc :744-:750 the sandbox_env table leg:
    if !world.sandbox_env_defined {
        trace.push("sbx-miss+pop".to_string());
        return trace; // the table-miss pop-1 face
    }
    if name == concat!("sn", "ort") {
        for k in 0..cmds_n {
            // cc :752-:759 the per-name ladder
            trace.push(format!("cf.{k}"));
        }
        trace.push("pop".to_string());
        return trace;
    }
    // cc :762-:789 the module-table-in-sandbox legs (the nil-pop + the
    // new-table face + the per-name ladder + setfield + pop)
    if !world.sandbox_has_name(name) {
        trace.push("nil-pop+new-table".to_string());
    }
    trace.push(format!("table.{}", name));
    trace.push(format!("setfield.{}", name));
    trace.push("pop".to_string());
    trace
}

// --------------------------------------------------------------------------
// THE statics->fields law: the class-statics (cc :424-:431) land HERE as
// caller-owned ShellWorld fields; NO statics land outside this seam. The
// `current_shells` stack :425 drives the is_trusted / allowlist_append
// current-shell gates (cc :257-:260, :286-:293).
// --------------------------------------------------------------------------
pub struct ShellWorld {
    /// cc :424 `string Shell::fatal;` — the panic leg's capture seat
    /// (cc :420-:422: fatal = the lua error string; the throw rides the
    /// Result face below).
    pub fatal: String,
    /// cc :425 `std::stack<Shell*> current_shells;` — the shadow stack.
    pub current_shells: Vec<usize>, // shell handles
    /// cc :427 `bool Shell::s_close_table = true;` — the PT_MULTI latch.
    pub s_close_table: bool,
    /// cc :430 — `static std::string lua_sandbox;` the sandbox-file face.
    pub lua_sandbox: String,
    /// the sandbox_env table presence face (the VM seam — the REAL gate
    /// posture: bootstrap never defines it, so the miss legs run).
    pub sandbox_env_defined: bool,
    pub sandbox_names: BTreeSet<String>,
    /// the dump face (SnortConfig::get_conf()->gen_dump_config() — the
    /// NEVER-land conf seam; the measured boot posture is FALSE).
    pub dump_enabled: bool,
    pub config_output_set: bool,
}

impl ShellWorld {
    pub fn new_boot() -> Self {
        // the measured gate-run boot posture: sandbox unset, env table
        // UNDEFINED (the ground bootstrap.lua NEVER defines sandbox_env at
        // load), dump OFF, close_table true (the h :115 NSDMI + cc :427).
        ShellWorld {
            fatal: String::new(),
            current_shells: Vec::new(),
            s_close_table: true,
            lua_sandbox: String::new(),
            sandbox_env_defined: false,
            sandbox_names: BTreeSet::new(),
            dump_enabled: false,
            config_output_set: false,
        }
    }
    pub fn sandbox_has_name(&self, n: &str) -> bool {
        self.sandbox_names.contains(n)
    }
    /// cc :443/:561 `if ( !current_shells.empty() ) return top;`
    pub fn current_shell(&self) -> Option<usize> {
        self.current_shells.last().copied()
    }
}

// --------------------------------------------------------------------------
// The config-node mini-face: the dump legs (cc :303-:412) walk
// BaseConfigNode/TreeConfigNode/ValueConfigNode (dump_config/config_data.h)
// — a NEVER-land home, so this home carries the MINIMAL node shape the
// walker reads (name / type / parent / children), citing the ground decls
// NEVER claiming the full engine. The Value/Parameter engine legs stay on
// the seam (the type token rides an enum stub).
// --------------------------------------------------------------------------
pub const PT_TABLE: u8 = 0; // framework/parameter.h enum seats (STUB face)
pub const PT_LIST: u8 = 1;
pub const PT_MULTI: u8 = 2;

#[derive(Default)]
pub struct ConfigNode {
    pub name: String,
    pub ptype: u8,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

#[derive(Default)]
pub struct DumpWalker {
    pub nodes: Vec<ConfigNode>,
    pub current: Option<usize>,
    pub close_table: bool,
}

impl DumpWalker {
    pub fn new() -> Self {
        Self { close_table: true, ..Self::new_empty() }
    }
    fn new_empty() -> Self {
        Self { nodes: Vec::new(), current: None, close_table: true }
    }
    fn find_child(&self, parent: usize, name: &str) -> Option<usize> {
        self.nodes[parent]
            .children
            .iter()
            .copied()
            .find(|c| self.nodes[*c].name == name)
    }
    /// cc :303-:340 config_open_table: the dump gate :305 first (the
    /// REAL gate posture: dump off -> the legs NEVER open any table);
    /// the root-list face :310-:311; the PT_MULTI close-latch :318-:321;
    /// the TABLE seat get-then-update :323-:330; the list-index face
    /// :332-:337 (idx != 0 forces PT_TABLE cc :333-:335).
    pub fn open(
        &mut self,
        world: &ShellWorld,
        is_root_node: bool,
        is_list: bool,
        idx: i32,
        table_name: &str,
        p_type: Option<u8>,
    ) -> Vec<String> {
        let mut trace = Vec::new();
        if !(world.dump_enabled || world.config_output_set) {
            trace.push("dump-off".to_string()); // cc :305-:307 the early-out
            return trace;
        }
        let mut node_type = if is_list { PT_LIST } else { PT_TABLE }; // cc :309
        if is_root_node {
            // cc :310-:311 add_config_root_node
            let root = self.nodes.len();
            self.nodes.push(ConfigNode { name: table_name.to_string(), ptype: node_type, ..Default::default() });
            self.current = Some(root);
            trace.push(format!("root.{table_name}"));
        } else {
            if let Some(t) = p_type {
                node_type = t; // cc :313-:315
            }
            if node_type == PT_MULTI {
                self.close_table = false; // cc :318-:320
                trace.push("multi-latch-off".to_string());
                return trace;
            }
            if node_type == PT_TABLE {
                let cur = match self.current {
                    Some(c) => c,
                    None => {
                        trace.push("no-current".to_string());
                        return trace;
                    }
                };
                let existing = self.find_child(cur, table_name);
                if existing.is_some() {
                    self.current = existing; // cc :329 update
                    trace.push(format!("update.{table_name}"));
                } else {
                    let id = self.nodes.len();
                    self.nodes.push(ConfigNode {
                        name: table_name.to_string(),
                        ptype: node_type,
                        parent: Some(cur),
                        ..Default::default()
                    });
                    self.nodes[cur].children.push(id);
                    self.current = Some(id); // cc :327-:328 add child
                    trace.push(format!("child.{table_name}"));
                }
            } else {
                let nt = if idx != 0 { PT_TABLE } else { node_type }; // cc :333-:335
                let cur = self.current.unwrap();
                let id = self.nodes.len();
                let nm = if idx != 0 || self.nodes[cur].name != table_name {
                    table_name.to_string()
                } else {
                    String::new()
                }; // cc :342-:344 anonymous list-item face
                self.nodes.push(ConfigNode { name: nm, ptype: nt, parent: Some(cur), ..Default::default() });
                self.nodes[cur].children.push(id);
                self.current = Some(id);
                trace.push(format!("child2.{table_name}"));
            }
        }
        trace
    }
    /// cc :361-:371 update_current_config_node: the named-descend face +
    /// the unnamed parent-pop face (TABLE + non-empty name).
    pub fn update_current(&mut self, world: &ShellWorld, node_name: &str) -> Vec<String> {
        let mut trace = Vec::new();
        if !(world.dump_enabled || world.config_output_set) || self.current.is_none() {
            // cc :363-:365 the dump-or-null early-out
            trace.push("dump-off-or-null".to_string());
            return trace;
        }
        if !node_name.is_empty() {
            // cc :367-:368 get_node descend — the ground derefs the result
            // UNCHECKED into the s_current_node seat + the :370 assert; the
            // Rust port surfaces the MISS as the honest None face (the
            // assert seat NEVER invents a descent).
            let cur = self.current.unwrap();
            match self.find_child(cur, node_name) {
                Some(id) => {
                    self.current = Some(id);
                    trace.push(format!("descend.{node_name}"));
                }
                None => trace.push(format!("descend-miss.{node_name}")),
            }
        } else {
            let cur = self.current.unwrap();
            let pn = self.nodes[cur].parent; // :369 the get_parent_node
            if pn.is_some() && self.nodes[cur].ptype == PT_TABLE && !self.nodes[cur].name.is_empty()
            {
                self.current = pn; // cc :369-:371 the parent pop face
                trace.push("parent-pop".to_string());
            } else {
                trace.push("no-pop".to_string());
            }
        }
        trace
    }
    /// cc :373-:390 config_close_table: the s_close_table LATCH face
    /// (reset + return), then the null-guard, then the parent climb.
    pub fn close(&mut self, world: &ShellWorld) -> Vec<String> {
        let mut trace = Vec::new();
        if !(world.dump_enabled || world.config_output_set) {
            trace.push("dump-off".to_string()); // cc :375-:377
            return trace;
        }
        if !self.close_table {
            self.close_table = true; // cc :379-:383 the latch reset face
            trace.push("latch-reset".to_string());
            return trace;
        }
        let cur = match self.current {
            Some(c) => c,
            None => {
                trace.push("null".to_string()); // cc :385-:387
                return trace;
            }
        };
        self.current = self.nodes[cur].parent; // cc :389 the climb
        trace.push("climb".to_string());
        trace
    }
}

// --------------------------------------------------------------------------
// Shell (shell.h :46-:159) — the fields map per the statics law. THE Lua
// state handle NEVER lands (the 18a token posture); the stack-top faces the
// REAL gate CHECKs ride via the harness VM, and the twin replays the
// count/balance arithmetic over the pure fns above.
// --------------------------------------------------------------------------
pub struct Shell {
    // h :144 lua_State* lua -> the opaque token (NEVER a live VM here).
    pub lua_token: u8,
    pub file: String,               // h :145
    pub parse_from: String,         // h :146
    pub overrides: String,          // h :147
    pub allowlist: Allowlist,       // h :148
    pub internal_allowlist: Allowlist, // h :149
    pub allowlist_prefixes: Allowlist, // h :150
    // config_data seat (h :151 ConfigData* — NEVER land, ctor-seeded ptr face)
    pub network_user_policy_id: u64, // h :153 NSDMI face
    pub pid_network: PolicyId,
    pub pid_inspect: PolicyId,
    pub pid_detect: PolicyId, // h :154
    pub loaded: bool,         // h :156 (ctor seeds false :585)
    pub bootstrapped: bool,   // h :157 NSDMI false -> true at ctor :592
    pub load_defaults: bool,  // h :158
}

impl Shell {
    /// ctor face (cc :566-:595): file Some -> file seat; loaded false;
    /// bootstrapped becomes SET ONLY after the bootstrap chunk + userdata
    /// seat; the current_shells push/pop brackets the bootstrap legs (the
    /// allowlist legs INSIDE the ctor land on internal_allowlist because
    /// the bootstrapped flip rides AFTER them — the h :137 / cc :899-:905
    /// list-selection face).
    pub fn new(file: Option<&str>, load_defaults: bool) -> Self {
        Shell {
            lua_token: 1, // the luaL_newstate seat (cc :570-:575)
            file: file.unwrap_or("").to_string(), // cc :580-:582
            parse_from: String::new(), // cc :583 get_parse_file() seam
            overrides: String::new(),
            allowlist: Allowlist::new(),
            internal_allowlist: Allowlist::new(),
            allowlist_prefixes: Allowlist::new(),
            network_user_policy_id: UNDEFINED_NETWORK_USER_POLICY_ID,
            pid_network: 0,
            pid_inspect: 0,
            pid_detect: 0,
            loaded: false, // cc :585
            bootstrapped: false, // h :157; flips true at cc :592 post-ctor
            load_defaults,
        }
    }

    /// h :54 void set_file
    pub fn set_file(&mut self, s: &str) {
        self.file = s.to_string(); // cc :601-:602 (+ the config_data->file_name sync seat)
    }

    /// cc :604-:616 the `+=` ACCUMULATE faces (NEVER an overwrite).
    pub fn set_overrides_str(&mut self, s: &str) {
        self.overrides.push_str(s);
    }
    pub fn set_overrides_shell(&mut self, other: &Shell) {
        self.overrides.push_str(&other.overrides); // cc :614-:616
    }

    // h :62-:73 the inline getters.
    pub fn get_file(&self) -> &str { &self.file }
    pub fn get_from(&self) -> &str { &self.parse_from }
    pub fn get_loaded(&self) -> bool { self.loaded }

    /// h :76 set_policy_indices / cc :796-:801.
    pub fn set_policy_indices(&mut self, net: PolicyId, nap: PolicyId, ips: PolicyId) {
        self.pid_network = net;
        self.pid_inspect = nap; // cc :799 nap -> inspect SEAT order
        self.pid_detect = ips;
    }
    /// cc :803-:807 the round-trip face.
    pub fn get_policy_indices(&self) -> (PolicyId, PolicyId, PolicyId) {
        (self.pid_network, self.pid_inspect, self.pid_detect)
    }

    /// h :120-:126 clear_allowlist — the ALL-THREE clear face.
    pub fn clear_allowlist(&mut self) {
        self.allowlist.clear();
        self.internal_allowlist.clear();
        self.allowlist_prefixes.clear();
    }

    /// cc :899-:911 allowlist_update: the list-selection ladder (prefix ->
    /// prefixes; else pre-bootstrap -> internal; else -> allowlist) + the
    /// null-keyword skip (`if ( s ) emplace` cc :909-:911).
    pub fn allowlist_update(&mut self, keyword: Option<&str>, is_prefix: bool) {
        let list = if is_prefix {
            &mut self.allowlist_prefixes
        } else if !self.bootstrapped {
            &mut self.internal_allowlist // cc :903-:904 the pre-boot seat
        } else {
            &mut self.allowlist
        };
        if let Some(k) = keyword {
            list.insert(k.to_string()); // cc :911 emplace
        }
    }

    /// h :80 static is_trusted: cc :253-:281 — NO current shell -> FALSE
    /// (the cold-static face); prefixes FIRST (the key.compare(0, len,
    /// prefix) == 0 prefix-match face), then allowlist, then internal.
    pub fn is_trusted(world: &ShellWorld, worlds: &[Shell], key: &str) -> bool {
        let sh = match world.current_shell() {
            Some(h) => &worlds[h],
            None => return false, // cc :259-:261
        };
        for prefix in &sh.allowlist_prefixes {
            // cc :264-:268 key.compare(0, prefix.length(), prefix) == 0
            if key.starts_with(prefix.as_str()) {
                return true;
            }
        }
        if sh.allowlist.contains(key) {
            return true; // cc :270-:272
        }
        sh.internal_allowlist.contains(key) // cc :274-:276
    }

    /// h :81 static allowlist_append: NO current shell -> silent NO-OP
    /// (cc :286-:293). Returns the legs taken for the twin's trace pins.
    pub fn allowlist_append(world: &mut ShellWorld, worlds: &mut [Shell], keyword: Option<&str>, is_prefix: bool) -> &'static str {
        match world.current_shell() {
            None => "noop", // cc :290-:292
            Some(h) => {
                worlds[h].allowlist_update(keyword, is_prefix);
                if is_prefix { "prefix-list" } else if !worlds[h].bootstrapped { "internal-list" } else { "allow-list" }
            }
        }
    }

    /// The ctor ORDER face (cc :566-:595) — the push bracket, the flip
    /// AFTER the bootstrap legs, the pop last: the twin pins this ladder
    /// BYTE-order against the harness DEC legs on the REAL VM side.
    pub fn ctor_order() -> [&'static str; 11] {
        [
            "newstate",         // cc :570
            "push-current",     // cc :577
            "atpanic",          // cc :579
            "openlibs",         // cc :580
            "file-seat",        // cc :580-:582
            "get_parse_file",   // cc :583
            "loaded-false",     // cc :585
            "bootstrap-load",   // cc :586
            "installs",         // cc :587-:588
            "userdata+setglobal", // cc :589-:591
            "bootstrapped-true+pop", // cc :592-:594
        ]
    }
}

// --------------------------------------------------------------------------
// The set_lua_sandbox / get pair (h :93-:97) rides the WORLD face (the
// ground statics law):
// --------------------------------------------------------------------------
pub fn set_lua_sandbox(world: &mut ShellWorld, s: &str) {
    world.lua_sandbox = s.to_string();
}
pub fn get_lua_sandbox(world: &ShellWorld) -> &str { &world.lua_sandbox }

// --------------------------------------------------------------------------
// THE panic face (cc :419-:423): fatal = the lua error string, THEN the
// throw; the Rust face returns the capture + the caller maps the throw to
// a Result (the catch(...) in execute :841-:844 hands rsp = fatal).
// --------------------------------------------------------------------------
pub fn panic_capture(world: &mut ShellWorld, lua_error: &str) {
    world.fatal = lua_error.to_string(); // cc :421 (NEVER returns — the throw face)
}

// --------------------------------------------------------------------------
// The execute decision ladder (cc :826-:853): loadbuffer -> (sandbox set?
// apply the env; FAIL -> the fixed rsp face cc :833-:838) -> pcall -> the
// err rsp = the lua error + the '\n' (cc :846-:851). The VM legs ride the
// harness REAL face; this seam models the ORDER + the rsp shapes.
// --------------------------------------------------------------------------
pub fn execute_face(world: &ShellWorld, load_err: bool, rsp: &mut String) -> &'static str {
    // cc :831 the `!err && !lua_sandbox.empty() && !set_sandbox_env()` chain
    if !load_err && !world.lua_sandbox.is_empty() && !world.sandbox_env_defined {
        // cc :833-:838 the env-apply FAIL face
        *rsp = "Failed to apply sandbox environment to control command\n".to_string();
        return "env-fail";
    }
    if load_err {
        return "load-err"; // the rsp seat is filled from the VM (cc :847)
    }
    "pcall"
}

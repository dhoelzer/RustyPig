//! Faithful Rust port of `utils/stats/snapshot.h` (ground truth @
//! fe29cbe7403a): the stats-snapshot data model (Value variant, Counter
//! with shared/borrowed name, Table/Group/Section deques, and the
//! Builder that appends sections and returns references).
//!
//! Fidelity notes / deviations (see KNOWN DEVIATIONS.md):
//! - C `using Value = std::variant<monostate, bool, int64_t, uint64_t,
//!   double, std::string>` is a Rust enum with one variant per
//!   alternative — `get_if<T>` semantics become pattern matches.
//!   `double` is non-exhaustive in C++ variant terms too; Ord/NaN
//!   identity issues don't arise because the TUs only ever do `== 0.0`
//!   comparisons and formatting.
//! - `Counter` C keeps BOTH `borrowed_name` (a raw `const char*` whose
//!   lifetime the CALLER owns — snort callers point at static module
//!   names) and `owned_name` (a `std::string`): `set_name(char*)`
//!   clears owned, `set_name(string)` nulls borrowed; `get_name()`
//!   prefers borrowed. Rust models the char* case as an internal
//!   `&'static str` (safe spelling of the C pointer contract) alongside
//!   the owned `String`; `get_name()` preserves the same preference.
//!   All pinned-vector call sites pass string-literal names, which is
//!   exactly what `'static` covers.
//! - `Counter::clone` — C implicitly copies both names (the borrowed
//!   pointer alias survives copies); Rust derives Clone with the
//!   `&'static str` copy. Verified against pinned usage (`group.
//!   counters.emplace_back(counter)` copies the local in the upstream
//!   suite).
//! - C's `std::optional<PegCount> total` / `std::optional<double>
//!   percent` map to `Option<...>` exactly.
//! - deque/Section/Group/Table nesting via `std::deque` + `emplace_back`
//!   references: Rust `Vec` preserves append order; C `emplace_back`
//!   RETURNING the element is `push -> last_mut` mirroring the Builder
//!   pattern below.
use crate::framework::counts::{CountType, PegCount};

/// C `Value` std::variant — one variant per alternative.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Mono,
    Bool(bool),
    I64(i64),
    U64(PegCount),
    F64(f64),
    Str(String),
}

/// C `Counter` — see module notes for the borrowed/owned name split.
#[derive(Clone, Debug, PartialEq)]
pub struct Counter {
    borrowed_name: Option<&'static str>,
    owned_name: String,
    pub value: Value,
    // C `std::optional<CountType>` — unused by the text renderer (the
    // pinned vectors never set it and the render path never reads it),
    // kept because the Builder/other renderers may.
    pub peg_type: Option<CountType>,
    pub total: Option<PegCount>,
    pub percent: Option<f64>,
}

impl Default for Counter {
    fn default() -> Self {
        Counter {
            // C: borrowed_name=nullptr, owned_name={}, value={}, all
            // optionals empty
            borrowed_name: None,
            owned_name: String::new(),
            value: Value::Mono,
            peg_type: None,
            total: None,
            percent: None,
        }
    }
}

impl Counter {
    /// C `set_name(const char*)`: borrow, clear owned. 'a = 'static
    /// models the C pointer-lifetime contract safely.
    pub fn set_name_static(&mut self, name: &'static str) {
        self.borrowed_name = Some(name);
        self.owned_name = String::new();
    }

    /// C `set_name(const std::string&)`: own, drop borrow.
    pub fn set_name_string(&mut self, name: &str) {
        self.borrowed_name = None;
        self.owned_name = name.to_string();
    }

    /// C `get_name()`: borrowed wins; otherwise the owned c_str.
    pub fn get_name(&self) -> &str {
        match self.borrowed_name {
            Some(s) => s,
            None => self.owned_name.as_str(),
        }
    }
}

/// C `Table` (member order preserved; Vec for deque).
#[derive(Default, Debug)]
pub struct Table {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub first_column_has_colon: bool,
}

#[derive(Default, Debug)]
pub struct Group {
    pub name: String,
    pub counters: Vec<Counter>,
    pub tables: Vec<Table>,
}

#[derive(Default, Debug)]
pub struct Section {
    pub name: String,
    pub groups: Vec<Group>,
}

#[derive(Default, Debug)]
pub struct Snapshot {
    pub sections: Vec<Section>,
}

/// C `struct DynamicStatsPolicy`.
#[derive(Default, Clone, Copy)]
pub struct DynamicStatsPolicy {
    pub include_zeros: bool,
}

/// The probe's `Counter{}` brace-init shorthand (Counter::default()).
pub fn counter_new() -> Counter {
    Counter::default()
}

/// C `Builder` over the snapshot. In C, `section()` keeps `snapshot`
/// borrowed through `section`/the returned reference; Rust cannot hold
/// `&mut` twice (the `section` receiver borrow and the returned
/// reference would alias), so `section` takes the snapshot by `&mut`
/// and returns it likewise; `group`/`table`/`row`/`counter` are the
/// C statics, already borrowed-reference safe in C and direct in Rust.
pub struct Builder<'a> {
    snapshot: &'a mut Snapshot,
}

impl<'a> Builder<'a> {
    pub fn new(snapshot: &'a mut Snapshot) -> Self {
        Builder { snapshot }
    }

    /// C: `snapshot.sections.emplace_back(); section.name = name?name:
    /// ""; return section`
    pub fn section(&mut self, name: &str) -> &mut Section {
        self.snapshot.sections.push(Section {
            name: name.to_string(),
            ..Default::default()
        });
        self.snapshot.sections.last_mut().unwrap()
    }

    /// Static in C; here an associated fn (matches the C statics, which
    /// do NOT touch `snapshot`). Lifetime is explicit because C++ ties
    /// the returned reference to `parent_section`.
    pub fn group<'s>(parent_section: &'s mut Section, name: &str) -> &'s mut Group {
        parent_section.groups.push(Group {
            name: name.to_string(),
            ..Default::default()
        });
        parent_section.groups.last_mut().unwrap()
    }

    pub fn table<'g>(
        parent_group: &'g mut Group,
        name: &str,
        columns: Vec<String>,
        first_column_has_colon: bool,
    ) -> &'g mut Table {
        parent_group.tables.push(Table {
            name: name.to_string(),
            columns,
            rows: Vec::new(),
            first_column_has_colon,
        });
        parent_group.tables.last_mut().unwrap()
    }

    pub fn row(stats_table: &mut Table, values: Vec<Value>) {
        stats_table.rows.push(values);
    }

    /// C statics pair: `counter(grp, const char*, Value)` forwards to
    /// the string overload; Rust is one impl using set_name_string.
    pub fn counter(parent_group: &mut Group, name: &str, value: Value) {
        let counter_name = name.to_string(); // C: `const std::string counter_name = name?name:""`
        let mut c = Counter::default();
        c.set_name_string(&counter_name);
        c.value = value;
        parent_group.counters.push(c);
    }
}

//! Whole-transcript replay of tools/chunk_harness/vectors.txt (REAL
//! LuaJIT 2.1 driving ORIGINAL utils/chunk.cc + lua/lua.cc, one
//! shared state) plus the embedded upstream [chunk] suite (1
//! TEST_CASE, 6 leaf sections; verbatim-C++ gate, 6 assertions).
//! Each upstream SECTION reruns the whole TEST_CASE body (fresh
//! `Lua::State lua(true)`), so each becomes its own #[test].
use std::cell::RefCell;
use std::rc::Rc;

use snort3::utils::chunk::{init_chunk, ChunkErrorSink, LuaState};

const VECTORS: &str = include_str!("../tools/chunk_harness/vectors.txt");

#[derive(Clone, Default)]
struct Sink {
    lines: Rc<RefCell<Vec<String>>>,
}

impl ChunkErrorSink for Sink {
    fn parse_error(&mut self, formatted: &str) {
        // the harness witness prints "PE " + raw formatted text (the
        // C printf emits "PE %s\n")
        self.lines.borrow_mut().push(format!("PE {formatted}"));
    }
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    st: &mut LuaState,
    sink: &mut Sink,
    lines: &Rc<RefCell<Vec<String>>>,
    idx: Option<usize>,
    tag: &str,
    chunk: &str,
    name: &str,
    args: &str,
) -> Vec<String> {
    let before = lines.borrow().len();
    let rc = init_chunk(st, sink, chunk, name, args);
    let mut out = vec![if let Some(i) = idx {
        format!("{tag}{i} rc={}", rc as i32)
    } else {
        format!("{tag} rc={}", rc as i32)
    }];
    // C witness order: PE lines emit DURING the call, the C line
    // after — so transcript rows are [PEs..., Cx rc=..].
    let mut rows = lines.borrow()[before..].to_vec();
    rows.append(&mut out);
    rows
}

#[test]
fn chunk_transcript_replay() {
    let mut st = LuaState::new();
    let lines = Rc::new(RefCell::new(Vec::new()));
    let mut sink = Sink { lines: lines.clone() };
    let name = "test";
    let mut got: Vec<String> = Vec::new();

    // the probe's exact case table, shared state
    let cases: [(&str, &str); 8] = [
        ("function init() return true end", "args = { a = 1, b = 2 }"), // C1
        ("init = 1", "args = { a = 1, b = 2 }"),                        // C2
        ("", "args = { a = 1, b = 2 }"),                                // C3
        ("function init()", "args = { a = 1, b = 2 }"),                 // C4
        ("function init() return true end", "args = {"),                // C5
        ("function init() return false end", "args = { a = 1, b = 2 }"), // C6
        ("function init() return 'boom' end", "args = { a = 1, b = 2 }"), // C7
        ("function init() end", "args = { a = 1, b = 2 }"),              // C8
    ];
    for (i, (c, a)) in cases.iter().enumerate() {
        let rows = run_case(&mut st, &mut sink, &lines, Some(i + 1), "C", c, name, a);
        got.extend(rows);
    }

    // C9: empty args dostring on the shared state
    let rows = run_case(
        &mut st,
        &mut sink,
        &lines,
        Some(9),
        "C",
        "function init() return true end",
        name,
        "",
    );
    got.extend(rows);

    // ALIVE: state still healthy after the failure storm
    let rows = run_case(
        &mut st,
        &mut sink,
        &lines,
        None,
        "ALIVE",
        "function init() return true end",
        name,
        "args = { c = 3 }",
    );
    got.extend(rows);
    got.push("DONE".to_string());

    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(got, want, "chunk transcript mismatch");
}

// -- upstream [chunk] suite: fresh Lua::State per TEST_CASE rerun ------------

const TN: &str = "test_alert_luajit";
const TA: &str = "args = { a = 1, b = 2 }";

// SECTION "normal initialization"
#[test]
fn chunk_normal_init() {
    let (mut st, l) = (LuaState::new(), Rc::new(RefCell::new(Vec::new())));
    let mut sink = Sink { lines: l.clone() };
    assert!(init_chunk(
        &mut st,
        &mut sink,
        "function init() return true end",
        TN,
        TA
    ));
}

// SECTION "init() edge cases" / "init is not a function"
#[test]
fn chunk_init_not_a_function() {
    let (mut st, l) = (LuaState::new(), Rc::new(RefCell::new(Vec::new())));
    let mut sink = Sink { lines: l.clone() };
    assert!(init_chunk(&mut st, &mut sink, "init = 1", TN, TA));
}

// SECTION "init() edge cases" / "init is not defined"
#[test]
fn chunk_init_not_defined() {
    let (mut st, l) = (LuaState::new(), Rc::new(RefCell::new(Vec::new())));
    let mut sink = Sink { lines: l.clone() };
    let empty = "";
    assert!(init_chunk(&mut st, &mut sink, empty, TN, TA));
}

// SECTION "initialization errors" / "malformed chunk"
#[test]
fn chunk_malformed_chunk() {
    let (mut st, l) = (LuaState::new(), Rc::new(RefCell::new(Vec::new())));
    let mut sink = Sink { lines: l.clone() };
    assert!(!init_chunk(&mut st, &mut sink, "function init()", TN, TA));
}

// SECTION "initialization errors" / "malformed args table"
#[test]
fn chunk_malformed_args() {
    let (mut st, l) = (LuaState::new(), Rc::new(RefCell::new(Vec::new())));
    let mut sink = Sink { lines: l.clone() };
    assert!(!init_chunk(
        &mut st,
        &mut sink,
        "function init() return true end",
        TN,
        "args = {"
    ));
}

// SECTION "initialization errors" / "init returns false"
#[test]
fn chunk_init_returns_false() {
    let (mut st, l) = (LuaState::new(), Rc::new(RefCell::new(Vec::new())));
    let mut sink = Sink { lines: l.clone() };
    assert!(!init_chunk(
        &mut st,
        &mut sink,
        "function init() return false end",
        TN,
        TA
    ));
}

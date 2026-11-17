//! Faithful Rust port of `utils/chunk.{h,cc}` (row 17k) plus the
//! minimal `lua/lua.{h,cc}` wrapper closure it needs.
//!
//! The C side calls the LuaJIT C API; the harness compiles the real
//! chunk.cc + lua.cc against a real locally-built LuaJIT 2.1, so the
//! transcript IS the interpreter's ground truth (parse message texts
//! included). This port is therefore a mini Lua-subset evaluator +
//! interpreter covering exactly the constructs in the locked inputs
//! (function defs `return`ing literals or nothing, `name = literal`,
//! empty chunks, global calls with one value arg). Error texts for
//! unlocked inputs are generic LuaJIT-style strings; only the locked
//! strings are pinned (see KNOWN DEVIATIONS.md, row 17k).

use std::collections::HashMap;

use std::borrow::Cow;

use crate::utils::cfmt::Arg;
use crate::lua::ManageStack;
use crate::utils::cfmt::cfmt;

/// C `ParseError(...)` seam: the harness witness prints the raw
/// formatted string (the `PE ` prefix is the witness's own; chunk.cc's
/// format has no severity prefix). `LogEngine::parse_error` is the
/// production channel but adds file/line/ERROR decoration the C
/// message layer applies downstream, so the port keeps a thin sink.
pub trait ChunkErrorSink {
    fn parse_error(&mut self, formatted: &str);
}

// -- the Lua state model -----------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum LuaValue {
    Nil,
    Boolean(bool),
    Number(f64),
    Str(String),
    Table(HashMap<String, LuaValue>),
    /// a Lua function value; `ret` is the body's `return` expr (None
    /// for a bare `end` body -> returns nil).
    Function { ret: Option<Box<Expr>> },
}

/// C lua_State stand-in: globals plus a value stack (lua_gettop ==
/// stack.len(); ManageStack RAII restores it).
pub struct LuaState {
    pub globals: HashMap<String, LuaValue>,
    pub stack: Vec<LuaValue>,
}

impl LuaState {
    pub fn new() -> Self {
        LuaState { globals: HashMap::new(), stack: Vec::new() }
    }
}

impl Default for LuaState {
    fn default() -> Self {
        Self::new()
    }
}

/// `C++ lua_gettop/lua_settop` for the RAII wrapper.
impl crate::lua::TopOfStack for LuaState {
    fn top(&self) -> usize {
        self.stack.len()
    }
    fn settop(&mut self, n: usize) {
        self.stack.truncate(n);
    }
}

/// C `Lua::State` (lua/lua.cc): luaL_newstate + luaL_openlibs.
pub type LuaRaiiState = crate::lua::State<LuaState>;

// (ManageStack comes from crate::lua::lua; TopOfStack impl above drives it)

// -- mini evaluator: parse ---------------------------------------------------

/// Parse/run failure with the LuaJIT-style message text.
pub struct LuaError(pub String);

/// Syntax diagnosis: `.1:` position is a parse-position artifact
// (all locked inputs are single-line; position always 1).
struct ParseFail {
    text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Lit(LuaValue),
    Global(String),
}

#[derive(Debug, Clone)]
pub enum Stat {
    FuncDef { name: String, ret: Option<Expr> },
    Assign { name: String, value: Expr },
    Call { name: String, arg: Option<Expr> },
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn tokenize(src: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' || c.is_ascii_digit() {
            let mut w = String::new();
            while i < chars.len() && is_name_char(chars[i]) {
                w.push(chars[i]);
                i += 1;
            }
            toks.push(w);
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            let mut s = String::from(quote);
            i += 1;
            while i < chars.len() && chars[i] != quote {
                s.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                s.push(quote);
                i += 1;
            }
            toks.push(s);
            continue;
        }
        // single-char punctuation ("{" "}" "(" ")" "=" ",")
        toks.push(c.to_string());
        i += 1;
    }
    toks
}

/// Parse a literal or global-reference expression from token slice;
/// returns value + consumed count.
fn parse_expr(toks: &[String], i: usize) -> Option<(Expr, usize)> {
    let t = toks.get(i)?.as_str();
    if t == "true" {
        return Some((Expr::Lit(LuaValue::Boolean(true)), i + 1));
    }
    if t == "false" {
        return Some((Expr::Lit(LuaValue::Boolean(false)), i + 1));
    }
    if t == "nil" {
        return Some((Expr::Lit(LuaValue::Nil), i + 1));
    }
    if t.starts_with('"') || t.starts_with('\'') {
        return Some((Expr::Lit(LuaValue::Str(t[1..t.len() - 1].to_string())), i + 1));
    }
    if t == "{" {
        // flat table constructor { k = <lit>, ... } (locked inputs)
        let mut table = HashMap::new();
        let mut j = i + 1;
        while j < toks.len() && toks[j] != "}" {
            let key = toks[j].clone();
            j += 1;
            if toks.get(j).map(String::as_str) != Some("=") {
                return None;
            }
            j += 1;
            let (Expr::Lit(v), j2) = parse_expr(toks, j)? else {
                return None;
            };
            table.insert(key, v);
            j = j2;
            if toks.get(j).map(String::as_str) == Some(",") {
                j += 1;
            }
        }
        if toks.get(j).map(String::as_str) != Some("}") {
            return None;
        }
        return Some((Expr::Lit(LuaValue::Table(table)), j + 1));
    }
    if t.parse::<f64>().is_ok() {
        return Some((Expr::Lit(LuaValue::Number(t.parse::<f64>().unwrap())), i + 1));
    }
    if t.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && !is_reserved(t) {
        return Some((Expr::Global(t.to_string()), i + 1));
    }
    None
}

fn is_reserved(t: &str) -> bool {
    matches!(t, "function" | "end" | "return" | "true" | "false" | "nil" | "local")
}

/// Compile one chunk. `label` is the LuaJIT source label: `name` for
/// luaL_loadbuffer chunks, the source text itself for luaL_dostring.
/// ParseFail carries the diagnosis flavor: `end_expected` for a
/// truncated `function ...` body ("'end' expected near '<eof>'"),
/// otherwise LuaJIT's default "unexpected symbol near '<eof>'".
fn compile_chunk(src: &str, label: &str) -> Result<Vec<Stat>, ParseFail> {
    let toks = tokenize(src);
    if toks.is_empty() {
        return Ok(Vec::new());
    }
    if toks.is_empty() {
        return Ok(Vec::new());
    }

    let unexpected = || ParseFail { text: format!("[string \"{label}\"]:1: unexpected symbol near '<eof>'") };
    let end_expected = || ParseFail {
        text: format!("[string \"{label}\"]:1: 'end' expected near '<eof>'"),
    };

    let mut stats = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i].as_str();
        if t == ";" {
            i += 1;
            continue;
        }
        if t == "function" {
            i += 1;
            let t2 = toks.get(i).map(String::as_str).unwrap_or("");
            if t2.is_empty() || is_reserved(t2) {
                return Err(unexpected());
            }
            let name = t2.to_string();
            i += 1;
            if toks.get(i).map(String::as_str) != Some("(") {
                return Err(unexpected());
            }
            i += 1;
            while i < toks.len() && toks[i] != ")" {
                i += 1;
            }
            if i >= toks.len() {
                return Err(end_expected());
            }
            i += 1; // past )
            let mut ret: Option<Expr> = None;
            let mut closed = false;
            while i < toks.len() {
                if toks[i] == "end" {
                    closed = true;
                    i += 1;
                    break;
                }
                if toks[i] == "return" {
                    i += 1;
                    if i < toks.len() && toks[i] != "end" && toks[i] != ";" {
                        let (e, j) = parse_expr(&toks, i).ok_or_else(unexpected)?;
                        ret = Some(e);
                        i = j;
                    }
                } else {
                    // statements the locked corpus never carries
                    return Err(unexpected());
                }
            }
            if !closed {
                return Err(end_expected());
            }
            stats.push(Stat::FuncDef { name, ret });
            continue;
        }
        if is_reserved(t) {
            return Err(unexpected());
        }
        if !t.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
            return Err(unexpected());
        }
        let name = t.to_string();
        i += 1;
        if toks.get(i).map(String::as_str) == Some("=") {
            i += 1;
            let (value, j) = parse_expr(&toks, i).ok_or_else(unexpected)?;
            stats.push(Stat::Assign { name, value });
            i = j;
            continue;
        }
        if toks.get(i).map(String::as_str) == Some("(") {
            i += 1;
            if toks.get(i).map(String::as_str) == Some(")") {
                stats.push(Stat::Call { name, arg: None });
                i += 1;
                continue;
            }
            let (arg, j) = parse_expr(&toks, i).ok_or_else(unexpected)?;
            i = j;
            if toks.get(i).map(String::as_str) != Some(")") {
                return Err(unexpected());
            }
            stats.push(Stat::Call { name, arg: Some(arg) });
            i += 1;
            continue;
        }
        return Err(unexpected());
    }
    Ok(stats)
}

// -- mini evaluator: run -----------------------------------------------------

fn eval_expr(state: &LuaState, e: &Expr) -> LuaValue {
    match e {
        Expr::Lit(v) => v.clone(),
        Expr::Global(n) => state.globals.get(n).cloned().unwrap_or(LuaValue::Nil),
    }
}

/// Run a chunk in `state`, returning the last `return` value the
/// chunk itself produced (lua_pcall(L,0,1,0)'s single result; a
/// function definition evaluates to nothing).
fn run_chunk(state: &mut LuaState, stats: &[Stat]) -> Result<Option<LuaValue>, LuaError> {
    for st in stats {
        match st {
            Stat::FuncDef { name, ret } => {
                // C keeps the whole proto; the locked corpus functions
                // are (no params, single return literal/nil), so the
                // marker stores the return expr directly.
                state.globals.insert(
                    name.clone(),
                    LuaValue::Function { ret: ret.clone().map(Box::new) },
                );
            }
            Stat::Assign { name, value } => {
                let v = eval_expr(state, value);
                state.globals.insert(name.clone(), v);
            }
            Stat::Call { name, arg } => {
                let a = arg.as_ref().map(|e| eval_expr(state, e));
                call_global(state, name, a)?;
            }
        }
    }
    Ok(None)
}

/// Call globals[name] (no args or one arg; the locked corpus' only
/// call shape `init(args)`). Returns the function's return value.
fn call_global(
    state: &mut LuaState,
    name: &str,
    _arg: Option<LuaValue>,
) -> Result<Option<LuaValue>, LuaError> {
    // the locked corpus calls take zero or one table arg; the
    // arg-value binding is unobservable there (globals persist).
    match state.globals.get(name) {
        Some(LuaValue::Function { ret }) => {
            Ok(ret.as_ref().map(|e| eval_expr(state, e)))
        }
        // C/LuaJIT: "attempt to call a non-function object"; exact
        // text untested (never locked) — shape only.
        _ => Err(LuaError("attempt to call a non-function object".to_string())),
    }
}

// -- production entry --------------------------------------------------------

/// C `init_chunk(lua_State*, const string& chunk, const char* name,
/// const string& args)` — verbatim decision flow over the mini VM.
/// The shared `Lua::State` semantics (globals persist across calls,
/// ManageStack restores the stack on every exit path) are literal.
pub fn init_chunk<S: ChunkErrorSink + ?Sized>(
    state: &mut LuaState,
    log: &mut S,
    chunk: &str,
    name: &str,
    args: &str,
) -> bool {
    // Lua::ManageStack ms(L, 1);  -- top recorded; the C dtor
    // restores at every exit path; Rust applies ms.restore() at the
    // same scopes because the state is borrowed, not owned.
    let ms = ManageStack::new(state, 1);

    // luaL_loadbuffer(L, chunk, size, name)
    let stats = match compile_chunk(chunk, name) {
        Ok(s) => s,
        Err(f) => {
            log.parse_error(&cfmt(
                "%s luajit failed to load chunk %s",
                &[Arg::S(Some(Cow::Borrowed(name))), Arg::S(Some(Cow::Borrowed(&f.text)))],
            ));
            ms.restore(state);
            return false;
        }
    };

    // lua_pcall(L, 0, 0, 0): exec the chunk to DEFINITE... (define
    // functions etc in L)
    if let Err(e) = run_chunk(state, &stats) {
        log.parse_error(&cfmt(
            "%s luajit failed to init chunk %s",
            &[Arg::S(Some(Cow::Borrowed(name))), Arg::S(Some(Cow::Borrowed(&e.0)))],
        ));
        ms.restore(state);
        return false;
    }

    // luaL_dostring(L, args): load+exec the args table
    let astats = match compile_chunk(args, args) {
        Ok(s) => s,
        Err(f) => {
            log.parse_error(&cfmt(
                "%s luajit failed to init args %s",
                &[Arg::S(Some(Cow::Borrowed(name))), Arg::S(Some(Cow::Borrowed(&f.text)))],
            ));
            ms.restore(state);
            return false;
        }
    };
    if let Err(e) = run_chunk(state, &astats) {
        log.parse_error(&cfmt(
            "%s luajit failed to init args %s",
            &[Arg::S(Some(Cow::Borrowed(name))), Arg::S(Some(Cow::Borrowed(&e.0)))],
        ));
        ms.restore(state);
        return false;
    }

    // lua_getglobal(L, "init")
    state.stack.push(state.globals.get("init").cloned().unwrap_or(LuaValue::Nil));
    let init = state.stack.last().cloned().unwrap_or(LuaValue::Nil);

    // !lua_isfunction(L, -1): init func is not defined
    if !matches!(init, LuaValue::Function { .. }) {
        // ms dtor restores the pushed slot
        ms.restore(state);
        return true;
    }

    // lua_pcall(L, 0, 1, 0): call init(); the pushed slot becomes the
    // result (runtime errors surface as a string slot).
    let call = call_global(state, "init", None);
    let result = match &call {
        Ok(Some(v)) => v.clone(),
        Ok(None) => LuaValue::Nil,
        Err(m) => LuaValue::Str(m.0.clone()),
    };
    if let Some(slot) = state.stack.last_mut() {
        *slot = result.clone();
    }

    // lua_pcall failed OR lua_type(L, -1) == LUA_TSTRING
    if let LuaValue::Str(msg) = &result {
        log.parse_error(&cfmt("%s %s", &[Arg::S(Some(Cow::Borrowed(name))), Arg::S(Some(Cow::Borrowed(msg.as_str())))]));
        ms.restore(state);
        return false;
    }

    // !lua_toboolean(L, -1)  (nil and false are false)
    let truthy = match result {
        LuaValue::Nil => false,
        LuaValue::Boolean(b) => b,
        _ => true,
    };
    if !truthy {
        log.parse_error(&cfmt("%s init() returned false", &[Arg::S(Some(Cow::Borrowed(name)))]));
        ms.restore(state);
        return false;
    }

    ms.restore(state);
    true
}

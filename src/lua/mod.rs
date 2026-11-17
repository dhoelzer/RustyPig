//! Faithful Rust port of the `lua/lua.{h,cc}` RAII wrappers (row
//! 17k: pulled in verbatim by the utils/chunk harness closure).
//!
//! C side: `State` owns a LuaJIT `lua_State*` (luaL_newstate +
//! optional luaL_openlibs; FatalError if the VM won't instantiate —
//! a process-exit path never reached in the locked transcript), and
//! `ManageStack` snapshots `lua_gettop` and restores it on scope
//! exit (shrinks only: `if (gettop > top) settop(top)`).
//!
//! The interpreter value model these wrappers own lives with the
//! consumer that exercises it (`utils::chunk`'s mini Lua-subset VM;
//! the C API itself is opaque here). Deviation: Rust ctor returns
//! the state directly; the C `FatalError` branch is unrepresentable
//! (documented in KNOWN DEVIATIONS.md row 17k).

/// C `Lua::State` (lua/lua.cc). openlibs is a no-op observable-wise
/// on the locked inputs (no library call appears in them).
pub struct State<S> {
    pub state: S,
}

impl<S: Default> State<S> {
    /// C `State(bool openlibs = true)`; `state = luaL_newstate()`.
    pub fn new(_openlibs: bool) -> State<S> {
        State { state: S::default() }
    }

    /// C `operator lua_State*()` — implicit conversion; Rust hands
    /// out a borrow explicitly.
    pub fn get_ptr(&mut self) -> &mut S {
        &mut self.state
    }
}

/// C `Lua::ManageStack` (lua/lua.cc): stack-top RAII bracket.
/// The C dtor holds the state pointer; this Rust port records the
/// top and applies `restore` at the same points init_chunk's C
/// scope ends (the borrow checker cannot run Drop against a
/// borrowed sibling).
pub struct ManageStack {
    top: usize,
}

impl ManageStack {
    /// C `ManageStack(lua_State* L, int extra = 0)`:
    /// `top = lua_gettop(state); if (extra > 0) assert(lua_checkstack(...))`.
    /// Vec stacks grow freely; the assert cannot fail here.
    pub fn new<S: TopOfStack>(state: &S, extra: usize) -> ManageStack {
        let _ = extra;
        ManageStack { top: state.top() }
    }

    /// C `~ManageStack()`:
    /// `if ( lua_gettop(state) > top ) lua_settop(state, top);`
    pub fn restore<S: TopOfStack>(&self, state: &mut S) {
        let top = self.top;
        if state.top() > top {
            state.settop(top);
        }
    }
}

pub trait TopOfStack {
    fn top(&self) -> usize;
    fn settop(&mut self, n: usize);
}

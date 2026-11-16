//! Faithful Rust port of `time/periodic.{h,cc}` (ground truth @
//! fe29cbe7403a): a priority-sorted handler list with a per-handler
//! countdown. `check()` visits handlers in priority order; a handler with
//! `time_left == 0` fires and reloads its period, otherwise its counter
//! decrements.
//!
//! Field types mirror the C exactly: `priority` is `uint16_t`, `period`
//! and `time_left` are `uint32_t` (lower priority number is higher
//! priority: the header comment says so and `register_handler`'s scan
//! relies on it).
//!
//! Fidelity notes / deviations (see KNOWN DEVIATIONS.md):
//! - C keeps `static std::list<PeriodicHookNode> s_periodic_handlers` at
//!   file scope (process-wide, single-threader in snort). Mirrored with a
//!   `thread_local!` vec: same iteration order, no thread races; cross-
//!   thread sharing matches nothing in the pinned vectors.
//! - `register_handler` walks while `it->priority < priority`, then
//!   `emplace(it, ...)` — i.e. insert before the first node with priority
//!   at or above the new one, so EQUAL priorities land BEFORE the existing
//!   node
//!   (LIFO per priority band, pinned in vectors P1 and in the upstream
//!   [periodic] test list order arg2,arg1,arg3).
//! - `check()` fires-then-reloads (`time_left == 0` → hook,
//!   `time_left = period`) and otherwise decrements. Consequence pinned
//!   by the vectors: a handler with period p fires once every p+1 checks,
//!   and period 0 fires on EVERY check.
//! - `unregister_handler` removes by HOOK POINTER identity via
//!   `remove_if` — every node whose hook equals the argument, regardless
//!   of its arg pointer or period (P5: two nodes, one call removes both).
//! - The C hook type is `void (*)(void*)` and is never null-checked; a Rust
//!   non-null `extern "C" fn` cannot express a null hook, matching every
//!   pinned vector (no null is ever registered).
use std::cell::RefCell;

pub type PeriodicHook = extern "C" fn(arg: *mut std::ffi::c_void);

/// C `PeriodicHookNode` (ctor seeds `time_left = period`).
#[derive(Clone, Copy)]
struct PeriodicHookNode {
    hook: PeriodicHook,
    arg: *mut std::ffi::c_void,
    priority: u16,
    period: u32,
    time_left: u32,
}

thread_local! {
    static S_PERIODIC_HANDLERS: RefCell<Vec<PeriodicHookNode>> = const {
        RefCell::new(Vec::new())
    };
}

/// C `Periodic::register_handler(hook, arg, priority, period)` — note the
/// C argument order (hook, arg, priority, period) preserved here.
pub fn register_handler(
    hook: PeriodicHook,
    arg: *mut std::ffi::c_void,
    priority: u16,
    period: u32,
) {
    S_PERIODIC_HANDLERS.with(|s| {
        let handlers = &mut *s.borrow_mut();
        let mut it = 0usize;
        // `while ( it != end && it->priority < priority ) ++it;`
        while it < handlers.len() && handlers[it].priority < priority {
            it += 1;
        }
        // `emplace(it, hook, arg, priority, period)` inserts before `it`
        handlers.insert(
            it,
            PeriodicHookNode { hook, arg, priority, period, time_left: period },
        );
    });
}

pub fn check() {
    S_PERIODIC_HANDLERS.with(|s| {
        let handlers = &mut *s.borrow_mut();
        for it in handlers.iter_mut() {
            if it.time_left == 0 {
                (it.hook)(it.arg);
                it.time_left = it.period;
            } else {
                // unreachable at 0, so no wrap concern
                it.time_left -= 1;
            }
        }
    });
}

pub fn unregister_handler(hook: PeriodicHook) {
    S_PERIODIC_HANDLERS.with(|s| {
        let handlers = &mut *s.borrow_mut();
        // fn_addr_eq == C's `node.hook == hook` on function pointers
        handlers.retain(|node| !std::ptr::fn_addr_eq(node.hook, hook));
    });
}

pub fn unregister_all() {
    S_PERIODIC_HANDLERS.with(|s| s.borrow_mut().clear());
}

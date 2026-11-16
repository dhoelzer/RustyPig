//! Whole-transcript replay of `tools/periodic_harness/vectors.txt` (the
//! ground-truth probe against ORIGINAL time/periodic.cc @ fe29cbe7403a)
//! through `snort_rs::time::periodic`, plus a direct translation of the
//! upstream `TEST_CASE("periodic", "[periodic]")` CATCH_TEST_BUILD block
//! embedded in periodic.cc (7 assertions; the C++ harness `gate` runs the
//! same suite against real C++ — both sides green is the bar).
//!
//! The hook args are raw pointers into a leaked fixed array, mirroring the
//! probe's static int label slots (deref-at-fire-time).
use snort3::time::periodic;
use std::cell::RefCell;
use std::ffi::c_void;

thread_local! {
    static FIRED: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
}

/// Probe's static label slots: leaked so pointers stay stable across
/// register and fire (deref-at-fire-time).
struct PtrCell(std::cell::UnsafeCell<[i32; 8]>);
// SAFETY: tests are single-thread; the static is written only via
// set_label and read only by the hooks it registered.
unsafe impl Sync for PtrCell {}
static LABELS: PtrCell = PtrCell(std::cell::UnsafeCell::new([1, 2, 3, 4, 5, 6, 7, 8]));

fn set_label(i: usize, v: i32) {
    unsafe { *(*LABELS.0.get()).get_unchecked_mut(i) = v };
}

extern "C" fn h1(p: *mut c_void) {
    FIRED.with(|f| f.borrow_mut().push(unsafe { *(p as *const i32) }));
}

extern "C" fn h2(p: *mut c_void) {
    FIRED.with(|f| f.borrow_mut().push(100 + unsafe { *(p as *const i32) }));
}

fn label(i: usize) -> *mut c_void {
    unsafe { (*LABELS.0.get()).as_mut_ptr().wrapping_add(i) as *mut c_void }
}

fn dump(tag: &str, out: &mut Vec<String>) {
    let fired = FIRED.with(|f| std::mem::take(&mut *f.borrow_mut()));
    let mut line = format!("{tag} fired:");
    for v in fired {
        line.push(' ');
        line.push_str(&v.to_string());
    }
    out.push(line);
}

/// Translation of the upstream embedded Catch suite in periodic.cc.
#[test]
fn upstream_periodic_test_case() {
    // The upstream file-scope list is shared across C++ process; this is
    // its Rust mirror. The suite starts from empty (REQUIRE empty).
    periodic::unregister_all();

    static ARG1: i32 = 1;
    static ARG2: i32 = 2;
    static ARG3: i32 = 3;
    // const vector<int> expect2 = {arg1}, expect3 = {arg2, arg3}
    let expect2 = vec![1i32];
    let expect3 = vec![2i32, 3];

    // REQUIRE( s_periodic_handlers.empty() );
    // REQUIRE( s_test_args.empty() );   -- tracked below via snapshot
    // (no public empty() in C; the Rust list is freshly cleared above)

    // register_handler(s_test_handler, (void*)&arg1, 1, 1);
    // register_handler(s_test_handler, (void*)&arg2, 1, 2);
    // register_handler(s_test_handler, (void*)&arg3, 2, 2);
    let sh: periodic::PeriodicHook = test_handler;
    periodic::register_handler(sh, &raw const ARG1 as *mut c_void, 1, 1);
    periodic::register_handler(sh, &raw const ARG2 as *mut c_void, 1, 2);
    periodic::register_handler(sh, &raw const ARG3 as *mut c_void, 2, 2);

    periodic::check();
    snapshot(sh, &[]); // CHECK( s_test_args.empty() )

    periodic::check();
    snapshot(sh, &expect2);
    // CHECK( s_test_args == expect2 ); clear() by snapshot

    periodic::check();
    snapshot(sh, &expect3);

    periodic::check();
    periodic::check();
    snapshot(sh, &expect2);

    periodic::unregister_all();
    // CHECK( s_periodic_handlers.empty() )
    periodic::check();
    snapshot(sh, &[]);
}

extern "C" fn test_handler(p: *mut c_void) {
    UPSTREAM_ARGS.with(|f| f.borrow_mut().push(unsafe { *(p as *const i32) }));
}

thread_local! {
    static UPSTREAM_ARGS: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
}

fn snapshot(hook: periodic::PeriodicHook, expect: &[i32]) {
    let got = UPSTREAM_ARGS.with(|f| std::mem::take(&mut *f.borrow_mut()));
    assert_eq!(got, expect);
    let _ = hook;
}

/// Whole-transcript replay of the 32-line locked vectors.
#[test]
fn periodic_transcript_replay() {
    let mut out: Vec<String> = Vec::new();

    for i in 0..8 {
        set_label(i, (i + 1) as i32);
    }

    // P0: check on empty list -> nothing
    periodic::unregister_all();
    periodic::check();
    dump("P0", &mut out);

    // P1: insert band. Expected final order [L3(pri1), L2(pri5), L1(pri5),
    // L4(pri7)] -- equal-priority insertion is LIFO, and the hook arg
    // label is dereferenced at CALL time.
    periodic::register_handler(h1, label(0), 5, 1); // L1=1
    periodic::register_handler(h1, label(1), 5, 2); // L2=2 (before L1)
    periodic::register_handler(h1, label(2), 1, 3); // L3=3 (head)
    periodic::register_handler(h1, label(3), 7, 0); // L4=4 (tail, period 0)
    for k in 1..=8 {
        periodic::check();
        dump("P1", &mut out);
        if k == 2 {
            set_label(1, 99); // next L2 fire prints 99
        }
    }

    // P2: unregister a hook that was never registered -> no change
    periodic::unregister_handler(h2);
    for _ in 1..=4 {
        periodic::check();
        dump("P2", &mut out);
    }

    // P3: register h2 twice (same fn pointer, different args/periods);
    // at k==3 unregister h2 removes BOTH h2 nodes in one call.
    periodic::register_handler(h2, label(4), 5, 1); // prints 105
    periodic::register_handler(h2, label(5), 3, 1); // prints 106
    periodic::register_handler(h1, label(6), 5, 4); // period 4
    for k in 1..=5 {
        periodic::check();
        dump("P3", &mut out);
        if k == 3 {
            periodic::unregister_handler(h2);
        }
    }
    for _ in 1..=6 {
        periodic::check();
        dump("P3b", &mut out);
    }

    // P4: unregister_all then check -> nothing; re-register resumes fresh
    periodic::unregister_all();
    periodic::check();
    dump("P4", &mut out);
    periodic::register_handler(h1, label(7), 9, 2); // label 8, time_left 2
    periodic::check();
    dump("P4b", &mut out); // 2->1, no fire
    periodic::check();
    dump("P4c", &mut out); // 1->0
    periodic::check();
    dump("P4d", &mut out); // fires on the 3rd check after register

    // P5: same hook + same arg registered twice; unregister removes both
    periodic::unregister_all();
    periodic::register_handler(h1, label(0), 1, 0);
    periodic::register_handler(h1, label(0), 1, 1);
    periodic::check(); // first (time_left 0) fires only
    dump("P5", &mut out);
    periodic::check();
    dump("P5b", &mut out);
    periodic::unregister_handler(h1); // removes BOTH
    periodic::check();
    dump("P5c", &mut out);

    out.push("DONE".to_string());

    let vectors = include_str!("../tools/periodic_harness/vectors.txt");
    let want: Vec<&str> = vectors.lines().collect();
    assert_eq!(out.len(), want.len(), "line count mismatch");
    for (i, (g, w)) in out.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "line {}", i + 1);
    }
}

//! Replay of tools/sflsq_harness/vectors.txt (probe over original sflsq.cc;
//! no upstream unit suite). Pins the cursor protocol: sflist_first sets the
//! cursor to head and returns its data; sflist_next advances first then
//! returns; null add_before is a no-op; head-delegation routes through
//! add_head; empty removals return null.

use snort3::utils::sflsq::{cursor_is_null, ListCursor, SfList};

fn dump(list: &SfList<i64>, tag: &str) -> String {
    let mut out = format!("{tag} cnt={}", list.count());
    let mut c = ListCursor::default();
    if let Some(d) = list.first(&mut c) {
        out.push(' ');
        out.push_str(&d.to_string());
        while let Some(d) = list.next(&mut c) {
            out.push(' ');
            out.push_str(&d.to_string());
        }
    } else if list.count() != 0 {
        panic!("count nonzero but list empty");
    }
    out
}

#[test]
fn replay_vectors() {
    let body = include_str!("../tools/sflsq_harness/vectors.txt");
    let want: Vec<&str> = body.lines().collect();
    let mut got: Vec<String> = Vec::new();

    let mut s = SfList::<i64>::new();
    got.push(dump(&s, "new"));
    s.add_tail(1);
    s.add_tail(2);
    s.add_head(0);
    s.add_head(-1);
    got.push(dump(&s, "hh/tt"));

    // iterator protocol incl. the probe's 0-sentinel loop
    let mut c = ListCursor::default();
    let d = *s.first(&mut c).unwrap_or(&0);
    got.push(format!("first {d}"));
    loop {
        let n = s.next(&mut c).copied().unwrap_or(0);
        if n == 0 {
            break;
        }
        got.push(format!("next {n}"));
    }
    let n = s.next(&mut c).copied().unwrap_or(0);
    let null_cursor = cursor_is_null(&c);
    got.push(format!(
        "next-end {n} cursor-null={}",
        if null_cursor { 1 } else { 0 }
    ));

    // C printf args evaluate right-to-left: s->count is read *before*
    // remove_head/remove_tail runs (pre-removal count), as in the probe.
    let cnt_before = s.count();
    let rh = s.remove_head().unwrap_or(0);
    got.push(format!("rmh {rh} cnt={cnt_before}"));
    let cnt_before = s.count();
    let rt = s.remove_tail().unwrap_or(0);
    got.push(format!("rmt {rt} cnt={cnt_before}"));
    got.push(dump(&s, "mid"));

    // add_before delegations
    let mut c2 = ListCursor::default();
    s.first(&mut c2); // head
    s.add_before(c2, 100); // head -> add_head
    s.first(&mut c2);
    s.next(&mut c2); // second node
    s.add_before(c2, 200);
    s.add_before(ListCursor::default(), 999); // invalid cursor -> no-op
    got.push(dump(&s, "before"));

    while s.count() != 0 {
        let d = s.remove_head().unwrap_or(0);
        got.push(format!("drain {d}"));
    }
    got.push(dump(&s, "empty"));
    got.push(format!("rmh-empty {}", s.remove_head().unwrap_or(0)));
    got.push(format!("rmt-empty {}", s.remove_tail().unwrap_or(0)));

    // single node add/removal updates both head and tail
    s.add_head(42);
    got.push(dump(&s, "one"));
    s.remove_head();
    got.push(dump(&s, "empty2"));

    assert_eq!(got.len(), want.len(), "line count mismatch:\n{got:#?}");
    for (g, w) in got.iter().zip(want.iter()) {
        assert_eq!(g, w, "vector mismatch");
    }
    assert!(want.len() >= 16);
}

#[test]
fn free_all_runs_callback() {
    let mut s = SfList::<i64>::new();
    s.add_tail(1);
    s.add_tail(2);
    let mut freed = Vec::new();
    s.free_all(|p| freed.push(p));
    assert_eq!(freed, vec![1, 2]);
}

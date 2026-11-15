//! Port of helpers/test/lockless_ring_test.cc TEST_CASE("Basic") sections.
use snort3::helpers::lockless_ring::LocklessRing;
use std::sync::Arc;

#[test]
fn try_read_empty() {
    let llr = LocklessRing::<u32>::new(1024);
    assert_eq!(llr.size(), 0);
    assert!(llr.try_pop().is_none());
}

#[test]
fn try_push_and_pop() {
    let llr = LocklessRing::<u32>::new(1024);
    assert_eq!(llr.size(), 0);
    for i in 0..512u32 {
        assert!(llr.try_push(i));
    }
    assert_eq!(llr.size(), 512);
    for i in 0..512u32 {
        assert_eq!(llr.try_pop(), Some(i));
    }
    assert_eq!(llr.size(), 0);
}

#[test]
fn try_push_over_capacity() {
    let llr = LocklessRing::<u32>::new(1024);
    assert_eq!(llr.size(), 0);
    for i in 0..1024u32 {
        assert!(llr.try_push(i));
    }
    assert_eq!(llr.size(), 1024);
    assert!(!llr.try_push(1024));
    assert_eq!(llr.size(), 1024);
    for i in 0..1024u32 {
        assert_eq!(llr.try_pop(), Some(i));
    }
    assert_eq!(llr.size(), 0);
}

#[test]
fn multiple_producers() {
    const NUM_PRODUCERS: u32 = 4;
    const ITEMS_PER_PRODUCER: u32 = 256;

    let llr = Arc::new(LocklessRing::<u32>::new(1024));
    let mut producers = Vec::new();
    for p in 0..NUM_PRODUCERS {
        let llr = Arc::clone(&llr);
        producers.push(std::thread::spawn(move || {
            for i in 0..ITEMS_PER_PRODUCER {
                while !llr.try_push(p * ITEMS_PER_PRODUCER + i) {
                    // busy wait (matches C test)
                    std::hint::spin_loop();
                }
            }
        }));
    }
    for prod in producers {
        prod.join().unwrap();
    }

    assert_eq!(llr.size(), NUM_PRODUCERS * ITEMS_PER_PRODUCER);

    let mut seen = vec![false; (NUM_PRODUCERS * ITEMS_PER_PRODUCER) as usize];
    for _ in 0..NUM_PRODUCERS * ITEMS_PER_PRODUCER {
        let value = llr.try_pop().expect("pop");
        seen[value as usize] = true;
    }
    for s in &seen {
        assert!(*s);
    }
    assert_eq!(llr.size(), 0);
}

#[test]
fn multiple_consumers() {
    const TOTAL_ITEMS: u32 = 1024;
    const NUM_CONSUMERS: u32 = 4;
    const ITEMS_PER_CONSUMER: u32 = 256;

    let llr = Arc::new(LocklessRing::<u32>::new(1024));
    for i in 0..TOTAL_ITEMS {
        assert!(llr.try_push(i));
    }
    assert_eq!(llr.size(), TOTAL_ITEMS);

    let seen: Arc<Vec<std::sync::atomic::AtomicBool>> =
        Arc::new((0..TOTAL_ITEMS).map(|_| std::sync::atomic::AtomicBool::new(false)).collect());
    let mut consumers = Vec::new();
    for _c in 0..NUM_CONSUMERS {
        let llr = Arc::clone(&llr);
        let seen = Arc::clone(&seen);
        consumers.push(std::thread::spawn(move || {
            for _i in 0..ITEMS_PER_CONSUMER {
                let value = loop {
                    match llr.try_pop() {
                        Some(v) => break v,
                        None => {
                            // busy wait (matches C test)
                            std::hint::spin_loop();
                        }
                    }
                };
                seen[value as usize].store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    for cons in consumers {
        cons.join().unwrap();
    }

    for s in seen.iter() {
        assert!(s.load(std::sync::atomic::Ordering::Relaxed));
    }
    assert_eq!(llr.size(), 0);
}

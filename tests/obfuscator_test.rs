//! Port of log/test/obfuscator_test.cc (CppUTest group ObfuscatorTests).

#![allow(clippy::needless_range_loop)] // index-walk mirrors C memset(&buf[b.offset], '.', b.length)
use snort3::log::obfuscator::*;


/// apply the block list to a 70-char buffer like the C tests
fn apply(buf: &mut [u8], ob: &mut Obfuscator) {
    let mut b = ObfuscatorBlock::default();
    let mut more = ob.first(&mut b);
    while more {
        for i in b.offset as usize..b.offset as usize + b.length {
            buf[i] = b'.';
        }
        more = ob.next(&mut b);
    }
}

fn buf70_a() -> Vec<u8> {
    let mut v = vec![b'A'; 69];
    v.push(0);
    v
}

fn buf70_dot() -> Vec<u8> {
    let mut v = vec![b'.'; 69];
    v.push(0);
    v
}

#[test]
fn test_1_block() {
    let mut buf = buf70_a();
    let mut ob = Obfuscator::new();
    ob.push(0, 69);
    apply(&mut buf, &mut ob);
    assert_eq!(buf, buf70_dot());
}

#[test]
fn test_2_block() {
    let mut buf = buf70_a();
    let mut ob = Obfuscator::new();
    ob.push(0, 10);
    ob.push(10, 59);
    apply(&mut buf, &mut ob);
    assert_eq!(buf, buf70_dot());
}

#[test]
fn test_3_block() {
    let mut buf = buf70_a();
    let mut ob = Obfuscator::new();
    ob.push(0, 10);
    ob.push(10, 10);
    ob.push(20, 49);
    apply(&mut buf, &mut ob);
    assert_eq!(buf, buf70_dot());
}

#[test]
fn test_3_block_with_gaps() {
    let mut buf = buf70_a();
    let mut ob = Obfuscator::new();
    ob.push(0, 10); // 0-9 dots
    ob.push(20, 10); // 10-19 A, 20-29 dots
    ob.push(40, 29); // 30-39 A, 40-68 dots, 69 NUL
    apply(&mut buf, &mut ob);
    // C buf2 is char[70]: 69 chars + implicit NUL at [69]
    let mut expect: Vec<u8> = b"..........AAAAAAAAAA..........AAAAAAAAAA.............................".to_vec();
    expect.push(0);
    assert_eq!(buf, expect);
    assert_eq!(expect.len(), 70);
}

#[test]
fn empty_list_test() {
    let mut ob = Obfuscator::new();
    let mut b = ObfuscatorBlock::default();
    assert!(!ob.first(&mut b));
}

#[test]
fn empty_list2_test() {
    let mut ob = Obfuscator::new();
    let mut b = ObfuscatorBlock::default();
    assert!(!ob.next(&mut b));
    ob.set_buffer("empty");
    assert!(!ob.next(&mut b));
}

#[test]
fn empty_list3_test() {
    let mut ob = Obfuscator::new();
    ob.push(0, 69);
    let mut b = ObfuscatorBlock::default();
    assert!(ob.first(&mut b));
    assert!(!ob.next(&mut b));
    assert!(!ob.next(&mut b));
}

#[test]
fn no_exact_match() {
    let mut ob = Obfuscator::new();
    for _ in 0..8 {
        ob.push(0, 1);
    }
    assert_eq!(ob.blocks().len(), 1); // ++b == end(): one element total
}

#[test]
fn update_exact_match() {
    let mut ob = Obfuscator::new();
    for l in 1..=8u32 {
        ob.push(0, l as usize);
    }
    let bs = ob.blocks();
    assert_eq!(bs.len(), 1);
    assert_eq!(bs[0].length, 8); // keeps the longest
}

#[test]
fn sorted_elements() {
    let mut ob = Obfuscator::new();
    ob.push(50, 0);
    ob.push(100, 0);
    ob.push(0, 0);
    let mut last = 0u32;
    for b in ob.blocks() {
        assert!(last <= b.offset);
        last = b.offset;
    }
}

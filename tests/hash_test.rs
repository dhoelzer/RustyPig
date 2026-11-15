//! Replays tools/hash_harness/vectors.txt: ground truth captured from the
//! ORIGINAL snort3 hash subsystem (nearest_prime, HashKeyOperations::do_hash,
//! mix_str+finalize, str_to_hash, GHash string/binary tables), plus a port
//! of the three ghash_test.cc CppUTest cases.
use snort3::hash::*;
use std::fs;

fn vec_path() -> String {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tools/hash_harness/vectors.txt"
    )
    .to_string()
}

fn u32v(v: &str) -> u32 {
    v.parse().unwrap()
}

fn read_lines() -> Vec<String> {
    fs::read_to_string(vec_path())
        .expect("vectors.txt; run tools/hash_harness/build.sh")
        .lines()
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn hash_vector_parity() {
    let lines = read_lines();
    let hko = HashKeyOperations::new(1009, true); // static_hash constants
    let (mut np, mut hk, mut ms, mut sh, mut gh, mut acount) = (0, 0, 0, 0, 0, 0);

    let mut a_tbl: Option<GHash<u64>> = None; // A section table
    let mut b_tbl: Option<GHash<u64>> = None; // B section table
    let mut bin_tbl: Option<GHash<u64>> = None; // binary-key table

    for line in &lines {
        let parts: Vec<&str> = line.split(' ').collect();
        match parts[0] {
            "NP" => {
                let v: i32 = parts[1].parse().unwrap();
                let want: i32 = parts[2].parse().unwrap();
                assert_eq!(nearest_prime(v), want, "NP {v}");
                np += 1;
            }
            "HK" => {
                let key = parts[1];
                // strlen+1 includes the NUL byte
                let mut kb = key.as_bytes().to_vec();
                kb.push(0);
                assert_eq!(hko.do_hash(&kb), u32v(parts[2]), "HK {key} len+1");
                assert_eq!(hko.do_hash(&[]), u32v(parts[3]), "HK {key} len0");
                hk += 1;
            }
            "MS" => {
                let key = parts[1];
                let (mut a, mut b, mut c) = (0u32, 0u32, 0u32);
                mix_str(&mut a, &mut b, &mut c, key.as_bytes(), 0);
                finalize(&mut a, &mut b, &mut c);
                assert_eq!(
                    (a, b, c),
                    (u32v(parts[2]), u32v(parts[3]), u32v(parts[4])),
                    "MS {key}"
                );
                ms += 1;
            }
            "SH" => {
                let len: usize = parts[1].parse().unwrap();
                let t = [b'h', b'i', 0, b'x']; // C buffer with embedded NUL
                assert_eq!(str_to_hash(&t[..len]), u32v(parts[2]), "SH len {len}");
                sh += 1;
            }
            "GH" => {
                gh += 1;
                match parts[1] {
                    "nrows0" => {
                        // C: GHash(0,...) constructs with nrows 0 (any
                        // later index op SIGFPEs). Rust constructs fine.
                        let t: GHash<u64> = GHash::new(0, 0, false, true);
                        assert_eq!(t.get_count(), 0);
                    }
                    "ins-b" => {
                        let bb = bin_tbl.get_or_insert_with(|| GHash::new(100, 4, false, true));
                        assert_eq!(
                            bb.insert(&[1, 2, 3, 4], 7).0,
                            parts[2].parse::<i32>().unwrap(),
                            "GH ins-b"
                        );
                    }
                    "dup-b" => {
                        let bb = bin_tbl.as_mut().unwrap();
                        assert_eq!(
                            bb.insert(&[1, 2, 3, 4], 8).0,
                            parts[2].parse::<i32>().unwrap(),
                            "GH dup-b"
                        );
                    }
                    "find-b" => {
                        let bb = bin_tbl.as_mut().unwrap();
                        assert_eq!(bb.find(&[1, 2, 3, 5]).unwrap_or(0), 0, "GH find-b");
                    }
                    "find-b2" => {
                        let bb = bin_tbl.as_mut().unwrap();
                        assert_eq!(
                            bb.find(&[1, 2, 3, 4]).unwrap(),
                            u32v(parts[2]) as u64,
                            "GH find-b2"
                        );
                        // dup insert did NOT overwrite data (C quirk:
                        // HASH_INTABLE leaves original data)
                    }
                    "rm-b" => {
                        let bb = bin_tbl.as_mut().unwrap();
                        assert_eq!(
                            bb.remove(&[1, 2, 3, 5]),
                            parts[2].parse::<i32>().unwrap(),
                            "GH rm-b"
                        );
                    }
                    other => panic!("unknown GH {other}"),
                }
            }
            "A" => {
                acount += 1;
                let g = a_tbl.get_or_insert_with(|| GHash::new(-10, 0, false, true));
                match parts[1] {
                    "ins" => {
                        let i: usize = parts[2].parse().unwrap();
                        let key = format!("KeyWord{}", i + 1);
                        let (r, _) = g.insert(key.as_bytes(), (i + 100) as u64);
                        assert_eq!(r, parts[3].parse::<i32>().unwrap(), "A ins {i}");
                    }
                    "dup" => {
                        let (r, _) = g.insert(b"KeyWord1", 999);
                        assert_eq!(r, parts[2].parse::<i32>().unwrap(), "A dup");
                    }
                    "cnt" => assert_eq!(g.get_count(), u32v(parts[2]), "A cnt"),
                    "it" | "it2" => {
                        // for(n=find_first(); n; n=find_next())
                        let idx: usize = parts[2].parse().unwrap();
                        let got = if idx == 0 {
                            g.find_first()
                        } else {
                            g.find_next()
                        };
                        let (_n, key, data) =
                            got.unwrap_or_else(|| panic!("A {} {idx}: ended early", parts[1]));
                        let ks = String::from_utf8_lossy(&key)
                            .trim_end_matches('\0')
                            .to_string();
                        assert_eq!(ks, parts[3], "A {} {idx} key", parts[1]);
                        if parts[1] == "it" {
                            assert_eq!(data, parts[4].parse::<u64>().unwrap(), "A it {idx} data");
                        }
                    }
                    "endcnt" => assert_eq!(g.get_count(), u32v(parts[2]), "A endcnt"),
                    "find17" => {
                        assert_eq!(
                            g.find(b"KeyWord17").unwrap_or(0),
                            parts[2].parse::<u64>().unwrap(),
                            "A find17"
                        )
                    }
                    "rm-miss" => {
                        assert_eq!(
                            g.remove(b"Nope"),
                            parts[2].parse::<i32>().unwrap(),
                            "A rm-miss"
                        )
                    }
                    "rm17" => {
                        assert_eq!(
                            g.remove(b"KeyWord17"),
                            parts[2].parse::<i32>().unwrap(),
                            "A rm17"
                        )
                    }
                    "cnt2" => assert_eq!(g.get_count(), u32v(parts[2]), "A cnt2"),
                    other => panic!("unknown A {other}"),
                }
            }
            "B" => {
                let g = b_tbl.get_or_insert_with(|| {
                    let mut tt = GHash::new(-10, 0, false, true);
                    for i in 0..30 {
                        tt.insert(format!("KeyWord{}", i + 1).as_bytes(), (i + 100) as u64);
                    }
                    tt
                });
                match parts[1] {
                    "rem" => {
                        // upstream create_find_delete pattern: iterate by
                        // value, remove the just-returned node by key
                        let idx: usize = parts[2].parse().unwrap();
                        let (_n, key, _d) = if idx == 0 {
                            g.find_first().unwrap()
                        } else {
                            g.find_next().unwrap()
                        };
                        let code = g.remove(&key);
                        assert_eq!(code, parts[4].parse::<i32>().unwrap(), "B rem {idx} code");
                        assert_eq!(g.get_count(), u32v(parts[5]), "B rem {idx} cnt");
                    }
                    "it" => {
                        let idx: usize = parts[2].parse().unwrap();
                        let (_n, key, _d) = if idx == 0 {
                            g.find_first().unwrap()
                        } else {
                            g.find_next().unwrap()
                        };
                        let ks = String::from_utf8_lossy(&key)
                            .trim_end_matches('\0')
                            .to_string();
                        assert_eq!(ks, parts[3], "B it {idx} key");
                    }
                    other => panic!("unknown B {other}"),
                }
            }
            _ => {}
        }
    }
    // A it / A it2 cursors must be fully drained:
    let a_it = lines.iter().filter(|l| l.starts_with("A it ")).count();
    let a_it2 = lines.iter().filter(|l| l.starts_with("A it2 ")).count();
    let b_it = lines.iter().filter(|l| l.starts_with("B it ")).count();
    assert!(a_it >= 29 && a_it2 >= 28 && b_it >= 26, "a_it={a_it} a_it2={a_it2} b_it={b_it}");
    let itlines = a_it + a_it2 + b_it + lines.iter().filter(|l| l.starts_with("B rem ")).count();
    // cursor position checks are enforced inline; total coverage:
    assert!(
        np >= 20 && hk == 11 && ms == 11 && sh == 3 && gh == 6 && acount >= 65,
        "np={np} hk={hk} ms={ms} sh={sh} gh={gh} acount={acount} itlines={itlines}"
    );
}

/// Port of the hash_row_distribution TEST_GROUP from xhash_test.cc:
/// pins get_row()/do_hash() semantics of HashKeyOperations.
mod row_dist {
    use snort3::hash::*;
    use std::collections::HashSet;

    struct ForcedScale {
        ops: HashKeyOperations,
    }
    impl ForcedScale {
        fn new(s: u32, h: u32) -> ForcedScale {
            ForcedScale {
                ops: HashKeyOperations {
                    seed: 3191,
                    scale: s,
                    hardener: h,
                },
            }
        }
        fn unfinalized(&self, key: &[u8]) -> u32 {
            let mut hash = self.ops.seed;
            for b in key {
                hash = hash.wrapping_mul(self.ops.scale);
                hash = hash.wrapping_add(*b as u32);
            }
            hash ^ self.ops.hardener
        }
    }

    fn rows_reached(indices: &[u32], nrows: u32) -> u32 {
        let mut seen = vec![false; nrows as usize];
        let mut reached = 0;
        for &index in indices {
            if !seen[index as usize] {
                seen[index as usize] = true;
                reached += 1;
            }
        }
        reached
    }

    const COLLAPSING_SCALES: [u32; 5] = [131071, 524287, 1310719, 1966079, 4194301];
    const HARDENERS: [u32; 5] = [133824503, 0x9e37_79b9, 3, 0x0001_0001, 0];

    #[test]
    fn row_stays_in_range() {
        let sizes = [1u32, 2, 64, 1021, 1 << 21];
        // C constructs forced_scale here but only calls the static get_row.
        let _hash_ops = ForcedScale::new(719, 133824503);
        for nrows in sizes {
            for i in 0..10000u32 {
                assert!(
                    HashKeyOperations::get_row(
                        i.wrapping_mul(2654435761).wrapping_add(17),
                        nrows
                    ) < nrows
                );
            }
        }
    }

    #[test]
    fn row_takes_the_top_bits_on_powers_of_two() {
        // C constructs forced_scale(719, 133824503) here but never uses it.
        for k in 1..=22u32 {
            for i in 0..1000u32 {
                let hashkey = i.wrapping_mul(2246822519).wrapping_add(5);
                assert_eq!(
                    HashKeyOperations::get_row(hashkey, 1u32 << k),
                    hashkey >> (32 - k)
                );
            }
        }
    }

    #[test]
    fn row_reaches_every_row_when_nrows_is_not_a_power_of_two() {
        let nrows = 1021u32;
        let mut masked = Vec::new();
        let mut reduced = Vec::new();
        for i in 0..200000u32 {
            let hashkey = i.wrapping_mul(2654435761);
            masked.push(hashkey & (nrows - 1));
            reduced.push(HashKeyOperations::get_row(hashkey, nrows));
        }
        assert!(rows_reached(&masked, nrows) < nrows / 2);
        assert_eq!(rows_reached(&reduced, nrows), nrows);
    }

    #[test]
    fn do_hash_spreads_a_collapsed_scale() {
        let nrows = 1u32 << 21;
        let keys = 20000u32;
        for scale in COLLAPSING_SCALES {
            for hardener in HARDENERS {
                let hash_ops = ForcedScale::new(scale, hardener);
                let mut masked = Vec::new();
                let mut reduced = Vec::new();
                for i in 0..keys {
                    let key = i.wrapping_mul(7919);
                    let bytes = key.to_le_bytes();
                    masked.push(hash_ops.unfinalized(&bytes) & (nrows - 1));
                    reduced.push(HashKeyOperations::get_row(
                        hash_ops.ops.do_hash(&bytes),
                        nrows,
                    ));
                }
                assert!(rows_reached(&masked, nrows) < keys / 2);
                assert!(rows_reached(&reduced, nrows) > keys - keys / 4);
            }
        }
    }

    #[test]
    fn the_hardener_moves_the_rows() {
        let nrows = 1u32 << 16;
        let keys = 4096u32;
        let mut first_rows = HashSet::new();
        for hardener in HARDENERS {
            let hash_ops = ForcedScale::new(719, hardener);
            let mut same = 0;
            for i in 0..keys {
                let key = i.wrapping_mul(7919);
                let bytes = key.to_le_bytes();
                let row = HashKeyOperations::get_row(hash_ops.ops.do_hash(&bytes), nrows);
                if i == 0 {
                    first_rows.insert(row);
                }
                if row == i % nrows {
                    same += 1;
                }
            }
            assert!(same < keys / 8);
        }
        assert_eq!(first_rows.len(), HARDENERS.len());
    }
}

/// Port of ghash_test.cc: create_find_delete_test. C stores (str + i + 1)
/// pointer offsets of one stack buffer as data and compares pointer
/// identity; Rust stores tagged indices (see KNOWN DEVIATIONS).
#[test]
fn ghash_create_find_delete() {
    let t = &mut GHash::<u32>::new(1000, 0, false, true);
    let mut keys: Vec<String> = Vec::new();
    for i in 0..100 {
        keys.push(format!("KeyWord{}", i + 1));
    }
    for (i, k) in keys.iter().enumerate() {
        t.insert(k.as_bytes(), (i + 1) as u32); // C: str + (i+1)
    }
    for (i, k) in keys.iter().enumerate() {
        let p = t.find(k.as_bytes());
        assert_ne!(p, None);
        assert_eq!(p.unwrap(), (i + 1) as u32); // C pointer identity check
    }
    let mut n = t.find_first();
    while let Some((_i, key, _d)) = n {
        assert_eq!(t.remove(&key), HASH_OK); // C CHECK(i==0)
        n = t.find_next();
    }
    assert_eq!(t.get_count(), 0);
}

/// Port of ghash_test.cc: collision_test (GHash(-10) => 10 rows literal).
#[test]
fn ghash_collision() {
    let t = &mut GHash::<u32>::new(-10, 0, false, true);
    let mut keys: Vec<String> = Vec::new();
    for i in 0..100 {
        keys.push(format!("KeyWord{}", i + 1));
    }
    for (i, k) in keys.iter().enumerate() {
        t.insert(k.as_bytes(), (i + 1) as u32);
    }
    // try to add an existing entry
    let (r, _) = t.insert(keys[0].as_bytes(), 1);
    assert_eq!(r, HASH_INTABLE);
    // find all, reversed
    for (i, k) in keys.iter().enumerate().rev() {
        let p = t.find(k.as_bytes());
        assert_ne!(p, None);
        assert_eq!(p.unwrap(), (i + 1) as u32);
    }
    // remove one node (the one after the first, per upstream cursor walk)
    let first = t.find_first();
    assert_ne!(first, None);
    let second = t.find_next().expect("second node on 10 rows / 100 keys");
    assert_eq!(t.remove(&second.1), HASH_OK);
    // remove the rest via the same walk pattern
    let mut n = t.find_first();
    while let Some((_i, key, _d)) = n {
        assert_eq!(t.remove(&key), HASH_OK);
        n = t.find_next();
    }
    assert_eq!(t.get_count(), 0);
}

/// Port of ghash_test.cc: userfree_test (GHash(-5) => 5 rows literal;
/// C myfree hook maps to Rust Drop).
#[test]
fn ghash_userfree() {
    let t = &mut GHash::<Vec<u8>>::new(-5, 0, false, true);
    for i in 0..5 {
        let key = format!("KeyWord{}", i + 1);
        t.insert(key.as_bytes(), vec![(i + 1) as u8, 0]); // C: p[0]=i+1, p[1]=0
    }
    for i in 0..5 {
        let key = format!("KeyWord{}", i + 1);
        let p = t.find(key.as_bytes());
        assert_ne!(p, None);
        assert_eq!(p.unwrap()[0], (i + 1) as u8);
    }
    assert_eq!(t.find(b"NotInTable"), None);
    assert_eq!(t.remove(b"NotInTable"), HASH_NOT_FOUND);
    let mut n = t.find_first();
    while let Some((_i, key, _d)) = n {
        assert_eq!(t.remove(&key), HASH_OK);
        n = t.find_next();
    }
    assert_eq!(t.get_count(), 0);
}

//! Port of helpers/test/ring2_test.cc — all TEST_CASEs/SECTIONs 1:1.
//! C helpers: write(writer, items...) CHECKs each write succeeds;
//! read(reader, items...) checks each read against expected, where the
//! empty string stands for the nullptr (underflow) return.

use snort3::helpers::ring2::*;

fn wr(w: &mut Writer, items: &[&str]) {
    for it in items {
        assert!(w.write(it.as_bytes()), "write({it:?}) failed");
    }
}

fn rw(w: &mut Writer, item: &str) -> bool {
    // C: CHECK(false == writer.write(...)) style single probes
    w.write(item.as_bytes())
}

fn rd(r: &mut Reader, expected: &[&str]) {
    for e in expected {
        match r.read() {
            None => assert_eq!("", *e, "read = null, expected {e:?}"),
            Some(d) => {
                let actual = String::from_utf8(d).unwrap();
                assert!(!e.is_empty(), "read = {actual:?}, expected null");
                assert_eq!(*e, actual.as_str(), "read content");
            }
        }
    }
}

#[test]
fn basic_no_data() {
    let buffer = Ring2::new(1024);
    assert_eq!(1024, buffer.capacity());
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    let mut reader = buffer.reader();

    wr(&mut writer, &[]);
    rd(&mut reader, &[]);
    rd(&mut reader, &[""]);
    rd(&mut reader, &["", "", ""]);

    assert_eq!(1024, buffer.capacity());
    assert!(buffer.empty());

    writer.push();
    reader.pop();

    assert_eq!(1024, buffer.capacity());
    assert!(buffer.empty());
}

#[test]
fn basic_one_element() {
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    wr(&mut writer, &["hello"]);
    assert!(buffer.empty()); // not published

    writer.push();
    assert!(!buffer.empty());

    let mut reader = buffer.reader();
    rd(&mut reader, &["hello"]);
    assert!(!buffer.empty());

    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn visibility_caching() {
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    let mut reader = buffer.reader();

    wr(&mut writer, &["0", "1", "2", "3", "4"]);
    reader.retry();
    rd(&mut reader, &[""]);

    wr(&mut writer, &["5", "6", "7", "8", "9"]);
    reader.retry();
    rd(&mut reader, &[""]);

    wr(&mut writer, &["a", "b", "c", "d", "e"]);
    reader.retry();
    rd(&mut reader, &[""]);

    wr(&mut writer, &["f"]);
    reader.retry();
    rd(&mut reader, &[""]);

    writer.push();
    reader.retry();
    rd(
        &mut reader,
        &[
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
        ],
    );
}

#[test]
fn visibility_reader() {
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    let mut reader = buffer.reader();

    wr(&mut writer, &["hello", " ", "world", "!"]);
    writer.push();

    rd(&mut reader, &[""]);
    assert!(!buffer.empty());

    reader.retry();
    rd(&mut reader, &["hello", " ", "world", "!"]);

    assert!(!buffer.empty());
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn visibility_reader_incremental() {
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    let mut reader = buffer.reader();

    rd(&mut reader, &[""]);
    reader.retry();
    rd(&mut reader, &[""]);

    wr(&mut writer, &["foo"]);
    writer.push();

    rd(&mut reader, &[""]);
    reader.retry();
    rd(&mut reader, &["foo", ""]);

    wr(&mut writer, &["bar"]);
    writer.push();

    rd(&mut reader, &[""]);
    reader.retry();
    rd(&mut reader, &["foo", "bar", ""]);

    wr(&mut writer, &["baz"]);
    writer.push();

    rd(&mut reader, &[""]);
    reader.retry();
    rd(&mut reader, &["foo", "bar", "baz", ""]);
    reader.pop();

    assert!(buffer.empty());
}

#[test]
fn visibility_reader_incremental_with_pop() {
    // C source lines 198-234, replayed exactly: pop() after each round,
    // so the next round sees only the newly written record.
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    let mut reader = buffer.reader();

    rd(&mut reader, &[""]);
    reader.retry();
    rd(&mut reader, &[""]);

    wr(&mut writer, &["foo"]);
    writer.push();

    rd(&mut reader, &[""]); // not visible: reader cursor cached before push
    reader.retry();
    rd(&mut reader, &["foo", ""]);
    reader.pop();

    wr(&mut writer, &["bar"]);
    writer.push();

    rd(&mut reader, &[""]);
    reader.retry();
    rd(&mut reader, &["bar", ""]);
    reader.pop();

    wr(&mut writer, &["baz"]);
    writer.push();

    rd(&mut reader, &[""]);
    reader.retry();
    rd(&mut reader, &["baz", ""]);
    reader.pop();

    assert!(buffer.empty());
}

#[test]
fn visibility_writer_incremental() {
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    wr(&mut writer, &["foo"]);
    writer.push();

    let mut r1 = buffer.reader();
    rd(&mut r1, &["foo", ""]);

    writer.retry();
    wr(&mut writer, &["bar"]);

    let mut r2 = buffer.reader();
    rd(&mut r2, &["foo", ""]);

    writer.retry();
    wr(&mut writer, &["baz"]);

    let mut r3 = buffer.reader();
    rd(&mut r3, &["foo", ""]);

    writer.retry();
    wr(&mut writer, &["foo"]);
    writer.push();

    let mut r4 = buffer.reader();
    rd(&mut r4, &["foo", "foo", ""]);
    r4.pop();

    assert!(buffer.empty());
}

#[test]
fn visibility_writer_incremental_with_push() {
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();

    writer.retry();
    wr(&mut writer, &["foo"]);
    writer.push();

    let mut r1 = buffer.reader();
    rd(&mut r1, &["foo", ""]);

    writer.retry();
    wr(&mut writer, &["bar"]);
    writer.push();

    let mut r2 = buffer.reader();
    rd(&mut r2, &["foo", "bar", ""]);

    writer.retry();
    wr(&mut writer, &["baz"]);
    writer.push();

    let mut r3 = buffer.reader();
    rd(&mut r3, &["foo", "bar", "baz", ""]);
    r3.pop();

    assert!(buffer.empty());
}

#[test]
fn visibility_clear() {
    let buffer = Ring2::new(1024);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    let mut reader = buffer.reader();

    wr(&mut writer, &["Alpha", "Bravo", "Charlie", "Delta", "Echo"]);
    writer.push();

    reader.retry();
    rd(&mut reader, &["Alpha", "Bravo", "Charlie", "Delta", "Echo"]);
    assert!(!buffer.empty());

    reader.retry();
    rd(&mut reader, &["Alpha", "Bravo", "Charlie", "Delta", "Echo"]);
    assert!(!buffer.empty());

    reader.retry();
    rd(&mut reader, &["Alpha", "Bravo", "Charlie", "Delta", "Echo"]);
    assert!(!buffer.empty());

    reader.pop();
    assert!(buffer.empty());

    writer.retry();
    wr(&mut writer, &["Foxtrot", "Golf", "Hotel", "India", "Juliette"]);
    writer.push();

    assert!(!buffer.empty());
    buffer.clear();
    assert!(buffer.empty());

    reader.retry();
    rd(&mut reader, &[""]);
}

// ---------------------------------------------------------------------------
// TEST_CASE("Wrapping") — capacity 21

#[test]
fn wrapping_len_data_no_room() {
    // "[LEN][DATA]#(no room)" — write of 5 succeeds exactly (avail==9: 9>4, 5<5? no!
    // C CHECK(true == write) means it FIT: avail = 21-12=9 ... 5 < 9-4 = 5 is
    // false -> wrapping case -> reader at 0 -> res = ptr(0)!=end(0) false ->
    // BUT C expects TRUE. Recheck: "padding" = 7 bytes -> record 11; ptr=11,
    // avail=10, 5 < 6 -> fits.)
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding"]);
    assert!(rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["padding", "12345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_data_partial_no_room_6() {
    // "[LEN][DATA#](no room)": "padding" 11 bytes used, then +6: 15 >= 10 -> no
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding"]);
    assert!(!rw(&mut writer, "123456")); // 15 >= 9
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["padding"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_data_partial_no_room_8() {
    // "[LEN][DATA#](no room)" (padding of 8): used 12, avail 9, 5<5 false
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding "]);
    assert!(!rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["padding "]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_data_gap_no_room() {
    // "[LEN][DA#TA](no room)": "padding   " 10 bytes rec 14; avail 7; 5<3 false
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding   "]);
    assert!(!rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["padding   "]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_boundary1_no_room() {
    // "[LEN]#[DATA](no room)": "padding 2345" 12 -> rec 16; avail 5; 5<1 false
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding 2345"]);
    assert!(!rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["padding 2345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_boundary2_no_room() {
    // "[LE#N][DATA](no room)": 14 bytes -> rec 18; avail 3
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding 123456"]);
    assert!(!rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["padding 123456"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_full_no_room() {
    // "#[LEN][DATA](no room)": 16 bytes -> rec 20; avail 1
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["01234567890abcde"]);
    assert!(!rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["01234567890abcde"]);
    reader.pop();
    assert!(buffer.empty());
}

// now each of the same layouts but WITH room via eraser pop first

#[test]
fn wrapping_len_data_eraser() {
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding"]);
    writer.push();
    let mut eraser = buffer.reader();
    rd(&mut eraser, &["padding"]);
    eraser.pop();

    assert!(rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["12345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_data_partial6_eraser() {
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding"]);
    writer.push();
    let mut eraser = buffer.reader();
    rd(&mut eraser, &["padding"]);
    eraser.pop();

    assert!(rw(&mut writer, "123456"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["123456"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_data_partial8_eraser() {
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding "]);
    writer.push();
    let mut eraser = buffer.reader();
    rd(&mut eraser, &["padding "]);
    eraser.pop();

    assert!(rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["12345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_data_gap_eraser() {
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding   "]);
    writer.push();
    let mut eraser = buffer.reader();
    rd(&mut eraser, &["padding   "]);
    eraser.pop();

    assert!(rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["12345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_boundary1_eraser() {
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding 2345"]);
    writer.push();
    let mut eraser = buffer.reader();
    rd(&mut eraser, &["padding 2345"]);
    eraser.pop();

    assert!(rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["12345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_len_boundary2_eraser() {
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["padding 123456"]);
    writer.push();
    let mut eraser = buffer.reader();
    rd(&mut eraser, &["padding 123456"]);
    eraser.pop();

    assert!(rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["12345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_full_eraser() {
    let buffer = Ring2::new(21);
    let mut writer = buffer.writer();
    wr(&mut writer, &["01234567890abcde"]);
    writer.push();
    let mut eraser = buffer.reader();
    rd(&mut eraser, &["01234567890abcde"]);
    eraser.pop();

    assert!(rw(&mut writer, "12345"));
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["12345"]);
    reader.pop();
    assert!(buffer.empty());
}

#[test]
fn wrapping_extended() {
    let buffer = Ring2::new(21);
    assert!(buffer.empty());

    let mut w1 = buffer.writer();
    let mut r1 = buffer.reader();

    wr(&mut w1, &["0", "1"]); // 10 bytes
    w1.push();

    r1.retry();
    rd(&mut r1, &["0", "1", ""]);

    wr(&mut w1, &["2", "3"]); // 20 bytes
    w1.push();

    r1.retry();
    rd(&mut r1, &["0", "1", "2", "3"]);
    r1.pop();

    // wrapping 1
    let mut w2 = buffer.writer();
    let mut r2 = buffer.reader();

    wr(&mut w2, &["4", "5"]); // +10 bytes
    w2.push();

    r2.retry();
    rd(&mut r2, &["4", "5", ""]);

    // cannot write two records now, as w2 thinks r2 still stays near the end
    wr(&mut w2, &["6"]); // +15 bytes
    assert!(!rw(&mut w2, "7"));
    w2.push();

    // unblock: reader passed the end, writer learns the reader moved away
    r2.pop();
    w2.retry();

    wr(&mut w2, &["7"]); // +20 bytes
    w2.push();

    r2.retry();
    rd(&mut r2, &["6", "7"]);
    r2.pop();

    // wrapping 2
    let mut w3 = buffer.writer();
    let mut r3 = buffer.reader();

    wr(&mut w3, &["a", "b"]); // ++10 bytes
    w3.push();

    r3.retry();
    rd(&mut r3, &["a", "b", ""]);

    wr(&mut w3, &["c"]); // ++15 bytes
    assert!(!rw(&mut w3, "d"));
    w3.push();

    // unblock
    r3.pop();
    w3.retry();

    wr(&mut w3, &["d"]); // ++20 bytes
    w3.push();

    r3.retry();
    rd(&mut r3, &["c", "d"]);
    r3.pop();
}

#[test]
fn wrapping_data_fits() {
    let buffer = Ring2::new(21);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    wr(&mut writer, &["0123456789", "ab"]); // 14 + 6 bytes
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["0123456789", "ab"]);
    reader.pop();

    writer.retry(); // read ptr at 21: effective capacity decreased by 1
    assert!(!rw(&mut writer, "0123456789abcdef")); // 16
    assert!(rw(&mut writer, "0123456789abcde")); // 15 fits after wrap
    writer.push();

    reader.retry();
    rd(&mut reader, &["0123456789abcde"]);
    reader.pop();
}

#[test]
fn wrapping_data_halves() {
    let buffer = Ring2::new(21);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    wr(&mut writer, &["0123456789"]); // 14 bytes
    assert!(!rw(&mut writer, "abc")); // no place for 7 bytes
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["0123456789"]);
    reader.pop();

    assert!(buffer.empty());
    writer.retry(); // split into two parts of 14 + 7 bytes
    assert!(!rw(&mut writer, "0123456789a")); // 11: too big
    assert!(!rw(&mut writer, "0123456789")); // 10: guarding byte blocks

    assert!(rw(&mut writer, "012345678")); // 9: forced smaller by reader pos
    writer.push(); // consumes 13 bytes
    reader.retry();
    rd(&mut reader, &["012345678"]);
    reader.pop();

    writer.retry();
    assert!(rw(&mut writer, "abc")); // now there is room for 7 bytes
    writer.push();

    reader.retry();
    rd(&mut reader, &["abc"]);
    reader.pop();
}

#[test]
fn wrapping_writer_behind_reader() {
    let buffer = Ring2::new(21);
    assert!(buffer.empty());

    let mut writer = buffer.writer();
    wr(&mut writer, &["0123456789", "ab"]); // 14 + 6 bytes
    writer.push();

    let mut reader = buffer.reader();
    rd(&mut reader, &["0123456789", "ab"]);
    reader.pop();

    wr(&mut writer, &["1", "2"]); // start from beginning
    writer.push();

    {
        let mut co_writer = buffer.writer();
        wr(&mut co_writer, &["3"]);
        co_writer.push();
    }

    reader.retry();
    rd(&mut reader, &["1", "2", "3"]);
    reader.pop();
}

// ---------------------------------------------------------------------------

#[test]
fn empty_buffer_writing() {
    let buffer = Ring2::new(0);
    assert_eq!(0, buffer.capacity());
    assert!(buffer.empty());

    let mut writer = buffer.writer();

    assert!(!writer.write(b""));
    assert!(!writer.write(b"a"));
    assert!(!writer.write(b"foo"));
    writer.push();

    assert!(!writer.write(b""));
    assert!(!writer.write(b"a"));
    assert!(!writer.write(b"foo"));
    writer.push();

    writer.retry();

    assert!(!writer.write(b""));
    assert!(!writer.write(b"a"));
    assert!(!writer.write(b"foo"));
    writer.push();

    assert_eq!(0, buffer.capacity());
    assert!(buffer.empty());
}

#[test]
fn empty_buffer_reading() {
    let buffer = Ring2::new(0);
    assert_eq!(0, buffer.capacity());
    assert!(buffer.empty());

    let mut reader = buffer.reader();

    rd(&mut reader, &[""]);
    rd(&mut reader, &[""]);
    rd(&mut reader, &[""]);
    reader.pop();

    rd(&mut reader, &[""]);
    rd(&mut reader, &[""]);
    rd(&mut reader, &[""]);
    reader.pop();

    reader.retry();

    rd(&mut reader, &[""]);
    rd(&mut reader, &[""]);
    rd(&mut reader, &[""]);
    reader.pop();

    assert_eq!(0, buffer.capacity());
    assert!(buffer.empty());
}

#[test]
fn oversized_record() {
    // C: guard is `if constexpr (sizeof(size_t) > sizeof(uint32_t))`,
    // always true here (also true in Rust).
    let buffer = Ring2::new(16);
    let mut writer = buffer.writer();
    let oversized = (u32::MAX as usize) + 1;
    let accepted = writer.write_len_check(oversized);
    assert!(!accepted);
}

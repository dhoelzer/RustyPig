//! Port of helpers/test/ber_test.cc — all 5 TEST_CASEs verbatim.
use snort3::framework::cursor::Cursor;
use snort3::helpers::ber::*;

#[test]
fn read_rejects_length_that_overflows_cursor_position() {
    let buf: &[u8] = &[0x80, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut c = Cursor::default();
    c.set("test", buf, false);

    let mut e = BerElement::default();
    {
        let ber = &mut BerReader::new(&c);
        assert!(!ber.read(c.start(), &mut e));
    }
}

#[test]
fn read_rejects_length_that_overflows_from_non_zero_offset() {
    // total length 0xFFFFFFFF fits at offset 0 but wraps at offset 4
    let buf: &[u8] = &[0x31, 0x08, 0xA0, 0x06, 0x80, 0x84, 0xFF, 0xFF, 0xFF, 0xF9];
    let mut e = BerElement::default();
    {
        let mut c = Cursor::default();
        c.set("test", &buf[4..], false);
        let ber = &mut BerReader::new(&c);
        assert!(ber.read(c.start(), &mut e));
        assert_eq!(e.total_length, u32::MAX as u64);
    }

    let mut c = Cursor::default();
    c.set("test", buf, false);
    c.set_pos(4);
    let ber = &mut BerReader::new(&c);
    assert!(!ber.read(c.start(), &mut e));
}

#[test]
fn read_accepts_truncated_element_with_representable_length() {
    let buf: &[u8] = &[0x04, 0x05, b'a'];
    let mut c = Cursor::default();
    c.set("test", buf, false);

    let mut e = BerElement::default();
    {
        let ber = &mut BerReader::new(&c);
        assert!(ber.read(c.start(), &mut e));
    }
    assert_eq!(e.r#type, 0x04);
    assert_eq!(e.length, 5);
    assert_eq!(e.header_length, 2);
    assert_eq!(e.data, 2); // buf + 2
}

#[test]
fn read_uncapped_accepts_length_that_overflows_cursor_position() {
    let buf: &[u8] = &[0x31, 0x08, 0xA0, 0x06, 0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, b'a'];
    let mut c = Cursor::default();
    c.set("test", buf, false);
    c.set_pos(4);

    let mut e = BerElement::default();
    {
        let ber = &mut BerReader::new(&c);
        assert!(ber.read_uncapped(c.start(), &mut e));
    }
    assert_eq!(e.r#type, 0x04);
    assert_eq!(e.length, u32::MAX);
    assert_eq!(e.header_length, 6);
    assert_eq!(e.total_length, 6u64 + u32::MAX as u64);
    assert_eq!(e.data, 10); // buf + 10
}

#[test]
fn read_uncapped_rejects_truncated_header() {
    let buf: &[u8] = &[0x04, 0x84, 0xFF, 0xFF];
    let mut c = Cursor::default();
    c.set("test", buf, false);

    let mut e = BerElement::default();
    {
        let ber = &mut BerReader::new(&c);
        assert!(!ber.read_uncapped(c.start(), &mut e));
    }
}

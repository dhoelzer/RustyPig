//! Port of the UNIT_TEST Catch2 suite embedded in framework/value.cc
//! (14 TEST_CASEs; the 15th section count comes from SECTIONs).
use snort3::framework::value::*;

#[test]
fn set_double_test() {
    let v = Value::from_double(12345.689);
    assert!(v.get_bool());
    assert_eq!(v.get_size(), 12345);
    assert_eq!(v.get_int16(), 12345);
    assert_eq!(v.get_uint16(), 12345);
    assert_eq!(v.get_int32(), 12345);
    assert_eq!(v.get_uint32(), 12345);
    assert_eq!(v.get_int64(), 12345);
    assert_eq!(v.get_uint64(), 12345);
    assert_eq!(v.get_real(), 12345.689);
    assert_eq!(v.get_ip4(), 12345);
}

#[test]
fn set_double_test_2() {
    let v = Value::from_double(123456.89);
    assert!(v.get_bool());
    assert_eq!(v.get_size(), 123456);
    assert_eq!(v.get_int32(), 123456);
    assert_eq!(v.get_uint32(), 123456);
    assert_eq!(v.get_int64(), 123456);
    assert_eq!(v.get_uint64(), 123456);
    assert_eq!(v.get_real(), 123456.89);
    assert_eq!(v.get_ip4(), 123456);
}

#[test]
fn set_double_test_3() {
    let v = Value::from_double(-123456.89);
    assert!(v.get_bool());
    assert_eq!(v.get_int32(), -123456);
    assert_eq!(v.get_int64(), -123456);
    assert_eq!(v.get_real(), -123456.89);
}

#[test]
fn mac_addr_negative_test() {
    let v = Value::from_str("12345");
    let (_, n) = v.get_buffer();
    assert_eq!(n, 5);
    assert_eq!(v.get_mac(), [0u8; 6]);
}

#[test]
fn get_addr_test_valid() {
    let v = Value::from_str("1234567890123456");
    let (test_str, n) = v.get_buffer();
    assert_eq!(n, 16);
    let addr = v.get_addr_raw();
    assert_eq!(addr, test_str);
}

#[test]
fn get_addr_test_invalid() {
    let v = Value::from_str("12345678901234567890");
    let (_, n) = v.get_buffer();
    assert_eq!(n, 20);
    let addr = v.get_addr_raw();
    assert_eq!(addr, [0u8; 16]);
}

#[test]
fn get_addr_ipv4_valid() {
    let v = Value::from_str("1234");
    let (test_str, n) = v.get_buffer();
    assert_eq!(n, 4);
    assert_eq!(v.get_addr_ip4(), test_str);
}

#[test]
fn get_addr_ipv4_invalid() {
    let v = Value::from_str("123456");
    let (_, n) = v.get_buffer();
    assert_eq!(n, 6);
    assert_eq!(v.get_addr_ip4(), [0u8; 4]);
}

#[test]
fn get_addr_ipv6_valid() {
    let v = Value::from_str("1234567890123456");
    let (test_str, n) = v.get_buffer();
    assert_eq!(n, 16);
    assert_eq!(v.get_addr_ip6(), test_str);
}

#[test]
fn get_addr_ipv6_invalid() {
    let v = Value::from_str("123456");
    let (_, n) = v.get_buffer();
    assert_eq!(n, 6);
    assert_eq!(v.get_addr_ip6(), [0u8; 16]);
}

#[test]
fn token_test() {
    // C quirk: set() does NOT reset ss; set_first_token recreates from the
    // *then-current* str. Sequence: ctor str "123456" -> set_first_token ->
    // set("123456,abcdef") (replaces str but old ss from "123456" persists)
    // -> set_first_token again (recreates from new str).
    let mut v = Value::from_str("123456");
    v.set_first_token();
    v.set_str("123456,abcdef");
    v.set_first_token();

    let mut tok = String::new();
    assert!(v.get_next_csv_token(&mut tok));
    assert_eq!(tok, "123456");
}

#[test]
fn get_as_string() {
    let mut v = Value::from_str("");
    v.set_bool(true);
    assert_eq!(v.get_as_string(), "true");

    v.set_double(6.0);
    assert_eq!(v.get_as_string(), "6");

    v.set_double(1234.2);
    assert_eq!(v.get_as_string(), "1234.2");

    v.set_double(123456.0893);
    assert_eq!(v.get_as_string(), "123456.0893");

    v.set_double(0.0803);
    assert_eq!(v.get_as_string(), "0.0803");
}

#[test]
fn update_mask_val_true_invert_true() {
    let v = Value::from_str("");
    let v = {
        let mut t = v;
        t.set_bool(true);
        t
    };
    let invert = true;

    let mut mask8 = 0x11u8;
    v.update_mask_u8(&mut mask8, 0x10, invert);
    assert_eq!(mask8, 0x01);

    let mut mask16 = 0x1100u16;
    v.update_mask_u16(&mut mask16, 0x1000, invert);
    assert_eq!(mask16, 0x0100);

    let mut mask32 = 0x1100_0000u32;
    v.update_mask_u32(&mut mask32, 0x1000_0000, invert);
    assert_eq!(mask32, 0x0100_0000);

    let mut mask64 = 0x1100_0000_0000_0000u64;
    v.update_mask_u64(&mut mask64, 0x1000_0000_0000_0000, invert);
    assert_eq!(mask64, 0x0100_0000_0000_0000);
}

#[test]
fn update_mask_val_true_invert_false() {
    let mut v = Value::from_str("");
    v.set_bool(true);
    let invert = false;

    let mut mask8 = 0x01u8;
    v.update_mask_u8(&mut mask8, 0x10, invert);
    assert_eq!(mask8, 0x11);

    let mut mask16 = 0x0100u16;
    v.update_mask_u16(&mut mask16, 0x1000, invert);
    assert_eq!(mask16, 0x1100);

    let mut mask32 = 0x0100_0000u32;
    v.update_mask_u32(&mut mask32, 0x1000_0000, invert);
    assert_eq!(mask32, 0x1100_0000);

    let mut mask64 = 0x0100_0000_0000_0000u64;
    v.update_mask_u64(&mut mask64, 0x1000_0000_0000_0000, invert);
    assert_eq!(mask64, 0x1100_0000_0000_0000);
}

// The upstream "val false" sections construct Value(true) (upstream bug /
// copy-paste) and run the invert true/false pairs — identical expectations
// to the val-true sections; replayed verbatim:
#[test]
fn update_mask_val_false_sections_verbatim() {
    update_mask_val_true_invert_true();
    update_mask_val_true_invert_false();
}

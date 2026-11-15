//! Port of the UNIT_TEST Catch2 cases embedded in utils/util_unfold.cc.
//! The two strip functions have no upstream tests; they are pinned by
//! tests/util_unfold_parity_test.rs against tools/unfold_harness vectors.
use snort3::utils::util_unfold::*;

#[test]
fn sf_unfold_header_input_size_limit() {
    let input = *b"        "; // const uint8_t input[8] of spaces
    let input_size = input.len() as u32;

    let mut output = vec![0u8; 1024];
    let mut is_folded = -1i32;

    let (ret, output_len) = sf_unfold_header(&input, &mut output, false, Some(&mut is_folded));

    assert_eq!(ret, 0);
    // C CHECK(output_len == input_size): *output_bytes is the byte count
    // written, and 8 spaces with trim_spaces=0 all land in the buffer.
    assert_eq!(output_len, input_size);
    assert_eq!(is_folded, 0);
}

#[test]
fn sf_unfold_header_output_size_limit() {
    let input = *b"        ";

    // C: uint8_t output[8]; output_size = sizeof(output)/2 -> 4
    let mut full = [0u8; 8];
    let output_size = full.len() / 2;
    let mut is_folded = -1i32;

    let (ret, output_len) = {
        let out = &mut full[..output_size];
        sf_unfold_header(&input, out, false, Some(&mut is_folded))
    };

    assert_eq!(ret, 0);
    assert_eq!(output_len, output_size as u32);
    assert_eq!(is_folded, 0);
}

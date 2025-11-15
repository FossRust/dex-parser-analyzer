use dex_core::{DexError, format, parse_dex};

#[test]
fn invalid_magic_rejected() {
    let bytes = vec![0u8; format::HEADER_SIZE];
    match parse_dex(&bytes) {
        Err(DexError::InvalidMagic { .. }) => {}
        Ok(_) => panic!("expected invalid magic"),
        Err(err) => panic!("unexpected error: {err:?}"),
    }
}

#[test]
fn out_of_bounds_section_detected() {
    let mut bytes = std::fs::read("tests/data/Test.dex").expect("fixture missing");
    let len = bytes.len() as u32;
    let string_off = len + 0x100;
    bytes[0x3C..0x40].copy_from_slice(&string_off.to_le_bytes());
    match parse_dex(&bytes) {
        Err(DexError::SectionOutOfBounds { section, .. }) if section == "string_ids" => {}
        Ok(_) => panic!("expected section bounds error"),
        Err(err) => panic!("unexpected error: {err:?}"),
    }
}

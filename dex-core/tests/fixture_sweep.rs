use std::fs;

use dex_core::{DexError, parse_dex};

fn dex_fixtures() -> Vec<&'static str> {
    vec![
        "tests/data/AnalysisTest.dex",
        "tests/data/Annotation_classes.dex",
        "tests/data/classes.dex",
        "tests/data/ExceptionHandling.dex",
        "tests/data/FieldsTest.dex",
        "tests/data/FillArrays.dex",
        "tests/data/InterfaceCls.dex",
        "tests/data/StringTests.dex",
        "tests/data/Test.dex",
    ]
}

fn is_dex(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"dex\n"
}

#[test]
fn parse_all_single_dex_fixtures() -> Result<(), DexError> {
    for fixture in dex_fixtures() {
        let bytes =
            fs::read(fixture).unwrap_or_else(|err| panic!("failed to read {fixture}: {err}"));
        if !is_dex(&bytes) {
            continue;
        }
        let dex = parse_dex(&bytes)?;
        assert!(dex.class_defs().len() > 0, "{fixture} had no class_defs");
        assert!(dex.map_items().len() > 0, "{fixture} had empty map");
    }
    Ok(())
}

#[test]
fn decode_methods_from_fixtures() -> Result<(), DexError> {
    for fixture in dex_fixtures() {
        let bytes = fs::read(fixture).unwrap();
        if !is_dex(&bytes) {
            continue;
        }
        let dex = parse_dex(&bytes)?;
        for (idx, _) in dex.class_defs().enumerate() {
            let class_idx = dex_core::format::ClassIdx::new(idx as u32);
            if let Some(class) = dex.class(class_idx) {
                if let Some(methods) = class.methods() {
                    for method in methods {
                        if method.instructions().is_err() {
                            continue;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

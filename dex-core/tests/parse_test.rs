use dex_core::{bytecode::Reference, format, parse_dex};

fn load_fixture() -> Vec<u8> {
    std::fs::read("tests/data/Test.dex").expect("missing fixture")
}

#[test]
fn parse_test_dex_header() {
    let bytes = load_fixture();
    let dex = parse_dex(&bytes).expect("failed to parse dex");
    let class = dex.classes().next().expect("expected class entry");
    assert_eq!(class.descriptor().unwrap(), "LTest;");
    assert!(dex.strings().any(|s| s == "Test.java"));
    assert!(!dex.map_items().is_empty());
    assert!(dex.section_bytes(format::MAP_TYPE_TYPE_ID_ITEM).is_some());
}

#[test]
fn decode_test_method_instructions() {
    let bytes = load_fixture();
    let dex = parse_dex(&bytes).expect("failed to parse dex");
    let method = dex
        .classes()
        .filter_map(|class| class.methods())
        .flatten()
        .next()
        .expect("expected at least one method");
    let instructions = method.instructions().expect("decode failed");
    assert!(!instructions.is_empty(), "method should contain bytecode");
    assert!(
        instructions.iter().any(|ins| !ins.registers.is_empty()),
        "expected at least one instruction with register operands"
    );
    // Sanity-check that references are parsed without panicking.
    for ins in instructions {
        if let Some(reference) = ins.reference {
            match reference {
                Reference::String(_) | Reference::Type(_) | Reference::Field(_) => {}
                Reference::Method(_) | Reference::Proto(_) => {}
                Reference::CallSite(_) | Reference::MethodHandle(_) => {}
            }
        }
    }
}

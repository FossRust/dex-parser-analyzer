use dex_core::{graphs, parse_dex};

fn load_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/data/{name}")).expect("missing fixture")
}

#[test]
fn cfg_splits_branchy_methods_into_blocks() {
    let bytes = load_fixture("ExceptionHandling.dex");
    let dex = parse_dex(&bytes).expect("parse");
    let branch_method =
        find_branch_method(&dex).expect("fixture should contain at least one branch");
    let cfg = graphs::build_method_cfg(&dex, branch_method).expect("cfg");
    assert!(
        cfg.node_count() > 1,
        "expected at least two basic blocks for branchy method"
    );
    assert!(
        cfg.edge_count() >= 2,
        "branchy method should have branch + fallthrough edges"
    );
}

#[test]
fn call_graph_covers_every_method() {
    let bytes = load_fixture("Test.dex");
    let dex = parse_dex(&bytes).expect("parse");
    let cg = graphs::build_call_graph(&dex).expect("call graph");
    assert_eq!(cg.node_count(), dex.method_count());
    assert!(
        cg.edge_count() > 0,
        "fixture should contain at least one invocation"
    );
}

#[test]
fn xrefs_capture_multiple_reference_types() {
    let string_bytes = load_fixture("StringTests.dex");
    let string_dex = parse_dex(&string_bytes).expect("parse strings fixture");
    let string_xrefs = graphs::build_xrefs(&string_dex).expect("string xrefs");
    assert!(
        !string_xrefs.method_strings.is_empty(),
        "strings fixture should contain string references"
    );

    let field_bytes = load_fixture("FieldsTest.dex");
    let field_dex = parse_dex(&field_bytes).expect("parse fields fixture");
    let field_xrefs = graphs::build_xrefs(&field_dex).expect("field xrefs");
    assert!(
        !field_xrefs.method_fields.is_empty()
            || !field_xrefs.method_types.is_empty()
            || !field_xrefs.method_protos.is_empty(),
        "expected at least one additional reference type"
    );
}

fn find_branch_method(dex: &dex_core::DexFile<'_>) -> Option<dex_core::format::MethodIdx> {
    for class in dex.classes() {
        if let Some(methods) = class.methods() {
            for method in methods {
                if let Ok(instructions) = method.instructions() {
                    if instructions
                        .iter()
                        .any(|ins| is_branch_like(ins.opcode, ins.switch.is_some()))
                    {
                        return Some(method.index());
                    }
                }
            }
        }
    }
    None
}

fn is_branch_like(opcode: u8, has_switch_payload: bool) -> bool {
    matches!(opcode, 0x28..=0x2a | 0x32..=0x37 | 0x38..=0x3d)
        || (has_switch_payload && matches!(opcode, 0x2b | 0x2c))
}

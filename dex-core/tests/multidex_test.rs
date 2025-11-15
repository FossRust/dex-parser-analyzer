use dex_core::{multidex::MultiDex, parse_dex};

fn load(bytes_path: &str) -> Vec<u8> {
    std::fs::read(bytes_path).expect("fixture missing")
}

#[test]
fn find_class_and_string_across_dexes() {
    let bytes_a = load("tests/data/AnalysisTest.dex");
    let bytes_b = load("tests/data/FieldsTest.dex");
    let dex_a = parse_dex(&bytes_a).expect("dex A");
    let dex_b = parse_dex(&bytes_b).expect("dex B");

    let multi = MultiDex::new(vec![dex_a, dex_b]).expect("multi-dex");
    assert!(multi.dexes().len() == 2);

    let class = multi
        .find_class("LAnalysisTest;")
        .expect("class from first dex");
    assert_eq!(class.descriptor().unwrap(), "LAnalysisTest;");

    // FieldsTest contains a class named LFieldsTest;
    let other = multi
        .find_class("LFieldsTest;")
        .expect("class from second dex");
    assert_eq!(other.descriptor().unwrap(), "LFieldsTest;");

    // Strings should be discoverable regardless of which dex they reside in.
    let string_literal = multi
        .find_string("AnalysisTest.java")
        .expect("string literal");
    assert_eq!(string_literal, "AnalysisTest.java");
}

use dex_core::{
    multidex::{MultiDex, read_dex_buffers_from_apk},
    parse_dex,
};

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

#[test]
fn unpack_multidex_apk() {
    let buffers = read_dex_buffers_from_apk("tests/data/multidex.apk").expect("apk");
    assert!(buffers.len() >= 1);
    let multi = MultiDex::from_buffers(&buffers).expect("multidex");
    assert!(multi.dexes().len() >= 1);
}

#[test]
fn duplicated_descriptors_surface_multiple_locations() {
    let bytes_a = load("tests/data/Test.dex");
    let bytes_b = load("tests/data/Test.dex");
    let dex_a = parse_dex(&bytes_a).expect("dex A");
    let dex_b = parse_dex(&bytes_b).expect("dex B");
    let multi = MultiDex::new(vec![dex_a, dex_b]).expect("multi");

    let descriptor = "LTest;";
    let class_entries = multi.class_entries(descriptor);
    let class_count = class_entries.len();
    assert_eq!(class_count, 2, "expected two class entries");
    let classes = multi.find_classes(descriptor);
    assert_eq!(classes.len(), class_count);
    assert!(
        multi.find_class(descriptor).is_some(),
        "lookup should succeed"
    );

    let methods = multi.find_methods("LTest;->aTestMethod(I)I");
    assert_eq!(methods.len(), 2);

    let string_pool: Vec<_> = multi.string_pool().collect();
    assert!(
        string_pool
            .iter()
            .any(|(value, entries)| { *value == "Test.java" && entries.len() == 2 }),
        "string pool should record both occurrences of Test.java"
    );
}

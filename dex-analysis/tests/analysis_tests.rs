use dex_analysis::{
    analyze_dex_bytes,
    config::AnalysisConfig,
    engine,
    model::{AnalysisReport, VulnerabilityKind},
};

fn load_fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dex-core/tests/data")
        .join(name);
    std::fs::read(path).expect("fixture present")
}

fn run_with_fixture(name: &str, config: AnalysisConfig) -> AnalysisReport {
    let bytes = load_fixture(name);
    let dex = dex_core::parse_dex(&bytes).expect("parse");
    engine::analyze_dex(&dex, &config)
}

#[test]
fn pattern_checks_detect_hardcoded_secret() {
    let mut config = AnalysisConfig::default();
    config.enable_structural_checks = false;
    config.enable_taint_checks = false;
    config.max_findings = None;
    let report = run_with_fixture("Annotation_classes.dex", config);
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f.kind, VulnerabilityKind::HardcodedSecret)),
        "expected hardcoded secret finding"
    );
}

#[test]
fn weak_crypto_detection_reports_cipher_usage() {
    let mut config = AnalysisConfig::default();
    config.enable_pattern_checks = true;
    config.enable_structural_checks = false;
    config.enable_taint_checks = false;
    config.max_findings = None;
    let report = run_with_fixture("Annotation_classes.dex", config);
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f.kind, VulnerabilityKind::WeakCrypto)),
        "expected weak crypto finding"
    );
}

#[test]
fn analyze_bytes_roundtrips_via_json() {
    let mut config = AnalysisConfig::default();
    config.enable_structural_checks = false;
    config.enable_taint_checks = false;
    config.max_findings = Some(5);
    let bytes = load_fixture("AnalysisTest.dex");
    let report = analyze_dex_bytes(&bytes, &config).expect("analysis succeeded");
    let json = serde_json::to_string(&report).expect("serialize");
    let round_trip: AnalysisReport =
        serde_json::from_str(&json).expect("report should deserialize");
    assert_eq!(report.findings.len(), round_trip.findings.len());
}

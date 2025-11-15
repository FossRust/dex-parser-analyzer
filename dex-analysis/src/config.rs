use serde::{Deserialize, Serialize};

/// Configuration that controls which analyzers execute and their heuristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Enable cheap string/API pattern checks (hardcoded secrets, weak crypto).
    pub enable_pattern_checks: bool,
    /// Enable CFG/XREF driven structural checks.
    pub enable_structural_checks: bool,
    /// Enable forward data-flow taint analysis.
    pub enable_taint_checks: bool,
    /// Minimum Shannon entropy a literal must exceed to be considered a secret.
    pub secret_min_entropy: f32,
    /// Optional upper bound on reported findings.
    pub max_findings: Option<usize>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_pattern_checks: true,
            enable_structural_checks: true,
            enable_taint_checks: true,
            secret_min_entropy: 3.5,
            max_findings: Some(500),
        }
    }
}

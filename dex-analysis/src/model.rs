use std::borrow::Cow;

use dex_core::{
    format::MethodIdx,
    model::DexFile,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Severity associated with a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Classification of the vulnerability triggered by a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilityKind {
    HardcodedSecret,
    WeakCrypto,
    InsecureRandom,
    InsecureCommunication,
    Custom(Cow<'static, str>),
}

/// Location metadata describing where an issue was found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub class_descriptor: String,
    pub method_name: String,
    pub method_signature: String,
    pub pc: Option<u32>,
}

impl Location {
    /// Build a placeholder when the analyzer is unable to resolve metadata.
    pub fn unknown() -> Self {
        Self {
            class_descriptor: "<unknown>".to_string(),
            method_name: "<unknown>".to_string(),
            method_signature: "()V".to_string(),
            pc: None,
        }
    }

    /// Convert parser level handles into a user friendly location description.
    pub fn from_method(dex: &DexFile<'_>, method: MethodIdx, pc: Option<u32>) -> Self {
        let summary = dex.method_summary(method);
        Self {
            class_descriptor: summary.class.clone(),
            method_name: summary.name.clone(),
            method_signature: summary.signature.clone(),
            pc,
        }
    }
}

/// Individual static-analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Cow<'static, str>,
    pub kind: VulnerabilityKind,
    pub severity: Severity,
    pub location: Location,
    pub message: String,
    pub extra: Value,
}

/// Aggregate statistics reported alongside findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub method_count: u32,
    pub string_count: u32,
    pub instruction_count: u64,
    pub elapsed_ms: Option<u64>,
}

/// Final report returned to callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub findings: Vec<Finding>,
    pub stats: AnalysisStats,
}

/// Convenience container summarizing a method descriptor.
pub use dex_core::model::MethodSummary;

use std::borrow::Cow;

use dex_core::{
    format::{MethodIdx, ProtoIdx},
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
        let summary = describe_method(dex, method);
        Self {
            class_descriptor: summary.class,
            method_name: summary.name,
            method_signature: summary.signature,
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
#[derive(Debug, Clone)]
pub struct MethodSummary {
    pub class: String,
    pub name: String,
    pub signature: String,
}

/// Describe the given method using the resolved class/name/signature tuples.
pub fn describe_method(dex: &DexFile<'_>, method: MethodIdx) -> MethodSummary {
    let Some(method_id) = dex.method_id(method) else {
        return MethodSummary {
            class: "<unknown>".into(),
            name: "<unknown>".into(),
            signature: "()V".into(),
        };
    };

    let class = dex
        .type_descriptor(method_id.class_idx)
        .unwrap_or("<unknown>")
        .to_string();
    let name = dex
        .string(method_id.name_idx)
        .unwrap_or("<unknown>")
        .to_string();
    let signature = proto_signature(dex, method_id.proto_idx).unwrap_or_else(|| "()V".into());
    MethodSummary {
        class,
        name,
        signature,
    }
}

fn proto_signature(dex: &DexFile<'_>, proto_idx: ProtoIdx) -> Option<String> {
    let proto = dex.proto_id(proto_idx)?;
    let mut signature = String::from("(");
    if proto.parameters_off != 0 {
        if let Some(list) = dex.type_list(proto.parameters_off) {
            for ty in &list.types {
                signature.push_str(dex.type_descriptor(*ty)?);
            }
        }
    }
    signature.push(')');
    signature.push_str(dex.type_descriptor(proto.return_type_idx)?);
    Some(signature)
}

use std::collections::HashMap;

use dex_core::{bytecode::Reference, format::MethodIdx, model::DexFile};
use serde_json::json;

use crate::{
    config::AnalysisConfig,
    model::{describe_method, Finding, Location, MethodSummary, Severity, VulnerabilityKind},
};

/// Execute structural CFG/XREF driven analyses. The first iteration focuses on
/// WebView misconfigurations which map to OWASP M7.
pub fn run_structural_checks(
    dex: &DexFile<'_>,
    _config: &AnalysisConfig,
    findings: &mut Vec<Finding>,
    _stats: &mut crate::model::AnalysisStats,
) {
    for idx in 0..dex.method_count() {
        let method_idx = MethodIdx::new(idx as u32);
        let Ok(instructions) = dex.decode_instructions(method_idx) else {
            continue;
        };
        if instructions.is_empty() {
            continue;
        }
        let mut web = WebViewState::default();
        let mut literals = LiteralTracker::default();
        let method_summary = describe_method(dex, method_idx);
        let mut calls_ssl_proceed = false;
        for inst in &instructions {
            literals.observe(inst);
            if let Some(target) = inst
                .reference
                .as_ref()
                .and_then(|r| method_reference_target(r))
            {
                let summary = describe_method(dex, target);
                match (
                    summary.class.as_str(),
                    summary.name.as_str(),
                    summary.signature.as_str(),
                ) {
                    ("Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V") => {
                        web.javascript_enabled_pc.get_or_insert(inst.pc);
                    }
                    ("Landroid/webkit/WebSettings;", "setAllowFileAccess", "(Z)V") => {
                        web.file_access_pc.get_or_insert(inst.pc);
                    }
                    (
                        "Landroid/webkit/WebView;",
                        "addJavascriptInterface",
                        "(Ljava/lang/Object;Ljava/lang/String;)V",
                    ) => {
                        web.javascript_interface_pc.get_or_insert(inst.pc);
                    }
                    ("Landroid/webkit/SslErrorHandler;", "proceed", "()V") => {
                        calls_ssl_proceed = true;
                    }
                    (
                        "Landroid/content/Context;",
                        "openFileOutput",
                        "(Ljava/lang/String;I)Ljava/io/FileOutputStream;",
                    ) => {
                        if let Some(mode_reg) = inst.registers.get(2) {
                            if literals.is_world_mode(*mode_reg) {
                                findings.push(Finding {
                                    id: "M9_INSECURE_FILE_MODE".into(),
                                    kind: VulnerabilityKind::Custom("InsecureFileMode".into()),
                                    severity: Severity::Medium,
                                    location: Location::from_method(dex, method_idx, Some(inst.pc)),
                                    message: "openFileOutput with MODE_WORLD_* flag detected"
                                        .to_string(),
                                    extra: json!({
                                        "mode_literal": literals.literal(*mode_reg),
                                    }),
                                });
                            }
                        }
                    }
                    ("Ljava/lang/Runtime;", "exec", _) => {
                        findings.push(Finding {
                            id: "M1_RUNTIME_EXEC".into(),
                            kind: VulnerabilityKind::Custom("RuntimeExec".into()),
                            severity: Severity::High,
                            location: Location::from_method(dex, method_idx, Some(inst.pc)),
                            message: "Runtime.exec invocation detected".to_string(),
                            extra: json!({ "signature": summary.signature }),
                        });
                    }
                    ("Ljava/lang/ProcessBuilder;", "<init>", _) => {
                        findings.push(Finding {
                            id: "M1_PROCESS_BUILDER".into(),
                            kind: VulnerabilityKind::Custom("ProcessBuilderExec".into()),
                            severity: Severity::High,
                            location: Location::from_method(dex, method_idx, Some(inst.pc)),
                            message: "ProcessBuilder constructor detected".to_string(),
                            extra: json!({ "signature": summary.signature }),
                        });
                    }
                    _ => {}
                }
            }
            if let Some(target) = inst
                .secondary_reference
                .as_ref()
                .and_then(|r| method_reference_target(r))
            {
                if is_ssl_proceed_method(dex, target) {
                    calls_ssl_proceed = true;
                }
            }
        }

        if web.javascript_enabled_pc.is_some() && web.javascript_interface_pc.is_some() {
            findings.push(Finding {
                id: "M7_WEBVIEW_JS_INTERFACE".into(),
                kind: VulnerabilityKind::Custom("WebViewJavascriptInterface".into()),
                severity: Severity::Critical,
                location: Location::from_method(
                    dex,
                    method_idx,
                    web.javascript_interface_pc.or(web.javascript_enabled_pc),
                ),
                message: "WebView enables JavaScript and attaches addJavascriptInterface"
                    .to_string(),
                extra: json!({
                    "javascript_enabled_pc": web.javascript_enabled_pc,
                    "javascript_interface_pc": web.javascript_interface_pc,
                }),
            });
        } else if web.javascript_enabled_pc.is_some() && web.file_access_pc.is_some() {
            findings.push(Finding {
                id: "M7_WEBVIEW_FILE_ACCESS".into(),
                kind: VulnerabilityKind::Custom("WebViewFileAccess".into()),
                severity: Severity::High,
                location: Location::from_method(
                    dex,
                    method_idx,
                    web.file_access_pc.or(web.javascript_enabled_pc),
                ),
                message: "WebSettings enables JavaScript and allows file access".to_string(),
                extra: json!({
                    "javascript_enabled_pc": web.javascript_enabled_pc,
                    "file_access_pc": web.file_access_pc,
                }),
            });
        } else if is_ssl_error_override(&method_summary) && calls_ssl_proceed {
            findings.push(Finding {
                id: "M5_SSL_BYPASS".into(),
                kind: VulnerabilityKind::Custom("SslErrorBypass".into()),
                severity: Severity::High,
                location: Location::from_method(dex, method_idx, None),
                message: "Method overrides onReceivedSslError and calls handler.proceed()"
                    .to_string(),
                extra: json!({
                    "method": method_summary.name,
                }),
            });
        }
    }
}

#[derive(Default)]
struct WebViewState {
    javascript_enabled_pc: Option<u32>,
    javascript_interface_pc: Option<u32>,
    file_access_pc: Option<u32>,
}

#[derive(Default)]
struct LiteralTracker {
    values: HashMap<u16, i64>,
}

impl LiteralTracker {
    fn observe(&mut self, inst: &dex_core::bytecode::Instruction) {
        let name = inst.name;
        if name.starts_with("const") {
            if let (Some(&dst), Some(value)) = (inst.registers.get(0), inst.literal) {
                self.values.insert(dst, value);
            }
            return;
        }
        if name.starts_with("move") {
            if let (Some(&dst), Some(&src)) = (inst.registers.get(0), inst.registers.get(1)) {
                if let Some(value) = self.values.get(&src).copied() {
                    self.values.insert(dst, value);
                } else {
                    self.values.remove(&dst);
                }
            }
            return;
        }
        if name.starts_with("return") {
            if let Some(&reg) = inst.registers.get(0) {
                self.values.remove(&reg);
            }
        }
    }

    fn literal(&self, reg: u16) -> Option<i64> {
        self.values.get(&reg).copied()
    }

    fn is_world_mode(&self, reg: u16) -> bool {
        matches!(
            self.literal(reg),
            Some(LITERAL_MODE_WORLD_READABLE) | Some(LITERAL_MODE_WORLD_WRITEABLE)
        )
    }
}

const LITERAL_MODE_WORLD_READABLE: i64 = 0x0001;
const LITERAL_MODE_WORLD_WRITEABLE: i64 = 0x0002;

const SSL_OVERRIDE_SIGNATURE: &str =
    "(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V";

fn method_reference_target(reference: &Reference) -> Option<MethodIdx> {
    match reference {
        Reference::Method(idx) => Some(*idx),
        _ => None,
    }
}

fn is_ssl_proceed_method(dex: &DexFile<'_>, idx: MethodIdx) -> bool {
    if let Some(method) = dex.method(idx) {
        if let Some(class) = method.class() {
            if let Ok(descriptor) = class.descriptor() {
                if descriptor == "Landroid/webkit/SslErrorHandler;" {
                    if let Ok(name) = method.name() {
                        return name == "proceed";
                    }
                }
            }
        }
    }
    false
}

fn is_ssl_error_override(summary: &MethodSummary) -> bool {
    summary.name == "onReceivedSslError" && summary.signature == SSL_OVERRIDE_SIGNATURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ssl_override_signature() {
        let summary = MethodSummary {
            class: "Lcom/example/WebViewClient;".into(),
            name: "onReceivedSslError".into(),
            signature: SSL_OVERRIDE_SIGNATURE.into(),
        };
        assert!(is_ssl_error_override(&summary));
        let other = MethodSummary {
            class: summary.class.clone(),
            name: "onReceivedError".into(),
            signature: "(Landroid/webkit/WebView;I)V".into(),
        };
        assert!(!is_ssl_error_override(&other));
    }
}

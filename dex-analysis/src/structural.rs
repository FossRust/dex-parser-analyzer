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
        let method_summary = describe_method(dex, method_idx);
        let mut calls_ssl_proceed = false;
        for inst in &instructions {
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

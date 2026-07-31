use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use dex_core::{
    format::{MethodIdx, StringIdx},
    graphs,
    model::DexFile,
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;

use crate::{
    config::AnalysisConfig,
    model::{describe_method, Finding, Location, Severity, VulnerabilityKind},
};

const SECRET_MIN_LENGTH: usize = 8;

static SECRET_REGEXES: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
        ("aws_access_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        (
            "private_key",
            Regex::new(r"BEGIN [A-Z ]+PRIVATE KEY").unwrap(),
        ),
        (
            "slack_token",
            Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
        ),
        (
            "jwt",
            Regex::new(r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}").unwrap(),
        ),
        (
            "password_assignment",
            Regex::new(r"(?i)password\s*[:=]").unwrap(),
        ),
    ]
});

static SECRET_KEYWORDS: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::new([
        "password=",
        "password:",
        "secret=",
        "secret:",
        "api_key",
        "token=",
        "token:",
        "authorization: basic",
    ])
    .expect("aho-corasick build")
});

static WEAK_CRYPTO_KEYWORDS: &[(&str, &'static str)] = &[
    ("md5", "MD5"),
    ("sha1", "SHA1"),
    ("sha-1", "SHA1"),
    ("des", "DES"),
    ("rc4", "RC4"),
    ("rc2", "RC2"),
    ("ecb", "ECB"),
];

struct MethodPattern {
    id: &'static str,
    class: &'static str,
    name: &'static str,
    signature: &'static str,
    description: &'static str,
}

static CRYPTO_SINKS: &[MethodPattern] = &[
    MethodPattern {
        id: "M10_CIPHER",
        class: "Ljavax/crypto/Cipher;",
        name: "getInstance",
        signature: "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        description: "javax.crypto.Cipher.getInstance",
    },
    MethodPattern {
        id: "M10_DIGEST",
        class: "Ljava/security/MessageDigest;",
        name: "getInstance",
        signature: "(Ljava/lang/String;)Ljava/security/MessageDigest;",
        description: "java.security.MessageDigest.getInstance",
    },
];

/// Execute pattern based checks (secrets + weak crypto heuristics).
pub fn run_pattern_checks(
    dex: &DexFile<'_>,
    config: &AnalysisConfig,
    findings: &mut Vec<Finding>,
    _stats: &mut crate::model::AnalysisStats,
) {
    let Ok(xrefs) = graphs::build_xrefs(dex) else {
        return;
    };
    let string_to_methods = build_string_to_methods(&xrefs);
    detect_hardcoded_secrets(dex, config, findings, &string_to_methods);
    detect_insecure_http(dex, findings, &string_to_methods);
    detect_weak_crypto(dex, findings, &xrefs, &string_to_methods);
}

fn detect_hardcoded_secrets(
    dex: &DexFile<'_>,
    config: &AnalysisConfig,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let mut emitted = HashSet::new();
    for idx in 0..dex.string_count() {
        let string_idx = StringIdx::new(idx as u32);
        let Some(value) = dex.string(string_idx) else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        if value.len() < SECRET_MIN_LENGTH && SECRET_KEYWORDS.find(value.as_bytes()).is_none() {
            continue;
        }

        let trigger = match classify_secret(value, config.secret_min_entropy) {
            Some(trigger) => trigger,
            None => continue,
        };

        let methods = string_map.get(&(idx as u32));
        if let Some(methods) = methods {
            for method in methods {
                if !emitted.insert((*method, trigger.label())) {
                    continue;
                }
                findings.push(Finding {
                    id: "M1_HARDCODED_SECRET".into(),
                    kind: VulnerabilityKind::HardcodedSecret,
                    severity: trigger.severity(),
                    location: Location::from_method(dex, MethodIdx::new(*method), None),
                    message: format!(
                        "Literal `{}` matched {} pattern",
                        preview_literal(value),
                        trigger.label()
                    ),
                    extra: json!({
                        "pattern": trigger.label(),
                        "literal": value,
                    }),
                });
            }
        } else if emitted.insert((u32::MAX, trigger.label())) {
            findings.push(Finding {
                id: "M1_HARDCODED_SECRET".into(),
                kind: VulnerabilityKind::HardcodedSecret,
                severity: trigger.severity(),
                location: Location::unknown(),
                message: format!(
                    "Literal `{}` matched {} pattern",
                    preview_literal(value),
                    trigger.label()
                ),
                extra: json!({
                    "pattern": trigger.label(),
                    "literal": value,
                }),
            });
        }
    }
}

fn detect_weak_crypto(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    xrefs: &graphs::Xrefs,
    string_to_methods: &HashMap<u32, Vec<u32>>,
) {
    let sink_lookup = build_sink_lookup(dex);
    if sink_lookup.is_empty() {
        if references_cipher_descriptor(dex) {
            findings.push(Finding {
                id: "M10_CIPHER".into(),
                kind: VulnerabilityKind::WeakCrypto,
                severity: Severity::Info,
                location: Location::unknown(),
                message: "Cipher APIs referenced but no invocations were resolved".to_string(),
                extra: json!({ "reason": "cipher_descriptor" }),
            });
        }
        return;
    }
    let method_to_strings = invert_string_map(string_to_methods);
    let weak_strings = classify_weak_strings(dex);
    let mut emitted = HashSet::new();
    let mut produced = false;

    for (caller, callee) in &xrefs.method_calls {
        let Some(sink) = sink_lookup.get(callee) else {
            continue;
        };
        let algorithm = method_to_strings
            .get(caller)
            .and_then(|strings| strings.iter().find_map(|idx| weak_strings.get(idx)))
            .copied();
        let severity = if algorithm.is_some() {
            Severity::High
        } else {
            Severity::Low
        };
        let key = (*caller, sink.id, algorithm.unwrap_or("UNKNOWN"));
        if !emitted.insert(key) {
            continue;
        }
        produced = true;
        let message = if let Some(alg) = algorithm {
            format!("{} invoked with weak algorithm `{alg}`", sink.description)
        } else {
            format!(
                "{} invoked (algorithm unknown – review manually)",
                sink.description
            )
        };
        findings.push(Finding {
            id: sink.id.into(),
            kind: VulnerabilityKind::WeakCrypto,
            severity,
            location: Location::from_method(dex, MethodIdx::new(*caller), None),
            message,
            extra: json!({
                "sink": sink.description,
                "algorithm": algorithm.unwrap_or("unknown"),
            }),
        });
    }

    if !produced && references_cipher_descriptor(dex) {
        findings.push(Finding {
            id: "M10_CIPHER".into(),
            kind: VulnerabilityKind::WeakCrypto,
            severity: Severity::Info,
            location: Location::unknown(),
            message: "Cipher APIs referenced but no invocations were resolved".to_string(),
            extra: json!({ "reason": "cipher_descriptor" }),
        });
    }
}

fn detect_insecure_http(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let mut emitted = HashSet::new();
    for idx in 0..dex.string_count() {
        let idx_u32 = idx as u32;
        let Some(value) = dex.string(StringIdx::new(idx_u32)) else {
            continue;
        };
        if !value.contains("http://") {
            continue;
        }
        let message = format!(
            "Insecure HTTP literal `{}` detected",
            preview_literal(value)
        );
        if let Some(methods) = string_map.get(&idx_u32) {
            for method in methods {
                if !emitted.insert((*method, idx_u32)) {
                    continue;
                }
                findings.push(Finding {
                    id: "M5_INSECURE_HTTP".into(),
                    kind: VulnerabilityKind::InsecureCommunication,
                    severity: Severity::Medium,
                    location: Location::from_method(dex, MethodIdx::new(*method), None),
                    message: message.clone(),
                    extra: json!({
                        "literal": value,
                        "kind": "http_literal",
                    }),
                });
            }
        } else if emitted.insert((u32::MAX, idx_u32)) {
            findings.push(Finding {
                id: "M5_INSECURE_HTTP".into(),
                kind: VulnerabilityKind::InsecureCommunication,
                severity: Severity::Medium,
                location: Location::unknown(),
                message: message.clone(),
                extra: json!({
                    "literal": value,
                    "kind": "http_literal",
                }),
            });
        }
    }
}

fn build_sink_lookup<'a>(dex: &'a DexFile<'_>) -> HashMap<u32, &'a MethodPattern> {
    let mut lookup = HashMap::new();
    for idx in 0..dex.method_count() {
        let method_idx = MethodIdx::new(idx as u32);
        let summary = describe_method(dex, method_idx);
        for sink in CRYPTO_SINKS {
            if summary.class == sink.class
                && summary.name == sink.name
                && summary.signature == sink.signature
            {
                lookup.insert(idx as u32, sink);
            }
        }
    }
    lookup
}

fn classify_secret(value: &str, entropy_threshold: f32) -> Option<SecretTrigger> {
    if let Some((label, _)) = SECRET_REGEXES
        .iter()
        .find(|(_, regex)| regex.is_match(value))
    {
        return Some(SecretTrigger::Pattern(label));
    }
    if SECRET_KEYWORDS.find(value.as_bytes()).is_some() {
        return Some(SecretTrigger::Keyword);
    }
    if value.len() >= SECRET_MIN_LENGTH {
        let entropy = shannon_entropy(value);
        if entropy >= entropy_threshold {
            return Some(SecretTrigger::Entropy(entropy));
        }
    }
    None
}

fn classify_weak_strings(dex: &DexFile<'_>) -> HashMap<u32, &'static str> {
    let mut map = HashMap::new();
    for idx in 0..dex.string_count() {
        let idx_u32 = idx as u32;
        let Some(value) = dex.string(StringIdx::new(idx_u32)) else {
            continue;
        };
        let lower = value.to_ascii_lowercase();
        if let Some((_, label)) = WEAK_CRYPTO_KEYWORDS
            .iter()
            .find(|(needle, _)| lower.contains(*needle))
        {
            map.insert(idx_u32, *label);
        }
    }
    map
}

fn build_string_to_methods(xrefs: &graphs::Xrefs) -> HashMap<u32, Vec<u32>> {
    let mut map: HashMap<u32, Vec<u32>> = HashMap::new();
    for (method, string_idx) in &xrefs.method_strings {
        map.entry(*string_idx).or_default().push(*method);
    }
    map
}

fn invert_string_map(map: &HashMap<u32, Vec<u32>>) -> HashMap<u32, Vec<u32>> {
    let mut inverted: HashMap<u32, Vec<u32>> = HashMap::new();
    for (string_idx, methods) in map {
        for method in methods {
            inverted.entry(*method).or_default().push(*string_idx);
        }
    }
    inverted
}

fn shannon_entropy(value: &str) -> f32 {
    let mut counts = [0u32; 256];
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for count in counts {
        if count == 0 {
            continue;
        }
        let probability = (count as f32) / len;
        entropy -= probability * probability.log2();
    }
    entropy
}

fn preview_literal(value: &str) -> String {
    let trimmed = value.trim();
    const MAX_LEN: usize = 64;
    if trimmed.len() <= MAX_LEN {
        trimmed.to_string()
    } else {
        // Find the largest byte index ≤ MAX_LEN that sits on a char boundary,
        // so we never slice through a multi-byte character.
        let boundary = (0..=MAX_LEN)
            .rev()
            .find(|&i| trimmed.is_char_boundary(i))
            .unwrap_or(0);
        format!("{}…", &trimmed[..boundary])
    }
}

fn references_cipher_descriptor(dex: &DexFile<'_>) -> bool {
    dex.strings()
        .filter_map(Result::ok)
        .any(|value| value.contains("javax/crypto/Cipher"))
}

enum SecretTrigger {
    Pattern(&'static str),
    Keyword,
    Entropy(f32),
}

impl SecretTrigger {
    fn label(&self) -> &'static str {
        match self {
            SecretTrigger::Pattern(label) => label,
            SecretTrigger::Keyword => "keyword",
            SecretTrigger::Entropy(_) => "entropy",
        }
    }

    fn severity(&self) -> Severity {
        match self {
            SecretTrigger::Pattern(_) => Severity::High,
            SecretTrigger::Keyword => Severity::Medium,
            SecretTrigger::Entropy(ent) if *ent > 4.5 => Severity::High,
            SecretTrigger::Entropy(_) => Severity::Medium,
        }
    }
}

use std::{cell::RefCell, collections::HashMap};

use dex_core::{
    bytecode::{Instruction, Reference},
    format::MethodIdx,
    model::DexFile,
};
use serde_json::json;

use crate::{
    config::AnalysisConfig,
    data_flow::{self, AnalysisContext, ForwardAnalysis},
    model::{describe_method, Finding, Location, Severity, VulnerabilityKind},
};

struct MethodPattern {
    id: &'static str,
    class: &'static str,
    name: &'static str,
    signature: &'static str,
    description: &'static str,
}

const SOURCES: &[MethodPattern] = &[
    MethodPattern {
        id: "SRC_INTENT_EXTRA",
        class: "Landroid/content/Intent;",
        name: "getStringExtra",
        signature: "(Ljava/lang/String;)Ljava/lang/String;",
        description: "Intent.getStringExtra",
    },
    MethodPattern {
        id: "SRC_SHARED_PREFS",
        class: "Landroid/content/SharedPreferences;",
        name: "getString",
        signature: "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        description: "SharedPreferences.getString",
    },
    MethodPattern {
        id: "SRC_TELEPHONY_IMEI",
        class: "Landroid/telephony/TelephonyManager;",
        name: "getDeviceId",
        signature: "()Ljava/lang/String;",
        description: "TelephonyManager.getDeviceId",
    },
    MethodPattern {
        id: "SRC_SECURE_SETTINGS",
        class: "Landroid/provider/Settings$Secure;",
        name: "getString",
        signature: "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
        description: "Settings.Secure.getString",
    },
];

const SINKS: &[MethodPattern] = &[
    MethodPattern {
        id: "SNK_LOG_DEBUG",
        class: "Landroid/util/Log;",
        name: "d",
        signature: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.d",
    },
    MethodPattern {
        id: "SNK_LOG_ERROR",
        class: "Landroid/util/Log;",
        name: "e",
        signature: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.e",
    },
    MethodPattern {
        id: "SNK_URL_CONSTRUCTOR",
        class: "Ljava/net/URL;",
        name: "<init>",
        signature: "(Ljava/lang/String;)V",
        description: "java.net.URL.<init>",
    },
    MethodPattern {
        id: "SNK_WEBVIEW_LOAD_URL",
        class: "Landroid/webkit/WebView;",
        name: "loadUrl",
        signature: "(Ljava/lang/String;)V",
        description: "WebView.loadUrl",
    },
];

/// Execute a lightweight forward taint analysis that tracks sensitive strings
/// flowing from Intent/SharedPreferences into the Android logging APIs.
pub fn run_taint_checks(
    dex: &DexFile<'_>,
    _config: &AnalysisConfig,
    findings: &mut Vec<Finding>,
    _stats: &mut crate::model::AnalysisStats,
) {
    let lookup = MethodLookup::build(dex);
    if lookup.sources.is_empty() || lookup.sinks.is_empty() {
        return;
    }

    for idx in 0..dex.method_count() {
        let method = MethodIdx::new(idx as u32);
        let Some(code_item) = dex.code_item(method) else {
            continue;
        };
        let register_count = code_item.registers_size as usize;
        if register_count == 0 {
            continue;
        }
        let analysis = MethodTaintAnalysis::new(register_count, &lookup);
        if data_flow::run_forward(dex, method, &analysis).is_err() {
            continue;
        }
        for incident in analysis.take_findings() {
            findings.push(Finding {
                id: incident.sink.id.into(),
                kind: VulnerabilityKind::Custom("SensitiveDataLeak".into()),
                severity: Severity::High,
                location: Location::from_method(dex, incident.method, Some(incident.pc)),
                message: format!("Tainted data reaches {}", incident.sink.description),
                extra: json!({
                    "sink": incident.sink.description,
                    "pc": incident.pc,
                    "register": incident.register,
                }),
            });
        }
    }
}

struct MethodLookup {
    sources: HashMap<u32, &'static MethodPattern>,
    sinks: HashMap<u32, &'static MethodPattern>,
}

impl MethodLookup {
    fn build(dex: &DexFile<'_>) -> Self {
        let mut sources = HashMap::new();
        let mut sinks = HashMap::new();
        for idx in 0..dex.method_count() {
            let method_idx = MethodIdx::new(idx as u32);
            let summary = describe_method(dex, method_idx);
            for src in SOURCES {
                if summary.class == src.class
                    && summary.name == src.name
                    && summary.signature == src.signature
                {
                    sources.insert(idx as u32, src);
                }
            }
            for sink in SINKS {
                if summary.class == sink.class
                    && summary.name == sink.name
                    && summary.signature == sink.signature
                {
                    sinks.insert(idx as u32, sink);
                }
            }
        }
        Self { sources, sinks }
    }

    #[cfg(test)]
    fn from_raw(
        sources_entries: &[(u32, &'static MethodPattern)],
        sink_entries: &[(u32, &'static MethodPattern)],
    ) -> Self {
        let mut sources = HashMap::new();
        let mut sinks = HashMap::new();
        for (idx, pattern) in sources_entries {
            sources.insert(*idx, *pattern);
        }
        for (idx, pattern) in sink_entries {
            sinks.insert(*idx, *pattern);
        }
        Self { sources, sinks }
    }
}

struct MethodTaintAnalysis<'a> {
    register_count: usize,
    lookup: &'a MethodLookup,
    findings: RefCell<Vec<TaintIncident<'a>>>,
}

impl<'a> MethodTaintAnalysis<'a> {
    fn new(register_count: usize, lookup: &'a MethodLookup) -> Self {
        Self {
            register_count,
            lookup,
            findings: RefCell::new(Vec::new()),
        }
    }

    fn take_findings(&self) -> Vec<TaintIncident<'a>> {
        self.findings.borrow_mut().drain(..).collect()
    }
}

#[derive(Clone, PartialEq)]
struct TaintState {
    registers: Vec<bool>,
}

impl TaintState {
    fn new(count: usize) -> Self {
        Self {
            registers: vec![false; count],
        }
    }

    fn set(&mut self, reg: u16, value: bool) {
        if let Some(slot) = self.registers.get_mut(reg as usize) {
            *slot = value;
        }
    }

    fn get(&self, reg: u16) -> bool {
        self.registers.get(reg as usize).copied().unwrap_or(false)
    }

    fn copy(&mut self, dst: u16, src: u16) {
        let value = self.get(src);
        self.set(dst, value);
    }

    fn clear(&mut self, reg: u16) {
        self.set(reg, false);
    }
}

struct TaintIncident<'a> {
    sink: &'a MethodPattern,
    method: MethodIdx,
    pc: u32,
    register: Option<u16>,
}

impl<'a> ForwardAnalysis for MethodTaintAnalysis<'a> {
    type State = TaintState;

    fn bottom(&self) -> Self::State {
        TaintState::new(self.register_count)
    }

    fn join(&self, state: &mut Self::State, other: &Self::State) -> bool {
        let mut changed = false;
        for (dst, src) in state.registers.iter_mut().zip(&other.registers) {
            if *src && !*dst {
                *dst = true;
                changed = true;
            }
        }
        changed
    }

    fn transfer_block(
        &self,
        ctx: &AnalysisContext<'_>,
        _block: &dex_core::graphs::BasicBlock,
        instructions: &[dex_core::bytecode::Instruction],
        state: &mut Self::State,
    ) {
        let mut pending_source: Option<&'static MethodPattern> = None;
        for inst in instructions {
            let name = inst.name;
            let registers = referenced_registers(inst);
            if is_move_object(name) {
                if let (Some(&dst), Some(&src)) = (registers.get(0), registers.get(1)) {
                    state.copy(dst, src);
                }
            } else if is_move_result_object(name) {
                if let Some(&dst) = registers.get(0) {
                    if pending_source.is_some() {
                        state.set(dst, true);
                    } else {
                        state.clear(dst);
                    }
                }
                pending_source = None;
            } else if is_const(name) {
                if let Some(&dst) = registers.get(0) {
                    state.clear(dst);
                }
            }

            if let Some(Reference::Method(target)) = inst.reference.as_ref() {
                let raw = target.raw();
                if let Some(source) = self.lookup.sources.get(&raw) {
                    pending_source = Some(source);
                    continue;
                }
                if let Some(sink) = self.lookup.sinks.get(&raw) {
                    pending_source = None;
                    let tainted_register = registers.iter().find(|reg| state.get(**reg));
                    if let Some(&reg) = tainted_register {
                        self.findings.borrow_mut().push(TaintIncident {
                            sink,
                            method: ctx.method,
                            pc: inst.pc,
                            register: Some(reg),
                        });
                    }
                    continue;
                }
            } else {
                pending_source = None;
            }
        }
    }
}

fn is_move_object(name: &str) -> bool {
    name.starts_with("move-object")
}

fn is_move_result_object(name: &str) -> bool {
    name.starts_with("move-result-object")
}

fn is_const(name: &str) -> bool {
    name.starts_with("const/") || name.starts_with("const-string")
}

fn referenced_registers(inst: &Instruction) -> Vec<u16> {
    if !inst.registers.is_empty() {
        return inst.registers.iter().copied().collect();
    }
    if let Some(range) = inst.range.as_ref() {
        let start = range.start as usize;
        let count = range.count as usize;
        return (0..count).map(|offset| (start + offset) as u16).collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_flow::AnalysisContext;
    use dex_core::{bytecode::Reference, graphs::BasicBlock, parse_dex};

    #[test]
    fn tainted_source_reaching_url_sink_triggers_finding() {
        const SRC_IDX: u32 = 1;
        const SINK_IDX: u32 = 2;
        let lookup = MethodLookup::from_raw(&[(SRC_IDX, &SOURCES[0])], &[(SINK_IDX, &SINKS[2])]);
        let analysis = MethodTaintAnalysis::new(4, &lookup);
        let mut state = TaintState::new(4);
        let bytes = load_fixture("AnalysisTest.dex");
        let dex = parse_dex(&bytes).expect("parse");
        let (method, invoke_template) = find_invoke_template(&dex);
        let ctx = AnalysisContext::new(&dex, method);
        let mut invoke_source = invoke_template.clone();
        invoke_source.reference = Some(Reference::Method(MethodIdx::new(SRC_IDX)));
        invoke_source.registers.clear();
        invoke_source.registers.extend_from_slice(&[0]);
        let mut move_result = invoke_template.clone();
        move_result.name = "move-result-object";
        move_result.reference = None;
        move_result.registers.clear();
        move_result.registers.push(1);
        let mut invoke_sink = invoke_template.clone();
        invoke_sink.reference = Some(Reference::Method(MethodIdx::new(SINK_IDX)));
        invoke_sink.registers.clear();
        invoke_sink.registers.extend_from_slice(&[2, 1]);
        let instructions = vec![invoke_source, move_result, invoke_sink];
        let block = BasicBlock {
            start_pc: 0,
            end_pc: instructions.len() as u32,
        };
        analysis.transfer_block(&ctx, &block, &instructions, &mut state);
        let findings = analysis.take_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink.id, "SNK_URL_CONSTRUCTOR");
        assert_eq!(findings[0].register, Some(1));
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../dex-core/tests/data")
            .join(name);
        std::fs::read(path).expect("fixture present")
    }

    fn find_invoke_template(
        dex: &dex_core::DexFile<'_>,
    ) -> (MethodIdx, dex_core::bytecode::Instruction) {
        for idx in 0..dex.method_count() {
            let method = MethodIdx::new(idx as u32);
            if dex.code_item(method).is_none() {
                continue;
            }
            if let Ok(instructions) = dex.decode_instructions(method) {
                if let Some(invoke) = instructions
                    .iter()
                    .find(|inst| inst.name.starts_with("invoke"))
                    .cloned()
                {
                    return (method, invoke);
                }
            }
        }
        panic!("missing templates");
    }
}

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
    model::{Finding, Location, MethodSummary, Severity, VulnerabilityKind},
};

struct MethodPattern {
    id: &'static str,
    class: &'static str,
    name: &'static str,
    signature: &'static str,
    description: &'static str,
    taint_args: &'static [usize],
}

const SOURCES: &[MethodPattern] = &[
    MethodPattern {
        id: "SRC_INTENT_EXTRA",
        class: "Landroid/content/Intent;",
        name: "getStringExtra",
        signature: "(Ljava/lang/String;)Ljava/lang/String;",
        description: "Intent.getStringExtra",
        taint_args: &[],
    },
    MethodPattern {
        id: "SRC_SHARED_PREFS",
        class: "Landroid/content/SharedPreferences;",
        name: "getString",
        signature: "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        description: "SharedPreferences.getString",
        taint_args: &[],
    },
    MethodPattern {
        id: "SRC_TELEPHONY_IMEI",
        class: "Landroid/telephony/TelephonyManager;",
        name: "getDeviceId",
        signature: "()Ljava/lang/String;",
        description: "TelephonyManager.getDeviceId",
        taint_args: &[],
    },
    MethodPattern {
        id: "SRC_SECURE_SETTINGS",
        class: "Landroid/provider/Settings$Secure;",
        name: "getString",
        signature: "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
        description: "Settings.Secure.getString",
        taint_args: &[],
    },
    MethodPattern {
        id: "SRC_BUNDLE_STRING",
        class: "Landroid/os/Bundle;",
        name: "getString",
        signature: "(Ljava/lang/String;)Ljava/lang/String;",
        description: "Bundle.getString",
        taint_args: &[],
    },
];

const SINKS: &[MethodPattern] = &[
    MethodPattern {
        id: "SNK_LOG_DEBUG",
        class: "Landroid/util/Log;",
        name: "d",
        signature: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.d",
        taint_args: &[1],
    },
    MethodPattern {
        id: "SNK_LOG_ERROR",
        class: "Landroid/util/Log;",
        name: "e",
        signature: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.e",
        taint_args: &[1],
    },
    MethodPattern {
        id: "SNK_URL_CONSTRUCTOR",
        class: "Ljava/net/URL;",
        name: "<init>",
        signature: "(Ljava/lang/String;)V",
        description: "java.net.URL.<init>",
        taint_args: &[0],
    },
    MethodPattern {
        id: "SNK_WEBVIEW_LOAD_URL",
        class: "Landroid/webkit/WebView;",
        name: "loadUrl",
        signature: "(Ljava/lang/String;)V",
        description: "WebView.loadUrl",
        taint_args: &[0],
    },
    MethodPattern {
        id: "SNK_SQLITE_EXEC",
        class: "Landroid/database/sqlite/SQLiteDatabase;",
        name: "execSQL",
        signature: "(Ljava/lang/String;)V",
        description: "SQLiteDatabase.execSQL",
        taint_args: &[1],
    },
    MethodPattern {
        id: "SNK_SQLITE_RAW_QUERY",
        class: "Landroid/database/sqlite/SQLiteDatabase;",
        name: "rawQuery",
        signature: "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;",
        description: "SQLiteDatabase.rawQuery",
        taint_args: &[1],
    },
    MethodPattern {
        id: "SNK_RUNTIME_EXEC",
        class: "Ljava/lang/Runtime;",
        name: "exec",
        signature: "(Ljava/lang/String;)Ljava/lang/Process;",
        description: "Runtime.exec",
        taint_args: &[1],
    },
];

struct PassthroughPattern {
    class: &'static str,
    name: &'static str,
    signature: &'static str,
    propagate_from: &'static [usize],
}

const PASSTHROUGH_METHODS: &[PassthroughPattern] = &[
    PassthroughPattern {
        class: "Ljava/lang/String;",
        name: "valueOf",
        signature: "(Ljava/lang/Object;)Ljava/lang/String;",
        propagate_from: &[0],
    },
    PassthroughPattern {
        class: "Ljava/lang/StringBuilder;",
        name: "toString",
        signature: "()Ljava/lang/String;",
        propagate_from: &[0],
    },
    PassthroughPattern {
        class: "Ljava/lang/StringBuilder;",
        name: "append",
        signature: "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        propagate_from: &[0, 1],
    },
    PassthroughPattern {
        class: "Ljava/lang/StringBuilder;",
        name: "append",
        signature: "(Ljava/lang/Object;)Ljava/lang/StringBuilder;",
        propagate_from: &[0, 1],
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

        // Taint can only ever begin at a source invocation (or a passthrough
        // carrying source-produced taint). If this method does not reference
        // any source method, no register can become tainted and the whole
        // CFG + worklist pass is wasted work — skip it.
        let Ok(instructions) = dex.decode_instructions(method) else {
            continue;
        };
        let references_source = instructions.iter().any(|inst| {
            matches!(
                inst.reference.as_ref(),
                Some(Reference::Method(target)) if lookup.sources.contains_key(&target.raw())
            )
        });
        if !references_source {
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
                message: format!(
                    "Tainted data reaches {} via arguments {:?}",
                    incident.sink.description,
                    incident
                        .arguments
                        .iter()
                        .map(|arg| arg.index)
                        .collect::<Vec<_>>()
                ),
                extra: json!({
                    "sink": incident.sink.description,
                    "pc": incident.pc,
                    "tainted_args": incident.arguments.iter().map(|arg| {
                        json!({
                            "index": arg.index,
                            "register": arg.register,
                        })
                    }).collect::<Vec<_>>(),
                }),
            });
        }
    }
}

struct MethodLookup<'a> {
    sources: HashMap<u32, &'a MethodPattern>,
    sinks: HashMap<u32, &'a MethodPattern>,
    passthrough: &'a [PassthroughPattern],
}

impl MethodLookup<'static> {
    fn build(dex: &DexFile<'_>) -> Self {
        let mut sources = HashMap::new();
        let mut sinks = HashMap::new();
        for idx in 0..dex.method_count() {
            let method_idx = MethodIdx::new(idx as u32);
            let summary = dex.method_summary(method_idx);
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
        Self {
            sources,
            sinks,
            passthrough: PASSTHROUGH_METHODS,
        }
    }
}

struct MethodTaintAnalysis<'a> {
    register_count: usize,
    lookup: &'a MethodLookup<'a>,
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
    arguments: Vec<TaintedArg>,
}

#[derive(Clone)]
struct TaintedArg {
    index: usize,
    register: u16,
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
        let mut pending_source: Option<PendingSource> = None;
        for inst in instructions {
            let name = inst.name();
            let registers = referenced_registers(inst);
            if is_move_object(name) {
                if let (Some(&dst), Some(&src)) = (registers.get(0), registers.get(1)) {
                    state.copy(dst, src);
                }
            } else if is_move_result_object(name) {
                if let Some(&dst) = registers.get(0) {
                    handle_move_result(state, dst, &pending_source);
                }
                pending_source = None;
            } else if is_const(name) {
                if let Some(&dst) = registers.get(0) {
                    state.clear(dst);
                }
            }

            if let Some(Reference::Method(target)) = inst.reference.as_ref() {
                let raw = target.raw();
                let summary = ctx.dex.method_summary(*target);
                if let Some(_source) = self.lookup.sources.get(&raw) {
                    pending_source = Some(PendingSource::Direct);
                    continue;
                }
                if let Some(sink) = self.lookup.sinks.get(&raw) {
                    let tainted_args = collect_tainted_args(state, &registers);
                    if sink_triggered(sink, &tainted_args) {
                        self.findings.borrow_mut().push(TaintIncident {
                            sink,
                            method: ctx.method,
                            pc: inst.pc,
                            arguments: tainted_args,
                        });
                    }
                    continue;
                }
                if let Some(pass) = match_passthrough(&summary, self.lookup.passthrough) {
                    pending_source = Some(PendingSource::Passthrough(pass, registers.clone()));
                    continue;
                }
                pending_source = None;
            } else {
                pending_source = None;
            }
        }
    }
}

enum PendingSource<'a> {
    Direct,
    Passthrough(&'a PassthroughPattern, Vec<u16>),
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

fn handle_move_result(state: &mut TaintState, dst: u16, pending: &Option<PendingSource<'_>>) {
    match pending {
        Some(PendingSource::Direct) => state.set(dst, true),
        Some(PendingSource::Passthrough(pattern, registers)) => {
            let tainted = if pattern.propagate_from.is_empty() {
                registers.iter().any(|reg| state.get(*reg))
            } else {
                pattern
                    .propagate_from
                    .iter()
                    .filter_map(|idx| registers.get(*idx))
                    .any(|reg| state.get(*reg))
            };
            if tainted {
                state.set(dst, true);
            } else {
                state.clear(dst);
            }
        }
        None => state.clear(dst),
    }
}

fn collect_tainted_args(state: &TaintState, registers: &[u16]) -> Vec<TaintedArg> {
    registers
        .iter()
        .enumerate()
        .filter_map(|(idx, reg)| {
            state.get(*reg).then_some(TaintedArg {
                index: idx,
                register: *reg,
            })
        })
        .collect()
}

fn sink_triggered(sink: &MethodPattern, args: &[TaintedArg]) -> bool {
    if sink.taint_args.is_empty() {
        !args.is_empty()
    } else {
        sink.taint_args
            .iter()
            .all(|required| args.iter().any(|arg| arg.index == *required))
    }
}

fn match_passthrough<'a>(
    summary: &MethodSummary,
    patterns: &'a [PassthroughPattern],
) -> Option<&'a PassthroughPattern> {
    patterns.iter().find(|pattern| {
        pattern.class == summary.class
            && pattern.name == summary.name
            && pattern.signature == summary.signature
    })
}

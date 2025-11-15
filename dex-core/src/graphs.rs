//! Graph construction utilities (CFG, call graph, and xrefs).

use std::collections::HashMap;

use petgraph::graph::Graph;
use serde::{Deserialize, Serialize};

use crate::{
    bytecode::Reference,
    dto::{DtoBasicBlock, DtoCfg},
    error::DexResult,
    format::MethodIdx,
    model::DexFile,
};

/// Basic block metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_pc: u32,
    pub end_pc: u32,
}

/// Alias for the CFG graph type.
pub type Cfg = Graph<BasicBlock, ()>;

/// Alias for the call graph type.
pub type CallGraph = Graph<u32, ()>;

/// Cross-reference container.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Xrefs {
    pub method_calls: Vec<(u32, u32)>,
    pub method_strings: Vec<(u32, u32)>,
}

/// Build a naive CFG for the given method (single basic block fallback).
pub fn build_method_cfg(dex: &DexFile<'_>, method: MethodIdx) -> DexResult<Cfg> {
    let mut graph = Graph::new();
    let instructions = dex.decode_instructions(method)?;
    if instructions.is_empty() {
        return Ok(graph);
    }
    let start = instructions.first().map(|ins| ins.pc).unwrap_or(0);
    let end = instructions
        .last()
        .map(|ins| ins.pc + ins.code_units() as u32)
        .unwrap_or(start);
    let entry = graph.add_node(BasicBlock {
        start_pc: start,
        end_pc: end,
    });

    if let Some(code_item) = dex.code_item(method) {
        let mut handler_nodes: HashMap<u32, petgraph::graph::NodeIndex> = HashMap::new();
        for try_item in &code_item.tries {
            if let Some(handler) = code_item.handler_for_offset(u32::from(try_item.handler_off)) {
                for typed in &handler.handlers {
                    let node = *handler_nodes.entry(typed.addr).or_insert_with(|| {
                        graph.add_node(BasicBlock {
                            start_pc: typed.addr,
                            end_pc: typed.addr,
                        })
                    });
                    graph.add_edge(entry, node, ());
                }
                if let Some(addr) = handler.catch_all_addr {
                    let node = *handler_nodes.entry(addr).or_insert_with(|| {
                        graph.add_node(BasicBlock {
                            start_pc: addr,
                            end_pc: addr,
                        })
                    });
                    graph.add_edge(entry, node, ());
                }
            }
        }
    }
    Ok(graph)
}

/// Converts a CFG into a DTO representation.
pub fn cfg_to_dto(cfg: &Cfg) -> DtoCfg {
    let mut blocks = Vec::new();
    for (idx, node) in cfg.node_indices().enumerate() {
        let bb = cfg.node_weight(node).expect("valid node");
        blocks.push(DtoBasicBlock {
            id: idx as u32,
            start_pc: bb.start_pc,
            end_pc: bb.end_pc,
        });
    }
    let edges = cfg
        .edge_indices()
        .map(|edge| {
            let (a, b) = cfg.edge_endpoints(edge).unwrap();
            (a.index() as u32, b.index() as u32)
        })
        .collect();
    DtoCfg { blocks, edges }
}

/// Build a whole-program call graph.
pub fn build_call_graph(dex: &DexFile<'_>) -> DexResult<CallGraph> {
    let mut graph = Graph::new();
    let mut nodes = Vec::new();
    for idx in 0..dex.method_count() {
        nodes.push(graph.add_node(idx as u32));
    }

    for (idx, node) in nodes.iter().enumerate() {
        let method_idx = MethodIdx::new(idx as u32);
        let instructions = match dex.decode_instructions(method_idx) {
            Ok(ins) => ins,
            Err(_) => continue,
        };
        for ins in instructions {
            if is_invoke(ins.opcode) {
                if let Some(target) = method_reference(&ins.reference, dex.method_count()) {
                    graph.add_edge(*node, nodes[target], ());
                }
            }
        }
    }

    Ok(graph)
}

/// Build simplified cross-reference data.
pub fn build_xrefs(dex: &DexFile<'_>) -> DexResult<Xrefs> {
    let mut xrefs = Xrefs::default();
    for idx in 0..dex.method_count() {
        let method_idx = MethodIdx::new(idx as u32);
        let instructions = match dex.decode_instructions(method_idx) {
            Ok(ins) => ins,
            Err(_) => continue,
        };
        for ins in &instructions {
            if is_invoke(ins.opcode) {
                if let Some(target) = method_reference(&ins.reference, dex.method_count()) {
                    xrefs.method_calls.push((idx as u32, target as u32));
                }
            } else if matches!(ins.reference, Some(Reference::String(_))) {
                if let Some(string_idx) = string_reference(&ins.reference) {
                    xrefs.method_strings.push((idx as u32, string_idx));
                }
            }
        }
    }
    Ok(xrefs)
}

fn is_invoke(opcode: u8) -> bool {
    matches!(opcode, 0x6e..=0x72 | 0x74..=0x78)
}

fn method_reference(reference: &Option<Reference>, method_count: usize) -> Option<usize> {
    match reference {
        Some(Reference::Method(idx)) => {
            let raw = idx.raw() as usize;
            (raw < method_count).then_some(raw)
        }
        _ => None,
    }
}

fn string_reference(reference: &Option<Reference>) -> Option<u32> {
    match reference {
        Some(Reference::String(idx)) => Some(idx.raw()),
        _ => None,
    }
}

//! Graph construction utilities (CFG, call graph, and xrefs).

use petgraph::graph::Graph;
use serde::{Deserialize, Serialize};

use crate::{
    bytecode::Instruction,
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
        .map(|ins| ins.pc + u32::from(ins.width) / 2)
        .unwrap_or(start);
    graph.add_node(BasicBlock {
        start_pc: start,
        end_pc: end,
    });
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
                if let Some(target) = decode_target_index(&ins, dex.method_count()) {
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
                if let Some(target) = decode_target_index(ins, dex.method_count()) {
                    xrefs.method_calls.push((idx as u32, target as u32));
                }
            } else if is_const_string(ins.opcode) {
                if let Some(string_idx) = ins.operands.first() {
                    xrefs
                        .method_strings
                        .push((idx as u32, u32::from(*string_idx)));
                }
            }
        }
    }
    Ok(xrefs)
}

fn is_invoke(opcode: u8) -> bool {
    matches!(opcode, 0x6e..=0x72 | 0x74..=0x78)
}

fn is_const_string(opcode: u8) -> bool {
    matches!(opcode, 0x1a | 0x1b)
}

fn decode_target_index(ins: &Instruction, method_count: usize) -> Option<usize> {
    ins.operands
        .last()
        .map(|value| usize::from(*value))
        .filter(|idx| *idx < method_count)
}

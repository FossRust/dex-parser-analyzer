//! Graph construction utilities (CFG, call graph, and xrefs).

use std::collections::{BTreeSet, HashMap};

use petgraph::graph::{Graph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::{
    bytecode::{Instruction, InstructionFormat, Reference, SwitchPayload},
    dto::{DtoBasicBlock, DtoCallGraph, DtoCfg, DtoXrefs},
    error::DexResult,
    format::{CodeItem, MethodIdx},
    model::DexFile,
};

/// Basic block metadata used by the CFG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Program counter (in 16-bit code units) where the block starts.
    pub start_pc: u32,
    /// Program counter where the block ends (exclusive).
    pub end_pc: u32,
}

/// Alias for the CFG graph type.
pub type Cfg = Graph<BasicBlock, ()>;

/// Alias for the call graph type.
pub type CallGraph = Graph<u32, ()>;

/// Cross-reference container that records simple relationships.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Xrefs {
    /// `(caller, callee)` pairs expressed as raw method indexes.
    pub method_calls: Vec<(u32, u32)>,
    /// `(method, string)` pairs expressing string usages.
    pub method_strings: Vec<(u32, u32)>,
    /// `(method, field)` pairs expressing field references.
    pub method_fields: Vec<(u32, u32)>,
    /// `(method, type)` pairs expressing type references.
    pub method_types: Vec<(u32, u32)>,
    /// `(method, proto)` pairs expressing prototype references.
    pub method_protos: Vec<(u32, u32)>,
    /// `(method, call_site)` pairs for `invoke-custom`.
    pub method_call_sites: Vec<(u32, u32)>,
    /// `(method, method_handle)` pairs for `const-method-handle` and friends.
    pub method_method_handles: Vec<(u32, u32)>,
}

/// Build a CFG for the given method.
///
/// The builder now emits a node per basic block, tracking conditional edges,
/// switch edges, fallthroughs, gotos, and exception handlers.
pub fn build_method_cfg(dex: &DexFile<'_>, method: MethodIdx) -> DexResult<Cfg> {
    let (cfg, _) = build_method_cfg_with_instructions(dex, method)?;
    Ok(cfg)
}

/// Build a CFG alongside the decoded instruction stream.
///
/// This helper avoids double-decoding bytecode for analyses that need both the
/// graph structure and the original instructions (e.g., data-flow passes).
pub fn build_method_cfg_with_instructions(
    dex: &DexFile<'_>,
    method: MethodIdx,
) -> DexResult<(Cfg, Vec<Instruction>)> {
    let Some(code_item) = dex.code_item(method) else {
        return Ok((Graph::new(), Vec::new()));
    };
    let instructions = dex.decode_instructions(method)?;
    let cfg = build_cfg_from_parts(code_item, &instructions);
    Ok((cfg, instructions))
}

fn build_cfg_from_parts(code_item: &CodeItem<'_>, instructions: &[Instruction]) -> Cfg {
    let mut graph = Graph::new();
    let total_units = code_item.insns_size;
    let real_instructions: Vec<&Instruction> = instructions
        .iter()
        .filter(|inst| is_real_instruction(inst))
        .collect();
    if real_instructions.is_empty() {
        return graph;
    }

    let mut block_starts = BTreeSet::new();
    if let Some(first) = real_instructions.first() {
        block_starts.insert(first.pc);
    }

    for inst in &real_instructions {
        if is_conditional_branch(inst.opcode) {
            if let Some(target) = compute_branch_target(inst.pc, inst.offset, total_units) {
                block_starts.insert(target);
            }
            if let Some(fallthrough) = fallthrough_start(inst, total_units) {
                block_starts.insert(fallthrough);
            }
        } else if is_switch(inst.opcode) {
            if let Some(payload) = &inst.switch {
                for target in switch_targets(inst.pc, payload, total_units) {
                    block_starts.insert(target);
                }
            }
            if let Some(fallthrough) = fallthrough_start(inst, total_units) {
                block_starts.insert(fallthrough);
            }
        } else if is_goto(inst.opcode) {
            if let Some(target) = compute_branch_target(inst.pc, inst.offset, total_units) {
                block_starts.insert(target);
            }
        }
    }

    for handler in &code_item.handlers {
        for typed in &handler.handlers {
            if typed.addr < total_units {
                block_starts.insert(typed.addr);
            }
        }
        if let Some(addr) = handler.catch_all_addr {
            if addr < total_units {
                block_starts.insert(addr);
            }
        }
    }

    let mut sorted_starts: Vec<u32> = block_starts.into_iter().collect();
    sorted_starts.sort_unstable();

    let mut start_to_index = HashMap::new();
    let mut blocks = Vec::new();
    for (idx, start) in sorted_starts.iter().enumerate() {
        if *start >= total_units {
            continue;
        }
        let end = sorted_starts.get(idx + 1).copied().unwrap_or(total_units);
        if end <= *start {
            continue;
        }
        let node = graph.add_node(BasicBlock {
            start_pc: *start,
            end_pc: end,
        });
        start_to_index.insert(*start, blocks.len());
        blocks.push(BlockInfo {
            node,
            start: *start,
            end,
        });
    }

    for block in &blocks {
        let Some(last_inst) = last_instruction_in_block(block, &real_instructions) else {
            continue;
        };
        if is_conditional_branch(last_inst.opcode) {
            if let Some(target) = compute_branch_target(last_inst.pc, last_inst.offset, total_units)
            {
                if let Some(&idx) = start_to_index.get(&target) {
                    graph.add_edge(block.node, blocks[idx].node, ());
                }
            }
            if let Some(next_node) = successor_node(block.end, &start_to_index, &blocks) {
                graph.add_edge(block.node, next_node, ());
            }
        } else if is_switch(last_inst.opcode) {
            if let Some(payload) = &last_inst.switch {
                for target in switch_targets(last_inst.pc, payload, total_units) {
                    if let Some(&idx) = start_to_index.get(&target) {
                        graph.add_edge(block.node, blocks[idx].node, ());
                    }
                }
            }
            if let Some(next_node) = successor_node(block.end, &start_to_index, &blocks) {
                graph.add_edge(block.node, next_node, ());
            }
        } else if is_goto(last_inst.opcode) {
            if let Some(target) = compute_branch_target(last_inst.pc, last_inst.offset, total_units)
            {
                if let Some(&idx) = start_to_index.get(&target) {
                    graph.add_edge(block.node, blocks[idx].node, ());
                }
            }
        } else if is_return_like(last_inst.opcode) || is_throw(last_inst.opcode) {
            // terminal blocks have no edges.
        } else if let Some(next_node) = successor_node(block.end, &start_to_index, &blocks) {
            graph.add_edge(block.node, next_node, ());
        }
    }

    if !code_item.tries.is_empty() {
        for try_item in &code_item.tries {
            let try_start = try_item.start_addr;
            let try_end = try_start.saturating_add(u32::from(try_item.insn_count));
            let Some(handler) = code_item.handler_for_offset(u32::from(try_item.handler_off))
            else {
                continue;
            };
            let mut handler_nodes = Vec::new();
            for typed in &handler.handlers {
                if let Some(&idx) = start_to_index.get(&typed.addr) {
                    handler_nodes.push(blocks[idx].node);
                }
            }
            if let Some(addr) = handler.catch_all_addr {
                if let Some(&idx) = start_to_index.get(&addr) {
                    handler_nodes.push(blocks[idx].node);
                }
            }
            if handler_nodes.is_empty() {
                continue;
            }

            for block in &blocks {
                if block.start < try_end && block.end > try_start {
                    for target in &handler_nodes {
                        graph.add_edge(block.node, *target, ());
                    }
                }
            }
        }
    }

    graph
}

fn is_real_instruction(inst: &Instruction) -> bool {
    !matches!(
        inst.format,
        InstructionFormat::ArrayPayload
            | InstructionFormat::PackedSwitchPayload
            | InstructionFormat::SparseSwitchPayload
            | InstructionFormat::Unresolved
    )
}

fn is_conditional_branch(opcode: u8) -> bool {
    matches!(opcode, 0x32..=0x37 | 0x38..=0x3d)
}

fn is_goto(opcode: u8) -> bool {
    matches!(opcode, 0x28 | 0x29 | 0x2a)
}

fn is_switch(opcode: u8) -> bool {
    matches!(opcode, 0x2b | 0x2c)
}

fn is_return_like(opcode: u8) -> bool {
    matches!(opcode, 0x0e..=0x11 | 0x73)
}

fn is_throw(opcode: u8) -> bool {
    opcode == 0x27
}

fn fallthrough_start(inst: &Instruction, limit: u32) -> Option<u32> {
    let width = inst.code_units() as u32;
    if width == 0 {
        return None;
    }
    let next_pc = inst.pc.saturating_add(width);
    (next_pc < limit).then_some(next_pc)
}

fn compute_branch_target(pc: u32, offset: Option<i32>, upper_bound: u32) -> Option<u32> {
    let offset = offset?;
    let target = (pc as i64) + (offset as i64);
    if target < 0 {
        return None;
    }
    let target = target as u32;
    if target >= upper_bound {
        None
    } else {
        Some(target)
    }
}

fn switch_targets(pc: u32, payload: &SwitchPayload, upper_bound: u32) -> Vec<u32> {
    match payload {
        SwitchPayload::Packed { targets, .. } => targets
            .iter()
            .filter_map(|offset| compute_branch_target(pc, Some(*offset), upper_bound))
            .collect(),
        SwitchPayload::Sparse { cases } => cases
            .iter()
            .filter_map(|(_, offset)| compute_branch_target(pc, Some(*offset), upper_bound))
            .collect(),
    }
}

fn last_instruction_in_block<'a>(
    block: &BlockInfo,
    instructions: &'a [&'a Instruction],
) -> Option<&'a Instruction> {
    instructions
        .iter()
        .copied()
        .filter(|inst| inst.pc >= block.start && inst.pc < block.end)
        .last()
}

fn successor_node(
    start: u32,
    start_to_index: &HashMap<u32, usize>,
    blocks: &[BlockInfo],
) -> Option<NodeIndex> {
    start_to_index.get(&start).map(|&idx| blocks[idx].node)
}

struct BlockInfo {
    node: NodeIndex,
    start: u32,
    end: u32,
}

/// Converts a CFG into a DTO representation.
///
/// The DTO mirrors the structure expected by `dex-gui` and higher-layer
/// serializers. Node indexes are re-numbered densely to make transport smaller.
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
///
/// The call graph treats each `invoke-*` instruction as a direct edge between
/// the declaring method and the referenced target index.
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

/// Convert a call graph into the DTO representation.
pub fn call_graph_to_dto(graph: &CallGraph) -> DtoCallGraph {
    let nodes = graph.node_indices().map(|node| graph[node]).collect();
    let edges = graph
        .edge_indices()
        .map(|edge| {
            let (a, b) = graph.edge_endpoints(edge).expect("edge endpoints");
            (a.index() as u32, b.index() as u32)
        })
        .collect();
    DtoCallGraph { nodes, edges }
}

/// Build simplified cross-reference data.
///
/// Returns the `(caller, callee)` pairs for all invocations found in the file
/// plus `(method, string)` pairs enumerating literal string references. Higher
/// layers can materialize richer databases on top of these seeds.
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
            }
            if let Some(reference) = ins.reference.as_ref() {
                record_reference(&mut xrefs, idx as u32, reference);
            }
            if let Some(reference) = ins.secondary_reference.as_ref() {
                record_reference(&mut xrefs, idx as u32, reference);
            }
        }
    }
    Ok(xrefs)
}

/// Convert the xref database into its DTO representation.
pub fn xrefs_to_dto(xrefs: &Xrefs) -> DtoXrefs {
    DtoXrefs {
        method_calls: xrefs.method_calls.clone(),
        method_strings: xrefs.method_strings.clone(),
        method_fields: xrefs.method_fields.clone(),
        method_types: xrefs.method_types.clone(),
        method_protos: xrefs.method_protos.clone(),
        method_call_sites: xrefs.method_call_sites.clone(),
        method_method_handles: xrefs.method_method_handles.clone(),
    }
}

fn is_invoke(opcode: u8) -> bool {
    matches!(opcode, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb)
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

fn record_reference(xrefs: &mut Xrefs, caller: u32, reference: &Reference) {
    match reference {
        Reference::String(idx) => xrefs.method_strings.push((caller, idx.raw())),
        Reference::Type(idx) => xrefs.method_types.push((caller, idx.raw())),
        Reference::Field(idx) => xrefs.method_fields.push((caller, idx.raw())),
        Reference::Proto(idx) => xrefs.method_protos.push((caller, idx.raw())),
        Reference::CallSite(idx) => xrefs.method_call_sites.push((caller, idx.raw())),
        Reference::MethodHandle(idx) => xrefs.method_method_handles.push((caller, idx.raw())),
        Reference::Method(_) => {}
    }
}

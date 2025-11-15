//! Prototype data-flow engine that operates on CFGs emitted by `graphs`.
//!
//! The engine is intentionally small: it provides a worklist-driven forward
//! solver plus a trait (`ForwardAnalysis`) that downstream crates (`dex-analysis`,
//! GUI overlays) can implement to express concrete analyses without re-building
//! the plumbing each time.

use std::collections::{HashMap, VecDeque};

use petgraph::{Direction, graph::NodeIndex, visit::NodeIndexable};

use crate::{
    DexResult,
    bytecode::Instruction,
    format::MethodIdx,
    graphs::{self, BasicBlock, Cfg},
    model::DexFile,
};

/// Shared context passed to [`ForwardAnalysis`] callbacks.
#[derive(Clone, Copy)]
pub struct AnalysisContext<'dex> {
    /// The backing dex file being analyzed.
    pub dex: &'dex DexFile<'dex>,
    /// Method currently under analysis.
    pub method: MethodIdx,
}

impl<'dex> AnalysisContext<'dex> {
    /// Convenience constructor.
    pub fn new(dex: &'dex DexFile<'dex>, method: MethodIdx) -> Self {
        Self { dex, method }
    }
}

/// Result of running a forward data-flow analysis.
#[derive(Debug)]
pub struct DataFlowResult<S> {
    entry_states: Vec<Option<S>>,
    exit_states: Vec<Option<S>>,
}

impl<S> DataFlowResult<S> {
    /// Borrow the entry state recorded for a node.
    pub fn entry(&self, node: NodeIndex) -> Option<&S> {
        self.entry_states
            .get(node.index())
            .and_then(|state| state.as_ref())
    }

    /// Borrow the exit state recorded for a node.
    pub fn exit(&self, node: NodeIndex) -> Option<&S> {
        self.exit_states
            .get(node.index())
            .and_then(|state| state.as_ref())
    }

    /// Internal ctor used by the solver.
    fn new(entry_states: Vec<Option<S>>, exit_states: Vec<Option<S>>) -> Self {
        Self {
            entry_states,
            exit_states,
        }
    }
}

/// Trait implemented by forward data-flow analyses.
pub trait ForwardAnalysis {
    /// State tracked at CFG boundaries.
    type State: Clone + PartialEq;

    /// Return the lattice's bottom element.
    fn bottom(&self) -> Self::State;

    /// Join `other` into `state`, returning whether `state` changed.
    fn join(&self, state: &mut Self::State, other: &Self::State) -> bool;

    /// Optional entry state used when a block has no predecessors.
    fn entry_state(&self, _ctx: &AnalysisContext<'_>) -> Self::State {
        self.bottom()
    }

    /// Transfer function applied to each basic block.
    fn transfer_block(
        &self,
        ctx: &AnalysisContext<'_>,
        block: &BasicBlock,
        instructions: &[Instruction],
        state: &mut Self::State,
    );
}

/// Execute a forward data-flow analysis starting from the underlying dex file.
pub fn run_forward<'dex, A>(
    dex: &'dex DexFile<'dex>,
    method: MethodIdx,
    analysis: &A,
) -> DexResult<DataFlowResult<A::State>>
where
    A: ForwardAnalysis,
{
    let (cfg, instructions) = graphs::build_method_cfg_with_instructions(dex, method)?;
    let ctx = AnalysisContext::new(dex, method);
    Ok(run_forward_with_cfg(analysis, &cfg, &instructions, ctx))
}

/// Execute a forward analysis using a pre-built CFG and decoded instructions.
pub fn run_forward_with_cfg<'dex, A>(
    analysis: &A,
    cfg: &Cfg,
    instructions: &[Instruction],
    ctx: AnalysisContext<'dex>,
) -> DataFlowResult<A::State>
where
    A: ForwardAnalysis,
{
    let bound = cfg.node_bound();
    if bound == 0 {
        return DataFlowResult::new(Vec::new(), Vec::new());
    }
    let mut entry_states = vec![None; bound];
    let mut exit_states = vec![None; bound];
    let mut worklist = VecDeque::new();
    let mut queued = vec![false; bound];
    let windows = compute_block_windows(cfg, instructions);

    for node in cfg.node_indices() {
        let idx = node.index();
        if idx >= bound {
            continue;
        }
        worklist.push_back(node);
        queued[idx] = true;
    }

    while let Some(node) = worklist.pop_front() {
        let node_idx = node.index();
        if node_idx >= bound {
            continue;
        }
        queued[node_idx] = false;

        let mut entry_state = analysis.bottom();
        let mut has_preds = false;
        for pred in cfg.neighbors_directed(node, Direction::Incoming) {
            has_preds = true;
            if let Some(pred_exit) = exit_states.get(pred.index()).and_then(|s| s.as_ref()) {
                analysis.join(&mut entry_state, pred_exit);
            }
        }
        if !has_preds {
            entry_state = analysis.entry_state(&ctx);
        }

        let mut changed = match entry_states.get(node_idx).and_then(|s| s.as_ref()) {
            Some(existing) if existing == &entry_state => false,
            _ => {
                entry_states[node_idx] = Some(entry_state.clone());
                true
            }
        };

        let mut exit_state = entry_state;
        if let Some(block) = cfg.node_weight(node) {
            let block_instructions = windows
                .get(node_idx)
                .and_then(|window| *window)
                .map(|(start, end)| &instructions[start..end])
                .unwrap_or_else(|| &[]);
            analysis.transfer_block(&ctx, block, block_instructions, &mut exit_state);
        }

        if match exit_states.get(node_idx).and_then(|s| s.as_ref()) {
            Some(existing) if existing == &exit_state => false,
            _ => {
                exit_states[node_idx] = Some(exit_state);
                true
            }
        } {
            changed = true;
        }

        if changed {
            for succ in cfg.neighbors_directed(node, Direction::Outgoing) {
                let succ_idx = succ.index();
                if succ_idx >= bound {
                    continue;
                }
                if !queued[succ_idx] {
                    queued[succ_idx] = true;
                    worklist.push_back(succ);
                }
            }
        }
    }

    DataFlowResult::new(entry_states, exit_states)
}

type BlockWindow = Option<(usize, usize)>;

fn compute_block_windows(cfg: &Cfg, instructions: &[Instruction]) -> Vec<BlockWindow> {
    let mut map = HashMap::new();
    for (idx, inst) in instructions.iter().enumerate() {
        map.entry(inst.pc).or_insert(idx);
    }
    let mut windows = vec![None; cfg.node_bound()];
    for node in cfg.node_indices() {
        let idx = node.index();
        if let Some(block) = cfg.node_weight(node) {
            windows[idx] = instruction_window(block, instructions, &map);
        }
    }
    windows
}

fn instruction_window(
    block: &BasicBlock,
    instructions: &[Instruction],
    pc_index: &HashMap<u32, usize>,
) -> BlockWindow {
    let start = match pc_index.get(&block.start_pc) {
        Some(idx) => *idx,
        None => return None,
    };
    let mut end = start;
    while end < instructions.len() && instructions[end].pc < block.end_pc {
        end += 1;
    }
    Some((start, end))
}

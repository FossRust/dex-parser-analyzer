use std::collections::BTreeSet;

use dex_core::{
    analysis::data_flow::{self, AnalysisContext, ForwardAnalysis},
    bytecode::{Instruction, InstructionFormat},
    format::MethodIdx,
    graphs, parse_dex,
};

struct OpcodeCollector;

impl ForwardAnalysis for OpcodeCollector {
    type State = BTreeSet<u8>;

    fn bottom(&self) -> Self::State {
        BTreeSet::new()
    }

    fn join(&self, state: &mut Self::State, other: &Self::State) -> bool {
        let before = state.len();
        state.extend(other);
        state.len() != before
    }

    fn transfer_block(
        &self,
        _ctx: &AnalysisContext<'_>,
        _block: &graphs::BasicBlock,
        instructions: &[Instruction],
        state: &mut Self::State,
    ) {
        for inst in instructions {
            if is_payload(inst) {
                continue;
            }
            state.insert(inst.opcode);
        }
    }
}

#[test]
fn opcode_collector_matches_instruction_set() {
    let bytes = load_fixture("AnalysisTest.dex");
    let dex = parse_dex(&bytes).expect("parse");
    let method = first_method_with_code(&dex);
    let (cfg, instructions) =
        graphs::build_method_cfg_with_instructions(&dex, method).expect("cfg");
    let ctx = AnalysisContext::new(&dex, method);
    let analysis = OpcodeCollector;
    let manual = data_flow::run_forward_with_cfg(&analysis, &cfg, &instructions, ctx);
    let mut expected = BTreeSet::new();
    for inst in &instructions {
        if !is_payload(inst) {
            expected.insert(inst.opcode);
        }
    }
    let mut aggregated = BTreeSet::new();
    for node in cfg.node_indices() {
        if let Some(exit) = manual.exit(node) {
            aggregated.extend(exit.iter().copied());
        }
    }
    assert_eq!(aggregated, expected, "data-flow should reach fixed point");

    let auto = data_flow::run_forward(&dex, method, &analysis).expect("auto");
    for node in cfg.node_indices() {
        assert_eq!(
            manual.exit(node),
            auto.exit(node),
            "mismatched exit state for node {}",
            node.index()
        );
    }
}

fn load_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/data/{name}")).expect("missing fixture")
}

fn first_method_with_code(dex: &dex_core::DexFile<'_>) -> MethodIdx {
    for idx in 0..dex.method_count() {
        let method = MethodIdx::new(idx as u32);
        if dex.code_item(method).is_some() {
            return method;
        }
    }
    panic!("fixture missing method with code");
}

fn is_payload(inst: &Instruction) -> bool {
    matches!(
        inst.format,
        InstructionFormat::ArrayPayload
            | InstructionFormat::PackedSwitchPayload
            | InstructionFormat::SparseSwitchPayload
            | InstructionFormat::Unresolved
    )
}

//! Serializable data-transfer objects for dex metadata.

use serde::{Deserialize, Serialize};

use crate::{
    bytecode::Instruction,
    error::DexResult,
    model::{ClassHandle, MethodHandle},
};

/// Transfer representation of a method.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoMethod {
    pub idx: u32,
    pub class: String,
    pub name: String,
}

/// Transfer representation of a class.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoClass {
    pub idx: u32,
    pub descriptor: String,
}

/// Transfer representation of instructions.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoInstruction {
    pub pc: u32,
    pub opcode: u8,
    pub name: String,
    pub format: String,
    pub registers: Vec<u16>,
    pub literal: Option<i64>,
    pub offset: Option<i32>,
    pub reference: Option<DtoReference>,
    pub secondary_reference: Option<DtoReference>,
    pub verification_error: Option<u8>,
    pub quickened_kind: Option<String>,
    pub quickened_index: Option<u16>,
}

/// Simple CFG DTO with a list of nodes and adjacency.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoCfg {
    pub blocks: Vec<DtoBasicBlock>,
    pub edges: Vec<(u32, u32)>,
}

/// Basic block DTO.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoBasicBlock {
    pub id: u32,
    pub start_pc: u32,
    pub end_pc: u32,
}

/// Call graph DTO.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoCallGraph {
    pub nodes: Vec<u32>,
    pub edges: Vec<(u32, u32)>,
}

/// Xref DTO storing simple relationships.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DtoXrefs {
    pub method_calls: Vec<(u32, u32)>,
    pub method_strings: Vec<(u32, u32)>,
}

/// Metadata about an indexed reference used by an instruction.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoReference {
    pub kind: String,
    pub index: u32,
}

/// Convert a method handle into a DTO.
pub fn method_to_dto(method: &MethodHandle<'_>) -> DexResult<DtoMethod> {
    let class_desc = method
        .class()
        .and_then(|class| class.descriptor().ok().map(|s| s.to_string()))
        .unwrap_or_else(|| "<unknown>".to_string());
    Ok(DtoMethod {
        idx: method.index().raw(),
        class: class_desc,
        name: method.name()?.to_string(),
    })
}

/// Convert a class handle into a DTO.
pub fn class_to_dto(class: &ClassHandle<'_>) -> DexResult<DtoClass> {
    Ok(DtoClass {
        idx: class.index().raw(),
        descriptor: class.descriptor()?.to_string(),
    })
}

/// Convert decoded instructions into DTO form.
pub fn instructions_to_dto(instructions: &[Instruction]) -> Vec<DtoInstruction> {
    instructions
        .iter()
        .map(|ins| {
            let reference = ins.reference.as_ref().map(|reference| DtoReference {
                kind: reference.kind_label().to_string(),
                index: reference.index(),
            });
            let secondary_reference =
                ins.secondary_reference
                    .as_ref()
                    .map(|reference| DtoReference {
                        kind: reference.kind_label().to_string(),
                        index: reference.index(),
                    });
            let quickened_kind = ins
                .quickened_info
                .as_ref()
                .map(|info| format!("{:?}", info.kind));
            let quickened_index = ins.quickened_info.map(|info| info.index);
            DtoInstruction {
                pc: ins.pc,
                opcode: ins.opcode,
                name: ins.name.to_string(),
                format: format!("{:?}", ins.format),
                registers: ins.registers.iter().copied().collect(),
                literal: ins.literal,
                offset: ins.offset,
                reference,
                secondary_reference,
                verification_error: ins.verification_error,
                quickened_kind,
                quickened_index,
            }
        })
        .collect()
}

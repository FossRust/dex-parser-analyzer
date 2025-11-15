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
    /// Raw `method_ids` index.
    pub idx: u32,
    /// Descriptor of the owning class (`Lpkg/Foo;`).
    pub class: String,
    /// Unqualified method name.
    pub name: String,
}

/// Transfer representation of a class.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoClass {
    /// Raw `type_ids` index.
    pub idx: u32,
    /// Descriptor string.
    pub descriptor: String,
}

/// Transfer representation of instructions.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoInstruction {
    /// Program counter measured in code units.
    pub pc: u32,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Human-friendly mnemonic.
    pub name: String,
    /// Instruction format label (`Fmt35c`, ...).
    pub format: String,
    /// Registers touched by the instruction.
    pub registers: Vec<u16>,
    /// Literal constant (if applicable).
    pub literal: Option<i64>,
    /// Branch offset (if applicable).
    pub offset: Option<i32>,
    /// Primary indexed reference (string/type/field/method).
    pub reference: Option<DtoReference>,
    /// Secondary reference for dual-reference opcodes (45cc/4rcc).
    pub secondary_reference: Option<DtoReference>,
    /// ART verification error code captured via quickened opcodes.
    pub verification_error: Option<u8>,
    /// Quickening kind for odex instructions.
    pub quickened_kind: Option<String>,
    /// Quickening index for odex instructions.
    pub quickened_index: Option<u16>,
}

/// Simple CFG DTO with a list of nodes and adjacency.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoCfg {
    /// Basic block collection.
    pub blocks: Vec<DtoBasicBlock>,
    /// Directed edges between block IDs.
    pub edges: Vec<(u32, u32)>,
}

/// Basic block DTO.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoBasicBlock {
    /// Stable identifier used inside DTO edges.
    pub id: u32,
    /// First program counter of the block.
    pub start_pc: u32,
    /// End program counter (exclusive).
    pub end_pc: u32,
}

/// Call graph DTO.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoCallGraph {
    /// Node identifiers (method indexes).
    pub nodes: Vec<u32>,
    /// Directed edges expressed as method index pairs.
    pub edges: Vec<(u32, u32)>,
}

/// Xref DTO storing simple relationships.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DtoXrefs {
    /// `(caller, callee)` tuples.
    pub method_calls: Vec<(u32, u32)>,
    /// `(method, string)` tuples.
    pub method_strings: Vec<(u32, u32)>,
    /// `(method, field)` tuples.
    pub method_fields: Vec<(u32, u32)>,
    /// `(method, type)` tuples.
    pub method_types: Vec<(u32, u32)>,
    /// `(method, proto)` tuples.
    pub method_protos: Vec<(u32, u32)>,
    /// `(method, call_site)` tuples.
    pub method_call_sites: Vec<(u32, u32)>,
    /// `(method, method_handle)` tuples.
    pub method_method_handles: Vec<(u32, u32)>,
}

/// Metadata about an indexed reference used by an instruction.
#[derive(Debug, Serialize, Deserialize)]
pub struct DtoReference {
    /// Reference category label.
    pub kind: String,
    /// Raw index into the referenced table.
    pub index: u32,
}

/// Convert a method handle into a DTO.
///
/// ```
/// # use dex_core::{dto, DexError, parse_dex};
/// # fn serialize_first_method(data: &[u8]) -> Result<(), DexError> {
/// let dex = parse_dex(data)?;
/// if let Some(method) = dex.method(dex_core::format::MethodIdx::new(0)) {
///     let dto = dto::method_to_dto(&method)?;
///     println!("method {} -> {}", dto.idx, dto.name);
/// }
/// # Ok(())
/// # }
/// ```
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

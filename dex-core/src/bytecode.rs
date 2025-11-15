//! Dalvik bytecode decoding utilities.

use serde::{Deserialize, Serialize};

use crate::{
    error::{DexError, DexResult},
    format::{CodeItem, MethodIdx},
    model::DexFile,
};

/// Simplified representation of a Dalvik instruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    /// Program counter expressed in code units (16-bit).
    pub pc: u32,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Width in bytes.
    pub width: u8,
    /// Raw operand words (little-endian).
    pub operands: Vec<u16>,
}

/// Decodes instructions directly from a [`CodeItem`].
pub fn decode_instructions<'a>(
    _dex: &DexFile<'a>,
    code_item: &CodeItem<'a>,
) -> DexResult<Vec<Instruction>> {
    decode_code_stream(code_item)
}

pub(crate) fn decode_instructions_internal<'a>(
    dex: &DexFile<'a>,
    method: MethodIdx,
) -> DexResult<Vec<Instruction>> {
    let code = dex.code_item(method).ok_or(DexError::Malformed {
        context: "method",
        message: "method is abstract or native",
    })?;
    decode_code_stream(code)
}

fn decode_code_stream(code_item: &CodeItem<'_>) -> DexResult<Vec<Instruction>> {
    let mut cursor = 0usize;
    let mut out = Vec::new();
    let insns = code_item.insns;
    while cursor < insns.len() {
        let opcode = insns[cursor];
        let width = instruction_width(opcode);
        let end = cursor.checked_add(width).ok_or(DexError::Malformed {
            context: "code_item",
            message: "instruction overflow",
        })?;
        if end > insns.len() {
            return Err(DexError::Malformed {
                context: "code_item",
                message: "truncated instruction",
            });
        }
        let operand_slice = &insns[cursor + 1..end];
        if operand_slice.len() % 2 != 0 {
            return Err(DexError::Malformed {
                context: "code_item",
                message: "operand alignment issue",
            });
        }
        let operands = operand_slice
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        out.push(Instruction {
            pc: (cursor / 2) as u32,
            opcode,
            width: width as u8,
            operands,
        });
        cursor = end;
    }
    Ok(out)
}

fn instruction_width(opcode: u8) -> usize {
    match opcode {
        0x1c..=0x1f => 4, // const/16 family
        0x20..=0x23 => 4,
        0x24 | 0x25 => 6, // array ops
        0x26 => 6,
        0x27 | 0x28 => 2,
        0x29..=0x2b => 4,
        0x2c..=0x31 => 4,
        0x32..=0x37 => 4,
        0x38..=0x3d => 4,
        0x44..=0x51 => 4,
        0x52..=0x5f => 6,
        0x60..=0x6d => 6,
        0x6e..=0x72 => 6,
        0x74..=0x78 => 6,
        0x7b..=0x8f => 4,
        0x90..=0x9f => 4,
        0xa0..=0xaf => 4,
        0xb0..=0xd7 => 4,
        0xe3..=0xe5 => 6,
        0xe6..=0xef => 6,
        0xf0 | 0xf1 => 6,
        0xf2 => 10,
        0xf3 => 8,
        0xf4..=0xff => 6,
        _ => 2,
    }
}

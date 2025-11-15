use smallvec::SmallVec;

use crate::{
    error::{DexError, DexResult},
    format::{
        CallSiteIdx, CodeItem, FieldIdx, MethodHandleIdx, MethodIdx, ProtoIdx, StringIdx, TypeIdx,
    },
    model::DexFile,
};

const MAX_INLINE_REGS: usize = 8;

/// Decoded Dalvik instruction.
#[derive(Clone, Debug)]
pub struct Instruction {
    /// Program counter measured in 16-bit code units.
    pub pc: u32,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Symbolic opcode name.
    pub name: &'static str,
    /// Instruction format metadata.
    pub format: InstructionFormat,
    /// Registers referenced by the instruction (order depends on opcode).
    pub registers: SmallVec<[u16; MAX_INLINE_REGS]>,
    /// Literal constant associated with the instruction (narrow or wide).
    pub literal: Option<i64>,
    /// Relative branch offset (in code units) when applicable.
    pub offset: Option<i32>,
    /// Referenced table entry (string, type, field, method, etc.).
    pub reference: Option<Reference>,
    /// Range metadata for range invoke instructions.
    pub range: Option<RangeInfo>,
    /// Parsed switch payload if the instruction references one.
    pub switch: Option<SwitchPayload>,
    /// Parsed fill-array-data payload if referenced.
    pub array: Option<ArrayPayload>,
    /// Raw bytes for instructions whose format isn't fully decoded yet.
    pub raw: Option<Vec<u8>>,
    reference_kind: ReferenceType,
}

impl Instruction {
    fn new(info: &OpcodeInfo, pc_units: usize) -> Self {
        Self {
            pc: pc_units as u32,
            opcode: info.opcode,
            name: info.name,
            format: info.format,
            registers: SmallVec::new(),
            literal: None,
            offset: None,
            reference: None,
            range: None,
            switch: None,
            array: None,
            raw: None,
            reference_kind: info.reference,
        }
    }

    fn payload(name: &'static str, format: InstructionFormat, pc_units: usize) -> Self {
        Self {
            pc: pc_units as u32,
            opcode: 0x00,
            name,
            format,
            registers: SmallVec::new(),
            literal: None,
            offset: None,
            reference: None,
            range: None,
            switch: None,
            array: None,
            raw: None,
            reference_kind: ReferenceType::None,
        }
    }

    /// Returns the number of 16-bit code units consumed by this instruction.
    pub fn code_units(&self) -> usize {
        self.format.units().unwrap_or(0)
    }
}

/// Range information for format 3rc instructions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeInfo {
    /// First register in the range.
    pub start: u16,
    /// Number of registers covered by the range.
    pub count: u16,
}

/// Switch payload variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwitchPayload {
    /// Dense packed switch.
    Packed { first_key: i32, targets: Vec<i32> },
    /// Sparse switch with explicit key/target pairs.
    Sparse { cases: Vec<(i32, i32)> },
}

/// Parsed data for `fill-array-data` payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArrayPayload {
    /// Width of each element in bytes.
    pub element_width: u16,
    /// Number of elements present.
    pub size: u32,
    /// Raw little-endian data buffer.
    pub data: Vec<u8>,
}

/// Public helper for decoding instructions from a [`CodeItem`].
pub fn decode_instructions<'a>(
    dex: &DexFile<'a>,
    code_item: &CodeItem<'a>,
) -> DexResult<Vec<Instruction>> {
    decode_stream(dex, code_item)
}

pub(crate) fn decode_instructions_internal<'a>(
    dex: &DexFile<'a>,
    method: MethodIdx,
) -> DexResult<Vec<Instruction>> {
    let code = dex.code_item(method).ok_or(DexError::Malformed {
        context: "method",
        message: "method is abstract or native",
    })?;
    decode_stream(dex, code)
}

fn decode_stream(_dex: &DexFile<'_>, code_item: &CodeItem<'_>) -> DexResult<Vec<Instruction>> {
    let total_units = code_item.insns_size as usize;
    let bytes = code_item.insns;
    let expected_len = total_units * 2;
    if bytes.len() < expected_len {
        return Err(DexError::Malformed {
            context: "code_item",
            message: "insns section shorter than declared size",
        });
    }

    let mut instructions = Vec::new();
    let mut pc_units = 0usize;
    let mut byte_offset = 0usize;

    while pc_units < total_units {
        let word = read_u16(bytes, byte_offset)?;
        if let Some((payload, units_consumed)) = decode_payload(word, bytes, byte_offset, pc_units)?
        {
            instructions.push(payload);
            pc_units += units_consumed;
            byte_offset += units_consumed * 2;
            continue;
        }

        let opcode = bytes[byte_offset];
        let info = &OPCODE_TABLE[opcode as usize];
        let width_units = info.format.units().ok_or(DexError::UnknownOpcode {
            opcode,
            pc: pc_units as u32,
        })?;
        if pc_units + width_units > total_units {
            return Err(DexError::Malformed {
                context: "code_item",
                message: "instruction extends past end of insns",
            });
        }

        let mut instruction = Instruction::new(info, pc_units);
        decode_format(&mut instruction, bytes, byte_offset, pc_units, total_units)?;
        instructions.push(instruction);

        pc_units += width_units;
        byte_offset += width_units * 2;
    }

    Ok(instructions)
}

fn decode_format(
    inst: &mut Instruction,
    bytes: &[u8],
    start: usize,
    pc_units: usize,
    total_units: usize,
) -> DexResult<()> {
    match inst.format {
        InstructionFormat::Format10x => {}
        InstructionFormat::Format10t => {
            let offset = read_i8(bytes, start + 1)? as i32;
            inst.offset = Some(offset);
        }
        InstructionFormat::Format11n => {
            let byte1 = read_u8(bytes, start + 1)?;
            inst.registers.push((byte1 & 0x0F) as u16);
            inst.literal = Some(((byte1 as i8) >> 4) as i64);
        }
        InstructionFormat::Format11x => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
        }
        InstructionFormat::Format12x => {
            let byte1 = read_u8(bytes, start + 1)?;
            inst.registers
                .extend_from_slice(&[((byte1 & 0x0F) as u16), ((byte1 >> 4) as u16)]);
        }
        InstructionFormat::Format20t => {
            inst.offset = Some(read_i16(bytes, start + 2)? as i32);
        }
        InstructionFormat::Format21s => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            inst.literal = Some(read_i16(bytes, start + 2)? as i64);
        }
        InstructionFormat::Format21ih => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            inst.literal = Some((read_i16(bytes, start + 2)? as i32 as i64) << 16);
        }
        InstructionFormat::Format21lh => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            inst.literal = Some((read_i16(bytes, start + 2)? as i64) << 48);
        }
        InstructionFormat::Format21t => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            inst.offset = Some(read_i16(bytes, start + 2)? as i32);
        }
        InstructionFormat::Format21c => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            let idx = read_u16(bytes, start + 2)? as u32;
            inst.reference = decode_reference(inst.reference_kind, idx);
        }
        InstructionFormat::Format22x => {
            inst.registers.extend_from_slice(&[
                read_u8(bytes, start + 1)? as u16,
                read_u16(bytes, start + 2)?,
            ]);
        }
        InstructionFormat::Format22t => {
            let byte1 = read_u8(bytes, start + 1)?;
            inst.registers
                .extend_from_slice(&[((byte1 & 0x0F) as u16), ((byte1 >> 4) as u16)]);
            inst.offset = Some(read_i16(bytes, start + 2)? as i32);
        }
        InstructionFormat::Format22c | InstructionFormat::Format22cs => {
            let byte1 = read_u8(bytes, start + 1)?;
            inst.registers
                .extend_from_slice(&[((byte1 & 0x0F) as u16), ((byte1 >> 4) as u16)]);
            let idx = read_u16(bytes, start + 2)? as u32;
            inst.reference = decode_reference(inst.reference_kind, idx);
        }
        InstructionFormat::Format22s => {
            let byte1 = read_u8(bytes, start + 1)?;
            inst.registers
                .extend_from_slice(&[((byte1 & 0x0F) as u16), ((byte1 >> 4) as u16)]);
            inst.literal = Some(read_i16(bytes, start + 2)? as i64);
        }
        InstructionFormat::Format22b => {
            inst.registers.extend_from_slice(&[
                read_u8(bytes, start + 1)? as u16,
                read_u8(bytes, start + 2)? as u16,
            ]);
            inst.literal = Some(read_i8(bytes, start + 3)? as i64);
        }
        InstructionFormat::Format23x => {
            inst.registers.extend_from_slice(&[
                read_u8(bytes, start + 1)? as u16,
                read_u8(bytes, start + 2)? as u16,
                read_u8(bytes, start + 3)? as u16,
            ]);
        }
        InstructionFormat::Format30t => {
            inst.offset = Some(read_i32(bytes, start + 2)?);
        }
        InstructionFormat::Format31i => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            inst.literal = Some(read_i32(bytes, start + 2)? as i64);
        }
        InstructionFormat::Format31c => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            let idx = read_u32(bytes, start + 2)?;
            inst.reference = decode_reference(inst.reference_kind, idx);
        }
        InstructionFormat::Format31t => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            let offset = read_i32(bytes, start + 2)?;
            inst.offset = Some(offset);
            let payload_pc = ((pc_units as i32) + offset) as usize;
            inst.switch = parse_switch_payload(bytes, inst.name, payload_pc, total_units)?;
            if inst.name == "FILL_ARRAY_DATA" {
                inst.array = parse_array_payload(bytes, payload_pc, total_units)?;
            }
        }
        InstructionFormat::Format32x => {
            inst.registers
                .extend_from_slice(&[read_u16(bytes, start + 2)?, read_u16(bytes, start + 4)?]);
        }
        InstructionFormat::Format35c => decode_format_35c(inst, bytes, start)?,
        InstructionFormat::Format3rc => {
            let count = read_u8(bytes, start + 1)? as u16;
            inst.range = Some(RangeInfo {
                start: read_u16(bytes, start + 4)?,
                count,
            });
            let idx = read_u16(bytes, start + 2)? as u32;
            inst.reference = decode_reference(inst.reference_kind, idx);
        }
        InstructionFormat::Format51l => {
            inst.registers.push(read_u8(bytes, start + 1)? as u16);
            inst.literal = Some(read_i64(bytes, start + 2)?);
        }
        _ => {
            inst.raw = Some(bytes[start..start + inst.format.bytes().unwrap_or(2)].to_vec());
        }
    }
    Ok(())
}

fn decode_format_35c(inst: &mut Instruction, bytes: &[u8], start: usize) -> DexResult<()> {
    let byte1 = read_u8(bytes, start + 1)?;
    let reg_count = (byte1 >> 4) as usize;
    let reg_g = byte1 & 0x0F;
    let idx = read_u16(bytes, start + 2)? as u32;
    inst.reference = decode_reference(inst.reference_kind, idx);

    let cd = read_u8(bytes, start + 4)?;
    let ef = read_u8(bytes, start + 5)?;
    let regs = [
        (cd & 0x0F) as u16,
        (cd >> 4) as u16,
        (ef & 0x0F) as u16,
        (ef >> 4) as u16,
        reg_g as u16,
    ];
    for reg in regs.iter().take(reg_count) {
        inst.registers.push(*reg);
    }
    Ok(())
}

fn decode_payload(
    first_word: u16,
    bytes: &[u8],
    start: usize,
    pc_units: usize,
) -> DexResult<Option<(Instruction, usize)>> {
    if first_word & 0xFF != 0 || first_word == 0 {
        return Ok(None);
    }
    match first_word >> 8 {
        0x01 => {
            let mut inst = Instruction::payload(
                "PACKED_SWITCH_PAYLOAD",
                InstructionFormat::PackedSwitchPayload,
                pc_units,
            );
            let size = read_u16(bytes, start + 2)? as usize;
            let first_key = read_i32(bytes, start + 4)?;
            let mut targets = Vec::with_capacity(size);
            let mut offset = start + 8;
            for _ in 0..size {
                targets.push(read_i32(bytes, offset)?);
                offset += 4;
            }
            inst.switch = Some(SwitchPayload::Packed { first_key, targets });
            let units = (offset - start) / 2;
            Ok(Some((inst, units)))
        }
        0x02 => {
            let mut inst = Instruction::payload(
                "SPARSE_SWITCH_PAYLOAD",
                InstructionFormat::SparseSwitchPayload,
                pc_units,
            );
            let size = read_u16(bytes, start + 2)? as usize;
            let mut cases = Vec::with_capacity(size);
            let mut keys_offset = start + 4;
            let mut targets_offset = start + 4 + size * 4;
            for _ in 0..size {
                let key = read_i32(bytes, keys_offset)?;
                let target = read_i32(bytes, targets_offset)?;
                cases.push((key, target));
                keys_offset += 4;
                targets_offset += 4;
            }
            inst.switch = Some(SwitchPayload::Sparse { cases });
            let units = (targets_offset - start) / 2;
            Ok(Some((inst, units)))
        }
        0x03 => {
            let mut inst = Instruction::payload(
                "FILL_ARRAY_DATA_PAYLOAD",
                InstructionFormat::ArrayPayload,
                pc_units,
            );
            let element_width = read_u16(bytes, start + 2)?;
            let size = read_u32(bytes, start + 4)?;
            let data_bytes = (element_width as usize) * (size as usize);
            let data_end = start + 8 + data_bytes;
            inst.array = Some(ArrayPayload {
                element_width,
                size,
                data: bytes[start + 8..data_end].to_vec(),
            });
            let padded_end = if data_bytes % 2 == 0 {
                data_end
            } else {
                data_end + 1
            };
            let units = (padded_end - start) / 2;
            Ok(Some((inst, units)))
        }
        _ => Ok(None),
    }
}

fn parse_switch_payload(
    bytes: &[u8],
    opcode_name: &str,
    payload_pc: usize,
    total_units: usize,
) -> DexResult<Option<SwitchPayload>> {
    if payload_pc >= total_units {
        return Err(DexError::Malformed {
            context: "switch",
            message: "payload offset out of range",
        });
    }
    let byte_offset = payload_pc * 2;
    let first_word = read_u16(bytes, byte_offset)?;
    match (first_word >> 8, opcode_name) {
        (0x01, "PACKED_SWITCH") => {
            let size = read_u16(bytes, byte_offset + 2)? as usize;
            let first_key = read_i32(bytes, byte_offset + 4)?;
            let mut targets = Vec::with_capacity(size);
            let mut off = byte_offset + 8;
            for _ in 0..size {
                targets.push(read_i32(bytes, off)?);
                off += 4;
            }
            Ok(Some(SwitchPayload::Packed { first_key, targets }))
        }
        (0x02, "SPARSE_SWITCH") => {
            let size = read_u16(bytes, byte_offset + 2)? as usize;
            let mut cases = Vec::with_capacity(size);
            let mut keys_off = byte_offset + 4;
            let mut targets_off = byte_offset + 4 + size * 4;
            for _ in 0..size {
                cases.push((read_i32(bytes, keys_off)?, read_i32(bytes, targets_off)?));
                keys_off += 4;
                targets_off += 4;
            }
            Ok(Some(SwitchPayload::Sparse { cases }))
        }
        _ => Ok(None),
    }
}

fn parse_array_payload(
    bytes: &[u8],
    payload_pc: usize,
    total_units: usize,
) -> DexResult<Option<ArrayPayload>> {
    if payload_pc >= total_units {
        return Ok(None);
    }
    let offset = payload_pc * 2;
    let first_word = read_u16(bytes, offset)?;
    if first_word >> 8 != 0x03 {
        return Ok(None);
    }
    let element_width = read_u16(bytes, offset + 2)?;
    let size = read_u32(bytes, offset + 4)?;
    let data_bytes = (element_width as usize) * (size as usize);
    let end = offset + 8 + data_bytes;
    Ok(Some(ArrayPayload {
        element_width,
        size,
        data: bytes[offset + 8..end].to_vec(),
    }))
}

fn decode_reference(kind: ReferenceType, index: u32) -> Option<Reference> {
    match kind {
        ReferenceType::None => None,
        ReferenceType::String => Some(Reference::String(StringIdx::new(index))),
        ReferenceType::Type => Some(Reference::Type(TypeIdx::new(index))),
        ReferenceType::Field => Some(Reference::Field(FieldIdx::new(index))),
        ReferenceType::Method => Some(Reference::Method(MethodIdx::new(index))),
        ReferenceType::Proto => Some(Reference::Proto(ProtoIdx::new(index))),
        ReferenceType::CallSite => Some(Reference::CallSite(CallSiteIdx::new(index))),
        ReferenceType::MethodHandle => Some(Reference::MethodHandle(MethodHandleIdx::new(index))),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference {
    String(StringIdx),
    Type(TypeIdx),
    Field(FieldIdx),
    Method(MethodIdx),
    Proto(ProtoIdx),
    CallSite(CallSiteIdx),
    MethodHandle(MethodHandleIdx),
}

impl Reference {
    /// Returns the raw index backing this reference.
    pub fn index(&self) -> u32 {
        match self {
            Reference::String(idx) => idx.raw(),
            Reference::Type(idx) => idx.raw(),
            Reference::Field(idx) => idx.raw(),
            Reference::Method(idx) => idx.raw(),
            Reference::Proto(idx) => idx.raw(),
            Reference::CallSite(idx) => idx.raw(),
            Reference::MethodHandle(idx) => idx.raw(),
        }
    }

    /// Returns a descriptive kind label for serialization purposes.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Reference::String(_) => "string",
            Reference::Type(_) => "type",
            Reference::Field(_) => "field",
            Reference::Method(_) => "method",
            Reference::Proto(_) => "proto",
            Reference::CallSite(_) => "call_site",
            Reference::MethodHandle(_) => "method_handle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionFormat {
    Format10t,
    Format10x,
    Format11n,
    Format11x,
    Format12x,
    Format20bc,
    Format20t,
    Format21c,
    Format21ih,
    Format21lh,
    Format21s,
    Format21t,
    Format22b,
    Format22c,
    Format22cs,
    Format22s,
    Format22t,
    Format22x,
    Format23x,
    Format30t,
    Format31c,
    Format31i,
    Format31t,
    Format32x,
    Format35c,
    Format35mi,
    Format35ms,
    Format3rc,
    Format3rmi,
    Format3rms,
    Format45cc,
    Format4rcc,
    Format51l,
    ArrayPayload,
    PackedSwitchPayload,
    SparseSwitchPayload,
    Unresolved,
}

impl InstructionFormat {
    const fn bytes(self) -> Option<usize> {
        match self {
            InstructionFormat::Format10t
            | InstructionFormat::Format10x
            | InstructionFormat::Format11n
            | InstructionFormat::Format11x
            | InstructionFormat::Format12x => Some(2),
            InstructionFormat::Format20bc
            | InstructionFormat::Format20t
            | InstructionFormat::Format21c
            | InstructionFormat::Format21ih
            | InstructionFormat::Format21lh
            | InstructionFormat::Format21s
            | InstructionFormat::Format21t
            | InstructionFormat::Format22b
            | InstructionFormat::Format22c
            | InstructionFormat::Format22cs
            | InstructionFormat::Format22s
            | InstructionFormat::Format22t
            | InstructionFormat::Format22x
            | InstructionFormat::Format23x => Some(4),
            InstructionFormat::Format30t
            | InstructionFormat::Format31c
            | InstructionFormat::Format31i
            | InstructionFormat::Format31t
            | InstructionFormat::Format32x
            | InstructionFormat::Format35c
            | InstructionFormat::Format35mi
            | InstructionFormat::Format35ms
            | InstructionFormat::Format3rc
            | InstructionFormat::Format3rmi
            | InstructionFormat::Format3rms => Some(6),
            InstructionFormat::Format45cc | InstructionFormat::Format4rcc => Some(8),
            InstructionFormat::Format51l => Some(10),
            InstructionFormat::ArrayPayload
            | InstructionFormat::PackedSwitchPayload
            | InstructionFormat::SparseSwitchPayload
            | InstructionFormat::Unresolved => None,
        }
    }

    const fn units(self) -> Option<usize> {
        match self.bytes() {
            Some(b) => Some(b / 2),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceType {
    None,
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

#[derive(Clone, Copy, Debug)]
struct OpcodeInfo {
    opcode: u8,
    name: &'static str,
    format: InstructionFormat,
    reference: ReferenceType,
}

impl OpcodeInfo {
    const fn default() -> Self {
        Self {
            opcode: 0,
            name: "UNDEFINED",
            format: InstructionFormat::Unresolved,
            reference: ReferenceType::None,
        }
    }
}

const OPCODE_TABLE: [OpcodeInfo; 256] = [
    OpcodeInfo {
        opcode: 0x00,
        name: "NOP",
        format: InstructionFormat::Format10x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x01,
        name: "MOVE",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x02,
        name: "MOVE_FROM16",
        format: InstructionFormat::Format22x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x03,
        name: "MOVE_16",
        format: InstructionFormat::Format32x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x04,
        name: "MOVE_WIDE",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x05,
        name: "MOVE_WIDE_FROM16",
        format: InstructionFormat::Format22x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x06,
        name: "MOVE_WIDE_16",
        format: InstructionFormat::Format32x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x07,
        name: "MOVE_OBJECT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x08,
        name: "MOVE_OBJECT_FROM16",
        format: InstructionFormat::Format22x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x09,
        name: "MOVE_OBJECT_16",
        format: InstructionFormat::Format32x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0a,
        name: "MOVE_RESULT",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0b,
        name: "MOVE_RESULT_WIDE",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0c,
        name: "MOVE_RESULT_OBJECT",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0d,
        name: "MOVE_EXCEPTION",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0e,
        name: "RETURN_VOID",
        format: InstructionFormat::Format10x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0f,
        name: "RETURN",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x10,
        name: "RETURN_WIDE",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x11,
        name: "RETURN_OBJECT",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x12,
        name: "CONST_4",
        format: InstructionFormat::Format11n,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x13,
        name: "CONST_16",
        format: InstructionFormat::Format21s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x14,
        name: "CONST",
        format: InstructionFormat::Format31i,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x15,
        name: "CONST_HIGH16",
        format: InstructionFormat::Format21ih,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x16,
        name: "CONST_WIDE_16",
        format: InstructionFormat::Format21s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x17,
        name: "CONST_WIDE_32",
        format: InstructionFormat::Format31i,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x18,
        name: "CONST_WIDE",
        format: InstructionFormat::Format51l,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x19,
        name: "CONST_WIDE_HIGH16",
        format: InstructionFormat::Format21lh,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1a,
        name: "CONST_STRING",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::String,
    },
    OpcodeInfo {
        opcode: 0x1b,
        name: "CONST_STRING_JUMBO",
        format: InstructionFormat::Format31c,
        reference: ReferenceType::String,
    },
    OpcodeInfo {
        opcode: 0x1c,
        name: "CONST_CLASS",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Type,
    },
    OpcodeInfo {
        opcode: 0x1d,
        name: "MONITOR_ENTER",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1e,
        name: "MONITOR_EXIT",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1f,
        name: "CHECK_CAST",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Type,
    },
    OpcodeInfo {
        opcode: 0x20,
        name: "INSTANCE_OF",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Type,
    },
    OpcodeInfo {
        opcode: 0x21,
        name: "ARRAY_LENGTH",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x22,
        name: "NEW_INSTANCE",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Type,
    },
    OpcodeInfo {
        opcode: 0x23,
        name: "NEW_ARRAY",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Type,
    },
    OpcodeInfo {
        opcode: 0x24,
        name: "FILLED_NEW_ARRAY",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Type,
    },
    OpcodeInfo {
        opcode: 0x25,
        name: "FILLED_NEW_ARRAY_RANGE",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Type,
    },
    OpcodeInfo {
        opcode: 0x26,
        name: "FILL_ARRAY_DATA",
        format: InstructionFormat::Format31t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x27,
        name: "THROW",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x28,
        name: "GOTO",
        format: InstructionFormat::Format10t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x29,
        name: "GOTO_16",
        format: InstructionFormat::Format20t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2a,
        name: "GOTO_32",
        format: InstructionFormat::Format30t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2b,
        name: "PACKED_SWITCH",
        format: InstructionFormat::Format31t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2c,
        name: "SPARSE_SWITCH",
        format: InstructionFormat::Format31t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2d,
        name: "CMPL_FLOAT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2e,
        name: "CMPG_FLOAT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2f,
        name: "CMPL_DOUBLE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x30,
        name: "CMPG_DOUBLE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x31,
        name: "CMP_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x32,
        name: "IF_EQ",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x33,
        name: "IF_NE",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x34,
        name: "IF_LT",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x35,
        name: "IF_GE",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x36,
        name: "IF_GT",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x37,
        name: "IF_LE",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x38,
        name: "IF_EQZ",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x39,
        name: "IF_NEZ",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3a,
        name: "IF_LTZ",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3b,
        name: "IF_GEZ",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3c,
        name: "IF_GTZ",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3d,
        name: "IF_LEZ",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
    },
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo {
        opcode: 0x44,
        name: "AGET",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x45,
        name: "AGET_WIDE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x46,
        name: "AGET_OBJECT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x47,
        name: "AGET_BOOLEAN",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x48,
        name: "AGET_BYTE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x49,
        name: "AGET_CHAR",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4a,
        name: "AGET_SHORT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4b,
        name: "APUT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4c,
        name: "APUT_WIDE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4d,
        name: "APUT_OBJECT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4e,
        name: "APUT_BOOLEAN",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4f,
        name: "APUT_BYTE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x50,
        name: "APUT_CHAR",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x51,
        name: "APUT_SHORT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x52,
        name: "IGET",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x53,
        name: "IGET_WIDE",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x54,
        name: "IGET_OBJECT",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x55,
        name: "IGET_BOOLEAN",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x56,
        name: "IGET_BYTE",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x57,
        name: "IGET_CHAR",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x58,
        name: "IGET_SHORT",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x59,
        name: "IPUT",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x5a,
        name: "IPUT_WIDE",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x5b,
        name: "IPUT_OBJECT",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x5c,
        name: "IPUT_BOOLEAN",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x5d,
        name: "IPUT_BYTE",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x5e,
        name: "IPUT_CHAR",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x5f,
        name: "IPUT_SHORT",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x60,
        name: "SGET",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x61,
        name: "SGET_WIDE",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x62,
        name: "SGET_OBJECT",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x63,
        name: "SGET_BOOLEAN",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x64,
        name: "SGET_BYTE",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x65,
        name: "SGET_CHAR",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x66,
        name: "SGET_SHORT",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x67,
        name: "SPUT",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x68,
        name: "SPUT_WIDE",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x69,
        name: "SPUT_OBJECT",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x6a,
        name: "SPUT_BOOLEAN",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x6b,
        name: "SPUT_BYTE",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x6c,
        name: "SPUT_CHAR",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x6d,
        name: "SPUT_SHORT",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
    },
    OpcodeInfo {
        opcode: 0x6e,
        name: "INVOKE_VIRTUAL",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x6f,
        name: "INVOKE_SUPER",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x70,
        name: "INVOKE_DIRECT",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x71,
        name: "INVOKE_STATIC",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x72,
        name: "INVOKE_INTERFACE",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
    },
    OpcodeInfo::default(),
    OpcodeInfo {
        opcode: 0x74,
        name: "INVOKE_VIRTUAL_RANGE",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x75,
        name: "INVOKE_SUPER_RANGE",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x76,
        name: "INVOKE_DIRECT_RANGE",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x77,
        name: "INVOKE_STATIC_RANGE",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
    },
    OpcodeInfo {
        opcode: 0x78,
        name: "INVOKE_INTERFACE_RANGE",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
    },
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo {
        opcode: 0x7b,
        name: "NEG_INT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7c,
        name: "NOT_INT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7d,
        name: "NEG_LONG",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7e,
        name: "NOT_LONG",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7f,
        name: "NEG_FLOAT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x80,
        name: "NEG_DOUBLE",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x81,
        name: "INT_TO_LONG",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x82,
        name: "INT_TO_FLOAT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x83,
        name: "INT_TO_DOUBLE",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x84,
        name: "LONG_TO_INT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x85,
        name: "LONG_TO_FLOAT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x86,
        name: "LONG_TO_DOUBLE",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x87,
        name: "FLOAT_TO_INT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x88,
        name: "FLOAT_TO_LONG",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x89,
        name: "FLOAT_TO_DOUBLE",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8a,
        name: "DOUBLE_TO_INT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8b,
        name: "DOUBLE_TO_LONG",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8c,
        name: "DOUBLE_TO_FLOAT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8d,
        name: "INT_TO_BYTE",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8e,
        name: "INT_TO_CHAR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8f,
        name: "INT_TO_SHORT",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x90,
        name: "ADD_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x91,
        name: "SUB_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x92,
        name: "MUL_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x93,
        name: "DIV_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x94,
        name: "REM_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x95,
        name: "AND_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x96,
        name: "OR_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x97,
        name: "XOR_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x98,
        name: "SHL_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x99,
        name: "SHR_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9a,
        name: "USHR_INT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9b,
        name: "ADD_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9c,
        name: "SUB_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9d,
        name: "MUL_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9e,
        name: "DIV_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9f,
        name: "REM_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa0,
        name: "AND_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa1,
        name: "OR_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa2,
        name: "XOR_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa3,
        name: "SHL_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa4,
        name: "SHR_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa5,
        name: "USHR_LONG",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa6,
        name: "ADD_FLOAT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa7,
        name: "SUB_FLOAT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa8,
        name: "MUL_FLOAT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa9,
        name: "DIV_FLOAT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xaa,
        name: "REM_FLOAT",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xab,
        name: "ADD_DOUBLE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xac,
        name: "SUB_DOUBLE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xad,
        name: "MUL_DOUBLE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xae,
        name: "DIV_DOUBLE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xaf,
        name: "REM_DOUBLE",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb0,
        name: "ADD_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb1,
        name: "SUB_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb2,
        name: "MUL_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb3,
        name: "DIV_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb4,
        name: "REM_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb5,
        name: "AND_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb6,
        name: "OR_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb7,
        name: "XOR_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb8,
        name: "SHL_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb9,
        name: "SHR_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xba,
        name: "USHR_INT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbb,
        name: "ADD_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbc,
        name: "SUB_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbd,
        name: "MUL_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbe,
        name: "DIV_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbf,
        name: "REM_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc0,
        name: "AND_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc1,
        name: "OR_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc2,
        name: "XOR_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc3,
        name: "SHL_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc4,
        name: "SHR_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc5,
        name: "USHR_LONG_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc6,
        name: "ADD_FLOAT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc7,
        name: "SUB_FLOAT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc8,
        name: "MUL_FLOAT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc9,
        name: "DIV_FLOAT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xca,
        name: "REM_FLOAT_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcb,
        name: "ADD_DOUBLE_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcc,
        name: "SUB_DOUBLE_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcd,
        name: "MUL_DOUBLE_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xce,
        name: "DIV_DOUBLE_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcf,
        name: "REM_DOUBLE_2ADDR",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd0,
        name: "ADD_INT_LIT16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd1,
        name: "RSUB_INT",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd2,
        name: "MUL_INT_LIT16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd3,
        name: "DIV_INT_LIT16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd4,
        name: "REM_INT_LIT16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd5,
        name: "AND_INT_LIT16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd6,
        name: "OR_INT_LIT16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd7,
        name: "XOR_INT_LIT16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd8,
        name: "ADD_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd9,
        name: "RSUB_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xda,
        name: "MUL_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdb,
        name: "DIV_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdc,
        name: "REM_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdd,
        name: "AND_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xde,
        name: "OR_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdf,
        name: "XOR_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe0,
        name: "SHL_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe1,
        name: "SHR_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe2,
        name: "USHR_INT_LIT8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
    },
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
];

fn read_u8(bytes: &[u8], offset: usize) -> DexResult<u8> {
    Ok(*bytes.get(offset).ok_or(DexError::SectionOutOfBounds {
        section: "code_item",
        offset,
        size: 1,
    })?)
}

fn read_i8(bytes: &[u8], offset: usize) -> DexResult<i8> {
    Ok(read_u8(bytes, offset)? as i8)
}

fn read_u16(bytes: &[u8], offset: usize) -> DexResult<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or(DexError::SectionOutOfBounds {
            section: "code_item",
            offset,
            size: 2,
        })?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_i16(bytes: &[u8], offset: usize) -> DexResult<i16> {
    Ok(read_u16(bytes, offset)? as i16)
}

fn read_u32(bytes: &[u8], offset: usize) -> DexResult<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(DexError::SectionOutOfBounds {
            section: "code_item",
            offset,
            size: 4,
        })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i32(bytes: &[u8], offset: usize) -> DexResult<i32> {
    Ok(read_u32(bytes, offset)? as i32)
}

fn read_u64(bytes: &[u8], offset: usize) -> DexResult<u64> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or(DexError::SectionOutOfBounds {
            section: "code_item",
            offset,
            size: 8,
        })?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_i64(bytes: &[u8], offset: usize) -> DexResult<i64> {
    Ok(read_u64(bytes, offset)? as i64)
}

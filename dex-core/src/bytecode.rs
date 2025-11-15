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
    reference_kind2: ReferenceType,
    /// Optional secondary reference (used by call-site/method-proto aware formats).
    pub secondary_reference: Option<Reference>,
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
            secondary_reference: None,
            range: None,
            switch: None,
            array: None,
            raw: None,
            reference_kind: info.reference,
            reference_kind2: info.reference2,
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
            reference_kind2: ReferenceType::None,
            secondary_reference: None,
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
    _dex: &DexFile<'a>,
    code_item: &CodeItem<'a>,
) -> DexResult<Vec<Instruction>> {
    decode_stream(code_item)
}

pub(crate) fn decode_instructions_internal<'a>(
    dex: &DexFile<'a>,
    method: MethodIdx,
) -> DexResult<Vec<Instruction>> {
    let code = dex.code_item(method).ok_or(DexError::Malformed {
        context: "method",
        message: "method is abstract or native",
    })?;
    decode_stream(code)
}

fn decode_stream(code_item: &CodeItem<'_>) -> DexResult<Vec<Instruction>> {
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
            let payload_pc = compute_payload_pc(pc_units, offset, total_units)?;
            match inst.opcode {
                0x2b => {
                    inst.switch = Some(parse_switch_payload(
                        bytes,
                        payload_pc,
                        total_units,
                        SwitchKind::Packed,
                    )?);
                }
                0x2c => {
                    inst.switch = Some(parse_switch_payload(
                        bytes,
                        payload_pc,
                        total_units,
                        SwitchKind::Sparse,
                    )?);
                }
                0x26 => {
                    inst.array = Some(parse_array_payload(bytes, payload_pc, total_units)?);
                }
                _ => {}
            }
        }
        InstructionFormat::Format32x => {
            inst.registers
                .extend_from_slice(&[read_u16(bytes, start + 2)?, read_u16(bytes, start + 4)?]);
        }
        InstructionFormat::Format35c => decode_format_35c(inst, bytes, start)?,
        InstructionFormat::Format45cc => decode_format_45cc(inst, bytes, start)?,
        InstructionFormat::Format4rcc => decode_format_4rcc(inst, bytes, start)?,
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

fn decode_format_45cc(inst: &mut Instruction, bytes: &[u8], start: usize) -> DexResult<()> {
    let byte1 = read_u8(bytes, start + 1)?;
    let reg_count = (byte1 >> 4) as usize;
    let reg_g = byte1 & 0x0F;
    let primary_idx = read_u16(bytes, start + 2)? as u32;
    inst.reference = decode_reference(inst.reference_kind, primary_idx);

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

    let secondary_idx = read_u16(bytes, start + 6)? as u32;
    inst.secondary_reference = decode_reference(inst.reference_kind2, secondary_idx);
    Ok(())
}

fn decode_format_4rcc(inst: &mut Instruction, bytes: &[u8], start: usize) -> DexResult<()> {
    let count = read_u8(bytes, start + 1)? as u16;
    inst.range = Some(RangeInfo {
        start: read_u16(bytes, start + 4)?,
        count,
    });
    let primary_idx = read_u16(bytes, start + 2)? as u32;
    inst.reference = decode_reference(inst.reference_kind, primary_idx);
    let secondary_idx = read_u16(bytes, start + 6)? as u32;
    inst.secondary_reference = decode_reference(inst.reference_kind2, secondary_idx);
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
            let data_bytes =
                (element_width as usize)
                    .checked_mul(size as usize)
                    .ok_or(DexError::Malformed {
                        context: "fill-array",
                        message: "payload size overflow",
                    })?;
            let data_end = start + 8 + data_bytes;
            let data = bytes
                .get(start + 8..data_end)
                .ok_or(DexError::Malformed {
                    context: "fill-array",
                    message: "payload truncated",
                })?
                .to_vec();
            inst.array = Some(ArrayPayload {
                element_width,
                size,
                data,
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

fn compute_payload_pc(pc_units: usize, offset: i32, total_units: usize) -> DexResult<usize> {
    let target = (pc_units as isize) + (offset as isize);
    if target < 0 {
        return Err(DexError::Malformed {
            context: "payload",
            message: "payload offset underflow",
        });
    }
    let target = target as usize;
    if target >= total_units {
        return Err(DexError::Malformed {
            context: "payload",
            message: "payload offset out of range",
        });
    }
    Ok(target)
}

enum SwitchKind {
    Packed,
    Sparse,
}

fn parse_switch_payload(
    bytes: &[u8],
    payload_pc: usize,
    total_units: usize,
    kind: SwitchKind,
) -> DexResult<SwitchPayload> {
    if payload_pc >= total_units {
        return Err(DexError::Malformed {
            context: "switch",
            message: "payload offset out of range",
        });
    }
    let byte_offset = payload_pc * 2;
    let ident = read_u16(bytes, byte_offset)?;
    match kind {
        SwitchKind::Packed => {
            if ident != 0x0100 {
                return Err(DexError::Malformed {
                    context: "packed-switch",
                    message: "payload ident mismatch",
                });
            }
            let size = read_u16(bytes, byte_offset + 2)? as usize;
            let first_key = read_i32(bytes, byte_offset + 4)?;
            let mut targets = Vec::with_capacity(size);
            let mut off = byte_offset + 8;
            for _ in 0..size {
                targets.push(read_i32(bytes, off)?);
                off += 4;
            }
            Ok(SwitchPayload::Packed { first_key, targets })
        }
        SwitchKind::Sparse => {
            if ident != 0x0200 {
                return Err(DexError::Malformed {
                    context: "sparse-switch",
                    message: "payload ident mismatch",
                });
            }
            let size = read_u16(bytes, byte_offset + 2)? as usize;
            let mut cases = Vec::with_capacity(size);
            let mut keys_off = byte_offset + 4;
            let mut targets_off = byte_offset + 4 + size * 4;
            for _ in 0..size {
                cases.push((read_i32(bytes, keys_off)?, read_i32(bytes, targets_off)?));
                keys_off += 4;
                targets_off += 4;
            }
            Ok(SwitchPayload::Sparse { cases })
        }
    }
}

fn parse_array_payload(
    bytes: &[u8],
    payload_pc: usize,
    total_units: usize,
) -> DexResult<ArrayPayload> {
    if payload_pc >= total_units {
        return Err(DexError::Malformed {
            context: "fill-array",
            message: "payload offset out of range",
        });
    }
    let offset = payload_pc * 2;
    let ident = read_u16(bytes, offset)?;
    if ident != 0x0300 {
        return Err(DexError::Malformed {
            context: "fill-array",
            message: "payload ident mismatch",
        });
    }
    let element_width = read_u16(bytes, offset + 2)?;
    let size = read_u32(bytes, offset + 4)?;
    let data_bytes =
        (element_width as usize)
            .checked_mul(size as usize)
            .ok_or(DexError::Malformed {
                context: "fill-array",
                message: "payload size overflow",
            })?;
    let end = offset + 8 + data_bytes;
    let data = bytes
        .get(offset + 8..end)
        .ok_or(DexError::Malformed {
            context: "fill-array",
            message: "payload truncated",
        })?
        .to_vec();
    Ok(ArrayPayload {
        element_width,
        size,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::CodeItem;

    fn code_item_from_bytes(bytes: &'static [u8]) -> CodeItem<'static> {
        CodeItem {
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            tries_size: 0,
            debug_info_off: 0,
            insns_size: (bytes.len() / 2) as u32,
            insns: bytes,
            tries: Vec::new(),
            handlers: Vec::new(),
            handler_offsets: Vec::new(),
        }
    }

    #[test]
    fn decode_format45cc_dual_reference() {
        static BYTES: [u8; 8] = [0xfa, 0x21, 0x34, 0x12, 0x43, 0x65, 0x78, 0x56];
        let code = code_item_from_bytes(&BYTES);
        let instructions = super::decode_stream(&code).expect("decode");
        assert_eq!(instructions.len(), 1);
        let inst = &instructions[0];
        let regs: Vec<_> = inst.registers.iter().copied().collect();
        assert_eq!(regs, vec![3, 4]);
        assert_eq!(
            inst.reference,
            Some(Reference::Method(MethodIdx::new(0x1234)))
        );
        assert_eq!(
            inst.secondary_reference,
            Some(Reference::Proto(ProtoIdx::new(0x5678)))
        );
    }

    #[test]
    fn decode_format4rcc_dual_reference() {
        static BYTES: [u8; 8] = [0xfb, 0x03, 0x00, 0x01, 0x20, 0x00, 0x00, 0x02];
        let code = code_item_from_bytes(&BYTES);
        let instructions = super::decode_stream(&code).expect("decode");
        assert_eq!(instructions.len(), 1);
        let inst = &instructions[0];
        assert_eq!(
            inst.range,
            Some(RangeInfo {
                start: 0x20,
                count: 3
            })
        );
        assert_eq!(
            inst.reference,
            Some(Reference::Method(MethodIdx::new(0x0100)))
        );
        assert_eq!(
            inst.secondary_reference,
            Some(Reference::Proto(ProtoIdx::new(0x0200)))
        );
    }

    #[test]
    fn packed_switch_payload_decodes() {
        static BYTES: [u8; 18] = [
            0x2b, 0x00, 0x03, 0x00, 0x00, 0x00, // packed-switch with offset 3 units
            0x00, 0x01, // ident
            0x01, 0x00, // size
            0x11, 0x00, 0x00, 0x00, // first key
            0x02, 0x00, 0x00, 0x00, // target offset
        ];
        let code = code_item_from_bytes(&BYTES);
        let instructions = super::decode_stream(&code).expect("decode");
        assert!(matches!(
            instructions[0].switch.as_ref(),
            Some(SwitchPayload::Packed { first_key, targets })
            if *first_key == 0x11 && targets == &vec![2]
        ));
    }

    #[test]
    fn packed_switch_payload_rejects_mismatched_ident() {
        static BYTES: [u8; 18] = [
            0x2b, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, // invalid ident
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let code = code_item_from_bytes(&BYTES);
        let err = super::decode_stream(&code).expect_err("should fail");
        assert!(matches!(err, DexError::Malformed { .. }));
    }

    #[test]
    fn packed_switch_multiple_entries() {
        static BYTES: [u8; 22] = [
            0x2b, 0x00, 0x03, 0x00, 0x00, 0x00, //
            0x00, 0x01, // ident
            0x02, 0x00, // size = 2
            0x01, 0x00, 0x00, 0x00, // first key
            0x10, 0x00, 0x00, 0x00, // target0
            0x20, 0x00, 0x00, 0x00, // target1
        ];
        let code = code_item_from_bytes(&BYTES);
        let instructions = super::decode_stream(&code).expect("decode");
        if let Some(SwitchPayload::Packed { first_key, targets }) = &instructions[0].switch {
            assert_eq!(*first_key, 1);
            assert_eq!(targets, &vec![0x10, 0x20]);
        } else {
            panic!("expected packed switch payload");
        }
    }

    #[test]
    fn const_method_handle_and_type() {
        static BYTES: [u8; 10] = [
            0xfe, 0x01, 0x02, 0x00, // const-method-handle v1, #2
            0xff, 0x02, 0x03, 0x00, // const-method-type v2, #3
            0x0e, 0x00, // return-void
        ];
        let code = code_item_from_bytes(&BYTES);
        let instructions = super::decode_stream(&code).expect("decode");
        assert!(matches!(
            instructions[0].reference,
            Some(Reference::MethodHandle(idx)) if idx.raw() == 0x0002
        ));
        assert!(matches!(
            instructions[1].reference,
            Some(Reference::Proto(idx)) if idx.raw() == 0x0003
        ));
    }

    #[test]
    fn invoke_custom_references_call_site() {
        static BYTES: [u8; 8] = [0xfc, 0x10, 0x01, 0x00, 0x32, 0x10, 0x00, 0x00];
        let code = code_item_from_bytes(&BYTES);
        let instructions = super::decode_stream(&code).expect("decode");
        assert_eq!(instructions[0].registers.len(), 1);
        assert!(matches!(
            instructions[0].reference,
            Some(Reference::CallSite(idx)) if idx.raw() == 0x0001
        ));
    }

    #[test]
    fn invoke_custom_range_references_call_site() {
        static BYTES: [u8; 8] = [0xfd, 0x02, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00];
        let code = code_item_from_bytes(&BYTES);
        let instructions = super::decode_stream(&code).expect("decode");
        assert!(matches!(
            instructions[0].reference,
            Some(Reference::CallSite(idx)) if idx.raw() == 0x0002
        ));
        assert!(matches!(
            instructions[0].range,
            Some(RangeInfo { start, count }) if start == 0x20 && count == 2
        ));
    }

    #[test]
    fn invalid_fill_array_payload_offset_errors() {
        // fill-array-data with offset pointing beyond insns_size.
        static BYTES: [u8; 10] = [0x26, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00];
        let code = code_item_from_bytes(&BYTES);
        let err = super::decode_stream(&code).expect_err("expected malformed");
        assert!(matches!(
            err,
            DexError::Malformed {
                context: "payload",
                ..
            }
        ));
    }
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
    reference2: ReferenceType,
}

impl OpcodeInfo {
    const fn default() -> Self {
        Self {
            opcode: 0,
            name: "UNDEFINED",
            format: InstructionFormat::Unresolved,
            reference: ReferenceType::None,
            reference2: ReferenceType::None,
        }
    }
}

const OPCODE_TABLE: [OpcodeInfo; 256] = [
    OpcodeInfo {
        opcode: 0x00,
        name: "nop",
        format: InstructionFormat::Format10x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x01,
        name: "move",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x02,
        name: "move/from16",
        format: InstructionFormat::Format22x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x03,
        name: "move/16",
        format: InstructionFormat::Format32x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x04,
        name: "move-wide",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x05,
        name: "move-wide/from16",
        format: InstructionFormat::Format22x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x06,
        name: "move-wide/16",
        format: InstructionFormat::Format32x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x07,
        name: "move-object",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x08,
        name: "move-object/from16",
        format: InstructionFormat::Format22x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x09,
        name: "move-object/16",
        format: InstructionFormat::Format32x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0a,
        name: "move-result",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0b,
        name: "move-result-wide",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0c,
        name: "move-result-object",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0d,
        name: "move-exception",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0e,
        name: "return-void",
        format: InstructionFormat::Format10x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x0f,
        name: "return",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x10,
        name: "return-wide",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x11,
        name: "return-object",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x12,
        name: "const/4",
        format: InstructionFormat::Format11n,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x13,
        name: "const/16",
        format: InstructionFormat::Format21s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x14,
        name: "const",
        format: InstructionFormat::Format31i,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x15,
        name: "const/high16",
        format: InstructionFormat::Format21ih,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x16,
        name: "const-wide/16",
        format: InstructionFormat::Format21s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x17,
        name: "const-wide/32",
        format: InstructionFormat::Format31i,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x18,
        name: "const-wide",
        format: InstructionFormat::Format51l,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x19,
        name: "const-wide/high16",
        format: InstructionFormat::Format21lh,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1a,
        name: "const-string",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::String,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1b,
        name: "const-string/jumbo",
        format: InstructionFormat::Format31c,
        reference: ReferenceType::String,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1c,
        name: "const-class",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Type,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1d,
        name: "monitor-enter",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1e,
        name: "monitor-exit",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x1f,
        name: "check-cast",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Type,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x20,
        name: "instance-of",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Type,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x21,
        name: "array-length",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x22,
        name: "new-instance",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Type,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x23,
        name: "new-array",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Type,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x24,
        name: "filled-new-array",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Type,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x25,
        name: "filled-new-array/range",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Type,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x26,
        name: "fill-array-data",
        format: InstructionFormat::Format31t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x27,
        name: "throw",
        format: InstructionFormat::Format11x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x28,
        name: "goto",
        format: InstructionFormat::Format10t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x29,
        name: "goto/16",
        format: InstructionFormat::Format20t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2a,
        name: "goto/32",
        format: InstructionFormat::Format30t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2b,
        name: "packed-switch",
        format: InstructionFormat::Format31t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2c,
        name: "sparse-switch",
        format: InstructionFormat::Format31t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2d,
        name: "cmpl-float",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2e,
        name: "cmpg-float",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x2f,
        name: "cmpl-double",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x30,
        name: "cmpg-double",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x31,
        name: "cmp-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x32,
        name: "if-eq",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x33,
        name: "if-ne",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x34,
        name: "if-lt",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x35,
        name: "if-ge",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x36,
        name: "if-gt",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x37,
        name: "if-le",
        format: InstructionFormat::Format22t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x38,
        name: "if-eqz",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x39,
        name: "if-nez",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3a,
        name: "if-ltz",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3b,
        name: "if-gez",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3c,
        name: "if-gtz",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x3d,
        name: "if-lez",
        format: InstructionFormat::Format21t,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo {
        opcode: 0x44,
        name: "aget",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x45,
        name: "aget-wide",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x46,
        name: "aget-object",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x47,
        name: "aget-boolean",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x48,
        name: "aget-byte",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x49,
        name: "aget-char",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4a,
        name: "aget-short",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4b,
        name: "aput",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4c,
        name: "aput-wide",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4d,
        name: "aput-object",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4e,
        name: "aput-boolean",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x4f,
        name: "aput-byte",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x50,
        name: "aput-char",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x51,
        name: "aput-short",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x52,
        name: "iget",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x53,
        name: "iget-wide",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x54,
        name: "iget-object",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x55,
        name: "iget-boolean",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x56,
        name: "iget-byte",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x57,
        name: "iget-char",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x58,
        name: "iget-short",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x59,
        name: "iput",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x5a,
        name: "iput-wide",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x5b,
        name: "iput-object",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x5c,
        name: "iput-boolean",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x5d,
        name: "iput-byte",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x5e,
        name: "iput-char",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x5f,
        name: "iput-short",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x60,
        name: "sget",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x61,
        name: "sget-wide",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x62,
        name: "sget-object",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x63,
        name: "sget-boolean",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x64,
        name: "sget-byte",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x65,
        name: "sget-char",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x66,
        name: "sget-short",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x67,
        name: "sput",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x68,
        name: "sput-wide",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x69,
        name: "sput-object",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x6a,
        name: "sput-boolean",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x6b,
        name: "sput-byte",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x6c,
        name: "sput-char",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x6d,
        name: "sput-short",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x6e,
        name: "invoke-virtual",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x6f,
        name: "invoke-super",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x70,
        name: "invoke-direct",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x71,
        name: "invoke-static",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x72,
        name: "invoke-interface",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x73,
        name: "return-void-no-barrier",
        format: InstructionFormat::Format10x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x74,
        name: "invoke-virtual/range",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x75,
        name: "invoke-super/range",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x76,
        name: "invoke-direct/range",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x77,
        name: "invoke-static/range",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x78,
        name: "invoke-interface/range",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::Method,
        reference2: ReferenceType::None,
    },
    OpcodeInfo::default(),
    OpcodeInfo::default(),
    OpcodeInfo {
        opcode: 0x7b,
        name: "neg-int",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7c,
        name: "not-int",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7d,
        name: "neg-long",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7e,
        name: "not-long",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x7f,
        name: "neg-float",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x80,
        name: "neg-double",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x81,
        name: "int-to-long",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x82,
        name: "int-to-float",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x83,
        name: "int-to-double",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x84,
        name: "long-to-int",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x85,
        name: "long-to-float",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x86,
        name: "long-to-double",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x87,
        name: "float-to-int",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x88,
        name: "float-to-long",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x89,
        name: "float-to-double",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8a,
        name: "double-to-int",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8b,
        name: "double-to-long",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8c,
        name: "double-to-float",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8d,
        name: "int-to-byte",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8e,
        name: "int-to-char",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x8f,
        name: "int-to-short",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x90,
        name: "add-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x91,
        name: "sub-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x92,
        name: "mul-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x93,
        name: "div-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x94,
        name: "rem-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x95,
        name: "and-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x96,
        name: "or-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x97,
        name: "xor-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x98,
        name: "shl-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x99,
        name: "shr-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9a,
        name: "ushr-int",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9b,
        name: "add-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9c,
        name: "sub-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9d,
        name: "mul-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9e,
        name: "div-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0x9f,
        name: "rem-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa0,
        name: "and-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa1,
        name: "or-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa2,
        name: "xor-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa3,
        name: "shl-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa4,
        name: "shr-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa5,
        name: "ushr-long",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa6,
        name: "add-float",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa7,
        name: "sub-float",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa8,
        name: "mul-float",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xa9,
        name: "div-float",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xaa,
        name: "rem-float",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xab,
        name: "add-double",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xac,
        name: "sub-double",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xad,
        name: "mul-double",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xae,
        name: "div-double",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xaf,
        name: "rem-double",
        format: InstructionFormat::Format23x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb0,
        name: "add-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb1,
        name: "sub-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb2,
        name: "mul-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb3,
        name: "div-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb4,
        name: "rem-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb5,
        name: "and-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb6,
        name: "or-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb7,
        name: "xor-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb8,
        name: "shl-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xb9,
        name: "shr-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xba,
        name: "ushr-int/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbb,
        name: "add-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbc,
        name: "sub-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbd,
        name: "mul-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbe,
        name: "div-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xbf,
        name: "rem-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc0,
        name: "and-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc1,
        name: "or-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc2,
        name: "xor-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc3,
        name: "shl-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc4,
        name: "shr-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc5,
        name: "ushr-long/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc6,
        name: "add-float/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc7,
        name: "sub-float/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc8,
        name: "mul-float/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xc9,
        name: "div-float/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xca,
        name: "rem-float/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcb,
        name: "add-double/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcc,
        name: "sub-double/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcd,
        name: "mul-double/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xce,
        name: "div-double/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xcf,
        name: "rem-double/2addr",
        format: InstructionFormat::Format12x,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd0,
        name: "add-int/lit16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd1,
        name: "rsub-int",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd2,
        name: "mul-int/lit16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd3,
        name: "div-int/lit16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd4,
        name: "rem-int/lit16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd5,
        name: "and-int/lit16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd6,
        name: "or-int/lit16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd7,
        name: "xor-int/lit16",
        format: InstructionFormat::Format22s,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd8,
        name: "add-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xd9,
        name: "rsub-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xda,
        name: "mul-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdb,
        name: "div-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdc,
        name: "rem-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdd,
        name: "and-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xde,
        name: "or-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xdf,
        name: "xor-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe0,
        name: "shl-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe1,
        name: "shr-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe2,
        name: "ushr-int/lit8",
        format: InstructionFormat::Format22b,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe3,
        name: "iget-volatile",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe4,
        name: "iput-volatile",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe5,
        name: "sget-volatile",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe6,
        name: "sput-volatile",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe7,
        name: "iget-object-volatile",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe8,
        name: "iget-wide-volatile",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xe9,
        name: "iput-wide-volatile",
        format: InstructionFormat::Format22c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xea,
        name: "sget-wide-volatile",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Field,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xeb,
        name: "iput-boolean-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xec,
        name: "iput-byte-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xed,
        name: "iput-char-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xee,
        name: "iput-short-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xef,
        name: "iget-boolean-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf0,
        name: "iget-byte-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf1,
        name: "iget-char-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf2,
        name: "iget-short-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf3,
        name: "iget-wide-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf4,
        name: "iget-object-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf5,
        name: "iput-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf6,
        name: "iput-wide-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf7,
        name: "iput-object-quick",
        format: InstructionFormat::Format22cs,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf8,
        name: "invoke-virtual-quick",
        format: InstructionFormat::Format35ms,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xf9,
        name: "invoke-virtual-quick/range",
        format: InstructionFormat::Format3rms,
        reference: ReferenceType::None,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xfa,
        name: "invoke-polymorphic",
        format: InstructionFormat::Format45cc,
        reference: ReferenceType::Method,
        reference2: ReferenceType::Proto,
    },
    OpcodeInfo {
        opcode: 0xfb,
        name: "invoke-polymorphic/range",
        format: InstructionFormat::Format4rcc,
        reference: ReferenceType::Method,
        reference2: ReferenceType::Proto,
    },
    OpcodeInfo {
        opcode: 0xfc,
        name: "invoke-custom",
        format: InstructionFormat::Format35c,
        reference: ReferenceType::CallSite,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xfd,
        name: "invoke-custom/range",
        format: InstructionFormat::Format3rc,
        reference: ReferenceType::CallSite,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xfe,
        name: "const-method-handle",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::MethodHandle,
        reference2: ReferenceType::None,
    },
    OpcodeInfo {
        opcode: 0xff,
        name: "const-method-type",
        format: InstructionFormat::Format21c,
        reference: ReferenceType::Proto,
        reference2: ReferenceType::None,
    },
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

//! Parsing entry points and helpers for `.dex` binaries.

use crate::{
    error::{DexError, DexResult},
    format::{
        AccessFlags, AnnotationsDirectoryItem, CatchHandler, ClassDataItem, ClassDef, ClassIdx,
        CodeItem, DexHeader, EncodedCatchHandler, EncodedField, EncodedMethod, FieldAnnotation,
        FieldId, FieldIdx, HEADER_SIZE, MAGIC_PREFIX, MapItem, MethodAnnotation, MethodId,
        MethodIdx, ParameterAnnotation, ProtoId, ProtoIdx, StringId, StringIdx, TryItem, TypeId,
        TypeIdx,
    },
    model::DexFile,
};

/// Parses a raw `.dex` file into an in-memory [`DexFile`] model.
pub fn parse_dex<'a>(bytes: &'a [u8]) -> DexResult<DexFile<'a>> {
    if bytes.len() < HEADER_SIZE {
        return Err(DexError::BufferTooSmall {
            expected: HEADER_SIZE,
            actual: bytes.len(),
        });
    }

    let header = parse_header(bytes)?;
    if !header.is_supported() {
        return Err(DexError::UnsupportedVersion {
            version: header.version,
        });
    }

    let mut map_items = parse_map_list(bytes, &header)?;
    map_items.sort_by_key(|item| item.offset);

    let string_ids = parse_string_ids(bytes, &header)?;
    let type_ids = parse_type_ids(bytes, &header)?;
    let proto_ids = parse_proto_ids(bytes, &header)?;
    let field_ids = parse_field_ids(bytes, &header)?;
    let method_ids = parse_method_ids(bytes, &header)?;
    let class_defs = parse_class_defs(bytes, &header)?;

    let mut class_data_items = Vec::with_capacity(class_defs.len());
    let mut method_code = vec![None; method_ids.len()];
    let mut method_owner = vec![None; method_ids.len()];
    let mut method_access = vec![AccessFlags::empty(); method_ids.len()];
    let mut annotations = Vec::with_capacity(class_defs.len());

    for (idx, class_def) in class_defs.iter().enumerate() {
        let class_idx = ClassIdx::new(idx as u32);
        if class_def.class_data_off == 0 {
            class_data_items.push(None);
            annotations.push(None);
            continue;
        }

        let class_data = parse_class_data(bytes, class_def.class_data_off)?;
        let annotation_dir = if class_def.annotations_off != 0 {
            Some(parse_annotations_directory(
                bytes,
                class_def.annotations_off,
            )?)
        } else {
            None
        };
        annotations.push(annotation_dir);

        for method in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            let mi = method.method_idx.to_usize();
            method_owner[mi] = Some(class_idx);
            method_access[mi] = method.access_flags;
            if method.code_off != 0 {
                method_code[mi] = Some(parse_code_item(bytes, method.code_off)?);
            }
        }
        class_data_items.push(Some(class_data));
    }

    let link_data = if header.link_size > 0 {
        Some(slice(
            bytes,
            header.link_off,
            header.link_size as usize,
            "link_data",
        )?)
    } else {
        None
    };

    Ok(DexFile::new(
        bytes,
        header,
        string_ids,
        type_ids,
        proto_ids,
        field_ids,
        method_ids,
        class_defs,
        class_data_items,
        method_owner,
        method_access,
        method_code,
        map_items,
        annotations,
        link_data,
    ))
}

fn parse_header(bytes: &[u8]) -> DexResult<DexHeader> {
    let magic: [u8; 8] = bytes[0..8].try_into().expect("slice length known");
    if &magic[0..4] != MAGIC_PREFIX {
        return Err(DexError::InvalidMagic { magic });
    }

    let version_bytes = &magic[4..7];
    let version = std::str::from_utf8(version_bytes)
        .map_err(|_| DexError::Malformed {
            context: "dex header",
            message: "version is not ascii digits",
        })?
        .parse()
        .map_err(|_| DexError::Malformed {
            context: "dex header",
            message: "version is not numeric",
        })?;

    let header_slice = &bytes[..HEADER_SIZE];
    let mut cursor = 8;
    let checksum = read_u32_from(header_slice, &mut cursor)?;
    let signature =
        {
            let mut sig = [0u8; 20];
            sig.copy_from_slice(header_slice.get(cursor..cursor + 20).ok_or(
                DexError::Malformed {
                    context: "dex header",
                    message: "signature missing",
                },
            )?);
            cursor += 20;
            sig
        };
    let file_size = read_u32_from(header_slice, &mut cursor)?;
    let header_size = read_u32_from(header_slice, &mut cursor)?;
    let endian_tag = read_u32_from(header_slice, &mut cursor)?;
    let link_size = read_u32_from(header_slice, &mut cursor)?;
    let link_off = read_u32_from(header_slice, &mut cursor)?;
    let map_off = read_u32_from(header_slice, &mut cursor)?;
    let string_ids_size = read_u32_from(header_slice, &mut cursor)?;
    let string_ids_off = read_u32_from(header_slice, &mut cursor)?;
    let type_ids_size = read_u32_from(header_slice, &mut cursor)?;
    let type_ids_off = read_u32_from(header_slice, &mut cursor)?;
    let proto_ids_size = read_u32_from(header_slice, &mut cursor)?;
    let proto_ids_off = read_u32_from(header_slice, &mut cursor)?;
    let field_ids_size = read_u32_from(header_slice, &mut cursor)?;
    let field_ids_off = read_u32_from(header_slice, &mut cursor)?;
    let method_ids_size = read_u32_from(header_slice, &mut cursor)?;
    let method_ids_off = read_u32_from(header_slice, &mut cursor)?;
    let class_defs_size = read_u32_from(header_slice, &mut cursor)?;
    let class_defs_off = read_u32_from(header_slice, &mut cursor)?;
    let data_size = read_u32_from(header_slice, &mut cursor)?;
    let data_off = read_u32_from(header_slice, &mut cursor)?;

    Ok(DexHeader {
        magic,
        version,
        checksum,
        signature,
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    })
}

fn read_u32_from(input: &[u8], cursor: &mut usize) -> DexResult<u32> {
    let end = *cursor + 4;
    let bytes = input.get(*cursor..end).ok_or(DexError::Malformed {
        context: "dex header",
        message: "unexpected eof",
    })?;
    *cursor = end;
    Ok(u32::from_le_bytes(bytes.try_into().expect("len checked")))
}

fn slice<'a>(
    bytes: &'a [u8],
    offset: u32,
    size: usize,
    section: &'static str,
) -> DexResult<&'a [u8]> {
    let start = offset as usize;
    let end = start
        .checked_add(size)
        .ok_or(DexError::SectionOutOfBounds {
            section,
            offset: start,
            size,
        })?;
    bytes.get(start..end).ok_or(DexError::SectionOutOfBounds {
        section,
        offset: start,
        size,
    })
}

fn parse_string_ids(bytes: &[u8], header: &DexHeader) -> DexResult<Box<[StringId]>> {
    let count = header.string_ids_size as usize;
    let len = count.checked_mul(4).ok_or(DexError::Malformed {
        context: "string_ids",
        message: "size overflow",
    })?;
    let section = slice(bytes, header.string_ids_off, len, "string_ids")?;
    let mut out = Vec::with_capacity(count);
    for chunk in section.chunks_exact(4) {
        let off = u32::from_le_bytes(chunk.try_into().expect("chunk len"));
        out.push(StringId {
            string_data_off: off,
        });
    }
    Ok(out.into_boxed_slice())
}

fn parse_type_ids(bytes: &[u8], header: &DexHeader) -> DexResult<Box<[TypeId]>> {
    let count = header.type_ids_size as usize;
    let section = slice(bytes, header.type_ids_off, count * 4, "type_ids")?;
    let mut out = Vec::with_capacity(count);
    for chunk in section.chunks_exact(4) {
        let idx = u32::from_le_bytes(chunk.try_into().expect("chunk len"));
        out.push(TypeId {
            descriptor_idx: StringIdx::new(idx),
        });
    }
    Ok(out.into_boxed_slice())
}

fn parse_proto_ids(bytes: &[u8], header: &DexHeader) -> DexResult<Box<[ProtoId]>> {
    let count = header.proto_ids_size as usize;
    let section = slice(bytes, header.proto_ids_off, count * 12, "proto_ids")?;
    let mut out = Vec::with_capacity(count);
    for chunk in section.chunks_exact(12) {
        let shorty_idx = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let return_type_idx = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let parameters_off = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        out.push(ProtoId {
            shorty_idx: StringIdx::new(shorty_idx),
            return_type_idx: TypeIdx::new(return_type_idx),
            parameters_off,
        });
    }
    Ok(out.into_boxed_slice())
}

fn parse_field_ids(bytes: &[u8], header: &DexHeader) -> DexResult<Box<[FieldId]>> {
    let count = header.field_ids_size as usize;
    let section = slice(bytes, header.field_ids_off, count * 8, "field_ids")?;
    let mut out = Vec::with_capacity(count);
    for chunk in section.chunks_exact(8) {
        let class_idx = u16::from_le_bytes(chunk[0..2].try_into().unwrap()) as u32;
        let type_idx = u16::from_le_bytes(chunk[2..4].try_into().unwrap()) as u32;
        let name_idx = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        out.push(FieldId {
            class_idx: TypeIdx::new(class_idx),
            type_idx: TypeIdx::new(type_idx),
            name_idx: StringIdx::new(name_idx),
        });
    }
    Ok(out.into_boxed_slice())
}

fn parse_method_ids(bytes: &[u8], header: &DexHeader) -> DexResult<Box<[MethodId]>> {
    let count = header.method_ids_size as usize;
    let section = slice(bytes, header.method_ids_off, count * 8, "method_ids")?;
    let mut out = Vec::with_capacity(count);
    for chunk in section.chunks_exact(8) {
        let class_idx = u16::from_le_bytes(chunk[0..2].try_into().unwrap()) as u32;
        let proto_idx = u16::from_le_bytes(chunk[2..4].try_into().unwrap()) as u32;
        let name_idx = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        out.push(MethodId {
            class_idx: TypeIdx::new(class_idx),
            proto_idx: ProtoIdx::new(proto_idx),
            name_idx: StringIdx::new(name_idx),
        });
    }
    Ok(out.into_boxed_slice())
}

fn parse_class_defs(bytes: &[u8], header: &DexHeader) -> DexResult<Box<[ClassDef]>> {
    let count = header.class_defs_size as usize;
    let section = slice(bytes, header.class_defs_off, count * 32, "class_defs")?;
    let mut out = Vec::with_capacity(count);
    for chunk in section.chunks_exact(32) {
        let class_idx = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let access_flags = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let super_class_idx = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let interfaces_off = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        let source_file_idx = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
        let annotations_off = u32::from_le_bytes(chunk[20..24].try_into().unwrap());
        let class_data_off = u32::from_le_bytes(chunk[24..28].try_into().unwrap());
        let static_values_off = u32::from_le_bytes(chunk[28..32].try_into().unwrap());

        out.push(ClassDef {
            class_idx: TypeIdx::new(class_idx),
            access_flags: AccessFlags::from_bits_truncate(access_flags),
            super_class_idx: if super_class_idx == u32::MAX {
                None
            } else {
                Some(TypeIdx::new(super_class_idx))
            },
            interfaces_off,
            source_file_idx: if source_file_idx == u32::MAX {
                None
            } else {
                Some(StringIdx::new(source_file_idx))
            },
            annotations_off,
            class_data_off,
            static_values_off,
        });
    }
    Ok(out.into_boxed_slice())
}

fn parse_class_data(bytes: &[u8], offset: u32) -> DexResult<ClassDataItem> {
    let mut cursor = offset as usize;
    let (static_fields_size, used) = read_uleb128(&bytes[cursor..], "class_data")?;
    cursor += used;
    let (instance_fields_size, used) = read_uleb128(&bytes[cursor..], "class_data")?;
    cursor += used;
    let (direct_methods_size, used) = read_uleb128(&bytes[cursor..], "class_data")?;
    cursor += used;
    let (virtual_methods_size, used) = read_uleb128(&bytes[cursor..], "class_data")?;
    cursor += used;

    let mut static_fields = parse_encoded_fields(bytes, &mut cursor, static_fields_size)?;
    let mut instance_fields = parse_encoded_fields(bytes, &mut cursor, instance_fields_size)?;
    let mut direct_methods = parse_encoded_methods(bytes, &mut cursor, direct_methods_size)?;
    let mut virtual_methods = parse_encoded_methods(bytes, &mut cursor, virtual_methods_size)?;

    static_fields.shrink_to_fit();
    instance_fields.shrink_to_fit();
    direct_methods.shrink_to_fit();
    virtual_methods.shrink_to_fit();

    Ok(ClassDataItem {
        static_fields,
        instance_fields,
        direct_methods,
        virtual_methods,
    })
}

fn parse_encoded_fields(
    bytes: &[u8],
    cursor: &mut usize,
    count: u32,
) -> DexResult<Vec<EncodedField>> {
    let mut out = Vec::with_capacity(count as usize);
    let mut running = 0u32;
    for _ in 0..count {
        let (field_idx_diff, used) = read_uleb128(&bytes[*cursor..], "encoded_field")?;
        *cursor += used;
        let (access_flags, used) = read_uleb128(&bytes[*cursor..], "encoded_field")?;
        *cursor += used;
        running = running
            .checked_add(field_idx_diff)
            .ok_or(DexError::Malformed {
                context: "encoded_field",
                message: "field index overflow",
            })?;
        out.push(EncodedField {
            field_idx: FieldIdx::new(running),
            access_flags: AccessFlags::from_bits_truncate(access_flags),
        });
    }
    Ok(out)
}

fn parse_encoded_methods(
    bytes: &[u8],
    cursor: &mut usize,
    count: u32,
) -> DexResult<Vec<EncodedMethod>> {
    let mut out = Vec::with_capacity(count as usize);
    let mut running = 0u32;
    for _ in 0..count {
        let (method_idx_diff, used) = read_uleb128(&bytes[*cursor..], "encoded_method")?;
        *cursor += used;
        let (access_flags, used) = read_uleb128(&bytes[*cursor..], "encoded_method")?;
        *cursor += used;
        let (code_off, used) = read_uleb128(&bytes[*cursor..], "encoded_method")?;
        *cursor += used;
        running = running
            .checked_add(method_idx_diff)
            .ok_or(DexError::Malformed {
                context: "encoded_method",
                message: "method index overflow",
            })?;
        out.push(EncodedMethod {
            method_idx: MethodIdx::new(running),
            access_flags: AccessFlags::from_bits_truncate(access_flags),
            code_off,
        });
    }
    Ok(out)
}

fn parse_code_item<'a>(bytes: &'a [u8], offset: u32) -> DexResult<CodeItem<'a>> {
    let mut cursor = offset as usize;
    let registers_size = read_u16(bytes, &mut cursor)?;
    let ins_size = read_u16(bytes, &mut cursor)?;
    let outs_size = read_u16(bytes, &mut cursor)?;
    let tries_size = read_u16(bytes, &mut cursor)?;
    let debug_info_off = read_u32(bytes, &mut cursor)?;
    let insns_size = read_u32(bytes, &mut cursor)?;

    let insns_byte_len = (insns_size as usize)
        .checked_mul(2)
        .ok_or(DexError::Malformed {
            context: "code_item",
            message: "insns_size overflow",
        })?;
    let cursor_u32 = u32::try_from(cursor).map_err(|_| DexError::SectionOutOfBounds {
        section: "code_item",
        offset: cursor,
        size: insns_byte_len,
    })?;
    let insns = slice(bytes, cursor_u32, insns_byte_len, "code_item")?;
    cursor += insns_byte_len;

    let padding = if tries_size > 0 && insns_size % 2 != 0 {
        2
    } else {
        0
    };
    cursor += padding as usize;

    let mut tries = Vec::with_capacity(tries_size as usize);
    for _ in 0..tries_size {
        let start_addr = read_u32(bytes, &mut cursor)?;
        let insn_count = read_u16(bytes, &mut cursor)?;
        let handler_off = read_u16(bytes, &mut cursor)?;
        tries.push(TryItem {
            start_addr,
            insn_count,
            handler_off,
        });
    }

    let mut handlers = Vec::new();
    let mut handler_offsets = Vec::new();
    if tries_size > 0 {
        let (handler_count, used) = read_uleb128(&bytes[cursor..], "encoded_catch_handler_list")?;
        cursor += used;
        let handlers_base = cursor;
        for _ in 0..handler_count {
            let relative = (cursor - handlers_base) as u32;
            handlers.push(parse_catch_handler(bytes, &mut cursor)?);
            handler_offsets.push(relative);
        }
    }

    Ok(CodeItem {
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns_size,
        insns,
        tries,
        handlers,
        handler_offsets,
    })
}

fn parse_catch_handler(bytes: &[u8], cursor: &mut usize) -> DexResult<EncodedCatchHandler> {
    let (size_raw, used) = read_sleb128(&bytes[*cursor..], "encoded_catch_handler")?;
    *cursor += used;
    let has_catch_all = size_raw <= 0;
    let handler_count = if has_catch_all {
        size_raw.unsigned_abs()
    } else {
        size_raw as u32
    };

    let mut handlers = Vec::with_capacity(handler_count as usize);
    for _ in 0..handler_count {
        let (type_idx, used) = read_uleb128(&bytes[*cursor..], "encoded_type_addr_pair")?;
        *cursor += used;
        let (addr, used) = read_uleb128(&bytes[*cursor..], "encoded_type_addr_pair")?;
        *cursor += used;
        handlers.push(CatchHandler {
            type_idx: TypeIdx::new(type_idx),
            addr,
        });
    }

    let catch_all_addr = if has_catch_all {
        let (addr, used) = read_uleb128(&bytes[*cursor..], "encoded_catch_handler")?;
        *cursor += used;
        Some(addr)
    } else {
        None
    };

    Ok(EncodedCatchHandler {
        handlers,
        catch_all_addr,
    })
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> DexResult<u16> {
    let end = *cursor + 2;
    let chunk = bytes
        .get(*cursor..end)
        .ok_or(DexError::SectionOutOfBounds {
            section: "code_item",
            offset: *cursor,
            size: 2,
        })?;
    *cursor = end;
    Ok(u16::from_le_bytes(chunk.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> DexResult<u32> {
    let end = *cursor + 4;
    let chunk = bytes
        .get(*cursor..end)
        .ok_or(DexError::SectionOutOfBounds {
            section: "code_item",
            offset: *cursor,
            size: 4,
        })?;
    *cursor = end;
    Ok(u32::from_le_bytes(chunk.try_into().unwrap()))
}

/// Reads an unsigned LEB128 value, returning the parsed value and number of bytes consumed.
pub(crate) fn read_uleb128(input: &[u8], context: &'static str) -> DexResult<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for (i, byte) in input.iter().enumerate() {
        let value = u32::from(byte & 0x7F);
        result |= value << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift >= 35 {
            return Err(DexError::Leb128 { context });
        }
    }
    Err(DexError::Leb128 { context })
}

/// Reads a signed LEB128 value.
pub(crate) fn read_sleb128(input: &[u8], context: &'static str) -> DexResult<(i32, usize)> {
    let mut result = 0i32;
    let mut shift = 0u32;
    let mut byte_count = 0usize;
    let mut byte;
    loop {
        if byte_count >= input.len() {
            return Err(DexError::Leb128 { context });
        }
        byte = input[byte_count];
        byte_count += 1;
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
    }
    if (shift < 32) && ((byte & 0x40) != 0) {
        result |= !0 << shift;
    }
    Ok((result, byte_count))
}

fn parse_map_list(bytes: &[u8], header: &DexHeader) -> DexResult<Vec<MapItem>> {
    if header.map_off == 0 {
        return Ok(Vec::new());
    }
    let mut cursor = header.map_off as usize;
    let size = read_u32(bytes, &mut cursor)? as usize;
    let mut items = Vec::with_capacity(size);
    for _ in 0..size {
        let type_code = read_u16(bytes, &mut cursor)?;
        cursor += 2; // unused field
        let section_size = read_u32(bytes, &mut cursor)?;
        let offset = read_u32(bytes, &mut cursor)?;
        items.push(MapItem {
            type_code,
            size: section_size,
            offset,
        });
    }
    Ok(items)
}

fn parse_annotations_directory(bytes: &[u8], offset: u32) -> DexResult<AnnotationsDirectoryItem> {
    let mut cursor = offset as usize;
    let class_off = read_u32(bytes, &mut cursor)?;
    let fields_size = read_u32(bytes, &mut cursor)? as usize;
    let methods_size = read_u32(bytes, &mut cursor)? as usize;
    let params_size = read_u32(bytes, &mut cursor)? as usize;

    let mut field_annotations = Vec::with_capacity(fields_size);
    for _ in 0..fields_size {
        let field_idx = read_u32(bytes, &mut cursor)?;
        let annotations_offset = read_u32(bytes, &mut cursor)?;
        field_annotations.push(FieldAnnotation {
            field_idx: FieldIdx::new(field_idx),
            annotations_offset,
        });
    }

    let mut method_annotations = Vec::with_capacity(methods_size);
    for _ in 0..methods_size {
        let method_idx = read_u32(bytes, &mut cursor)?;
        let annotations_offset = read_u32(bytes, &mut cursor)?;
        method_annotations.push(MethodAnnotation {
            method_idx: MethodIdx::new(method_idx),
            annotations_offset,
        });
    }

    let mut parameter_annotations = Vec::with_capacity(params_size);
    for _ in 0..params_size {
        let method_idx = read_u32(bytes, &mut cursor)?;
        let annotations_offset = read_u32(bytes, &mut cursor)?;
        parameter_annotations.push(ParameterAnnotation {
            method_idx: MethodIdx::new(method_idx),
            annotations_offset,
        });
    }

    Ok(AnnotationsDirectoryItem {
        class_annotations_off: (class_off != 0).then_some(class_off),
        field_annotations,
        method_annotations,
        parameter_annotations,
    })
}

#[cfg(test)]
mod tests {
    use super::{read_sleb128, read_uleb128};

    fn encode_uleb(value: u32) -> Vec<u8> {
        let mut remaining = value;
        let mut encoded = Vec::new();
        loop {
            let mut byte = (remaining & 0x7F) as u8;
            remaining >>= 7;
            if remaining != 0 {
                byte |= 0x80;
            }
            encoded.push(byte);
            if remaining == 0 {
                break;
            }
        }
        encoded
    }

    fn encode_sleb(value: i32) -> Vec<u8> {
        let mut remaining = value as i64;
        let mut encoded = Vec::new();
        loop {
            let byte = (remaining & 0x7F) as u8;
            remaining >>= 7;
            let done =
                (remaining == 0 && (byte & 0x40) == 0) || (remaining == -1 && (byte & 0x40) != 0);
            encoded.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
        encoded
    }

    #[test]
    fn leb128_round_trip() {
        let values = [0u32, 1, 0x7F, 0x80, 0x1234, 0xFFFF, 0x1FFFFF, u32::MAX / 2];
        for value in values {
            let bytes = encode_uleb(value);
            let (decoded, used) = read_uleb128(&bytes, "test").expect("decode");
            assert_eq!(decoded, value);
            assert_eq!(used, bytes.len());
        }
    }

    #[test]
    fn sleb128_round_trip() {
        let values = [
            0i32,
            -1,
            1,
            -64,
            64,
            -12345,
            12345,
            i32::MAX >> 1,
            i32::MIN >> 1,
        ];
        for value in values {
            let bytes = encode_sleb(value);
            let (decoded, used) = read_sleb128(&bytes, "test").expect("decode");
            assert_eq!(decoded, value);
            assert_eq!(used, bytes.len());
        }
    }
}

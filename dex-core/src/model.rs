//! High-level, consumer-friendly DEX abstractions.

use std::borrow::Cow;

use once_cell::unsync::OnceCell;

use crate::{
    bytecode::{decode_instructions_internal, Instruction},
    error::{DexError, DexResult},
    format::{
        AccessFlags, ClassDataItem, ClassDef, ClassIdx, CodeItem, FieldId, MethodId, MethodIdx,
        ProtoId, ProtoIdx, StringId, StringIdx, TypeId, TypeIdx, DexHeader,
    },
};

/// Central data structure representing a parsed `.dex` file.
pub struct DexFile<'a> {
    pub(crate) data: &'a [u8],
    header: DexHeader,
    string_ids: Box<[StringId]>,
    type_ids: Box<[TypeId]>,
    proto_ids: Box<[ProtoId]>,
    field_ids: Box<[FieldId]>,
    method_ids: Box<[MethodId]>,
    class_defs: Box<[ClassDef]>,
    class_data: Vec<Option<ClassDataItem>>,
    method_owner: Vec<Option<ClassIdx>>,
    method_access: Vec<AccessFlags>,
    method_code: Vec<Option<CodeItem<'a>>>,
    string_cache: Vec<OnceCell<String>>,
}

impl<'a> DexFile<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        data: &'a [u8],
        header: DexHeader,
        string_ids: Box<[StringId]>,
        type_ids: Box<[TypeId]>,
        proto_ids: Box<[ProtoId]>,
        field_ids: Box<[FieldId]>,
        method_ids: Box<[MethodId]>,
        class_defs: Box<[ClassDef]>,
        class_data: Vec<Option<ClassDataItem>>,
        method_owner: Vec<Option<ClassIdx>>,
        method_access: Vec<AccessFlags>,
        method_code: Vec<Option<CodeItem<'a>>>,
    ) -> Self {
        let string_cache = vec![OnceCell::new(); string_ids.len()];
        Self {
            data,
            header,
            string_ids,
            type_ids,
            proto_ids,
            field_ids,
            method_ids,
            class_defs,
            class_data,
            method_owner,
            method_access,
            method_code,
            string_cache,
        }
    }

    /// Returns the parsed header.
    #[must_use]
    pub fn header(&self) -> &DexHeader {
        &self.header
    }

    /// Returns all strings as an iterator.
    pub fn strings(&'a self) -> Strings<'a> {
        Strings {
            dex: self,
            index: 0,
        }
    }

    /// Returns a resolved string, or `None` if the index is invalid.
    pub fn string(&'a self, idx: StringIdx) -> Option<&'a str> {
        self.try_string(idx).ok()
    }

    /// Resolves a string index, returning a detailed error on failure.
    pub fn try_string(&'a self, idx: StringIdx) -> DexResult<&'a str> {
        let raw_idx = idx.to_usize();
        let cache = self
            .string_cache
            .get(raw_idx)
            .ok_or(DexError::InvalidIndex {
                table: "string_ids",
                index: idx.raw(),
            })?;
        let string_ref = cache.get_or_try_init(|| self.decode_string(idx))?;
        Ok(string_ref.as_str())
    }

    fn decode_string(&self, idx: StringIdx) -> DexResult<String> {
        let id = self
            .string_ids
            .get(idx.to_usize())
            .ok_or(DexError::InvalidIndex {
                table: "string_ids",
                index: idx.raw(),
            })?;
        let offset = id.string_data_off as usize;
        let tail = self.data.get(offset..).ok_or(DexError::SectionOutOfBounds {
            section: "string_data_item",
            offset,
            size: 1,
        })?;
        let (len, used) = crate::parser::read_uleb128(tail, "string_data_item")?;
        let data = &tail[used..];
        let terminator = data
            .iter()
            .position(|b| *b == 0)
            .ok_or(DexError::Mutf8 {
                offset: id.string_data_off,
            })?;
        let payload = &data[..terminator];
        if payload.len() < len as usize {
            return Err(DexError::Malformed {
                context: "string_data_item",
                message: "declared length larger than payload",
            });
        }
        let cow = simd_cesu8::mutf8::decode(payload).map_err(|_| DexError::Mutf8 {
            offset: id.string_data_off,
        })?;
        Ok(match cow {
            Cow::Borrowed(s) => s.to_owned(),
            Cow::Owned(s) => s,
        })
    }

    /// Resolves a type descriptor string.
    pub fn type_descriptor(&'a self, idx: TypeIdx) -> Option<&'a str> {
        let type_id = self.type_ids.get(idx.to_usize())?;
        self.string(type_id.descriptor_idx)
    }

    /// Returns the raw [`MethodId`] for the provided index.
    pub fn method_id(&self, idx: MethodIdx) -> Option<&MethodId> {
        self.method_ids.get(idx.to_usize())
    }

    /// Returns the [`ProtoId`] for the provided index.
    pub fn proto_id(&self, idx: ProtoIdx) -> Option<&ProtoId> {
        self.proto_ids.get(idx.to_usize())
    }

    /// Returns the [`FieldId`] for the provided index.
    pub fn field_id(&self, idx: crate::format::FieldIdx) -> Option<&FieldId> {
        self.field_ids.get(idx.to_usize())
    }

    /// Returns all classes as an iterator.
    pub fn classes(&'a self) -> Classes<'a> {
        Classes {
            dex: self,
            index: 0,
        }
    }

    /// Returns a specific class handle.
    pub fn class(&'a self, idx: ClassIdx) -> Option<ClassHandle<'a>> {
        self.class_defs.get(idx.to_usize())?;
        Some(ClassHandle { dex: self, idx })
    }

    /// Returns a class handle by descriptor, if present.
    pub fn get_class(&'a self, descriptor: &str) -> Option<ClassHandle<'a>> {
        self.classes()
            .find(|class| class.descriptor().map(|d| d == descriptor).unwrap_or(false))
    }

    /// Returns a method handle by descriptor string, e.g. `Lpkg/Foo;->bar()V`.
    pub fn get_method(&'a self, descriptor: &str) -> Option<MethodHandle<'a>> {
        let (class_desc, rest) = descriptor.split_once("->")?;
        let (name, proto) = rest.split_once('(')?;
        let shorty = compute_shorty(&format!("({}", proto))?;
        self.method_ids.iter().enumerate().find_map(|(idx, method)| {
            let type_desc = self.type_descriptor(method.class_idx)?;
            if type_desc != class_desc {
                return None;
            }
            let name_str = self.string(method.name_idx).ok()?;
            if name_str != name {
                return None;
            }
            let proto_id = self.proto_id(method.proto_idx)?;
            let stored_shorty = self.string(proto_id.shorty_idx).ok()?;
            if stored_shorty != shorty {
                return None;
            }
            Some(MethodHandle {
                dex: self,
                idx: MethodIdx::new(idx as u32),
            })
        })
    }

    /// Returns a handle for a method index.
    pub fn method(&'a self, idx: MethodIdx) -> Option<MethodHandle<'a>> {
        self.method_ids.get(idx.to_usize())?;
        Some(MethodHandle { dex: self, idx })
    }

    /// Returns the class definitions iterator.
    pub fn class_defs(&self) -> impl ExactSizeIterator<Item = &ClassDef> {
        self.class_defs.iter()
    }

    /// Returns the data backing a class.
    pub(crate) fn class_data(&self, class_idx: ClassIdx) -> Option<&ClassDataItem> {
        self.class_data
            .get(class_idx.to_usize())
            .and_then(|entry| entry.as_ref())
    }

    /// Returns the owning class of a method.
    pub fn method_owner(&self, idx: MethodIdx) -> Option<ClassHandle<'a>> {
        let class_idx = self.method_owner.get(idx.to_usize())?.as_ref()?;
        self.class(*class_idx)
    }

    /// Returns a parsed [`CodeItem`] for the given method, if any.
    pub fn code_item(&self, idx: MethodIdx) -> Option<&CodeItem<'a>> {
        self.method_code.get(idx.to_usize())?.as_ref()
    }

    /// Returns the access flags for the given method.
    pub fn method_access_flags(&self, idx: MethodIdx) -> Option<AccessFlags> {
        self.method_access.get(idx.to_usize()).copied()
    }

    /// Decodes the bytecode stream for a method.
    pub fn decode_instructions(&self, method: MethodIdx) -> DexResult<Vec<Instruction>> {
        decode_instructions_internal(self, method)
    }
}

/// Iterator over all strings in a `DexFile`.
pub struct Strings<'a> {
    dex: &'a DexFile<'a>,
    index: usize,
}

impl<'a> Iterator for Strings<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.dex.string_ids.len() {
            return None;
        }
        let idx = StringIdx::new(self.index as u32);
        self.index += 1;
        Some(
            self.dex
                .try_string(idx)
                .unwrap_or_else(|err| panic!("invalid string entry: {err}")),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.dex.string_ids.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Strings<'a> {}

/// Iterator over classes.
pub struct Classes<'a> {
    dex: &'a DexFile<'a>,
    index: usize,
}

impl<'a> Iterator for Classes<'a> {
    type Item = ClassHandle<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.dex.class_defs.len() {
            return None;
        }
        let handle = ClassHandle {
            dex: self.dex,
            idx: ClassIdx::new(self.index as u32),
        };
        self.index += 1;
        Some(handle)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.dex.class_defs.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Classes<'a> {}

/// Handle to a class definition.
pub struct ClassHandle<'a> {
    dex: &'a DexFile<'a>,
    idx: ClassIdx,
}

impl<'a> ClassHandle<'a> {
    /// Returns the underlying [`ClassIdx`].
    pub fn index(&self) -> ClassIdx {
        self.idx
    }

    /// Returns the raw [`ClassDef`].
    pub fn def(&self) -> &'a ClassDef {
        &self.dex.class_defs[self.idx.to_usize()]
    }

    /// Returns the descriptor string for this class.
    pub fn descriptor(&self) -> DexResult<&'a str> {
        self.dex
            .type_descriptor(self.def().class_idx)
            .ok_or(DexError::Malformed {
                context: "class_def",
                message: "descriptor missing",
            })
    }

    /// Returns the super class descriptor (if any).
    pub fn super_class(&self) -> Option<&'a str> {
        self.def()
            .super_class_idx
            .and_then(|idx| self.dex.type_descriptor(idx))
    }

    /// Returns all encoded methods for this class.
    pub fn methods(&self) -> Option<Vec<MethodHandle<'a>>> {
        let data = self.dex.class_data(self.idx)?;
        let mut handles = Vec::with_capacity(
            data.direct_methods.len() + data.virtual_methods.len(),
        );
        for method in data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
        {
            handles.push(MethodHandle {
                dex: self.dex,
                idx: method.method_idx,
            });
        }
        Some(handles)
    }
}

/// Handle to a method definition.
pub struct MethodHandle<'a> {
    dex: &'a DexFile<'a>,
    idx: MethodIdx,
}

impl<'a> MethodHandle<'a> {
    /// Returns the index.
    pub fn index(&self) -> MethodIdx {
        self.idx
    }

    /// Returns the raw [`MethodId`].
    pub fn id(&self) -> &'a MethodId {
        &self.dex.method_ids[self.idx.to_usize()]
    }

    /// Returns the defining class.
    pub fn class(&self) -> Option<ClassHandle<'a>> {
        self.dex.method_owner(self.idx)
    }

    /// Returns the name of the method.
    pub fn name(&self) -> DexResult<&'a str> {
        self.dex
            .string(self.id().name_idx)
            .ok_or(DexError::Malformed {
                context: "method_id",
                message: "name missing",
            })
    }

    /// Returns the prototype descriptor.
    pub fn prototype(&self) -> DexResult<&'a ProtoId> {
        self.dex
            .proto_id(self.id().proto_idx)
            .ok_or(DexError::Malformed {
                context: "proto_id",
                message: "missing",
            })
    }

    /// Returns the code item if present.
    pub fn code_item(&self) -> Option<&'a CodeItem<'a>> {
        self.dex.code_item(self.idx)
    }

    /// Decodes bytecode instructions for this method.
    pub fn instructions(&self) -> DexResult<Vec<Instruction>> {
        self.dex.decode_instructions(self.idx)
    }
}

fn compute_shorty(proto: &str) -> Option<String> {
    let mut chars = proto.chars();
    if chars.next()? != '(' {
        return None;
    }
    let mut shorty = String::new();
    let mut nesting = 0usize;
    for ch in chars.by_ref() {
        if ch == ')' {
            break;
        }
        match ch {
            '[' => {
                nesting += 1;
            }
            'L' => {
                shorty.push('L');
                // skip until ';'
                while let Some(next) = chars.next() {
                    if next == ';' {
                        break;
                    }
                }
                nesting = 0;
            }
            _ => {
                shorty.push(ch);
                nesting = 0;
            }
        }
    }

    if let Some(ret) = chars.next() {
        match ret {
            'L' => shorty.push('L'),
            '[' => shorty.push('L'),
            other => shorty.push(other),
        }
    }
    Some(shorty)
}

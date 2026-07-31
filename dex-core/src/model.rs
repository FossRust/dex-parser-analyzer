//! High-level, consumer-friendly DEX abstractions.

use std::{borrow::Cow, collections::BTreeMap};

use once_cell::unsync::OnceCell;

use crate::{
    bytecode::{Instruction, decode_instructions_internal},
    error::{DexError, DexResult},
    format::{
        AccessFlags, AnnotationItem, AnnotationSetItem, AnnotationSetRefList,
        AnnotationsDirectoryItem, CallSiteIdItem, ClassDataItem, ClassDef, ClassIdx, CodeItem,
        DexHeader, EncodedArrayItem, FieldId, MapItem, MethodHandleItem, MethodId, MethodIdx,
        ProtoId, ProtoIdx, StringId, StringIdx, TypeId, TypeIdx, TypeList,
    },
};

/// Central data structure representing a parsed `.dex` file.
///
/// `DexFile` keeps a reference to the original byte buffer and exposes
/// higher-level handles for strings, types, classes, and methods. All lookups
/// are zero-copy and indexed via the strong newtypes defined in `format`.
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
    map_items: Box<[MapItem]>,
    annotations: Vec<Option<AnnotationsDirectoryItem>>,
    link_data: Option<&'a [u8]>,
    data_end: usize,
    type_lists: BTreeMap<u32, TypeList>,
    annotation_set_ref_lists: BTreeMap<u32, AnnotationSetRefList>,
    annotation_sets: BTreeMap<u32, AnnotationSetItem>,
    annotation_items: BTreeMap<u32, AnnotationItem<'a>>,
    encoded_arrays: BTreeMap<u32, EncodedArrayItem<'a>>,
    call_site_ids: Vec<CallSiteIdItem>,
    method_handles: Vec<MethodHandleItem>,
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
        map_items: Vec<MapItem>,
        annotations: Vec<Option<AnnotationsDirectoryItem>>,
        link_data: Option<&'a [u8]>,
        type_lists: BTreeMap<u32, TypeList>,
        annotation_set_ref_lists: BTreeMap<u32, AnnotationSetRefList>,
        annotation_sets: BTreeMap<u32, AnnotationSetItem>,
        annotation_items: BTreeMap<u32, AnnotationItem<'a>>,
        encoded_arrays: BTreeMap<u32, EncodedArrayItem<'a>>,
        call_site_ids: Vec<CallSiteIdItem>,
        method_handles: Vec<MethodHandleItem>,
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
            map_items: map_items.into_boxed_slice(),
            annotations,
            link_data,
            data_end: (header.data_off + header.data_size) as usize,
            type_lists,
            annotation_set_ref_lists,
            annotation_sets,
            annotation_items,
            encoded_arrays,
            call_site_ids,
            method_handles,
        }
    }

    /// Returns the parsed header.
    #[must_use]
    pub fn header(&self) -> &DexHeader {
        &self.header
    }

    /// Returns the parsed `map_list` entries.
    ///
    /// Each [`MapItem`](crate::format::MapItem) describes a contiguous region of
    /// the file and is often used to discover optional tables such as call sites
    /// or hidden API metadata. Use this alongside [`section_bytes`](Self::section_bytes)
    /// to read raw sections that do not yet have high-level helpers.
    ///
    /// ```
    /// # use dex_core::{parse_dex, DexError};
    /// # fn dump_sections(data: &[u8]) -> Result<(), DexError> {
    /// let dex = parse_dex(data)?;
    /// for item in dex.map_items() {
    ///     println!("type=0x{:04x} count={}", item.type_code, item.size);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn map_items(&self) -> &[MapItem] {
        &self.map_items
    }

    /// Returns the optional link data section, if present.
    ///
    /// Link data bundles odex/ART relocation metadata and is kept as a raw slice
    /// so higher layers can deserialize toolchain-specific structures.
    pub fn link_data(&self) -> Option<&'a [u8]> {
        self.link_data
    }

    /// Returns the annotations directory for the given class.
    ///
    /// The resulting [`AnnotationsDirectoryItem`](crate::format::AnnotationsDirectoryItem)
    /// contains offsets into the annotations section. Use those offsets with
    /// [`section_bytes`](Self::section_bytes) to fetch the encoded values when
    /// you want to interpret annotations yourself.
    pub fn annotations_directory(&self, idx: ClassIdx) -> Option<&AnnotationsDirectoryItem> {
        self.annotations.get(idx.to_usize())?.as_ref()
    }

    /// Returns a raw slice covering the section identified by the map type.
    ///
    /// This is useful for optional sections such as annotation sets or
    /// vendor-specific payloads where `dex-core` intentionally stays hands-off.
    /// The slice is derived from the original buffer and therefore inherits the
    /// lifetime of `self`.
    ///
    /// ```
    /// # use dex_core::format::MAP_TYPE_CLASS_DATA_ITEM;
    /// # fn inspect_class_data(dex: &dex_core::DexFile<'_>) {
    /// if let Some(bytes) = dex.section_bytes(MAP_TYPE_CLASS_DATA_ITEM) {
    ///     println!("class_data section size: {}", bytes.len());
    /// }
    /// # }
    /// ```
    pub fn section_bytes(&self, type_code: u16) -> Option<&'a [u8]> {
        let entry = self
            .map_items
            .iter()
            .filter(|item| item.type_code == type_code && item.offset != 0)
            .min_by_key(|item| item.offset)?;
        let start = entry.offset as usize;
        let next_offset = self
            .map_items
            .iter()
            .filter(|item| item.offset as usize > start)
            .map(|item| item.offset as usize)
            .min()
            .unwrap_or(self.data_end);
        if next_offset <= start || next_offset > self.data.len() {
            return None;
        }
        self.data.get(start..next_offset)
    }

    /// Returns all strings as an iterator.
    ///
    /// The iterator lazily decodes each entry and therefore doubles as a
    /// low-cost validation pass that ensures all strings can be materialized.
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

    /// Total number of strings in this dex.
    pub fn string_count(&self) -> usize {
        self.string_ids.len()
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
        let tail = self
            .data
            .get(offset..)
            .ok_or(DexError::SectionOutOfBounds {
                section: "string_data_item",
                offset,
                size: 1,
            })?;
        let (len, used) = crate::parser::read_uleb128(tail, "string_data_item")?;
        let data = &tail[used..];
        let terminator = data.iter().position(|b| *b == 0).ok_or(DexError::Mutf8 {
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

    /// Number of methods in the file.
    pub fn method_count(&self) -> usize {
        self.method_ids.len()
    }

    /// Returns the number of declared types.
    pub fn type_count(&self) -> usize {
        self.type_ids.len()
    }

    /// Returns the [`ProtoId`] for the provided index.
    pub fn proto_id(&self, idx: ProtoIdx) -> Option<&ProtoId> {
        self.proto_ids.get(idx.to_usize())
    }

    /// Number of prototype descriptors.
    pub fn proto_count(&self) -> usize {
        self.proto_ids.len()
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
        self.method_ids
            .iter()
            .enumerate()
            .find_map(|(idx, method)| {
                let type_desc = self.type_descriptor(method.class_idx)?;
                if type_desc != class_desc {
                    return None;
                }
                let name_str = self.string(method.name_idx)?;
                if name_str != name {
                    return None;
                }
                let proto_id = self.proto_id(method.proto_idx)?;
                let stored_shorty = self.string(proto_id.shorty_idx)?;
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
    pub fn method_owner(&'a self, idx: MethodIdx) -> Option<ClassHandle<'a>> {
        let class_idx = *self.method_owner.get(idx.to_usize())?.as_ref()?;
        self.class(class_idx)
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

    /// Returns the parsed [`TypeList`] at the given file offset.
    pub fn type_list(&self, offset: u32) -> Option<&TypeList> {
        self.type_lists.get(&offset)
    }

    /// Returns the parsed [`AnnotationSetRefList`] at the given file offset.
    pub fn annotation_set_ref_list(&self, offset: u32) -> Option<&AnnotationSetRefList> {
        self.annotation_set_ref_lists.get(&offset)
    }

    /// Returns the parsed [`AnnotationSetItem`] at the given file offset.
    pub fn annotation_set(&self, offset: u32) -> Option<&AnnotationSetItem> {
        self.annotation_sets.get(&offset)
    }

    /// Returns the [`AnnotationItem`] located at `offset`.
    pub fn annotation_item(&self, offset: u32) -> Option<&AnnotationItem<'a>> {
        self.annotation_items.get(&offset)
    }

    /// Returns the [`EncodedArrayItem`] located at `offset`.
    pub fn encoded_array(&self, offset: u32) -> Option<&EncodedArrayItem<'a>> {
        self.encoded_arrays.get(&offset)
    }

    /// Returns the table of call-site identifiers.
    pub fn call_site_ids(&self) -> &[CallSiteIdItem] {
        &self.call_site_ids
    }

    /// Returns the table of method handles.
    pub fn method_handles(&self) -> &[MethodHandleItem] {
        &self.method_handles
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
                .unwrap_or("\u{FFFD}"),
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
        let mut handles =
            Vec::with_capacity(data.direct_methods.len() + data.virtual_methods.len());
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
    while let Some(ch) = chars.next() {
        if ch == ')' {
            break;
        }
        match ch {
            '[' => continue,
            'L' => {
                shorty.push('L');
                while let Some(next) = chars.next() {
                    if next == ';' {
                        break;
                    }
                }
            }
            other => shorty.push(other),
        }
    }

    if let Some(ret) = chars.next() {
        match ret {
            'L' | '[' => shorty.push('L'),
            other => shorty.push(other),
        }
    }
    Some(shorty)
}

//! Low-level DEX data structures that closely mirror the on-disk layout.

use serde::{Deserialize, Serialize};

/// Size in bytes of the DEX header.
pub const HEADER_SIZE: usize = 0x70;

/// Known header magic prefix (`dex\n`).
pub const MAGIC_PREFIX: &[u8; 4] = b"dex\n";

/// Known versions supported by this crate.
pub const SUPPORTED_VERSIONS: &[u16] = &[35, 37, 38, 39, 40, 41];

/// Map item type codes used in `map_list`.
pub const MAP_TYPE_HEADER_ITEM: u16 = 0x0000;
pub const MAP_TYPE_STRING_ID_ITEM: u16 = 0x0001;
pub const MAP_TYPE_TYPE_ID_ITEM: u16 = 0x0002;
pub const MAP_TYPE_PROTO_ID_ITEM: u16 = 0x0003;
pub const MAP_TYPE_FIELD_ID_ITEM: u16 = 0x0004;
pub const MAP_TYPE_METHOD_ID_ITEM: u16 = 0x0005;
pub const MAP_TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
pub const MAP_TYPE_CALL_SITE_ID_ITEM: u16 = 0x0007;
pub const MAP_TYPE_METHOD_HANDLE_ITEM: u16 = 0x0008;
pub const MAP_TYPE_MAP_LIST: u16 = 0x1000;
pub const MAP_TYPE_TYPE_LIST: u16 = 0x1001;
pub const MAP_TYPE_ANNOTATION_SET_REF_LIST: u16 = 0x1002;
pub const MAP_TYPE_ANNOTATION_SET_ITEM: u16 = 0x1003;
pub const MAP_TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
pub const MAP_TYPE_CODE_ITEM: u16 = 0x2001;
pub const MAP_TYPE_STRING_DATA_ITEM: u16 = 0x2002;
pub const MAP_TYPE_DEBUG_INFO_ITEM: u16 = 0x2003;
pub const MAP_TYPE_ANNOTATION_ITEM: u16 = 0x2004;
pub const MAP_TYPE_ENCODED_ARRAY_ITEM: u16 = 0x2005;
pub const MAP_TYPE_ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;
pub const MAP_TYPE_HIDDENAPI_CLASS_DATA_ITEM: u16 = 0x2007;

macro_rules! define_index {
    ($name:ident) => {
        #[doc = concat!("Strongly typed index for the ", stringify!($name), " table.")]
        #[derive(
            Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
        )]
        pub struct $name(pub u32);

        impl $name {
            /// Create a new index from a raw value.
            #[inline]
            pub const fn new(value: u32) -> Self {
                Self(value)
            }

            /// Returns the raw underlying value.
            #[inline]
            pub const fn raw(self) -> u32 {
                self.0
            }

            /// Returns the index as `usize`.
            #[inline]
            pub const fn to_usize(self) -> usize {
                self.0 as usize
            }
        }
    };
}

define_index!(StringIdx);
define_index!(TypeIdx);
define_index!(ProtoIdx);
define_index!(FieldIdx);
define_index!(MethodIdx);
define_index!(ClassIdx);
define_index!(CallSiteIdx);
define_index!(MethodHandleIdx);

/// Entry inside the `map_list` section.
///
/// Each entry provides the type code, size, and offset for a section present in
/// the file. `dex-core` preserves the raw values so callers can recover optional
/// sections without re-parsing the entire binary.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MapItem {
    /// Section type identifier (e.g. [`MAP_TYPE_CLASS_DEF_ITEM`]).
    pub type_code: u16,
    /// Number of items present in the section.
    pub size: u32,
    /// File offset for the first byte of the section.
    pub offset: u32,
}

/// Representation of the DEX header (`header_item`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct DexHeader {
    /// Raw 8-byte magic value.
    pub magic: [u8; 8],
    /// Parsed version string (e.g. `39`).
    pub version: u16,
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl DexHeader {
    /// Returns `true` if the version is known to the crate.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        SUPPORTED_VERSIONS.contains(&self.version)
    }
}

/// Entry inside the `string_ids` table.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct StringId {
    /// Offset from the start of the file to the `string_data_item`.
    pub string_data_off: u32,
}

/// Entry inside the `type_ids` table.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TypeId {
    /// Index into `string_ids`.
    pub descriptor_idx: StringIdx,
}

/// Entry inside the `proto_ids` table.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ProtoId {
    /// Method shorty descriptor string.
    pub shorty_idx: StringIdx,
    /// Return type descriptor.
    pub return_type_idx: TypeIdx,
    /// Offset to the parameter type list.
    pub parameters_off: u32,
}

/// Entry inside the `field_ids` table.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FieldId {
    /// Defining class (type descriptor).
    pub class_idx: TypeIdx,
    /// Field type (type descriptor).
    pub type_idx: TypeIdx,
    /// Name string index.
    pub name_idx: StringIdx,
}

/// Entry inside the `method_ids` table.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MethodId {
    /// Defining class (type descriptor).
    pub class_idx: TypeIdx,
    /// Prototype index.
    pub proto_idx: ProtoIdx,
    /// Name string index.
    pub name_idx: StringIdx,
}

bitflags::bitflags! {
    /// Bitflags describing access control for classes, fields, and methods.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct AccessFlags: u32 {
        const PUBLIC       = 0x0000_0001;
        const PRIVATE      = 0x0000_0002;
        const PROTECTED    = 0x0000_0004;
        const STATIC       = 0x0000_0008;
        const FINAL        = 0x0000_0010;
        const SYNCHRONIZED = 0x0000_0020;
        const VOLATILE     = 0x0000_0040;
        const BRIDGE       = 0x0000_0040;
        const TRANSIENT    = 0x0000_0080;
        const VARARGS      = 0x0000_0080;
        const NATIVE       = 0x0000_0100;
        const INTERFACE    = 0x0002_0000;
        const ABSTRACT     = 0x0000_0400;
        const STRICT       = 0x0000_0800;
        const SYNTHETIC    = 0x0000_1000;
        const ANNOTATION   = 0x0002_0000;
        const ENUM         = 0x0004_0000;
        const CONSTRUCTOR  = 0x0001_0000;
        const DECLARED_SYNCHRONIZED = 0x0000_2000;
    }
}

/// Entry inside the `class_defs` table.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ClassDef {
    /// Index into [`TypeId`] describing the class.
    pub class_idx: TypeIdx,
    /// Bitmask of [`AccessFlags`] applied to the class.
    pub access_flags: AccessFlags,
    /// Optional reference to the super class descriptor.
    pub super_class_idx: Option<TypeIdx>,
    /// Offset to the interface type list.
    pub interfaces_off: u32,
    /// Optional index into `string_ids` for the source file.
    pub source_file_idx: Option<StringIdx>,
    /// Offset to the annotations directory.
    pub annotations_off: u32,
    /// Offset to the [`ClassDataItem`].
    pub class_data_off: u32,
    /// Offset to initial static values (`encoded_array_item`).
    pub static_values_off: u32,
}

/// Variable-length list of [`TypeIdx`] entries referenced by protos and class data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeList {
    /// Element descriptors stored in order.
    pub types: Vec<TypeIdx>,
}

/// Representation of a `try_item`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TryItem {
    /// Start program counter of the protected range.
    pub start_addr: u32,
    /// Length in 16-bit code units of the protected range.
    pub insn_count: u16,
    /// Offset (in bytes) from the start of the catch handler list.
    pub handler_off: u16,
}

/// Representation of a single typed catch handler.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CatchHandler {
    /// Type of the caught exception.
    pub type_idx: TypeIdx,
    /// Handler entry program counter.
    pub addr: u32,
}

/// Representation of an encoded catch handler structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedCatchHandler {
    /// List of typed handlers (ordered as encoded in the file).
    pub handlers: Vec<CatchHandler>,
    /// Optional "catch all" target.
    pub catch_all_addr: Option<u32>,
}

/// Fully parsed `code_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeItem<'a> {
    /// Total number of virtual registers used by this code.
    pub registers_size: u16,
    /// Number of registers dedicated to incoming arguments.
    pub ins_size: u16,
    /// Number of registers available to outgoing arguments.
    pub outs_size: u16,
    /// Number of [`TryItem`] entries attached to this method.
    pub tries_size: u16,
    /// Offset to associated debug info (`debug_info_item`).
    pub debug_info_off: u32,
    /// Size of the instruction stream in 16-bit code units.
    pub insns_size: u32,
    /// Raw little-endian 16-bit code units (`insns` field).
    pub insns: &'a [u8],
    /// Structured `try_item` entries for exception information.
    pub tries: Vec<TryItem>,
    /// Parsed catch handlers referenced by [`TryItem::handler_off`].
    pub handlers: Vec<EncodedCatchHandler>,
    /// Offsets used to resolve [`TryItem::handler_off`] into [`EncodedCatchHandler`] entries.
    pub handler_offsets: Vec<u32>,
}

impl<'a> CodeItem<'a> {
    /// Returns the catch handler associated with the given offset.
    ///
    /// The offset corresponds to a [`TryItem::handler_off`] and is used by the
    /// CFG builder to add edges from protected regions to their exception
    /// targets.
    pub fn handler_for_offset(&self, offset: u32) -> Option<&EncodedCatchHandler> {
        self.handler_offsets
            .iter()
            .position(|off| *off == offset)
            .and_then(|idx| self.handlers.get(idx))
    }
}

/// Field entry inside a `class_data_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedField {
    /// Index into the `field_ids` table.
    pub field_idx: FieldIdx,
    /// Associated access flags.
    pub access_flags: AccessFlags,
}

/// Method entry inside a `class_data_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedMethod {
    /// Index into the `method_ids` table.
    pub method_idx: MethodIdx,
    /// Associated access flags.
    pub access_flags: AccessFlags,
    /// Offset to the [`CodeItem`] (if any).
    pub code_off: u32,
}

/// Parsed `class_data_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassDataItem {
    /// Static field records sorted by index difference.
    pub static_fields: Vec<EncodedField>,
    /// Instance field records sorted by index difference.
    pub instance_fields: Vec<EncodedField>,
    /// Direct (private + constructors) method records.
    pub direct_methods: Vec<EncodedMethod>,
    /// Virtual method records.
    pub virtual_methods: Vec<EncodedMethod>,
}

/// Parsed `annotations_directory_item` contents.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnotationsDirectoryItem {
    /// Offset to the class annotation set.
    pub class_annotations_off: Option<u32>,
    /// Field annotations keyed by [`FieldIdx`].
    pub field_annotations: Vec<FieldAnnotation>,
    /// Method annotations keyed by [`MethodIdx`].
    pub method_annotations: Vec<MethodAnnotation>,
    /// Parameter annotations keyed by [`MethodIdx`].
    pub parameter_annotations: Vec<ParameterAnnotation>,
}

/// Field-level annotation metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldAnnotation {
    /// Index of the annotated field.
    pub field_idx: FieldIdx,
    /// Offset to the annotation set.
    pub annotations_offset: u32,
}

/// Method-level annotation metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodAnnotation {
    /// Index of the annotated method.
    pub method_idx: MethodIdx,
    /// Offset to the annotation set.
    pub annotations_offset: u32,
}

/// Parameter-level annotation metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParameterAnnotation {
    /// Index of the annotated method.
    pub method_idx: MethodIdx,
    /// Offset to the parameter annotation list.
    pub annotations_offset: u32,
}

/// List of annotation set references, e.g. from class data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnotationSetRefList {
    /// Offsets to [`AnnotationSetItem`] structures.
    pub items: Vec<u32>,
}

/// Aggregation of annotations applied to a single entity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnotationSetItem {
    /// Offsets to [`AnnotationItem`] entries.
    pub items: Vec<u32>,
}

/// Raw annotation payload decoded from the `annotation_item` section.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnotationItem<'a> {
    /// Visibility of the annotation (`runtime`, `build`, etc.).
    pub visibility: u8,
    /// Underlying `encoded_annotation` bytes.
    pub encoded_annotation: &'a [u8],
}

/// Raw encoded array payload from the `encoded_array_item` section.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedArrayItem<'a> {
    /// Underlying `encoded_array` bytes.
    pub data: &'a [u8],
}

/// Entry inside the `call_site_ids` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallSiteIdItem {
    /// Offset to the encoded call-site array.
    pub call_site_off: u32,
}

/// Entry inside the `method_handle_items` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodHandleItem {
    /// Kind of method handle (see DEX spec).
    pub handle_type: u16,
    /// Target field or method index.
    pub field_or_method_idx: u32,
}

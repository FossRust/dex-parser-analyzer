//! Low-level DEX data structures that closely mirror the on-disk layout.

use serde::{Deserialize, Serialize};

/// Size in bytes of the DEX header.
pub const HEADER_SIZE: usize = 0x70;

/// Known header magic prefix (`dex\n`).
pub const MAGIC_PREFIX: &[u8; 4] = b"dex\n";

/// Known versions supported by this crate.
pub const SUPPORTED_VERSIONS: &[u16] = &[35, 37, 38, 39, 40, 41];

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
    pub class_idx: TypeIdx,
    pub access_flags: AccessFlags,
    pub super_class_idx: Option<TypeIdx>,
    pub interfaces_off: u32,
    pub source_file_idx: Option<StringIdx>,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

/// Representation of a `try_item`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

/// Representation of a single typed catch handler.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CatchHandler {
    pub type_idx: TypeIdx,
    pub addr: u32,
}

/// Representation of an encoded catch handler structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedCatchHandler {
    pub handlers: Vec<CatchHandler>,
    pub catch_all_addr: Option<u32>,
}

/// Fully parsed `code_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeItem<'a> {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    /// Raw little-endian 16-bit code units (`insns` field).
    pub insns: &'a [u8],
    pub tries: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandler>,
}

/// Field entry inside a `class_data_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedField {
    pub field_idx: FieldIdx,
    pub access_flags: AccessFlags,
}

/// Method entry inside a `class_data_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedMethod {
    pub method_idx: MethodIdx,
    pub access_flags: AccessFlags,
    pub code_off: u32,
}

/// Parsed `class_data_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassDataItem {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

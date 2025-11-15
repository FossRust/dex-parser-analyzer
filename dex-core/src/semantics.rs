//! Semantic helper utilities layered atop [`DexFile`].

use serde::{Deserialize, Serialize};

use crate::{
    error::DexResult,
    format::{MethodIdx, StringIdx, TypeIdx},
    model::{ClassHandle, DexFile, MethodHandle},
};

/// Resolved type descriptor returned by [`resolve_type`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeDescriptor {
    /// Raw descriptor string such as `Ljava/lang/String;`.
    pub descriptor: String,
}

/// Resolve a string index.
///
/// ```
/// # use dex_core::{semantics, DexError, parse_dex};
/// # fn show_first_string(data: &[u8]) -> Result<(), DexError> {
/// let dex = parse_dex(data)?;
/// if dex.string_count() > 0 {
///     let value = semantics::resolve_string(&dex, dex_core::format::StringIdx::new(0))?;
///     println!("first string: {value}");
/// }
/// # Ok(())
/// # }
/// ```
pub fn resolve_string<'a>(dex: &'a DexFile<'a>, idx: StringIdx) -> DexResult<&'a str> {
    dex.try_string(idx)
}

/// Resolve a type descriptor into an owned helper.
///
/// The helper is convenient when the caller wants to store the descriptor
/// beyond the lifetime of the `DexFile`.
pub fn resolve_type<'a>(dex: &'a DexFile<'a>, idx: TypeIdx) -> Option<TypeDescriptor> {
    dex.type_descriptor(idx).map(|descriptor| TypeDescriptor {
        descriptor: descriptor.to_string(),
    })
}

/// Pretty printer for a method signature (`Lpkg/Foo;->bar` form).
pub fn pretty_method(dex: &DexFile<'_>, idx: MethodIdx) -> DexResult<String> {
    let method = dex
        .method(idx)
        .ok_or_else(|| crate::error::DexError::InvalidIndex {
            table: "method_ids",
            index: idx.raw(),
        })?;
    let class = method
        .class()
        .and_then(|cls| cls.descriptor().ok().map(|s| s.to_string()))
        .unwrap_or_else(|| "<unknown>".to_string());
    let name = method.name()?;
    Ok(format!("{class}->{name}"))
}

/// Iterate all methods inside a class.
///
/// This helper flattens direct + virtual method lists into a single iterator
/// that is easy to feed into property tests or graph traversals.
pub fn class_methods<'a>(class: &ClassHandle<'a>) -> impl Iterator<Item = MethodHandle<'a>> + 'a {
    class.methods().into_iter().flatten().into_iter()
}

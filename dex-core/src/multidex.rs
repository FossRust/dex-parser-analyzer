//! Helpers for coordinating multiple DEX files (e.g., multi-dex APKs).

use std::{
    collections::HashMap,
    fs::File,
    io::{Cursor, Read, Seek},
    path::Path,
};

use crate::{
    error::DexResult,
    format::{ClassIdx, MethodIdx, StringIdx, TypeIdx},
    model::{ClassHandle, DexFile, MethodHandle},
    parse_dex,
};
use zip::ZipArchive;

/// Identifies an item inside a specific dex file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DexEntry<Idx> {
    /// Index of the dex file inside `MultiDex::dexes`.
    pub dex: usize,
    /// Table index inside the pointed-to dex file.
    pub index: Idx,
}

impl<Idx> DexEntry<Idx> {
    /// Create a new entry descriptor.
    pub const fn new(dex: usize, index: Idx) -> Self {
        Self { dex, index }
    }
}

/// Aggregated view spanning multiple `DexFile`s.
pub struct MultiDex<'a> {
    dexes: Vec<DexFile<'a>>,
    class_index: HashMap<String, Vec<DexEntry<ClassIdx>>>,
    method_index: HashMap<String, Vec<DexEntry<MethodIdx>>>,
    string_index: HashMap<String, Vec<DexEntry<StringIdx>>>,
    type_index: HashMap<String, Vec<DexEntry<TypeIdx>>>,
}

impl<'a> MultiDex<'a> {
    /// Builds a multi-dex view from already-parsed `DexFile`s.
    ///
    /// The caller must ensure the underlying buffers outlive the returned
    /// `MultiDex`, just as they would for individual `DexFile`s.
    pub fn new(dexes: Vec<DexFile<'a>>) -> DexResult<Self> {
        let mut class_index: HashMap<String, Vec<DexEntry<ClassIdx>>> = HashMap::new();
        let mut method_index: HashMap<String, Vec<DexEntry<MethodIdx>>> = HashMap::new();
        let mut string_index: HashMap<String, Vec<DexEntry<StringIdx>>> = HashMap::new();
        let mut type_index: HashMap<String, Vec<DexEntry<TypeIdx>>> = HashMap::new();

        for (dex_idx, dex) in dexes.iter().enumerate() {
            for (class_idx, class_def) in dex.class_defs().enumerate() {
                if let Some(desc) = dex.type_descriptor(class_def.class_idx) {
                    class_index
                        .entry(desc.to_owned())
                        .or_default()
                        .push(DexEntry::new(dex_idx, ClassIdx::new(class_idx as u32)));
                    type_index
                        .entry(desc.to_owned())
                        .or_default()
                        .push(DexEntry::new(dex_idx, class_def.class_idx));
                }
            }

            for type_idx in 0..dex.type_count() {
                let idx = TypeIdx::new(type_idx as u32);
                if let Some(desc) = dex.type_descriptor(idx) {
                    type_index
                        .entry(desc.to_owned())
                        .or_default()
                        .push(DexEntry::new(dex_idx, idx));
                }
            }

            for method_idx in 0..dex.method_count() {
                let handle = MethodIdx::new(method_idx as u32);
                if let Some(signature) = method_descriptor(dex, handle) {
                    method_index
                        .entry(signature)
                        .or_default()
                        .push(DexEntry::new(dex_idx, handle));
                }
            }

            for string_idx in 0..dex.string_count() {
                let idx = StringIdx::new(string_idx as u32);
                if let Ok(value) = dex.try_string(idx) {
                    string_index
                        .entry(value.to_owned())
                        .or_default()
                        .push(DexEntry::new(dex_idx, idx));
                }
            }
        }

        Ok(Self {
            dexes,
            class_index,
            method_index,
            string_index,
            type_index,
        })
    }

    /// Builds a `MultiDex` over the provided in-memory dex buffers.
    /// The caller must keep each buffer alive for as long as the returned `MultiDex`.
    pub fn from_buffers(buffers: &'a [Vec<u8>]) -> DexResult<Self> {
        let mut dexes = Vec::with_capacity(buffers.len());
        for buf in buffers {
            dexes.push(parse_dex(buf)?);
        }
        Self::new(dexes)
    }

    /// Returns the underlying dex files.
    pub fn dexes(&self) -> &[DexFile<'a>] {
        &self.dexes
    }

    /// Number of dex files tracked by this aggregator.
    pub fn dex_count(&self) -> usize {
        self.dexes.len()
    }

    /// Looks up a class descriptor across all dex files.
    pub fn find_class(&'a self, descriptor: &str) -> Option<ClassHandle<'a>> {
        self.find_classes(descriptor).into_iter().next()
    }

    /// Returns all classes matching the descriptor across dex files.
    pub fn find_classes(&'a self, descriptor: &str) -> Vec<ClassHandle<'a>> {
        self.class_index
            .get(descriptor)
            .into_iter()
            .flat_map(|entries| entries.iter())
            .filter_map(|entry| self.dexes.get(entry.dex)?.class(entry.index))
            .collect()
    }

    /// Returns all class locations for the descriptor.
    pub fn class_entries(&self, descriptor: &str) -> Vec<DexEntry<ClassIdx>> {
        self.class_index
            .get(descriptor)
            .cloned()
            .unwrap_or_default()
    }

    /// Finds a method by its pretty descriptor `Lpkg/Class;->method(...)Return`.
    pub fn find_method(&'a self, descriptor: &str) -> Option<MethodHandle<'a>> {
        self.find_methods(descriptor).into_iter().next()
    }

    /// Returns all methods matching the descriptor.
    pub fn find_methods(&'a self, descriptor: &str) -> Vec<MethodHandle<'a>> {
        self.method_index
            .get(descriptor)
            .into_iter()
            .flat_map(|entries| entries.iter())
            .filter_map(|entry| self.dexes.get(entry.dex)?.method(entry.index))
            .collect()
    }

    /// Returns raw method locations for the descriptor.
    pub fn method_entries(&self, descriptor: &str) -> Vec<DexEntry<MethodIdx>> {
        self.method_index
            .get(descriptor)
            .cloned()
            .unwrap_or_default()
    }

    /// Finds a string literal across all dex files.
    pub fn find_string(&'a self, value: &str) -> Option<&'a str> {
        self.find_strings(value).into_iter().next()
    }

    /// Returns all occurrences of a string literal.
    pub fn find_strings(&'a self, value: &str) -> Vec<&'a str> {
        self.string_index
            .get(value)
            .into_iter()
            .flat_map(|entries| entries.iter())
            .filter_map(|entry| self.dexes.get(entry.dex)?.string(entry.index))
            .collect()
    }

    /// Returns string pool metadata (unique literal + its locations).
    pub fn string_pool(&self) -> impl Iterator<Item = (&str, &[DexEntry<StringIdx>])> {
        self.string_index
            .iter()
            .map(|(literal, entries)| (literal.as_str(), entries.as_slice()))
    }

    /// Finds the type descriptor entry for the provided descriptor.
    pub fn find_type(&'a self, descriptor: &str) -> Option<&'a str> {
        self.find_types(descriptor).into_iter().next()
    }

    /// Returns all occurrences of a type descriptor.
    pub fn find_types(&'a self, descriptor: &str) -> Vec<&'a str> {
        self.type_index
            .get(descriptor)
            .into_iter()
            .flat_map(|entries| entries.iter())
            .filter_map(|entry| self.dexes.get(entry.dex)?.type_descriptor(entry.index))
            .collect()
    }

    /// Returns raw type locations.
    pub fn type_entries(&self, descriptor: &str) -> Vec<DexEntry<TypeIdx>> {
        self.type_index.get(descriptor).cloned().unwrap_or_default()
    }
}

/// Reads all `classes*.dex` entries from a multi-dex APK/zip archive on disk.
pub fn read_dex_buffers_from_apk<P: AsRef<Path>>(path: P) -> DexResult<Vec<Vec<u8>>> {
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    read_dex_entries(&mut archive)
}

/// Reads dex entries from an in-memory zip archive.
pub fn read_dex_buffers_from_bytes(bytes: &[u8]) -> DexResult<Vec<Vec<u8>>> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)?;
    read_dex_entries(&mut archive)
}

fn method_descriptor(dex: &DexFile<'_>, idx: MethodIdx) -> Option<String> {
    let method = dex.method(idx)?;
    let class = method.class()?.descriptor().ok()?.to_string();
    let name = method.name().ok()?.to_string();
    let proto = method.prototype().ok()?;
    let mut params = String::from("(");
    if proto.parameters_off != 0 {
        if let Some(list) = dex.type_list(proto.parameters_off) {
            for ty in &list.types {
                params.push_str(dex.type_descriptor(*ty)?);
            }
        }
    }
    params.push(')');
    let return_desc = dex.type_descriptor(proto.return_type_idx)?.to_string();
    params.push_str(&return_desc);
    Some(format!("{class}->{name}{params}"))
}

fn read_dex_entries<R: Read + Seek>(archive: &mut ZipArchive<R>) -> DexResult<Vec<Vec<u8>>> {
    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_owned();
        if !name.ends_with(".dex") {
            continue;
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        if buf.starts_with(b"dex\n") {
            entries.push((name, buf));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries.into_iter().map(|(_, data)| data).collect())
}

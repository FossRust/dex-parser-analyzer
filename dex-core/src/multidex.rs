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
    parse_dex, semantics,
};
use zip::ZipArchive;

/// Aggregated view spanning multiple `DexFile`s.
pub struct MultiDex<'a> {
    dexes: Vec<DexFile<'a>>,
    class_index: HashMap<String, (usize, ClassIdx)>,
    method_index: HashMap<String, (usize, MethodIdx)>,
    string_index: HashMap<String, (usize, StringIdx)>,
    type_index: HashMap<String, (usize, TypeIdx)>,
}

impl<'a> MultiDex<'a> {
    /// Builds a multi-dex view from already-parsed `DexFile`s.
    ///
    /// The caller must ensure the underlying buffers outlive the returned
    /// `MultiDex`, just as they would for individual `DexFile`s.
    pub fn new(dexes: Vec<DexFile<'a>>) -> DexResult<Self> {
        let mut class_index = HashMap::new();
        let mut method_index = HashMap::new();
        let mut string_index = HashMap::new();
        let mut type_index = HashMap::new();

        for (dex_idx, dex) in dexes.iter().enumerate() {
            for (class_idx, class_def) in dex.class_defs().enumerate() {
                if let Some(desc) = dex.type_descriptor(class_def.class_idx) {
                    class_index
                        .entry(desc.to_owned())
                        .or_insert((dex_idx, ClassIdx::new(class_idx as u32)));
                    type_index
                        .entry(desc.to_owned())
                        .or_insert((dex_idx, class_def.class_idx));
                }
            }

            for method_idx in 0..dex.method_count() {
                let handle = MethodIdx::new(method_idx as u32);
                if let Ok(signature) = semantics::pretty_method(dex, handle) {
                    method_index.entry(signature).or_insert((dex_idx, handle));
                }
            }

            for string_idx in 0..dex.string_count() {
                let idx = StringIdx::new(string_idx as u32);
                if let Ok(value) = dex.try_string(idx) {
                    string_index
                        .entry(value.to_owned())
                        .or_insert((dex_idx, idx));
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

    /// Looks up a class descriptor across all dex files.
    pub fn find_class(&'a self, descriptor: &str) -> Option<ClassHandle<'a>> {
        let (dex_idx, class_idx) = self.class_index.get(descriptor)?;
        self.dexes[*dex_idx].class(*class_idx)
    }

    /// Finds a method by its pretty descriptor `Lpkg/Class;->method(...)Return`.
    pub fn find_method(&'a self, descriptor: &str) -> Option<MethodHandle<'a>> {
        let (dex_idx, method_idx) = self.method_index.get(descriptor)?;
        self.dexes[*dex_idx].method(*method_idx)
    }

    /// Finds a string literal across all dex files.
    pub fn find_string(&'a self, value: &str) -> Option<&'a str> {
        let (dex_idx, string_idx) = self.string_index.get(value)?;
        self.dexes[*dex_idx].string(*string_idx)
    }

    /// Finds the type descriptor entry for the provided descriptor.
    pub fn find_type(&'a self, descriptor: &str) -> Option<&'a str> {
        let (dex_idx, type_idx) = self.type_index.get(descriptor)?;
        self.dexes[*dex_idx].type_descriptor(*type_idx)
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

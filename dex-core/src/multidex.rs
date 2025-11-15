//! Helpers for coordinating multiple DEX files (e.g., multi-dex APKs).

use std::collections::HashMap;

use crate::{
    error::DexResult,
    format::{ClassIdx, MethodIdx, StringIdx, TypeIdx},
    model::{ClassHandle, DexFile, MethodHandle},
    semantics,
};

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

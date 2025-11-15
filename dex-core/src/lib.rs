#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]

//! `dex-core` is the parsing, modeling, and program-graph foundation for the
//! `dex-parser-analyzer` workspace.

pub mod bytecode;
pub mod dto;
pub mod format;
pub mod graphs;
pub mod analysis;
pub mod model;
pub mod multidex;
pub mod parser;
pub mod semantics;

mod error;

pub use crate::error::DexError;
pub use crate::model::{ClassHandle, DexFile, MethodHandle};
pub use crate::parser::parse_dex;

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]

//! High-level static analysis crate layered atop `dex-core`.
//!
//! The crate orchestrates multiple kinds of security checks – fast pattern
//! scans, structural control-flow inspections, and taint-style data-flow – and
//! exposes a WASM-friendly API for GUI or cloud runtimes.

pub mod config;
pub mod engine;
pub mod error;
pub mod ffi;
pub mod model;
pub mod pattern;
pub mod structural;
pub mod taint;

pub use config::AnalysisConfig;
pub use engine::{analyze_dex, analyze_dex_bytes};
pub use error::AnalysisError;
pub use model::{AnalysisReport, AnalysisStats, Finding, Location, Severity, VulnerabilityKind};

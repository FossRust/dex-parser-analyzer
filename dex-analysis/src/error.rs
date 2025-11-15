use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by the analysis engine.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum AnalysisError {
    #[error("Failed to parse DEX: {0}")]
    Parse(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Internal analysis error: {0}")]
    Internal(String),
}

impl From<dex_core::DexError> for AnalysisError {
    fn from(err: dex_core::DexError) -> Self {
        AnalysisError::Parse(err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
use serde_wasm_bindgen as swb;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::{config::AnalysisConfig, engine, error::AnalysisError, model::AnalysisReport};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn analyze_dex(bytes: &[u8], config: JsValue) -> Result<JsValue, JsValue> {
    let config: AnalysisConfig =
        swb::from_value(config).map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;
    let report: AnalysisReport = engine::analyze_dex_bytes(bytes, &config)
        .map_err(|e: AnalysisError| JsValue::from_str(&e.to_string()))?;
    swb::to_value(&report).map_err(|e| JsValue::from_str(&format!("Serialize error: {e}")))
}

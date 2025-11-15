#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use serde_wasm_bindgen as swb;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::{config::AnalysisConfig, engine, error::AnalysisError, model::AnalysisReport};
#[cfg(target_arch = "wasm32")]
use dex_core::{
    dto::{self, DexOverviewDto},
    parse_dex,
};

#[cfg(target_arch = "wasm32")]
#[derive(Serialize, Deserialize)]
pub struct DexAndAnalysisDto {
    pub dex: DexOverviewDto,
    pub analysis: AnalysisReport,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn analyze_dex(bytes: &[u8], config: JsValue) -> Result<JsValue, JsValue> {
    let config: AnalysisConfig =
        swb::from_value(config).map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;
    let report: AnalysisReport = engine::analyze_dex_bytes(bytes, &config)
        .map_err(|e: AnalysisError| JsValue::from_str(&e.to_string()))?;
    swb::to_value(&report).map_err(|e| JsValue::from_str(&format!("Serialize error: {e}")))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn load_and_analyze_dex(bytes: &[u8], config: JsValue) -> Result<JsValue, JsValue> {
    let config: AnalysisConfig =
        swb::from_value(config).map_err(|e| JsValue::from_str(&format!("Invalid config: {e}")))?;
    let dex = parse_dex(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let overview = dto::dex_to_overview(&dex)
        .map_err(|e| JsValue::from_str(&format!("dex overview error: {e}")))?;
    let analysis = engine::analyze_dex(&dex, &config);
    let payload = DexAndAnalysisDto {
        dex: overview,
        analysis,
    };
    swb::to_value(&payload).map_err(|e| JsValue::from_str(&format!("Serialize error: {e}")))
}

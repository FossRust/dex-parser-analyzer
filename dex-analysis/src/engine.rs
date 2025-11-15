use std::time::Instant;

use dex_core::format::MethodIdx;
use dex_core::model::DexFile;

use crate::{
    config::AnalysisConfig,
    error::AnalysisError,
    model::{AnalysisReport, AnalysisStats},
    pattern, structural, taint,
};

/// Run the enabled analyses on an already parsed [`DexFile`].
pub fn analyze_dex<'a>(dex: &DexFile<'a>, config: &AnalysisConfig) -> AnalysisReport {
    let start = Instant::now();
    let mut findings = Vec::new();
    let mut stats = AnalysisStats::default();
    stats.method_count = dex.method_count() as u32;
    stats.string_count = dex.string_count() as u32;
    stats.instruction_count = count_instructions(dex);

    if config.enable_pattern_checks {
        pattern::run_pattern_checks(dex, config, &mut findings, &mut stats);
    }
    if config.enable_structural_checks {
        structural::run_structural_checks(dex, config, &mut findings, &mut stats);
    }
    if config.enable_taint_checks {
        taint::run_taint_checks(dex, config, &mut findings, &mut stats);
    }

    if let Some(max) = config.max_findings {
        if findings.len() > max {
            findings.truncate(max);
        }
    }

    stats.elapsed_ms = Some(start.elapsed().as_millis() as u64);
    AnalysisReport { findings, stats }
}

/// Parse bytes and execute the configured analyses.
pub fn analyze_dex_bytes(
    bytes: &[u8],
    config: &AnalysisConfig,
) -> Result<AnalysisReport, AnalysisError> {
    let dex = dex_core::parse_dex(bytes)?;
    Ok(analyze_dex(&dex, config))
}

fn count_instructions(dex: &DexFile<'_>) -> u64 {
    let mut total = 0_u64;
    for idx in 0..dex.method_count() {
        let method = MethodIdx::new(idx as u32);
        if let Ok(ins) = dex.decode_instructions(method) {
            total = total.saturating_add(ins.len() as u64);
        }
    }
    total
}

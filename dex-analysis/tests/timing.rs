//! Per-stage timing of the DEX analysis pipeline on a real APK.
//!
//! Run with the target APK supplied as an env var so the 157 MB file is not
//! committed into the repo:
//!
//!   $env:DEX_TIMING_APK="C:\...\com.ttech.android.onlineislem_base.apk"
//!   cargo test -p dex-analysis --release --test timing -- --nocapture
//!
//! Prints, per classes*.dex and per stage (parse / string-dump / analyze /
//! xrefs), the wall time so the 28.9 s mobile DEX scan can be traced to its
//! true bottleneck before any rewrite decision.

use std::time::Instant;

use dex_analysis::model::AnalysisStats;
use dex_analysis::{config::AnalysisConfig, pattern, structural, taint};
use dex_core::format::MethodIdx;
use dex_core::graphs::build_xrefs;
use dex_core::multidex::read_dex_buffers_from_apk;
use dex_core::parse_dex;

fn config() -> AnalysisConfig {
    AnalysisConfig {
        enable_pattern_checks: true,
        enable_structural_checks: true,
        enable_taint_checks: true,
        secret_min_entropy: 3.5,
        max_findings: Some(500),
    }
}

fn count_instructions(dex: &dex_core::model::DexFile<'_>) -> u64 {
    let mut total = 0_u64;
    for idx in 0..dex.method_count() {
        let method = MethodIdx::new(idx as u32);
        if let Ok(ins) = dex.decode_instructions(method) {
            total = total.saturating_add(ins.len() as u64);
        }
    }
    total
}

#[test]
fn timing_real_apk() {
    let apk = std::env::var("DEX_TIMING_APK")
        .unwrap_or_else(|_| {
            eprintln!("set DEX_TIMING_APK to a multi-dex APK to run this test");
            return String::new();
        });
    if apk.is_empty() {
        eprintln!("SKIP: DEX_TIMING_APK not set");
        return;
    }

    let t0 = Instant::now();
    let buffers = read_dex_buffers_from_apk(&apk).expect("unpack apk");
    println!(
        "APK read+unpack: {:?} — {} dex buffers ({} MB total)",
        t0.elapsed(),
        buffers.len(),
        buffers.iter().map(|b| b.len()).sum::<usize>() / (1024 * 1024)
    );

    let mut tot_parse = 0u128;
    let mut tot_strings = 0u128;
    let mut tot_count = 0u128;
    let mut tot_pattern = 0u128;
    let mut tot_structural = 0u128;
    let mut tot_taint = 0u128;
    let mut tot_xrefs = 0u128;
    let mut total_methods = 0usize;
    let mut total_strings = 0usize;
    let mut total_findings = 0usize;
    let mut max_pattern_ms = 0u128;

    for (i, buf) in buffers.iter().enumerate() {
        println!("=== classes.{i}.dex ({:.1} MB) ===", buf.len() as f64 / (1024.0 * 1024.0));

        let t = Instant::now();
        let dex = parse_dex(buf).expect("parse");
        let parse_ms = t.elapsed().as_millis();
        tot_parse += parse_ms;

        let t = Instant::now();
        let mut text = String::new();
        for s in dex.strings().flatten() {
            text.push_str(s);
            text.push('\n');
            if text.len() >= 8 * 1024 * 1024 {
                break;
            }
        }
        let strings_ms = t.elapsed().as_millis();
        tot_strings += strings_ms;

        let methods = dex.method_count();
        let strs = dex.string_count();
        total_methods += methods;
        total_strings += strs;

        let t = Instant::now();
        let instrs = count_instructions(&dex);
        let count_ms = t.elapsed().as_millis();
        tot_count += count_ms;

        let cfg = config();
        let mut findings = Vec::new();
        let mut stats = AnalysisStats::default();

        let t = Instant::now();
        pattern::run_pattern_checks(&dex, &cfg, &mut findings, &mut stats);
        let pattern_ms = t.elapsed().as_millis();
        tot_pattern += pattern_ms;
        if pattern_ms > max_pattern_ms {
            max_pattern_ms = pattern_ms;
        }

        let t = Instant::now();
        structural::run_structural_checks(&dex, &cfg, &mut findings, &mut stats);
        let structural_ms = t.elapsed().as_millis();
        tot_structural += structural_ms;

        let t = Instant::now();
        taint::run_taint_checks(&dex, &cfg, &mut findings, &mut stats);
        let taint_ms = t.elapsed().as_millis();
        tot_taint += taint_ms;

        total_findings += findings.len();

        let t = Instant::now();
        let xrefs = build_xrefs(&dex).expect("xrefs");
        let xrefs_ms = t.elapsed().as_millis();
        tot_xrefs += xrefs_ms;

        println!(
            "  methods={methods} strings={strs} instrs={instrs} findings={} method_calls={} | parse={parse_ms}ms strings={strings_ms}ms count={count_ms}ms pattern={pattern_ms}ms structural={structural_ms}ms taint={taint_ms}ms xrefs={xrefs_ms}ms",
            findings.len(),
            xrefs.method_calls.len(),
        );

        // Surface the actual critical/pattern findings for sanity.
        let sev: std::collections::HashMap<String, usize> = {
            let mut m = std::collections::HashMap::new();
            for f in &findings {
                *m.entry(format!("{:?}", f.severity)).or_insert(0) += 1;
            }
            m
        };
        let kinds: std::collections::HashMap<String, usize> = {
            let mut m = std::collections::HashMap::new();
            for f in &findings {
                *m.entry(format!("{:?}", f.kind)).or_insert(0) += 1;
            }
            m
        };
        println!("  severities: {sev:?}");
        println!("  kinds: {kinds:?}");
    }

    println!("=== TOTAL ===");
    println!("parse={tot_parse}ms strings={tot_strings}ms count={tot_count}ms pattern={tot_pattern}ms structural={tot_structural}ms taint={tot_taint}ms xrefs={tot_xrefs}ms (max single dex pattern={max_pattern_ms}ms)");
    println!(
        "methods={total_methods} strings={total_strings} findings={total_findings} dex_files={}",
        buffers.len()
    );
}

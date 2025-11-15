use std::{cmp::Reverse, fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use dex_analysis::{config::AnalysisConfig, engine::analyze_dex};
use dex_core::{dto::dex_to_overview, parse_dex};

/// Simple CLI for inspecting a single `.dex` file.
#[derive(Debug, Parser)]
#[command(author, version, about = "Inspect and analyze a DEX file", long_about = None)]
struct Args {
    /// Path to the `.dex` file to inspect.
    #[arg(value_name = "DEX")]
    input: PathBuf,

    /// Optional maximum number of findings to print.
    #[arg(long, value_name = "COUNT")]
    max_findings: Option<usize>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let bytes = fs::read(&args.input)
        .with_context(|| format!("failed to read {}", args.input.display()))?;

    let dex = parse_dex(&bytes).context("failed to parse dex file")?;
    let overview = dex_to_overview(&dex).context("failed to build dex summary")?;

    let mut config = AnalysisConfig::default();
    if let Some(max) = args.max_findings {
        config.max_findings = Some(max);
    }

    let report = analyze_dex(&dex, &config);

    println!("Dex summary for {}\n", args.input.display());
    println!("Version:        {}", overview.version);
    println!("Checksum:       {}", overview.checksum);
    println!("File size:      {} bytes", overview.file_size);
    println!("Strings:        {}", overview.string_count);
    println!("Types:          {}", overview.type_count);
    println!("Fields:         {}", overview.field_count);
    println!("Methods:        {}", overview.method_count);
    println!("Classes:        {}", overview.class_count);

    let mut classes = overview.classes.iter().collect::<Vec<_>>();
    classes.sort_by_key(|cls| Reverse(cls.method_count));
    println!("\nTop classes by method count:");
    for class in classes.iter().take(10) {
        println!("  {:<5} {}", class.method_count, class.descriptor);
    }
    if classes.is_empty() {
        println!("  (no classes decoded)");
    }

    println!(
        "\nAnalysis stats: methods={} strings={} instructions={} findings={}",
        report.stats.method_count,
        report.stats.string_count,
        report.stats.instruction_count,
        report.findings.len()
    );
    if let Some(ms) = report.stats.elapsed_ms {
        println!("Analysis elapsed: {} ms", ms);
    }

    println!("\nAnalysis findings ({} total):", report.findings.len());
    for (idx, finding) in report.findings.iter().enumerate() {
        let loc = &finding.location;
        println!(
            "{:>3}. [{:?}] {} :: {}::{}",
            idx + 1,
            finding.severity,
            finding.id,
            loc.class_descriptor,
            loc.method_name,
        );
        println!("     {}", finding.message);
        if let Some(pc) = loc.pc {
            println!("     @pc {}", pc);
        }
    }

    if report.findings.is_empty() {
        println!("  No findings reported.");
    }

    Ok(())
}

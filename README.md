# dex-parser-analyzer
Dex Parser and Static Analysis tool (and GUI) written in Rust

## Workspace Layout

- `dex-core`: zero-copy DEX parser plus modeling/helpers (strings, CFGs, graphs, DTOs).
- `dex-analysis`: higher-level static analysis primitives that build on `dex-core`, starting with the reusable forward data-flow framework extracted from `dex-core/src/analysis`.
- `dex-cli`: command-line interface that prints parser summaries plus analyzer findings.
- `dex-gui`: Leptos WASM GUI that lets you upload a `.dex` and explore metrics/findings.

## Sample usage

### dex-core

```rust
use dex_core::{parse_dex, DexError};

fn print_classes(bytes: &[u8]) -> Result<(), DexError> {
    let dex = parse_dex(bytes)?;
    println!("DEX version {}", dex.header().version);
    for class in dex.classes() {
        let descriptor = class.descriptor()?;
        println!("class: {descriptor}");
    }
    Ok(())
}
```

### dex-analysis

```rust
use dex_analysis::{config::AnalysisConfig, engine::analyze_dex};
use dex_core::parse_dex;

fn run_analysis(bytes: &[u8]) -> anyhow::Result<()> {
    let dex = parse_dex(bytes)?;
    let report = analyze_dex(&dex, &AnalysisConfig::default());
    for finding in report.findings {
        println!("{:?}: {}", finding.severity, finding.message);
    }
    Ok(())
}
```

### dex-cli

```bash
cargo run -p dex-cli -- path/to/classes.dex --max-findings 25
```

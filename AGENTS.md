# Repository Guidelines

## Project Structure & Module Organization
The root will host the Rust crate once `Cargo.toml` and `src/` are added; keep parsing logic in `src/parser/`, static analysis utilities in `src/analysis/`, and GUI adapters in `src/gui/`. Shared types belong in `src/model.rs` so both parser and analyzer stay decoupled. Research notes and design references live in `docs/research/00-03-*.md`; update these when architectural decisions change so new agents can onboard quickly. Place integration fixtures under `tests/` and keep any large binary samples in `assets/dex-samples/` to avoid cluttering version control.

## Build, Test, and Development Commands
Run `cargo build` for a debug build of every crate in the workspace, and `cargo build --release` when benchmarking parser throughput. Use `cargo run --bin dex-analyzer <dex-file>` to exercise the CLI analyzer locally. Format with `cargo fmt` and lint with `cargo clippy --all-targets --all-features`; both must pass before a PR. When touching the GUI layer, run `wasm-pack build gui` to ensure the WebAssembly bundle still compiles.

## Coding Style & Naming Conventions
Stick to rustfmt defaults: 4-space indentation, 100-character lines, and module-level `//!` docs describing the subsystem. Types and traits use `PascalCase`, functions and modules use `snake_case`, and constants are `SCREAMING_SNAKE_CASE`. Organize modules so each file exposes a focused public API; re-export symbols via `pub use crate::parser::DexParser` patterns instead of deep imports. Prefer `anyhow::Result` for CLI-facing errors and strongly typed `thiserror` enums inside libraries.

## Testing Guidelines
Unit tests sit beside their modules inside `src/**/*_test.rs`, while integration and regression suites belong in `tests/`. Use the sample bytecode from `assets/dex-samples/` to create deterministic fixtures. Write property tests with `proptest` when validating bytecode invariants, and ensure new analyzer rules include both positive and negative cases. Always run `cargo test --all` plus any GUI-specific harnesses after modifying parsing logic; target ≥80% coverage for parser and analyzer crates.

## Commit & Pull Request Guidelines
Follow the short, imperative style already in history (`fix minor typo`, `add research docs`). Group related changes per commit, reference issue IDs when available, and keep bodies under 72 columns. PRs need a brief summary, test evidence (`cargo test --all` output, screenshots for GUI changes), updated docs when behavior shifts, and a checklist noting lint/format status. Tag reviewers familiar with both Rust backend and GUI surface when changes span layers.

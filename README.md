# dex-parser-analyzer
Dex Parser and Static Analysis tool (and GUI) written in Rust

## Workspace Layout

- `dex-core`: zero-copy DEX parser plus modeling/helpers (strings, CFGs, graphs, DTOs).
- `dex-analysis`: higher-level static analysis primitives that build on `dex-core`, starting with the reusable forward data-flow framework extracted from `dex-core/src/analysis`.

# dex-core Progress Tracker

## Completed Work
- Established workspace with `dex-core` crate and flake-based dev environment.
- Implemented DEX format structs, strong index newtypes, `DexError`, and driver+slicing parser that populates `DexFile` with lazy string resolution and method/class handles.
- Added comprehensive bytecode decoder with opcode table, register/literal/reference extraction, and payload parsing for switch/fill-array instructions (now covering dual-reference formats 45cc/4rcc and validating payload idents).
- Exposed semantic helpers, DTOs, CFG/call-graph/xref builders, and regression tests driven by the `tests/data/Test.dex` fixture.
- Parsed `map_list`, link data, and per-class annotation directories; `DexFile` now exposes section slices and annotation metadata for analysis consumers.

## Next Steps
1. Build additional fixtures/property tests to stress map/annotation parsing, graph builders, and bytecode decoding beyond the current synthetic samples.
2. Document public APIs (README + Rustdoc examples) and add CI scripts (fmt/clippy/test) for `dex-core`.
3. Expose serde DTOs for graphs/xrefs to higher layers (`dex-analysis`, `dex-gui`) and prototype data flow integrations.
4. Plan multi-dex coordination utilities (parsing multiple `classes*.dex` buffers and linking cross-dex references).

# dex-core Progress Tracker

## Completed Work
- Established workspace with `dex-core` crate and flake-based dev environment.
- Implemented DEX format structs, strong index newtypes, `DexError`, and driver+slicing parser that populates `DexFile` with lazy string resolution and method/class handles.
- Added comprehensive bytecode decoder with opcode table, register/literal/reference extraction, and payload parsing for switch/fill-array instructions (now covering dual-reference formats 45cc/4rcc and validating payload idents).
- Exposed semantic helpers, DTOs, CFG/call-graph/xref builders, and regression tests driven by the `tests/data/Test.dex` fixture.
- Parsed `map_list`, link data, annotations directories, and surfaced section slices + annotation metadata through `DexFile`.
- Extended CFG builder to add nodes/edges for exception handlers, and `CodeItem` now exposes handler lookup metadata for try/catch blocks.
- Added a “fixture sweep” test suite that parses/decode bytecode across the provided Androguard `.dex` corpus to catch regressions against real-world files.
- Introduced `multidex::MultiDex`, an aggregator that builds shared string/type/class/method indexes across several `DexFile`s, plus tests that prove cross-dex lookups work using bundled fixtures.
- Added fuzz/property tests: leb128 round-trips, handler offset validation, comprehensive string/type iteration, and malformed fixture tests (bad magic, out-of-bounds sections, corrupt payloads) to harden the parser against invalid inputs.
- Implemented ART/odex extensions: Format20bc instructions now record verification metadata, quickened opcodes (35mi/35ms/3rmi/3rms) capture inline/vtable indices, DTOs expose the new fields, and tests cover these cases.

## Next Steps
1. Build additional fixtures/property tests to stress map/annotation parsing, graph builders, and bytecode decoding beyond the current synthetic samples (e.g., multi-dex APK unpacking).
2. Document public APIs (README + Rustdoc examples) and add CI scripts (fmt/clippy/test) for `dex-core`.
3. Expose serde DTOs for graphs/xrefs to higher layers (`dex-analysis`, `dex-gui`) and prototype data flow integrations.
4. Plan multi-dex coordination utilities (parsing multiple `classes*.dex` buffers and linking cross-dex references).

# dex-core Progress Tracker

## Completed Work
- Established workspace with `dex-core` crate and flake-based dev environment.
- Implemented DEX format structs, strong index newtypes, `DexError`, and driver+slicing parser that populates `DexFile` with lazy string resolution and method/class handles.
- Added comprehensive bytecode decoder with opcode table, register/literal/reference extraction, and payload parsing for switch/fill-array instructions.
- Exposed semantic helpers, DTOs, CFG/call-graph/xref builders, and regression tests driven by the `tests/data/Test.dex` fixture.

## Next Steps
1. Expand instruction decoder coverage (e.g., 45cc/4rcc, method handle/call-site payloads) and verify switch payload edge cases.
2. Build property/unit tests for bytecode formats, graph builders, and string/type resolution (possibly using additional fixtures).
3. Document public APIs (README + Rustdoc examples) and add CI scripts (fmt/clippy/test) for `dex-core`.
4. Expose serde DTOs for graphs/xrefs to higher layers (`dex-analysis`, `dex-gui`) and prototype data flow integrations.

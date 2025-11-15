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
- Added multi-dex unpacking helpers based on the `zip` crate (`read_dex_buffers_from_apk`/`from_buffers`) and tests that unpack the bundled `multidex.apk` fixture.
- Expanded Rustdoc coverage for map/annotation helpers, semantic utilities, graphs (CFG/call-graph/xrefs), DTOs, and section accessor APIs so downstream users have examples for every public entry point.
- Reworked CFG construction to emit real basic blocks with fallthrough, branch, switch, and exception edges; call graphs now understand polymorphic invokes; xref modeling tracks string/field/type/proto/call-site/method-handle references with regression tests.
- Multi-dex helpers now build shared class/method/string/type pools with multi-location lookups, canonical method descriptors (including prototypes), and tests covering duplicate descriptors across dex files.
- Parsed optional map_list-driven sections (type lists, annotation set refs/items, annotation items, encoded arrays, call-site and method-handle tables) and surfaced them via `DexFile` so downstream analyzers can inspect data that isn’t referenced directly by class data. Added tests ensuring proto parameter offsets and static value arrays resolve through the new APIs.
- Audited overall parser coverage so far: confirmed every mandatory table, bytecode payload, and multi-dex helper is implemented while documenting the remaining optional sections (debug info, hidden-API metadata, checksum/signature validation) that still need wire-up work.

## Next Steps
1. Enforce header/file integrity by verifying checksum/signature/file_size/endian_tag values against the input buffer so corrupt or truncated dex files are rejected earlier.
2. Parse and surface the remaining map_list entries we currently skip (e.g., `debug_info_item`, hidden-API metadata) and add ergonomic getters/DTOs for that data.
3. Expand the fixture+property-test matrix to include annotation-heavy dexes, odex/quickened samples, multi-dex APKs, and regression files that stress annotation decoding, quickening metadata, and the new optional sections.
4. Flesh out higher-level exports (serde DTOs for graphs/xrefs/debug info) and document usage in the workspace README/CI scripts so `dex-analysis`/GUI consumers can immediately leverage the richer parser surface.

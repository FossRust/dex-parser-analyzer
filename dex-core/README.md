# dex-core

`dex-core` exposes the parsing and modeling primitives that every crate in this
workspace builds upon. The crate consumes a `&[u8]` containing a single
`classes.dex` file and turns it into a `DexFile` abstraction with lazy lookups,
semantic helpers, and program-graph builders.

## Minimum Example

```rust
use dex_core::{parse_dex, DexError};

fn inspect_dex(bytes: &[u8]) -> Result<(), DexError> {
    let dex = parse_dex(bytes)?;

    println!("DEX version {}", dex.header().version);
    for class in dex.classes() {
        let descriptor = class.descriptor()?;
        println!("class: {descriptor}");

        if let Some(methods) = class.methods() {
            for method in methods {
                // Access semantic metadata
                let name = method.name()?;
                println!("  method: {name}");

                // Decode Dalvik bytecode
                for ins in method.instructions()? {
                    println!("    {:#06x}: {}", ins.pc, ins.name);
                }
            }
        }
    }

    Ok(())
}
```

## Graph Builders and DTOs

Once a file is parsed you can build higher-level program structures:

```rust
use dex_core::{graphs, parse_dex};

fn call_graph_edges(bytes: &[u8]) -> Result<Vec<(u32, u32)>, dex_core::DexError> {
    let dex = parse_dex(bytes)?;
    let cg = graphs::build_call_graph(&dex)?;
    Ok(cg.edge_indices()
        .map(|edge| cg.edge_endpoints(edge).unwrap())
        .map(|(src, dst)| (src.index() as u32, dst.index() as u32))
        .collect())
}
```

Use the `dto` module when serializing data across a process or FFI boundary.
For example, `dto::instructions_to_dto` turns decoded bytecode into plain
`serde`-friendly structs that contain opcode names, registers, literals, and
both primary/secondary references.

## API Surface

* `parse_dex(&[u8]) -> DexFile`: parse and validate a single `.dex` buffer.
* `DexFile` getters: `strings()`, `classes()`, `class_defs()`, `method()`.
* Bytecode decoding: `DexFile::decode_instructions(MethodIdx)` or
  `bytecode::decode_instructions(&DexFile, &CodeItem)` for manual control.
* Graphs: `graphs::build_method_cfg`, `graphs::build_call_graph`,
  `graphs::build_xrefs`.
* DTOs: use `dto::method_to_dto`, `dto::class_to_dto`, `dto::instructions_to_dto`
  when emitting data outside of Rust.

See the inline Rustdoc on each module for more details.

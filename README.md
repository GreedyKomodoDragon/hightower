# Hightower

Hightower is a work-in-progress Ethereum beacon node, written in Zig. Largely a learning project at the moment.

Current focus is on core Ethereum serialization primitives: RLP (execution layer) and SSZ (consensus layer), which everything else — blocks, transactions, beacon state — builds on.

> Status: early / experimental. APIs are unstable and much is unimplemented.

## Features

- **RLP encoding** (`src/rlp/`) — Recursive Length Prefix as used by Ethereum execution clients
  - Short / long strings, short / long lists per Ethereum spec
  - Generic `rlp(writer, value)` entry point for byte strings and lists of byte strings
- **SSZ types** (`src/ssz/`) — Simple Serialize for the consensus layer
  - Fixed and variable-size containers, lists, bitlists, and vectors; official vectors cover implemented cases
- **SSZ Merkleization / hash-tree-root** (`src/merkle/chunking.zig`)
  - Chunking, Merkleization, hash-tree roots, list length mixing, and some progressive types
- Standard Zig CLI + library layout (`src/main.zig`, `src/root.zig`)

## Requirements

- Zig `0.16.0` (see `minimum_zig_version` in `build.zig.zon`)
- No external dependencies

Check version:

```sh
zig version
```

## Getting started

```sh
# build
zig build

# run
zig build run
zig build run -- arg1 arg2

# run all wired-in tests
zig build test

# run with test fuzzer
zig build test -- --fuzz
```

The compiled binary lands in `zig-out/bin/hightower`.

CI (`.github/workflows/ci.yml`): `zig fmt --check`, `zig build`, `zig build test`, `zig build test-transition`, pinned Geth v1.17.7–v1.17.10 Engine API interoperability checks, and Bruno HTTP checks on Zig 0.16.0.

## JSON conventions

Build valid JSON from structured values and serialize it; parse responses and check their fields. Do not embed valid JSON as escaped string literals or assemble it by concatenating strings, including in tests. Use raw literals only when the exact bytes matter, such as a malformed-JSON test or a wire-format fixture.

## Project layout

```
build.zig       build script (exe, run step, and test steps for library, RLP, SSZ, Merkle, and vectors)
build.zig.zon   package manifest (name, version, min Zig version)
src/
  main.zig      CLI entry point (template greeting + arg logging)
  root.zig      library root (template helpers)
  rlp/
    rlp.zig         generic RLP encoder + encodeList via buffered payload
    encoding.zig    low-level encodeString (0x80..) / encodeBytes-as-list (0xc0..) + big-endian length
    tests.zig       RLP test runner entry
    rlp_test.zig
    encoding_test.zig
  ssz/
    ssz.zig     serialize/deserialize for supported fixed and variable-size SSZ types
    tests.zig   SSZ test runner entry
    ssz_test.zig
  merkle/
    chunking.zig       GetChunks / HashTreeRoot / Merkleize
    tests.zig          merkle test runner entry
    chunking_test.zig  GetChunks coverage
    merkle_test.zig    Merkleize coverage
```

## Process — implementation status

The project has grown beyond its original serialization primitives. Current coverage is focused on Fulu's minimal preset and selected fixtures:

1. **RLP** — canonical encoding and decoding, including integer encoding and streaming decode.
2. **SSZ and Merkleization** — fixed and variable-size serialization, deserialization, hash-tree-roots, and selected official vectors; unsupported cases remain.
3. **Fulu types** — Beacon block and state schemas with shared nested types.
4. **Consensus processing** — selected helper, block, epoch, and fork-choice behavior with pinned minimal-preset fixtures.
5. **Cryptography and execution boundary** — signing domains and BLS verification are implemented; execution payload validation uses an interface with a deterministic test engine, not a production execution client.

Run `zig build test` for RLP, SSZ, Merkle, Fulu type, and library tests; `zig build test-transition` for selected consensus fixtures and BLS tests; and `zig build test-vectors` for the separate official SSZ vector corpus, which includes unsupported cases. `zig build` compiles the executable.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the current codebase assessment and the proposed path from SSZ/Merkle primitives to a Beacon Chain state transition, fork choice, and node.

## References

- [Ethereum RLP spec](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/)
- [Ethereum SSZ spec](https://ethereum.github.io/consensus-specs/ssz/simple-serialize/)
- [Zig 0.16.0 release notes](https://ziglang.org/learn/releases/0-16-0/)

## License

TBD — no license file yet.

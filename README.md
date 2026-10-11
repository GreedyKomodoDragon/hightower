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

CI (`.github/workflows/ci.yml`): `zig fmt --check`, `zig build`, `zig build test` on Zig 0.16.0.

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

## Process — what has been done so far

Bottom-up, test-first, one primitive at a time:

1. **Scaffold** — `zig init` layout on Zig 0.16.0, no deps. CI runs `zig fmt --check`, `zig build`, `zig build test`.
2. **RLP prefixes (`encoding.zig`)** — all four ranges: single byte, short/long string, short/long list, minimal big-endian lengths.
3. **RLP encoder (`rlp.zig`)** — `@typeInfo` dispatch for byte strings + lists via buffered payload. Tested: empty/single-byte/`"dog"`/`["cat","dog"]`/55-vs-56-byte boundary. Gaps: int encode stubbed, no decode, 4 KiB list cap.
4. **SSZ (`ssz.zig`)** — fixed and variable-size serialization/deserialization, with generated official vectors. Unsupported cases remain.
5. **Merkle (`chunking.zig`)** — chunking, Merkleization, hash-tree roots, list length mixing, and some progressive types. Tests run through `zig build test`; unsupported cases remain.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the current codebase assessment and the proposed path from SSZ/Merkle primitives to a Beacon Chain state transition, fork choice, and node.

## References

- [Ethereum RLP spec](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/)
- [Ethereum SSZ spec](https://ethereum.github.io/consensus-specs/ssz/simple-serialize/)
- [Zig 0.16.0 release notes](https://ziglang.org/learn/releases/0-16-0/)

## License

TBD — no license file yet.

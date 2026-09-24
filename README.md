# Hightower

Hightower is a work-in-progress Ethereum beacon node, written in Zig. Largely a learning project at the moment.

Current focus is on core Ethereum serialization primitives: RLP (execution layer) and SSZ (consensus layer), which everything else — blocks, transactions, beacon state — builds on.

> Status: early / experimental. APIs are unstable and much is unimplemented.

## Features

- **RLP encoding** (`src/rlp/`) — Recursive Length Prefix as used by Ethereum execution clients
  - Short / long strings, short / long lists per Ethereum spec
  - Generic `rlp(writer, value)` entry point for byte strings and lists of byte strings
- **SSZ fixed-size types** (`src/ssz/`) — Simple Serialize for the consensus layer
  - `serialize` / `deserialize` for `bool`, unsigned `u8/u16/u32/u64/u128/u256` (little-endian), fixed arrays `[N]T`, and `struct` containers (including nested)
  - Round-trip tested (serialize → deserialize → equal)
- **SSZ Merkleization / hash-tree-root** (`src/merkle/chunking.zig`)
  - `GetChunks` — reduce a value to `[][32]u8`: ints/bools zero-padded to one chunk, int arrays packed (`ceil(bytes/32)` chunks), structs/arrays-of-structs recursed via `HashTreeRoot`
  - `Merkleize` — pad leaves to next power of two with zero chunks, pairwise `SHA-256` reduction to one root; 0 chunks → zero root, 1 chunk → identity
  - `HashTreeRoot` — `GetChunks` + `Merkleize`
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

# run all wired-in tests (rlp + ssz + lib + exe)
zig build test

# run with test fuzzer
zig build test -- --fuzz

# merkle tests are not yet wired into build.zig — run directly:
zig test src/merkle/tests.zig
zig test src/rlp/tests.zig
zig test src/ssz/tests.zig
```

The compiled binary lands in `zig-out/bin/hightower`.

CI (`.github/workflows/ci.yml`): `zig fmt --check`, `zig build`, `zig build test` on Zig 0.16.0.

## Project layout

```
build.zig       build script (exe, run step, test steps for rlp + ssz)
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
    ssz.zig     serialize/deserialize for fixed-size SSZ only
    tests.zig   SSZ test runner entry
    ssz_test.zig
  merkle/
    chunking.zig       GetChunks / HashTreeRoot / Merkleize
    tests.zig          merkle test runner entry (untracked, not in build.zig yet)
    chunking_test.zig  GetChunks coverage
    merkle_test.zig    Merkleize coverage (untracked, not in build.zig yet)
```

## Process — what has been done so far

Bottom-up, test-first, one primitive at a time:

1. **Scaffold** — `zig init` layout on Zig 0.16.0, no deps. CI runs `zig fmt --check`, `zig build`, `zig build test`.
2. **RLP prefixes (`encoding.zig`)** — all four ranges: single byte, short/long string, short/long list, minimal big-endian lengths.
3. **RLP encoder (`rlp.zig`)** — `@typeInfo` dispatch for byte strings + lists via buffered payload. Tested: empty/single-byte/`"dog"`/`["cat","dog"]`/55-vs-56-byte boundary. Gaps: int encode stubbed, no decode, 4 KiB list cap.
4. **SSZ fixed-size (`ssz.zig`)** — `serialize`/`deserialize` for uints (LE), `bool`, fixed arrays, nested structs. 41 tests incl. round-trips. Gaps: no variable-size types (offsets, lists, bitlists).
5. **Merkle (`chunking.zig`)** — `GetChunks` (scalar pad, int-array pack, per-field/per-element roots) + `Merkleize` (zero-pad to power of two, pairwise SHA-256). Gaps: int-arrays only, no length-mixing, merkle tests not yet wired into `zig build test` (61 tests passing without them).

## Roadmap

- [ ] Finish RLP encode (integers big-endian minimal, nested lists) + add decoding
- [ ] Wire `src/merkle/tests.zig` into `build.zig` test step; `zig fmt` the new files
- [ ] SSZ variable-size types (offsets, lists/vectors, bitlists, unions)
- [ ] SSZ Merkleization: list length-mixing, generalized indices / proofs
- [ ] Ethereum wire types built on RLP/SSZ
- [ ] Networking / beacon sync
- [ ] Docs + spec references

## References

- [Ethereum RLP spec](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/)
- [Ethereum SSZ spec](https://ethereum.github.io/consensus-specs/ssz/simple-serialize/)
- [Zig 0.16.0 release notes](https://ziglang.org/learn/releases/0-16-0/)

## License

TBD — no license file yet.

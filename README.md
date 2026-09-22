# Hightower

Hightower is a work-in-progress Ethereum beacon node, written in Zig. Largely a learning project at the moment.

Current focus is on core Ethereum serialization primitives: RLP (execution layer) and SSZ (consensus layer), which everything else — blocks, transactions, beacon state — builds on.

> Status: early / experimental. APIs are unstable and much is unimplemented.

## Features

- **RLP encoding** (`src/rlp/`) — Recursive Length Prefix as used by Ethereum execution clients
  - Short / long strings, short / long lists per Ethereum spec
  - Generic `rlp(writer, value)` entry point for ints, byte strings, lists
- **SSZ stub** (`src/ssz/`) — Simple Serialize for the consensus layer (placeholder for now)
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

# run all tests
zig build test

# run with test fuzzer
zig build test -- --fuzz
```

The compiled binary lands in `zig-out/bin/hightower`.

## Project layout

```
build.zig       build script (exe, run step, test steps)
build.zig.zon   package manifest (name, version, min Zig version)
src/
  main.zig      CLI entry point
  root.zig      library root
  rlp/
    rlp.zig         generic RLP encoder
    encoding.zig    low-level string/list prefix logic
    tests.zig       RLP test runner entry
    rlp_test.zig
    encoding_test.zig
  ssz/
    ssz.zig     SSZ placeholder
```

## Roadmap

- [ ] Finish RLP encode (integers, nested lists, decoding)
- [ ] SSZ basic types (uint, bool, vectors, lists, containers)
- [ ] Ethereum wire types built on RLP/SSZ
- [ ] Networking / beacon sync
- [ ] Docs + spec references

## References

- [Ethereum RLP spec](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/)
- [Ethereum SSZ spec](https://ethereum.github.io/consensus-specs/ssz/simple-serialize/)
- [Zig 0.16.0 release notes](https://ziglang.org/learn/releases/0-16-0/)

## License

TBD — no license file yet.

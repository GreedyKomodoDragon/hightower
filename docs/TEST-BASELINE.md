# Test baseline

Captured for FULU-002 on 2026-10-11 with Zig 0.16.0.

## Standard checks

| Command | Result |
| --- | --- |
| `zig fmt --check build.zig build.zig.zon src` | Pass |
| `zig build` | Pass |
| `zig build test --summary all` | Pass: 127/127 tests across RLP, SSZ, Merkle, library, and executable test roots |

## Official SSZ vectors

`zig build test-vectors --summary all` runs 118 vectors: 79 pass and 39 fail with the explicit `VectorNotImplemented` placeholder. These are known unsupported coverage, not unexpected test failures.

The 39 unsupported vectors cover compatible unions (including containers and lists that contain them) and progressive SSZ types (lists, bitlists, and containers). Each generated test currently returns `error.VectorNotImplemented`; implementing these types is outside this baseline task.

## Reproduce

Run the checks from the repository root:

```sh
zig version
zig fmt --check build.zig build.zig.zon src
zig build
zig build test --summary all
zig build test-vectors --summary all
```

The standard suite and vector suite are separate build steps. The vector command exits non-zero while the 39 unsupported placeholders remain.

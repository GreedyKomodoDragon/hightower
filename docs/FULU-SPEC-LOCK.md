# Fulu specification and test bundle lock

| Item | Pinned value |
| --- | --- |
| Fork | `fulu` |
| Preset | `minimal` |
| Specification | [`ethereum/consensus-specs` v1.6.1](https://github.com/ethereum/consensus-specs/releases/tag/v1.6.1) |
| Spec commit | [`5fa6edcca8ab4cf548653e6680b17b9d3e04d225`](https://github.com/ethereum/consensus-specs/commit/5fa6edcca8ab4cf548653e6680b17b9d3e04d225) |
| Test bundle | [`minimal.tar.gz` from the same v1.6.1 release](https://github.com/ethereum/consensus-specs/releases/download/v1.6.1/minimal.tar.gz) |
| Bundle size | 467,646,726 bytes |
| Published SHA-256 | `e1d0c9dc3d09fb74a98b324c40b2587a17dc555e6149d3f9741601fffcf43901` |

The fork implementation uses the pinned [Fulu fork rules](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/fulu/fork.md): an Electra state at an epoch boundary is copied, its fork metadata changes to Fulu, and proposer indices for the current and following epoch are stored in the new window. The minimal preset retains the disabled fork epoch from its pinned configuration for automatic activation; fork fixture tests invoke the upgrade explicitly. Mainnet uses fork epoch `411392` and version `0x06000000`.

Genesis follows the pinned [Phase 0 deposit initialization](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/phase0/beacon-chain.md) and supplies inherited later-fork fields directly. It verifies each deposit proof against the corresponding prefix root, ignores invalid signatures for new keys, activates fully funded validators, and then initializes Fulu sync committees and proposer lookahead. The constructor requires at least one eligible proposer; an empty or wholly invalid deposit set returns `NoEligibleProposer`.

The v1.6.1 tag resolves to the commit above. The size and SHA-256 are the release asset's published values and were checked against a local download. The standalone `consensus-spec-tests` repository is archived; the matching generated tests are attached to the `consensus-specs` release.

From the repository root, download and verify the bundle:

```sh
mkdir -p testdata/consensus-specs-v1.6.1
curl -fL https://github.com/ethereum/consensus-specs/releases/download/v1.6.1/minimal.tar.gz \
  -o testdata/consensus-specs-v1.6.1/minimal.tar.gz
test "$(wc -c < testdata/consensus-specs-v1.6.1/minimal.tar.gz | tr -d ' ')" = 467646726
printf '%s  %s\n' e1d0c9dc3d09fb74a98b324c40b2587a17dc555e6149d3f9741601fffcf43901 \
  testdata/consensus-specs-v1.6.1/minimal.tar.gz | shasum -a 256 -c -
tar -xzf testdata/consensus-specs-v1.6.1/minimal.tar.gz \
  -C testdata/consensus-specs-v1.6.1 tests/minimal/fulu
```

The extracted Fulu cases are under `testdata/consensus-specs-v1.6.1/tests/minimal/fulu/`. The full archive also contains other forks and suites; extract those from the same verified file when needed. Both archive and extracted files remain under ignored `testdata/` and are not committed.

These are [consensus-spec tests](https://github.com/ethereum/consensus-specs/blob/v1.6.1/tests/formats/README.md), organized by preset, fork, runner, handler, suite, and case, with YAML and compressed SSZ inputs/outputs. The existing `testdata/ssz-test-vectors/` holds generic SSZ JSON vectors used to check serialization and Merkle behavior without a Fulu fork or minimal-preset state transition. The two fixture sets serve different checks.

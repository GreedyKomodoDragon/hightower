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

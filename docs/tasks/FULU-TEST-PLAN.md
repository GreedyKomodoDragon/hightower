# Fulu conformance test plan

## Pinned source and normal test runner

Use the minimal Fulu tests from consensus-specs v1.6.1, pinned in [FULU-SPEC-LOCK.md](../FULU-SPEC-LOCK.md). The archive and extracted cases stay in ignored `testdata/`; ordinary Zig tests use only the selected, decompressed `.ssz` files checked in under `src/ssz/fixtures/fulu_static/`. Static inputs use Snappy block compression in `serialized.ssz_snappy` and a sibling `roots.yaml` oracle. Current Zig fixtures check decode, hash-tree-root, and byte-identical re-encoding. PySpec transition cases use compressed `pre.ssz_snappy`, `blocks_N.ssz_snappy`, and `post.ssz_snappy`, with `meta.yaml` or `slots.yaml` describing the scenario. No PySpec runner is wired into Zig yet.

## Selected static SSZ and hash-root cases

- Keep `ssz_nil/case_0` for each implemented Fulu recursive schema, plus `BeaconBlock/ssz_random/case_7` and `case_22`. These already cover the declared block schemas and their shared nested types.
- Add `BeaconState` cases `ssz_nil/case_0`, `ssz_zero/case_0`, `ssz_one/case_0`, and `ssz_random/case_0`. These exercise empty, zero-valued, one-valued, and mixed state values against the pinned root oracle.
- The ordinary `zig build test` path embeds only those decompressed case files; it does not require the ignored test bundle or a Snappy library. Record the source case and root alongside each test.
- There is no separate helper fixture handler in the pinned Fulu tree. Generic SSZ encode/decode and hash-root behavior is exercised by the static schema fixtures. Generalized-index Merkle proofs remain outside this initial selection because their verifier is not part of the current schema/SSZ path.

## Selected transition cases for the next implementation slice

These paths define the small first Fulu slot/block conformance set. They remain reference fixtures until the associated state-transition code exists.

| Suite | Case | Purpose and files |
| --- | --- | --- |
| `sanity/slots` | `slots_1` | Basic multi-slot processing; `pre.ssz_snappy`, `slots.yaml`, `post.ssz_snappy` |
| `sanity/slots` | `over_epoch_boundary` | Slot processing across an epoch boundary; same three files |
| `epoch_processing/proposer_lookahead` | `proposer_lookahead_in_state_matches_computed_lookahead` | Fulu lookahead field update; `pre.ssz_snappy`, `pre_epoch.ssz_snappy`, `post_epoch.ssz_snappy`, `post.ssz_snappy` |
| `epoch_processing/proposer_lookahead` | `proposer_lookahead_does_not_contain_exited_validators` | Exited-validator edge case; same four files |
| `sanity/blocks` | `empty_block_transition` | Valid block processing; `pre.ssz_snappy`, `blocks_0.ssz_snappy`, `post.ssz_snappy`, `meta.yaml` |
| `sanity/blocks` | `invalid_incorrect_state_root` | Invalid block rejection; `pre.ssz_snappy`, `blocks_0.ssz_snappy`, `meta.yaml` (no post state) |

Run these PySpec cases with the consensus-specs runner once their transition handlers are implemented. Preserve the per-case metadata and expected post-state; invalid cases must reject the block and must not be treated as successful post-state comparisons. Cases not listed here, including large randomized/fork-choice suites, are deferred and can be selected when those implementations are in scope.

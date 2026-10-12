# Selected Fulu transition fixtures

These compressed SSZ files come from the minimal Fulu tests in `ethereum/consensus-specs` v1.6.1, commit `5fa6edcca8ab4cf548653e6680b17b9d3e04d225`. Their upstream source is the matching case directory listed below. The normal test suite embeds only these selected files; the full archive is not needed to run it.

| Local case | Upstream source case | Expected result |
| --- | --- | --- |
| `slots_1` | `tests/minimal/fulu/sanity/slots/pyspec_tests/slots_1` | Post-state |
| `over_epoch_boundary` | `tests/minimal/fulu/sanity/slots/pyspec_tests/over_epoch_boundary` | Post-state |
| `double_empty_epoch` | `tests/minimal/fulu/sanity/slots/pyspec_tests/double_empty_epoch` | Post-state |
| `proposer_lookahead_in_state_matches_computed_lookahead` | `tests/minimal/fulu/epoch_processing/proposer_lookahead/pyspec_tests/proposer_lookahead_in_state_matches_computed_lookahead` | Post-epoch and post-state |
| `proposer_lookahead_does_not_contain_exited_validators` | `tests/minimal/fulu/epoch_processing/proposer_lookahead/pyspec_tests/proposer_lookahead_does_not_contain_exited_validators` | Post-epoch and post-state |
| `empty_block_transition` | `tests/minimal/fulu/sanity/blocks/pyspec_tests/empty_block_transition` | Post-state |
| `invalid_incorrect_state_root` | `tests/minimal/fulu/sanity/blocks/pyspec_tests/invalid_incorrect_state_root` | Reject; no post-state |
| `basic_pending_consolidation` | `tests/minimal/fulu/epoch_processing/pending_consolidations/pyspec_tests/basic_pending_consolidation` | Post-epoch balances and pending queue |
| `process_pending_deposits_multiple_pending_deposits_below_churn` | `tests/minimal/fulu/epoch_processing/pending_deposits/pyspec_tests/process_pending_deposits_multiple_pending_deposits_below_churn` | Post-epoch balances and pending queue |
| `process_pending_deposits_not_finalized` | `tests/minimal/fulu/epoch_processing/pending_deposits/pyspec_tests/process_pending_deposits_not_finalized` | Post-epoch new validator and pending queue |

The archived source, published size, and SHA-256 are recorded in [`docs/FULU-SPEC-LOCK.md`](../../../../docs/FULU-SPEC-LOCK.md). The ignored archive is useful for selecting future cases, while these checked-in fixtures keep ordinary tests repeatable and offline.

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
| `consolidation_not_yet_withdrawable_validator` | `tests/minimal/fulu/epoch_processing/pending_consolidations/pyspec_tests/consolidation_not_yet_withdrawable_validator` | Keep the unready consolidation queued |
| `skip_consolidation_when_source_slashed` | `tests/minimal/fulu/epoch_processing/pending_consolidations/pyspec_tests/skip_consolidation_when_source_slashed` | Drop the slashed-source request without moving balance |
| `effective_balance_hysteresis` | `tests/minimal/fulu/epoch_processing/effective_balance_updates/pyspec_tests/effective_balance_hysteresis` | Epoch effective-balance update |
| `eth1_vote_reset` | `tests/minimal/fulu/epoch_processing/eth1_data_reset/pyspec_tests/eth1_vote_reset` | Eth1 voting-period reset |
| `historical_summaries_accumulator` | `tests/minimal/fulu/epoch_processing/historical_summaries_update/pyspec_tests/historical_summaries_accumulator` | Historical summary ring update |
| `random_inactivity_scores_empty_participation` | `tests/minimal/fulu/epoch_processing/inactivity_updates/pyspec_tests/random_inactivity_scores_empty_participation` | Inactivity score update |
| `12_ok_support` | `tests/minimal/fulu/epoch_processing/justification_and_finalization/pyspec_tests/12_ok_support` | Justification and finalization |
| `slightly_larger_random` | `tests/minimal/fulu/epoch_processing/participation_flag_updates/pyspec_tests/slightly_larger_random` | Participation flag rotation |
| `activation_churn_limit__less_than_activation_limit` | `tests/minimal/fulu/epoch_processing/registry_updates/pyspec_tests/activation_churn_limit__less_than_activation_limit` | Registry activation and exit queue updates |
| `genesis_epoch_no_attestations_no_penalties` | `tests/minimal/fulu/epoch_processing/rewards_and_penalties/pyspec_tests/genesis_epoch_no_attestations_no_penalties` | Inherited rewards and penalties |
| `low_penalty` | `tests/minimal/fulu/epoch_processing/slashings/pyspec_tests/low_penalty` | Correlation penalty processing |
| `flush_slashings` | `tests/minimal/fulu/epoch_processing/slashings_reset/pyspec_tests/flush_slashings` | Slashings vector reset |
| `updated_randao_mixes` | `tests/minimal/fulu/epoch_processing/randao_mixes_reset/pyspec_tests/updated_randao_mixes` | RANDAO mix ring update |
| `sync_committees_progress_not_genesis` | `tests/minimal/fulu/epoch_processing/sync_committee_updates/pyspec_tests/sync_committees_progress_not_genesis` | Sync committee period rotation |

The archived source, published size, and SHA-256 are recorded in [`docs/FULU-SPEC-LOCK.md`](../../../../docs/FULU-SPEC-LOCK.md). The ignored archive is useful for selecting future cases, while these checked-in fixtures keep ordinary tests repeatable and offline.

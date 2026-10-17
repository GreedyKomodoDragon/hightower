# Consensus processing flow

The consensus package moves a `BeaconState` forward through slots, applies epoch updates at epoch boundaries, and checks blocks when they arrive. A slot still passes when no block arrives. This repository uses eight slots per epoch in its minimal test preset; Ethereum's regular preset uses 32.

## When a block arrives

`block.stateTransition` in [`block.zig`](block.zig) applies a signed block to the state:

```text
current state
    │
    ├─ advance through any intervening slots
    │      └─ record state and block roots; run epoch updates at boundaries
    ├─ check proposer signature
    ├─ check slot, selected proposer, parent root, and supported operations
    ├─ update block header and process execution payload, RANDAO, Eth1 vote,
    │  and sync aggregate
    └─ compare resulting state root with the block's declared state root
```

If any check fails, the transition returns an error. Processing mutates the supplied state along the way, so callers should discard that state when an error is returned.

Block operation lists and withdrawals are currently required to be empty. The execution payload is checked through the supplied execution-engine interface.

## Advancing slots and epochs

[`transition.zig`](transition.zig) advances time one slot at a time. It records the state and latest block-header roots in history rings before moving past a slot. This happens whether or not a block was received for that slot. When the last slot of an epoch is processed, it calls [`epoch.processEpoch`](epoch.zig).

`processEpoch` runs the Fulu epoch handlers in consensus order:

```text
justification/finality
  → inactivity scores and rewards/penalties
  → validator registry and slashings
  → Eth1 vote reset and pending deposits/consolidations
  → effective balances and history resets/summaries
  → participation rotation and sync committee update
  → proposer lookahead
```

The order matters because later handlers use state updated by earlier handlers. For example, pending balance changes happen before effective balances are recalculated, and the proposer lookahead uses the updated validator registry.

## Tests and fixtures

[`tests.zig`](tests.zig) is the test root. [`fixture_runner.zig`](fixture_runner.zig) describes the selected pinned consensus-spec fixtures, decodes their compressed SSZ state and block data, and sends them through the matching slot, epoch, or block path. Handler-specific tests compare the fields owned by that handler; selected end-to-end fixtures compare the full resulting state.

The implementation and selected fixture coverage target Fulu's minimal preset. The selected fixtures do not cover every consensus-spec case.

[`helpers.zig`](helpers.zig) derives beacon committees from the validators active in a slot's epoch. Its seed combines the epoch, an attestation purpose tag, and a historical RANDAO mix; the pinned shuffle assigns validators across the minimal preset's eight slots, with up to four committees per slot. A small active set can produce empty committees.

## Fork-choice clock and anchor

[`fork_choice.zig`](fork_choice.zig) initializes fork-choice metadata from a trusted anchor block and state. The clock advances one slot at a time; entering a slot clears proposer boost, and entering an epoch promotes newer unrealized checkpoints. Its current tick path targets the minimal preset's six-second slots and eight-slot epochs. Fulu's data-availability validation is performed by block processing and is not stored in the fork-choice store.

## Signing domains and BLS verification

`domains.computeDomain` takes the network fork version explicitly. `getDomain`
selects the state's previous version before `state.fork.epoch`, and its current
version at or after that epoch. Fixed-version operations instead call
`computeDomain`: deposits use the genesis version with a zero validators root;
BLS-to-execution changes use the genesis version with the chain's validators
root; voluntary exits use the Capella version with that chain root. The existing
pending-deposit path uses the pinned minimal genesis version `0x00000001`.
Exit and address-change operation handlers remain outside the supported path.

The domain tests contain known answers independently evaluated with Python
`hashlib.sha256` from the two-field SSZ container formulas in the
[v1.6.1 Phase 0 specification](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/phase0/beacon-chain.md#compute_domain),
using `0x02` repeated for the chain root and `0x03` repeated for the object root.
Versions come from the [pinned minimal configuration](https://github.com/ethereum/consensus-specs/blob/v1.6.1/configs/minimal.yaml).
These are specification-derived known answers, not separately published official
domain vectors. The pinned block and pending-deposit fixtures additionally check
signatures against official signing roots through transition processing.
The [Deneb exit rule](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/deneb/beacon-chain.md#modified-process_voluntary_exit)
and [Capella address-change rule](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/capella/beacon-chain.md#new-process_bls_to_execution_change)
are inherited by Fulu.

`bls.zig` keeps transition code independent of the existing pinned `blst` v0.3.17
API. It accepts only 32-byte messages, 48-byte public keys, and 96-byte signatures;
malformed points, wrong subgroups, infinity keys, and verification failures return
errors. `verifyAggregate` implements Ethereum's `eth_fast_aggregate_verify`:
empty participation succeeds only with the canonical infinity signature. Keys
must already have proofs of possession, as validator registration provides.

`bls_vectors_test.zig` copies small inputs verbatim, with each upstream path
recorded beside its test. It includes all 12 Ethereum aggregate verification cases
from [consensus-specs v1.6.1 general.tar.gz](https://github.com/ethereum/consensus-specs/releases/tag/v1.6.1)
(verified SHA-256 `87898ba7a3fa16bc66b08c88b4ccab008833a517a7602cf421c6ce79734e07e9`).
That bundle does not include the standalone `verify` suite. The 29 single-signature
cases and two subgroup-rejection inputs come from the official
[bls12-381-tests v0.1.2 bls_tests_json.tar.gz](https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2)
(downloaded SHA-256 `0dc1dfabfa7b3e0f8e8029f9cb2bb8733597526fa085b18f160d2c4eb0b448bc`).
The generic BLS suite's empty-aggregate rule differs from Ethereum's; the Ethereum
cases are used for this wrapper. Run these tests with `zig build test-transition`.

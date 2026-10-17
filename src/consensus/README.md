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

## Fork-choice clock and anchor

[`fork_choice.zig`](fork_choice.zig) initializes fork-choice metadata from a trusted anchor block and state. The clock advances one slot at a time; entering a slot clears proposer boost, and entering an epoch promotes newer unrealized checkpoints. Its current tick path targets the minimal preset's six-second slots and eight-slot epochs. Fulu's data-availability validation is performed by block processing and is not stored in the fork-choice store.

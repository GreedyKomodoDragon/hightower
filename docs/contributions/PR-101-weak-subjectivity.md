# PR #101: Fulu weak subjectivity validation

[PR #101](https://github.com/GreedyKomodoDragon/hightower/pull/101) implements [issue #72](https://github.com/GreedyKomodoDragon/hightower/issues/72). The evidence below maps each issue acceptance criterion to the code and checks that demonstrate it.

## Acceptance criteria and evidence

### The period is computed per the spec from validator balances

`computeWeakSubjectivityPeriod` counts validators active at the state's current epoch, derives their average effective balance and Fulu balance churn, then applies the two weak-subjectivity formula branches using integer arithmetic. Fulu's 2,048 ETH effective-balance cap and Electra churn limit are used where the Phase 0 formula's 32 ETH assumptions no longer apply.

- Implementation: [`helpers.zig`](../../src/consensus/helpers.zig#L187-L219).
- Reference equations: [consensus-specs v1.6.1 weak-subjectivity guide](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/phase0/weak-subjectivity.md#compute_weak_subjectivity_period).
- Test evidence: [`helpers.zig`](../../src/consensus/helpers.zig#L470-L508) checks a 32 ETH validator and a 32,768-validator compounding set. The expected results are 256 and 354 epochs, respectively; the latter exercises the validator churn and top-up branch.

### A stale checkpoint is rejected; a fresh one is accepted

`isWithinWeakSubjectivityPeriod` accepts a checkpoint when the current epoch is at most its epoch plus the computed period, and returns `false` after that boundary.

- Implementation: [`fork_choice.zig`](../../src/consensus/fork_choice.zig#L148-L162).
- Test evidence: [`fork_choice.zig`](../../src/consensus/fork_choice.zig#L261-L299) checks acceptance at the inclusive boundary and rejection one epoch later.

### Checkpoint root/epoch consistency is checked before use

Before calculating freshness, the validator checks that the supplied state's slot maps to the checkpoint epoch and that the checkpoint root matches the state's block root for that epoch. For checkpoints at or below local finality, it also checks the root against the canonical finalized chain.

- Implementation: [`fork_choice.zig`](../../src/consensus/fork_choice.zig#L148-L157).
- Test evidence: [`fork_choice.zig`](../../src/consensus/fork_choice.zig#L281-L298) rejects mismatched roots and epochs, including a root that conflicts with the finalized chain.

### Unit tests cover period boundaries

- Fresh at the exact boundary and stale one epoch later: [`fork_choice.zig`](../../src/consensus/fork_choice.zig#L274-L291).
- Formula branches and the empty active-validator error: [`helpers.zig`](../../src/consensus/helpers.zig#L470-L508).
- Tests are included through the consensus test root: [`tests.zig`](../../src/consensus/tests.zig#L1-L25), run by `zig build test-transition`.

## Verification record

- `zig build test`: passed.
- `zig build test-transition`: 108 passed, 1 failed. The failure is the fork-choice block import test returning `InvalidParentRoot`; the weak subjectivity tests passed in that run.
- `git diff --check`: passed before the implementation commit.

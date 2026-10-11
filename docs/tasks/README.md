# Fulu task backlog

The project target is **Fulu with the minimal preset for local development and conformance**. This page indexes the first batch of small, reviewable GitHub issues. It does not claim current Hoodi or mainnet compatibility.

GitHub Issues in [`GreedyKomodoDragon/hightower`](https://github.com/GreedyKomodoDragon/hightower) are the source of truth for ticket scope, acceptance criteria, status, and dependencies. This page is a compact index; issue bodies contain the full task details.

## First batch

| Key | Issue | Size | Depends on | Outcome |
| --- | --- | --- | --- | --- |
| FULU-001 | [Pin Fulu spec and test-vector revisions (#12)](https://github.com/GreedyKomodoDragon/hightower/issues/12) | S | — | Reproducible source revisions and fixture checksum |
| FULU-002 | [Capture the current test baseline (#13)](https://github.com/GreedyKomodoDragon/hightower/issues/13) | S | — | Known pass/fail/unsupported baseline |
| FULU-003 | [Map Fulu SSZ schemas to current support (#14)](https://github.com/GreedyKomodoDragon/hightower/issues/14) | M | 001, 002 | Field/type coverage matrix and ranked gaps |
| FULU-004 | [Select the first Fulu conformance suites (#15)](https://github.com/GreedyKomodoDragon/hightower/issues/15) | S | 001 | Pinned, minimal first fixture set |
| FULU-005 | [Turn the coverage gaps into implementation tickets (#16)](https://github.com/GreedyKomodoDragon/hightower/issues/16) | S | 002, 003, 004 | A concrete next batch of code tickets |

**Recommended order:** FULU-001 and FULU-002 can start independently; FULU-003 and FULU-004 follow; FULU-005 closes the batch by producing implementation tickets from evidence.

## Later workstreams

These are planning buckets, not yet sized tickets. Split each into issues after FULU-005 has established actual gaps and fixture scope.

1. Fulu SSZ/hash-tree-root support and complete Fulu Beacon types.
2. Consensus helpers and Fulu slot/epoch processing.
3. Fulu block processing and operation suites.
4. Fulu fork choice.
5. Persistence and Engine API.
6. Fulu P2P, sync, and PeerDAS/data availability.
7. Beacon API and Hoodi interoperability.

## Using GitHub Issues

Use the repository's Issues page:

- **Milestones:** `Fulu baseline`, `Fulu types and roots`, `Fulu local state transition`, `Fulu fork choice`, `Hoodi interoperability`.
- **Dependencies:** keep `Depends on` in the issue body and cross-link GitHub issues when the dependent ticket is filed.
- **Labels:** use labels such as `ssz`, `fixtures`, `beacon-types`, `state-transition`, `fork-choice`, `execution-api`, and `networking` when they help filter the backlog.
- **Status and assignee:** use GitHub for live status; keep technical decisions and implementation artifacts in the repository.
- **Size:** keep the rough S/M/L estimates in the issue body. They are triage estimates, not commitments.

Keep the local key (`FULU-###`) in each issue title. Dependent issues link to their prerequisites.

## Ticket definition of ready

A ticket should name one outcome, its dependencies, the files or protocol surfaces likely involved, and observable acceptance criteria. Split work if its estimate is `L` or if it has multiple independently reviewable outcomes. Do not pre-create implementation tickets for SSZ gaps before the coverage inventory identifies them.

Use [TEMPLATE.md](TEMPLATE.md) as a starting point for new issue bodies.

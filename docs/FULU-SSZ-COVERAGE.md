# Fulu SSZ schema coverage

## Baseline

This inventory uses the Fulu v1.6.1 specification pinned at commit `5fa6edcca8ab4cf548653e6680b17b9d3e04d225` and the minimal preset. Fulu builds on Electra; the schemas below include the relevant inherited Phase0, Altair, Bellatrix, Capella, Deneb, and Electra definitions, then apply the Fulu `BeaconState` extension. See [the lock](FULU-SPEC-LOCK.md), [FULU-001](https://github.com/GreedyKomodoDragon/hightower/issues/12), [FULU-002](https://github.com/GreedyKomodoDragon/hightower/issues/13), [pinned Fulu spec](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/fulu/beacon-chain.md), and [pinned Electra spec](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/electra/beacon-chain.md).

The 39 remaining generic vector tests explicitly return `VectorNotImplemented`; they cover compatible unions and progressive types, which do not appear in the Fulu beacon schema closure inventoried here.

## Support key

The SSZ library has generic encode/decode routes for unsigned integers through 256 bits, booleans, fixed arrays, bitvectors, bitlists, bytevectors, bytelists, lists, and regular containers. Its hash-tree-root path covers those same required kinds, including nested containers, vectors, and lists. Relevant routes are in [`type_descriptor.zig`](../src/ssz/type_descriptor.zig), [`serialize.zig`](../src/ssz/serialize.zig), [`deserialize.zig`](../src/ssz/deserialize.zig), [`hash_tree_root.zig`](../src/merkle/hash_tree_root.zig), and [`get_chunks.zig`](../src/merkle/get_chunks.zig).

**Generic route only** means the kind can be processed when supplied as a Zig type, but no named Fulu type exists for it yet. [`fulu.zig`](../src/types/fulu.zig) declares shared types, block schemas, and `ExecutionPayloadHeader`. [`fulu_test.zig`](../src/types/fulu_test.zig) checks basic block type structure; SSZ roots, round trips, and pinned fixtures live in [`fulu_fixture_test.zig`](../src/ssz/fulu_fixture_test.zig). That test covers one `ssz_nil` fixture for each listed Fulu block schema and nested type, plus random `BeaconBlock` cases 7 and 22. The raw SSZ fixtures are checked in under [`src/ssz/fixtures`](../src/ssz/fixtures), decoded and re-encoded byte-for-byte, and checked against the roots from the pinned fixture tree. `BeaconState` remains incomplete. “Fixture cases” counts the pinned test bundle’s cases on disk, not cases currently executed by Hightower.

## BeaconState fields

Each field in the Fulu state is listed explicitly. Bounds are resolved against the pinned minimal preset.

| Field | SSZ type and minimal bound | Code / fixture |
| --- | --- | --- |
| `genesis_time` | `uint64` | Generic route only; `BeaconState` fixture |
| `genesis_validators_root` | `Root` (`Bytes32`) | Generic route only; `BeaconState` fixture |
| `slot` | `Slot` (`uint64`) | Generic route only; `BeaconState` fixture |
| `fork` | `Fork` container | `Fork` implemented; BeaconState field not yet declared |
| `latest_block_header` | `BeaconBlockHeader` container | `BeaconBlockHeader` implemented; BeaconState field not yet declared |
| `block_roots` | `Vector[Root, 64]` | Generic route only; `BeaconState` fixture |
| `state_roots` | `Vector[Root, 64]` | Generic route only; `BeaconState` fixture |
| `historical_roots` | `List[Root, 16,777,216]` | Generic route only; `BeaconState` fixture |
| `eth1_data` | `Eth1Data` container | `Eth1Data` implemented; BeaconState field not yet declared |
| `eth1_data_votes` | `List[Eth1Data, 32]` (`4 × 8`) | Generic route only; `BeaconState` fixture |
| `eth1_deposit_index` | `uint64` | Generic route only; `BeaconState` fixture |
| `validators` | `List[Validator, 1,099,511,627,776]` | `Validator` implemented; BeaconState field not yet declared |
| `balances` | `List[Gwei, 1,099,511,627,776]` (`Gwei = uint64`) | Generic route only; `BeaconState` fixture |
| `randao_mixes` | `Vector[Bytes32, 64]` | Generic route only; `BeaconState` fixture |
| `slashings` | `Vector[Gwei, 64]` (`Gwei = uint64`) | Generic route only; `BeaconState` fixture |
| `previous_epoch_participation` | `List[ParticipationFlags, 1,099,511,627,776]` (`ParticipationFlags = uint8`) | Generic route only; `BeaconState` fixture |
| `current_epoch_participation` | `List[ParticipationFlags, 1,099,511,627,776]` (`ParticipationFlags = uint8`) | Generic route only; `BeaconState` fixture |
| `justification_bits` | `Bitvector[4]` | Generic route only; `BeaconState` fixture |
| `previous_justified_checkpoint` | `Checkpoint` container | `Checkpoint` implemented; BeaconState field not yet declared |
| `current_justified_checkpoint` | `Checkpoint` container | `Checkpoint` implemented; BeaconState field not yet declared |
| `finalized_checkpoint` | `Checkpoint` container | `Checkpoint` implemented; BeaconState field not yet declared |
| `inactivity_scores` | `List[uint64, 1,099,511,627,776]` | Generic route only; `BeaconState` fixture |
| `current_sync_committee` | `SyncCommittee` container | `SyncCommittee` implemented; BeaconState field not yet declared |
| `next_sync_committee` | `SyncCommittee` container | `SyncCommittee` implemented; BeaconState field not yet declared |
| `latest_execution_payload_header` | `ExecutionPayloadHeader` container | `ExecutionPayloadHeader` implemented; BeaconState field not yet declared |
| `next_withdrawal_index` | `WithdrawalIndex` (`uint64`) | Generic route only; `BeaconState` fixture |
| `next_withdrawal_validator_index` | `ValidatorIndex` (`uint64`) | Generic route only; `BeaconState` fixture |
| `historical_summaries` | `List[HistoricalSummary, 16,777,216]` | `HistoricalSummary` implemented; BeaconState field not yet declared |
| `deposit_requests_start_index` | `uint64` | Generic route only; `BeaconState` fixture |
| `deposit_balance_to_consume` | `Gwei` (`uint64`) | Generic route only; `BeaconState` fixture |
| `exit_balance_to_consume` | `Gwei` (`uint64`) | Generic route only; `BeaconState` fixture |
| `earliest_exit_epoch` | `Epoch` (`uint64`) | Generic route only; `BeaconState` fixture |
| `consolidation_balance_to_consume` | `Gwei` (`uint64`) | Generic route only; `BeaconState` fixture |
| `earliest_consolidation_epoch` | `Epoch` (`uint64`) | Generic route only; `BeaconState` fixture |
| `pending_deposits` | `List[PendingDeposit, 134,217,728]` | `PendingDeposit` implemented; BeaconState field not yet declared |
| `pending_partial_withdrawals` | `List[PendingPartialWithdrawal, 64]` | `PendingPartialWithdrawal` implemented; BeaconState field not yet declared |
| `pending_consolidations` | `List[PendingConsolidation, 64]` | `PendingConsolidation` implemented; BeaconState field not yet declared |
| `proposer_lookahead` | `Vector[ValidatorIndex, 16]` (`(1 + 1) × 8`) | Generic route only; `BeaconState` fixture |

## Recursive container schemas

Fields are given as `field: SSZ type`; aliases follow the pinned consensus specifications. Every listed type has 123 expected-root cases in `testdata/consensus-specs-v1.6.1/tests/minimal/fulu/ssz_static/<Type>/`, across `ssz_lengthy`, `ssz_max`, `ssz_nil`, `ssz_one`, `ssz_random`, `ssz_random_chaos`, and `ssz_zero`. The fixture test uses `ssz_nil/case_0` for each listed block schema and nested type, including `ExecutionPayloadHeader`, plus random `BeaconBlock` cases 7 and 22. The checked-in raw SSZ files are decompressed copies of each case's `serialized.ssz_snappy`; tests decode them, check the root from the adjacent `roots.yaml`, and verify byte-for-byte reserialization. Most pinned cases remain unwired.

| Type (kind) | Schema fields and bounds | Fixture cases |
| --- | --- | --- |
| `Attestation` (container) | `aggregation_bits: Bitlist[8192]`; `data: AttestationData`; `signature: BLSSignature`; `committee_bits: Bitvector[4]` | 123: `ssz_static/Attestation/` |
| `AttestationData` (container) | `slot: Slot`; `index: CommitteeIndex`; `beacon_block_root: Root`; `source: Checkpoint`; `target: Checkpoint` | 123: `ssz_static/AttestationData/` |
| `AttesterSlashing` (container) | `attestation_1: IndexedAttestation`; `attestation_2: IndexedAttestation` | 123: `ssz_static/AttesterSlashing/` |
| `BLSToExecutionChange` (container) | `validator_index: ValidatorIndex`; `from_bls_pubkey: BLSPubkey`; `to_execution_address: ExecutionAddress` | 123: `ssz_static/BLSToExecutionChange/` |
| `BeaconBlock` (container) | `slot: Slot`; `proposer_index: ValidatorIndex`; `parent_root: Root`; `state_root: Root`; `body: BeaconBlockBody` | 123: `ssz_static/BeaconBlock/` |
| `BeaconBlockBody` (container) | `randao_reveal: BLSSignature`; `eth1_data: Eth1Data`; `graffiti: Bytes32`; `proposer_slashings: List[ProposerSlashing, 16]`; `attester_slashings: List[AttesterSlashing, 1]`; `attestations: List[Attestation, 8]`; `deposits: List[Deposit, 16]`; `voluntary_exits: List[SignedVoluntaryExit, 16]`; `sync_aggregate: SyncAggregate`; `execution_payload: ExecutionPayload`; `bls_to_execution_changes: List[SignedBLSToExecutionChange, 16]`; `blob_kzg_commitments: List[KZGCommitment, 4096]`; `execution_requests: ExecutionRequests` | 123: `ssz_static/BeaconBlockBody/` |
| `BeaconBlockHeader` (container) | `slot: Slot`; `proposer_index: ValidatorIndex`; `parent_root: Root`; `state_root: Root`; `body_root: Root` | 123: `ssz_static/BeaconBlockHeader/` |
| `Checkpoint` (container) | `epoch: Epoch`; `root: Root` | 123: `ssz_static/Checkpoint/` |
| `ConsolidationRequest` (container) | `source_address: ExecutionAddress`; `source_pubkey: BLSPubkey`; `target_pubkey: BLSPubkey` | 123: `ssz_static/ConsolidationRequest/` |
| `Deposit` (container) | `proof: Vector[Bytes32, 33]`; `data: DepositData` | 123: `ssz_static/Deposit/` |
| `DepositData` (container) | `pubkey: BLSPubkey`; `withdrawal_credentials: Bytes32`; `amount: Gwei`; `signature: BLSSignature` | 123: `ssz_static/DepositData/` |
| `DepositRequest` (container) | `pubkey: BLSPubkey`; `withdrawal_credentials: Bytes32`; `amount: Gwei`; `signature: BLSSignature`; `index: uint64` | 123: `ssz_static/DepositRequest/` |
| `Eth1Data` (container) | `deposit_root: Root`; `deposit_count: uint64`; `block_hash: Hash32` | 123: `ssz_static/Eth1Data/` |
| `ExecutionPayload` (container) | `parent_hash: Hash32`; `fee_recipient: ExecutionAddress`; `state_root: Bytes32`; `receipts_root: Bytes32`; `logs_bloom: ByteVector[256]`; `prev_randao: Bytes32`; `block_number: uint64`; `gas_limit: uint64`; `gas_used: uint64`; `timestamp: uint64`; `extra_data: ByteList[32]`; `base_fee_per_gas: uint256`; `block_hash: Hash32`; `transactions: List[Transaction, 1,048,576]` (`Transaction = ByteList[1,073,741,824]`); `withdrawals: List[Withdrawal, 4]`; `blob_gas_used: uint64`; `excess_blob_gas: uint64` | 123: `ssz_static/ExecutionPayload/` |
| `ExecutionPayloadHeader` (container) | `parent_hash: Hash32`; `fee_recipient: ExecutionAddress`; `state_root: Bytes32`; `receipts_root: Bytes32`; `logs_bloom: ByteVector[256]`; `prev_randao: Bytes32`; `block_number: uint64`; `gas_limit: uint64`; `gas_used: uint64`; `timestamp: uint64`; `extra_data: ByteList[32]`; `base_fee_per_gas: uint256`; `block_hash: Hash32`; `transactions_root: Root`; `withdrawals_root: Root`; `blob_gas_used: uint64`; `excess_blob_gas: uint64` | 123: `ssz_static/ExecutionPayloadHeader/` |
| `ExecutionRequests` (container) | `deposits: List[DepositRequest, 8192]`; `withdrawals: List[WithdrawalRequest, 16]`; `consolidations: List[ConsolidationRequest, 2]` | 123: `ssz_static/ExecutionRequests/` |
| `Fork` (container) | `previous_version: Version`; `current_version: Version`; `epoch: Epoch` | 123: `ssz_static/Fork/` |
| `HistoricalSummary` (container) | `block_summary_root: Root`; `state_summary_root: Root` | 123: `ssz_static/HistoricalSummary/` |
| `IndexedAttestation` (container) | `attesting_indices: List[ValidatorIndex, 8192]`; `data: AttestationData`; `signature: BLSSignature` | 123: `ssz_static/IndexedAttestation/` |
| `PendingConsolidation` (container) | `source_index: ValidatorIndex`; `target_index: ValidatorIndex` | 123: `ssz_static/PendingConsolidation/` |
| `PendingDeposit` (container) | `pubkey: BLSPubkey`; `withdrawal_credentials: Bytes32`; `amount: Gwei`; `signature: BLSSignature`; `slot: Slot` | 123: `ssz_static/PendingDeposit/` |
| `PendingPartialWithdrawal` (container) | `validator_index: ValidatorIndex`; `amount: Gwei`; `withdrawable_epoch: Epoch` | 123: `ssz_static/PendingPartialWithdrawal/` |
| `ProposerSlashing` (container) | `signed_header_1: SignedBeaconBlockHeader`; `signed_header_2: SignedBeaconBlockHeader` | 123: `ssz_static/ProposerSlashing/` |
| `SignedBLSToExecutionChange` (container) | `message: BLSToExecutionChange`; `signature: BLSSignature` | 123: `ssz_static/SignedBLSToExecutionChange/` |
| `SignedBeaconBlock` (container) | `message: BeaconBlock`; `signature: BLSSignature` | 123: `ssz_static/SignedBeaconBlock/` |
| `SignedBeaconBlockHeader` (container) | `message: BeaconBlockHeader`; `signature: BLSSignature` | 123: `ssz_static/SignedBeaconBlockHeader/` |
| `SignedVoluntaryExit` (container) | `message: VoluntaryExit`; `signature: BLSSignature` | 123: `ssz_static/SignedVoluntaryExit/` |
| `SyncAggregate` (container) | `sync_committee_bits: Bitvector[32]`; `sync_committee_signature: BLSSignature` | 123: `ssz_static/SyncAggregate/` |
| `SyncCommittee` (container) | `pubkeys: Vector[BLSPubkey, 32]`; `aggregate_pubkey: BLSPubkey` | 123: `ssz_static/SyncCommittee/` |
| `Validator` (container) | `pubkey: BLSPubkey`; `withdrawal_credentials: Bytes32`; `effective_balance: Gwei`; `slashed: boolean`; `activation_eligibility_epoch: Epoch`; `activation_epoch: Epoch`; `exit_epoch: Epoch`; `withdrawable_epoch: Epoch` | 123: `ssz_static/Validator/` |
| `VoluntaryExit` (container) | `epoch: Epoch`; `validator_index: ValidatorIndex` | 123: `ssz_static/VoluntaryExit/` |
| `Withdrawal` (container) | `index: WithdrawalIndex`; `validator_index: ValidatorIndex`; `address: ExecutionAddress`; `amount: Gwei` | 123: `ssz_static/Withdrawal/` |
| `WithdrawalRequest` (container) | `source_address: ExecutionAddress`; `validator_pubkey: BLSPubkey`; `amount: Gwei` | 123: `ssz_static/WithdrawalRequest/` |

Aliases relevant to the closure: `Slot`, `Epoch`, `CommitteeIndex`, `ValidatorIndex`, `WithdrawalIndex`, and `Gwei` are `uint64`; `ParticipationFlags` is `uint8`; `Root`, `Hash32`, and `Bytes32` are 32-byte vectors; `Version` is 4 bytes; `ExecutionAddress` is 20 bytes; `BLSPubkey` and `KZGCommitment` are 48 bytes; `BLSSignature` is 96 bytes; `boolean` is `bool`.

The `blob_kzg_commitments` SSZ bound is the fixed minimal-preset `MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096`. Fulu's blob schedule changes the epoch-dependent block validity limit, not this SSZ list bound.

## Ranked gaps

| Rank | Gap | Evidence and consequence |
| --- | --- | --- |
| 1 | BeaconState schema remains incomplete | `BeaconBlock`, `BeaconBlockBody`, `SignedBeaconBlock`, their nested types, and `ExecutionPayloadHeader` are declared and have pinned minimal fixture coverage. The complete Fulu state root still cannot be computed through a named project type. |
| 2 | Most Fulu static fixtures are not wired into the project test build | `src/ssz/fulu_fixture_test.zig` covers one `ssz_nil` case per block schema and nested type plus two random `BeaconBlock` cases. The broader fixture selection and integration tracked by FULU-004 and FULU-009 remain outstanding. |
| Out of scope | Generic compatible-union and progressive-type gaps | The 39 baseline placeholders cover those features; none occurs in the Fulu schema closure above. Generalized-index proof helpers are also outside SSZ serialization and hash-tree-root for these values. |

No generic primitive or container-kind gap was found in this schema closure. The next implementation work is to complete the state schema and extend fixture execution to the set selected by FULU-004.

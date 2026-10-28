//! Shared Fulu consensus types used by the beacon block and beacon state schemas.
//!
//! A BeaconBlock is an SSZ container ordered as `slot`, `proposer_index`,
//! `parent_root`, `state_root`, and `body`. The body groups the block's
//! attestations and slashings, deposits and exits, sync aggregate, execution
//! payload, BLS changes, blob commitments, and execution requests. A
//! SignedBeaconBlock wraps the block with its proposer signature.
//!
//! BeaconState is a separate container for fork metadata, the latest block
//! header, historical roots, Eth1 data, validators and balances, sync
//! committees, the latest execution payload header, pending queues, and
//! proposer lookahead. This file defines the Fulu block and shared nested
//! containers. Struct field order is SSZ field order. Fixed vectors use Zig
//! arrays, while variable lists use the generic SSZ List type.

const types = @import("types");
const preset = @import("consensus_preset").Config;

/// Scalar aliases and fixed-width byte values shared by the selected Fulu preset.
pub const Slot = u64;
pub const Epoch = u64;
pub const CommitteeIndex = u64;
pub const ValidatorIndex = u64;
pub const WithdrawalIndex = u64;
pub const Gwei = u64;
pub const ParticipationFlags = u8;

pub const Root = [32]u8;
pub const Hash32 = [32]u8;
pub const Bytes32 = [32]u8;
pub const Version = [4]u8;
pub const ExecutionAddress = [20]u8;
pub const BLSPubkey = [48]u8;
pub const KZGCommitment = [48]u8;
pub const BLSSignature = [96]u8;

pub const Fork = struct {
    previous_version: Version,
    current_version: Version,
    epoch: Epoch,
};

/// Block metadata stored in a BeaconState or wrapped as a signed header.
pub const BeaconBlockHeader = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Root,
    state_root: Root,
    body_root: Root,
};

pub const SignedBeaconBlockHeader = struct {
    message: BeaconBlockHeader,
    signature: BLSSignature,
};

pub const Checkpoint = struct {
    epoch: Epoch,
    root: Root,
};

pub const Eth1Data = struct {
    deposit_root: Root,
    deposit_count: u64,
    block_hash: Hash32,
};

pub const Validator = struct {
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    effective_balance: Gwei,
    slashed: bool,
    activation_eligibility_epoch: Epoch,
    activation_epoch: Epoch,
    exit_epoch: Epoch,
    withdrawable_epoch: Epoch,
};

pub const SyncCommittee = struct {
    /// Public key count is selected by the active consensus preset.
    pubkeys: [preset.SYNC_COMMITTEE_SIZE]BLSPubkey,
    aggregate_pubkey: BLSPubkey,
};

pub const SyncAggregate = struct {
    sync_committee_bits: types.BitVector(preset.SYNC_COMMITTEE_SIZE),
    sync_committee_signature: BLSSignature,
};

pub const HistoricalSummary = struct {
    block_summary_root: Root,
    state_summary_root: Root,
};

pub const AttestationData = struct {
    slot: Slot,
    index: CommitteeIndex,
    beacon_block_root: Root,
    source: Checkpoint,
    target: Checkpoint,
};

pub const PendingDeposit = struct {
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: BLSSignature,
    slot: Slot,
};

pub const PendingPartialWithdrawal = struct {
    validator_index: ValidatorIndex,
    amount: Gwei,
    withdrawable_epoch: Epoch,
};

pub const PendingConsolidation = struct {
    source_index: ValidatorIndex,
    target_index: ValidatorIndex,
};

pub const Attestation = struct {
    aggregation_bits: types.BitList(preset.MAX_VALIDATORS_PER_COMMITTEE),
    data: AttestationData,
    signature: BLSSignature,
    committee_bits: types.BitVector(preset.MAX_COMMITTEES_PER_SLOT),
};

pub const IndexedAttestation = struct {
    attesting_indices: types.List(ValidatorIndex, preset.MAX_VALIDATORS_PER_COMMITTEE),
    data: AttestationData,
    signature: BLSSignature,
};

pub const AttesterSlashing = struct {
    attestation_1: IndexedAttestation,
    attestation_2: IndexedAttestation,
};

pub const ProposerSlashing = struct {
    signed_header_1: SignedBeaconBlockHeader,
    signed_header_2: SignedBeaconBlockHeader,
};

pub const DepositData = struct {
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: BLSSignature,
};

pub const DepositDataList = types.List(DepositData, @as(usize, 1) << 32);

pub const Deposit = struct {
    proof: [33]Bytes32,
    data: DepositData,
};

pub const VoluntaryExit = struct {
    epoch: Epoch,
    validator_index: ValidatorIndex,
};

pub const SignedVoluntaryExit = struct {
    message: VoluntaryExit,
    signature: BLSSignature,
};

pub const BLSToExecutionChange = struct {
    validator_index: ValidatorIndex,
    from_bls_pubkey: BLSPubkey,
    to_execution_address: ExecutionAddress,
};

pub const SignedBLSToExecutionChange = struct {
    message: BLSToExecutionChange,
    signature: BLSSignature,
};

pub const Withdrawal = struct {
    index: WithdrawalIndex,
    validator_index: ValidatorIndex,
    address: ExecutionAddress,
    amount: Gwei,
};

pub const DepositRequest = struct {
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: BLSSignature,
    index: u64,
};

pub const WithdrawalRequest = struct {
    source_address: ExecutionAddress,
    validator_pubkey: BLSPubkey,
    amount: Gwei,
};

pub const ConsolidationRequest = struct {
    source_address: ExecutionAddress,
    source_pubkey: BLSPubkey,
    target_pubkey: BLSPubkey,
};

pub const ExecutionPayload = struct {
    parent_hash: Hash32,
    fee_recipient: ExecutionAddress,
    state_root: Bytes32,
    receipts_root: Bytes32,
    logs_bloom: [256]u8,
    prev_randao: Bytes32,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: types.ByteList(32),
    base_fee_per_gas: u256,
    block_hash: Hash32,
    transactions: types.List(types.ByteList(preset.MAX_TRANSACTION_BYTES), preset.MAX_TRANSACTIONS_PER_PAYLOAD),
    withdrawals: types.List(Withdrawal, preset.MAX_WITHDRAWALS_PER_PAYLOAD),
    blob_gas_used: u64,
    excess_blob_gas: u64,
};

pub const ExecutionPayloadHeader = struct {
    parent_hash: Hash32,
    fee_recipient: ExecutionAddress,
    state_root: Bytes32,
    receipts_root: Bytes32,
    logs_bloom: [256]u8,
    prev_randao: Bytes32,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: types.ByteList(32),
    base_fee_per_gas: u256,
    block_hash: Hash32,
    transactions_root: Root,
    withdrawals_root: Root,
    blob_gas_used: u64,
    excess_blob_gas: u64,
};

pub const ExecutionRequests = struct {
    deposits: types.List(DepositRequest, preset.MAX_DEPOSIT_REQUESTS_PER_PAYLOAD),
    withdrawals: types.List(WithdrawalRequest, preset.MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD),
    consolidations: types.List(ConsolidationRequest, preset.MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD),
};

pub const BeaconBlockBody = struct {
    randao_reveal: BLSSignature,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: types.List(ProposerSlashing, preset.MAX_PROPOSER_SLASHINGS),
    attester_slashings: types.List(AttesterSlashing, preset.MAX_ATTESTER_SLASHINGS_ELECTRA),
    attestations: types.List(Attestation, preset.MAX_ATTESTATIONS_ELECTRA),
    deposits: types.List(Deposit, preset.MAX_DEPOSITS_PER_BLOCK),
    voluntary_exits: types.List(SignedVoluntaryExit, preset.MAX_VOLUNTARY_EXITS),
    sync_aggregate: SyncAggregate,
    execution_payload: ExecutionPayload,
    bls_to_execution_changes: types.List(SignedBLSToExecutionChange, preset.MAX_BLS_TO_EXECUTION_CHANGES),
    blob_kzg_commitments: types.List(KZGCommitment, preset.MAX_BLOB_COMMITMENTS_PER_BLOCK),
    execution_requests: ExecutionRequests,
};

/// Phase 0 empty body layout used to seed the genesis block header root.
pub const GenesisBlockBody = struct {
    randao_reveal: BLSSignature,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: types.List(ProposerSlashing, preset.MAX_PROPOSER_SLASHINGS),
    attester_slashings: types.List(AttesterSlashing, 2),
    attestations: types.List(Attestation, 128),
    deposits: types.List(Deposit, preset.MAX_DEPOSITS_PER_BLOCK),
    voluntary_exits: types.List(SignedVoluntaryExit, preset.MAX_VOLUNTARY_EXITS),
};

pub const BeaconBlock = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Root,
    state_root: Root,
    body: BeaconBlockBody,
};

pub const SignedBeaconBlock = struct {
    message: BeaconBlock,
    signature: BLSSignature,
};

/// Beacon state schema for the selected Fulu preset, in consensus-spec field order.
pub const BeaconState = struct {
    genesis_time: u64,
    genesis_validators_root: Root,
    slot: Slot,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: [preset.SLOTS_PER_HISTORICAL_ROOT]Root,
    state_roots: [preset.SLOTS_PER_HISTORICAL_ROOT]Root,
    historical_roots: types.List(Root, preset.HISTORICAL_ROOTS_LIMIT),
    eth1_data: Eth1Data,
    eth1_data_votes: types.List(Eth1Data, @intCast(preset.EPOCHS_PER_ETH1_VOTING_PERIOD * preset.SLOTS_PER_EPOCH)),
    eth1_deposit_index: u64,
    validators: types.List(Validator, preset.VALIDATOR_REGISTRY_LIMIT),
    balances: types.List(Gwei, preset.VALIDATOR_REGISTRY_LIMIT),
    randao_mixes: [preset.EPOCHS_PER_HISTORICAL_VECTOR]Bytes32,
    slashings: [preset.EPOCHS_PER_SLASHINGS_VECTOR]Gwei,
    previous_epoch_participation: types.List(ParticipationFlags, preset.VALIDATOR_REGISTRY_LIMIT),
    current_epoch_participation: types.List(ParticipationFlags, preset.VALIDATOR_REGISTRY_LIMIT),
    justification_bits: types.BitVector(preset.JUSTIFICATION_BITS_LENGTH),
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: types.List(u64, preset.VALIDATOR_REGISTRY_LIMIT),
    current_sync_committee: SyncCommittee,
    next_sync_committee: SyncCommittee,
    latest_execution_payload_header: ExecutionPayloadHeader,
    next_withdrawal_index: WithdrawalIndex,
    next_withdrawal_validator_index: ValidatorIndex,
    historical_summaries: types.List(HistoricalSummary, preset.HISTORICAL_SUMMARIES_LIMIT),
    deposit_requests_start_index: u64,
    deposit_balance_to_consume: Gwei,
    exit_balance_to_consume: Gwei,
    earliest_exit_epoch: Epoch,
    consolidation_balance_to_consume: Gwei,
    earliest_consolidation_epoch: Epoch,
    pending_deposits: types.List(PendingDeposit, preset.PENDING_DEPOSITS_LIMIT),
    pending_partial_withdrawals: types.List(PendingPartialWithdrawal, preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT),
    pending_consolidations: types.List(PendingConsolidation, preset.PENDING_CONSOLIDATIONS_LIMIT),
    proposer_lookahead: [2 * preset.SLOTS_PER_EPOCH]ValidatorIndex,
};

/// Electra state at the fork boundary; its SSZ fields precede Fulu's proposer window.
pub const ElectraBeaconState = struct {
    genesis_time: u64,
    genesis_validators_root: Root,
    slot: Slot,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: [preset.SLOTS_PER_HISTORICAL_ROOT]Root,
    state_roots: [preset.SLOTS_PER_HISTORICAL_ROOT]Root,
    historical_roots: types.List(Root, preset.HISTORICAL_ROOTS_LIMIT),
    eth1_data: Eth1Data,
    eth1_data_votes: types.List(Eth1Data, @intCast(preset.EPOCHS_PER_ETH1_VOTING_PERIOD * preset.SLOTS_PER_EPOCH)),
    eth1_deposit_index: u64,
    validators: types.List(Validator, preset.VALIDATOR_REGISTRY_LIMIT),
    balances: types.List(Gwei, preset.VALIDATOR_REGISTRY_LIMIT),
    randao_mixes: [preset.EPOCHS_PER_HISTORICAL_VECTOR]Bytes32,
    slashings: [preset.EPOCHS_PER_SLASHINGS_VECTOR]Gwei,
    previous_epoch_participation: types.List(ParticipationFlags, preset.VALIDATOR_REGISTRY_LIMIT),
    current_epoch_participation: types.List(ParticipationFlags, preset.VALIDATOR_REGISTRY_LIMIT),
    justification_bits: types.BitVector(preset.JUSTIFICATION_BITS_LENGTH),
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: types.List(u64, preset.VALIDATOR_REGISTRY_LIMIT),
    current_sync_committee: SyncCommittee,
    next_sync_committee: SyncCommittee,
    latest_execution_payload_header: ExecutionPayloadHeader,
    next_withdrawal_index: WithdrawalIndex,
    next_withdrawal_validator_index: ValidatorIndex,
    historical_summaries: types.List(HistoricalSummary, preset.HISTORICAL_SUMMARIES_LIMIT),
    deposit_requests_start_index: u64,
    deposit_balance_to_consume: Gwei,
    exit_balance_to_consume: Gwei,
    earliest_exit_epoch: Epoch,
    consolidation_balance_to_consume: Gwei,
    earliest_consolidation_epoch: Epoch,
    pending_deposits: types.List(PendingDeposit, preset.PENDING_DEPOSITS_LIMIT),
    pending_partial_withdrawals: types.List(PendingPartialWithdrawal, preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT),
    pending_consolidations: types.List(PendingConsolidation, preset.PENDING_CONSOLIDATIONS_LIMIT),
};

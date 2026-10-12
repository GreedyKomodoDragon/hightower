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
//! containers; BeaconState is still defined by separate schema work. Struct
//! field order is SSZ field order. Fixed vectors use Zig arrays, while
//! variable lists use the generic SSZ List type.

const types = @import("types");

/// Scalar aliases and fixed-width byte values from the Fulu minimal preset.
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
    /// The minimal preset uses 32 public keys per sync committee.
    pubkeys: [32]BLSPubkey,
    aggregate_pubkey: BLSPubkey,
};

pub const SyncAggregate = struct {
    sync_committee_bits: types.BitVector(32),
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
    aggregation_bits: types.BitList(8192),
    data: AttestationData,
    signature: BLSSignature,
    committee_bits: types.BitVector(4),
};

pub const IndexedAttestation = struct {
    attesting_indices: types.List(ValidatorIndex, 8192),
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
    transactions: types.List(types.ByteList(1_073_741_824), 1_048_576),
    withdrawals: types.List(Withdrawal, 4),
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
    deposits: types.List(DepositRequest, 8192),
    withdrawals: types.List(WithdrawalRequest, 16),
    consolidations: types.List(ConsolidationRequest, 2),
};

pub const BeaconBlockBody = struct {
    randao_reveal: BLSSignature,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: types.List(ProposerSlashing, 16),
    attester_slashings: types.List(AttesterSlashing, 1),
    attestations: types.List(Attestation, 8),
    deposits: types.List(Deposit, 16),
    voluntary_exits: types.List(SignedVoluntaryExit, 16),
    sync_aggregate: SyncAggregate,
    execution_payload: ExecutionPayload,
    bls_to_execution_changes: types.List(SignedBLSToExecutionChange, 16),
    blob_kzg_commitments: types.List(KZGCommitment, 4096),
    execution_requests: ExecutionRequests,
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

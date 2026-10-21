// A consensus preset supplies the fixed values that shape Fulu state and
// determine slot, epoch, fork, withdrawal, and blob processing. Every module
// must use the same compile-time selection: changing it also changes SSZ
// vector lengths, so values cannot safely be mixed at runtime.
const std = @import("std");
const build_options = @import("build_options");

pub const Name = enum { minimal, mainnet };
pub const BlobParameters = struct { epoch: u64, max_blobs_per_block: u64 };

/// Returns the selected preset name, rejecting unsupported build options.
fn parseName(value: []const u8) Name {
    if (std.mem.eql(u8, value, "minimal")) return .minimal;
    if (std.mem.eql(u8, value, "mainnet")) return .mainnet;
    @compileError("unsupported preset; choose minimal or mainnet");
}

pub const name = parseName(build_options.preset);

/// Preset constants used by the supported Fulu state and processing code.
pub const Config = switch (name) {
    .minimal => Minimal,
    .mainnet => Mainnet,
};

pub const Minimal = struct {
    pub const SECONDS_PER_SLOT: u64 = 6;
    pub const PROPOSER_BOOST_WINDOW_SECONDS: u64 = 2;
    pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;
    pub const SLOTS_PER_EPOCH: u64 = 8;
    pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 64;
    pub const EPOCHS_PER_HISTORICAL_VECTOR: u64 = 64;
    pub const EPOCHS_PER_SLASHINGS_VECTOR: u64 = 64;
    pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 4;
    pub const ETH1_DATA_VOTE_SUPERMAJORITY_NUMERATOR: u64 = 2;
    pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 8;
    pub const EPOCH_OFFSET: u64 = 1;
    pub const SYNC_COMMITTEE_SIZE: usize = 32;
    pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576;
    pub const MAX_TRANSACTION_BYTES: usize = 1_073_741_824;
    pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;
    pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8192;
    pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;
    pub const MAX_PROPOSER_SLASHINGS: usize = 16;
    pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
    pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;
    pub const JUSTIFICATION_BITS_LENGTH: usize = 4;
    pub const JUSTIFICATION_SUPERMAJORITY_NUMERATOR: u64 = 2;
    pub const JUSTIFICATION_SUPERMAJORITY_DENOMINATOR: u64 = 3;
    pub const PARTICIPATION_FLAG_WEIGHTS = [_]u64{ 14, 26, 14 };
    pub const MAX_DEPOSITS_PER_BLOCK: usize = 16;
    pub const MAX_VOLUNTARY_EXITS: usize = 16;
    pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;
    pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
    pub const MAX_SNAPPY_DECOMPRESSED_BLOCK_BYTES: usize = 64 * 1024 * 1024;
    pub const HISTORICAL_ROOTS_LIMIT: usize = 16_777_216;
    pub const VALIDATOR_REGISTRY_LIMIT: usize = 1_099_511_627_776;
    pub const HISTORICAL_SUMMARIES_LIMIT: usize = 16_777_216;
    pub const MAX_COMMITTEES_PER_SLOT: usize = 4;
    pub const TARGET_COMMITTEE_SIZE: usize = 4;
    pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 4;
    pub const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: usize = 16;
    pub const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: usize = 8;
    pub const MAX_PENDING_DEPOSITS_PER_EPOCH: usize = 16;
    pub const PENDING_DEPOSITS_LIMIT: usize = 134_217_728;
    pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 64;
    pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 64;
    pub const MAX_BLOBS_PER_BLOCK_ELECTRA: u64 = 9;
    pub const BLOB_SCHEDULE: [0]BlobParameters = .{};
    pub const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;
    pub const MAX_EFFECTIVE_BALANCE_ELECTRA: u64 = 2_048_000_000_000;
    pub const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
    pub const EJECTION_BALANCE: u64 = 16_000_000_000;
    pub const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: u64 = 64_000_000_000;
    pub const MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: u64 = 128_000_000_000;
    pub const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
    pub const EFFECTIVE_BALANCE_HYSTERESIS_DOWNWARD: u64 = 250_000_000;
    pub const EFFECTIVE_BALANCE_HYSTERESIS_UPWARD: u64 = 1_250_000_000;
    pub const MAX_SEED_LOOKAHEAD: u64 = 4;
    pub const MIN_SEED_LOOKAHEAD: u64 = 1;
    pub const SHUFFLE_ROUND_COUNT: u8 = 10;
    pub const MAX_DEPOSITS: u64 = 16;
    pub const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;
    pub const CHURN_LIMIT_QUOTIENT: u64 = 32;
    pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 8192;
    pub const ETH_TO_GWEI: u64 = 1_000_000_000;
    pub const SAFETY_DECAY: u64 = 10;
    pub const INACTIVITY_LEAK_EPOCH_THRESHOLD: u64 = 4;
    pub const INACTIVITY_SCORE_BIAS: u64 = 4;
    pub const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;
    pub const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64 = 16_777_216;
    pub const BASE_REWARD_FACTOR: u64 = 64;
    pub const BASE_REWARDS_PER_EPOCH: u64 = 4;
    pub const WEIGHT_DENOMINATOR: u64 = 64;
    pub const PROPOSER_WEIGHT: u64 = 8;
    pub const SYNC_REWARD_WEIGHT: u64 = 2;
    pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64 = 4096;
    pub const MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64 = 4096;
    pub const SHARD_COMMITTEE_PERIOD: u64 = 64;
    pub const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;
    pub const GENESIS_FORK_VERSION: [4]u8 = .{ 0, 0, 0, 1 };
    pub const CAPELLA_FORK_VERSION: [4]u8 = .{ 3, 0, 0, 1 };
    pub const ELECTRA_FORK_EPOCH: u64 = std.math.maxInt(u64);
};

pub const Mainnet = struct {
    pub const SECONDS_PER_SLOT: u64 = 12;
    pub const PROPOSER_BOOST_WINDOW_SECONDS: u64 = 4;
    pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;
    pub const SLOTS_PER_EPOCH: u64 = 32;
    pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;
    pub const EPOCHS_PER_HISTORICAL_VECTOR: u64 = 65_536;
    pub const EPOCHS_PER_SLASHINGS_VECTOR: u64 = 8192;
    pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 64;
    pub const ETH1_DATA_VOTE_SUPERMAJORITY_NUMERATOR: u64 = 2;
    pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
    pub const EPOCH_OFFSET: u64 = 1;
    pub const SYNC_COMMITTEE_SIZE: usize = 512;
    pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576;
    pub const MAX_TRANSACTION_BYTES: usize = 1_073_741_824;
    pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;
    pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8192;
    pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;
    pub const MAX_PROPOSER_SLASHINGS: usize = 16;
    pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
    pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;
    pub const JUSTIFICATION_BITS_LENGTH: usize = 4;
    pub const JUSTIFICATION_SUPERMAJORITY_NUMERATOR: u64 = 2;
    pub const JUSTIFICATION_SUPERMAJORITY_DENOMINATOR: u64 = 3;
    pub const PARTICIPATION_FLAG_WEIGHTS = [_]u64{ 14, 26, 14 };
    pub const MAX_DEPOSITS_PER_BLOCK: usize = 16;
    pub const MAX_VOLUNTARY_EXITS: usize = 16;
    pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;
    pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
    pub const MAX_SNAPPY_DECOMPRESSED_BLOCK_BYTES: usize = 64 * 1024 * 1024;
    pub const HISTORICAL_ROOTS_LIMIT: usize = 16_777_216;
    pub const VALIDATOR_REGISTRY_LIMIT: usize = 1_099_511_627_776;
    pub const HISTORICAL_SUMMARIES_LIMIT: usize = 16_777_216;
    pub const MAX_COMMITTEES_PER_SLOT: usize = 64;
    pub const TARGET_COMMITTEE_SIZE: usize = 128;
    pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
    pub const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: usize = 16;
    pub const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: usize = 8;
    pub const MAX_PENDING_DEPOSITS_PER_EPOCH: usize = 16;
    pub const PENDING_DEPOSITS_LIMIT: usize = 134_217_728;
    pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 134_217_728;
    pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 262_144;
    pub const MAX_BLOBS_PER_BLOCK_ELECTRA: u64 = 9;
    pub const BLOB_SCHEDULE = [_]BlobParameters{
        .{ .epoch = 412_672, .max_blobs_per_block = 15 },
        .{ .epoch = 419_072, .max_blobs_per_block = 21 },
    };
    pub const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;
    pub const MAX_EFFECTIVE_BALANCE_ELECTRA: u64 = 2_048_000_000_000;
    pub const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
    pub const EJECTION_BALANCE: u64 = 16_000_000_000;
    pub const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: u64 = 128_000_000_000;
    pub const MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: u64 = 256_000_000_000;
    pub const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
    pub const EFFECTIVE_BALANCE_HYSTERESIS_DOWNWARD: u64 = 250_000_000;
    pub const EFFECTIVE_BALANCE_HYSTERESIS_UPWARD: u64 = 1_250_000_000;
    pub const MAX_SEED_LOOKAHEAD: u64 = 4;
    pub const MIN_SEED_LOOKAHEAD: u64 = 1;
    pub const SHUFFLE_ROUND_COUNT: u8 = 90;
    pub const MAX_DEPOSITS: u64 = 16;
    pub const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;
    pub const CHURN_LIMIT_QUOTIENT: u64 = 65_536;
    pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
    pub const ETH_TO_GWEI: u64 = 1_000_000_000;
    pub const SAFETY_DECAY: u64 = 10;
    pub const INACTIVITY_LEAK_EPOCH_THRESHOLD: u64 = 4;
    pub const INACTIVITY_SCORE_BIAS: u64 = 4;
    pub const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;
    pub const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64 = 16_777_216;
    pub const BASE_REWARD_FACTOR: u64 = 64;
    pub const BASE_REWARDS_PER_EPOCH: u64 = 4;
    pub const WEIGHT_DENOMINATOR: u64 = 64;
    pub const PROPOSER_WEIGHT: u64 = 8;
    pub const SYNC_REWARD_WEIGHT: u64 = 2;
    pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64 = 4096;
    pub const MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64 = 4096;
    pub const SHARD_COMMITTEE_PERIOD: u64 = 256;
    pub const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;
    pub const GENESIS_FORK_VERSION: [4]u8 = .{ 0, 0, 0, 0 };
    pub const CAPELLA_FORK_VERSION: [4]u8 = .{ 3, 0, 0, 0 };
    pub const ELECTRA_FORK_EPOCH: u64 = 364_032;
};

test "both consensus preset profiles expose their network dimensions" {
    try std.testing.expectEqual(@as(u64, 8), Minimal.SLOTS_PER_EPOCH);
    try std.testing.expectEqual(@as(u64, 32), Mainnet.SLOTS_PER_EPOCH);
    try std.testing.expectEqual(@as(u64, 6), Minimal.SECONDS_PER_SLOT);
    try std.testing.expectEqual(@as(u64, 12), Mainnet.SECONDS_PER_SLOT);
    try std.testing.expectEqual(@as(usize, 32), Minimal.SYNC_COMMITTEE_SIZE);
    try std.testing.expectEqual(@as(usize, 512), Mainnet.SYNC_COMMITTEE_SIZE);
}

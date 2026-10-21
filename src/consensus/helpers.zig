// An epoch groups SLOTS_PER_EPOCH slots; slot-to-epoch arithmetic determines
// validator eligibility and the ring-buffer position used by consensus state.
// Seed, shuffle, and balance rules must use the same epoch and preset values
// because proposer selection depends on both ordering and exact integer math.
// The selected compile-time preset supplies dimensions and limits. Blob
// parameters select the latest configured epoch entry and otherwise fall back
// to the Electra limit.
//
//   slot -> epoch -> active validators -> seeded shuffle -> proposer indices
const std = @import("std");
const fulu = @import("fulu");
const preset = @import("consensus_preset").Config;

pub const SLOTS_PER_EPOCH = preset.SLOTS_PER_EPOCH;
pub const SLOTS_PER_HISTORICAL_ROOT = preset.SLOTS_PER_HISTORICAL_ROOT;
pub const EPOCHS_PER_HISTORICAL_VECTOR = preset.EPOCHS_PER_HISTORICAL_VECTOR;
pub const EPOCHS_PER_SLASHINGS_VECTOR = preset.EPOCHS_PER_SLASHINGS_VECTOR;
pub const EPOCHS_PER_ETH1_VOTING_PERIOD = preset.EPOCHS_PER_ETH1_VOTING_PERIOD;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD = preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
pub const EPOCHS_PER_HISTORICAL_SUMMARY: u64 = SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH;
pub const EPOCH_OFFSET = preset.EPOCH_OFFSET;
pub const MIN_SEED_LOOKAHEAD = preset.MIN_SEED_LOOKAHEAD;
pub const MAX_SEED_LOOKAHEAD = preset.MAX_SEED_LOOKAHEAD;
pub const SHUFFLE_ROUND_COUNT = preset.SHUFFLE_ROUND_COUNT;
pub const MAX_COMMITTEES_PER_SLOT = preset.MAX_COMMITTEES_PER_SLOT;
pub const TARGET_COMMITTEE_SIZE = preset.TARGET_COMMITTEE_SIZE;
pub const JUSTIFICATION_BITS_LENGTH = preset.JUSTIFICATION_BITS_LENGTH;
pub const JUSTIFICATION_SUPERMAJORITY_NUMERATOR = preset.JUSTIFICATION_SUPERMAJORITY_NUMERATOR;
pub const JUSTIFICATION_SUPERMAJORITY_DENOMINATOR = preset.JUSTIFICATION_SUPERMAJORITY_DENOMINATOR;
pub const INACTIVITY_LEAK_EPOCH_THRESHOLD = preset.INACTIVITY_LEAK_EPOCH_THRESHOLD;

// Effective balances are rounded in increments; Electra raises the cap only
// for compounding validators while keeping activation at 32 ETH.
pub const EFFECTIVE_BALANCE_INCREMENT = preset.EFFECTIVE_BALANCE_INCREMENT;
pub const EFFECTIVE_BALANCE_HYSTERESIS_DOWNWARD = preset.EFFECTIVE_BALANCE_HYSTERESIS_DOWNWARD;
pub const EFFECTIVE_BALANCE_HYSTERESIS_UPWARD = preset.EFFECTIVE_BALANCE_HYSTERESIS_UPWARD;
pub const MAX_EFFECTIVE_BALANCE = preset.MAX_EFFECTIVE_BALANCE;
pub const MAX_EFFECTIVE_BALANCE_ELECTRA = preset.MAX_EFFECTIVE_BALANCE_ELECTRA;
pub const MIN_ACTIVATION_BALANCE = preset.MIN_ACTIVATION_BALANCE;
pub const EJECTION_BALANCE = preset.EJECTION_BALANCE;
pub const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA = preset.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA;
pub const MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT = preset.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT;
pub const CHURN_LIMIT_QUOTIENT = preset.CHURN_LIMIT_QUOTIENT;
pub const MIN_VALIDATOR_WITHDRAWABILITY_DELAY = preset.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
const MAX_DEPOSITS = preset.MAX_DEPOSITS;
const SAFETY_DECAY = preset.SAFETY_DECAY;
const ETH_TO_GWEI = preset.ETH_TO_GWEI;

// Inactivity scores and participation weights are shared by Altair reward
// accounting and the inherited Fulu epoch transition. Fulu uses Bellatrix's
// stronger inactivity penalty.
pub const INACTIVITY_SCORE_BIAS = preset.INACTIVITY_SCORE_BIAS;
pub const INACTIVITY_SCORE_RECOVERY_RATE = preset.INACTIVITY_SCORE_RECOVERY_RATE;
pub const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX = preset.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
pub const BASE_REWARD_FACTOR = preset.BASE_REWARD_FACTOR;
pub const BASE_REWARDS_PER_EPOCH = preset.BASE_REWARDS_PER_EPOCH;
pub const WEIGHT_DENOMINATOR = preset.WEIGHT_DENOMINATOR;
pub const PROPOSER_WEIGHT = preset.PROPOSER_WEIGHT;
pub const SYNC_REWARD_WEIGHT = preset.SYNC_REWARD_WEIGHT;
pub const PARTICIPATION_FLAG_WEIGHTS = preset.PARTICIPATION_FLAG_WEIGHTS;
pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;
pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;
pub const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = preset.PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;
pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA = preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
pub const FAR_FUTURE_EPOCH: u64 = std.math.maxInt(u64);

// Fulu inherits this limit when no blob-schedule entry applies.
pub const MAX_BLOBS_PER_BLOCK_ELECTRA = preset.MAX_BLOBS_PER_BLOCK_ELECTRA;
pub const ELECTRA_FORK_EPOCH = preset.ELECTRA_FORK_EPOCH;

pub const BlobParameters = @import("consensus_preset").BlobParameters;

pub const BLOB_SCHEDULE = preset.BLOB_SCHEDULE;

// A schedule entry takes effect at its epoch and remains active until the next
// entry. Selection is by greatest applicable epoch, independent of list order.
pub fn getBlobParameters(epoch: fulu.Epoch, schedule: []const BlobParameters) BlobParameters {
    var selected: ?BlobParameters = null;
    for (schedule) |entry| {
        if (entry.epoch <= epoch and (selected == null or entry.epoch > selected.?.epoch)) {
            selected = entry;
        }
    }
    return selected orelse .{
        // The fallback epoch is part of the fork digest as well as its limit.
        .epoch = ELECTRA_FORK_EPOCH,
        .max_blobs_per_block = MAX_BLOBS_PER_BLOCK_ELECTRA,
    };
}

// Fulu folds the active blob parameters into the normal fork digest so a
// blob-parameter-only change produces a distinct network digest. The caller
// supplies the fork version selected for this epoch.
pub fn computeForkDigest(
    fork_version: fulu.Version,
    genesis_validators_root: fulu.Root,
    epoch: fulu.Epoch,
    schedule: []const BlobParameters,
) [4]u8 {
    // ForkData SSZ hashing pads the four-byte version to one 32-byte chunk.
    var fork_data = [_]u8{0} ** 64;
    @memcpy(fork_data[0..4], &fork_version);
    @memcpy(fork_data[32..64], &genesis_validators_root);
    var fork_data_root: fulu.Root = undefined;
    std.crypto.hash.sha2.Sha256.hash(&fork_data, &fork_data_root, .{});

    const parameters = getBlobParameters(epoch, schedule);
    var blob_data: [16]u8 = undefined;
    // SSZ uint64 values are encoded little-endian before hashing.
    std.mem.writeInt(u64, blob_data[0..8], parameters.epoch, .little);
    std.mem.writeInt(u64, blob_data[8..16], parameters.max_blobs_per_block, .little);
    var blob_hash: fulu.Root = undefined;
    std.crypto.hash.sha2.Sha256.hash(&blob_data, &blob_hash, .{});

    var digest: [4]u8 = undefined;
    // Only the first four bytes are used for the network's ForkDigest.
    for (&digest, fork_data_root[0..4], blob_hash[0..4]) |*out, base, blob| out.* = base ^ blob;
    return digest;
}

pub const DOMAIN_BEACON_PROPOSER = [_]u8{ 0, 0, 0, 0 };
pub const DOMAIN_BEACON_ATTESTER = [_]u8{ 1, 0, 0, 0 };
pub const DOMAIN_RANDAO = [_]u8{ 2, 0, 0, 0 };
pub const DOMAIN_DEPOSIT = [_]u8{ 3, 0, 0, 0 };
pub const DOMAIN_VOLUNTARY_EXIT = [_]u8{ 4, 0, 0, 0 };
pub const DOMAIN_SELECTION_PROOF = [_]u8{ 5, 0, 0, 0 };
pub const DOMAIN_AGGREGATE_AND_PROOF = [_]u8{ 6, 0, 0, 0 };
pub const DOMAIN_SYNC_COMMITTEE = [_]u8{ 7, 0, 0, 0 };
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF = [_]u8{ 8, 0, 0, 0 };
pub const DOMAIN_CONTRIBUTION_AND_PROOF = [_]u8{ 9, 0, 0, 0 };
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE = [_]u8{ 10, 0, 0, 0 };
pub const DOMAIN_APPLICATION_MASK = [_]u8{ 0, 0, 0, 1 };

// Pinned minimal network configuration, not the mainnet genesis version.
pub const GENESIS_FORK_VERSION: fulu.Version = preset.GENESIS_FORK_VERSION;

pub fn computeEpochAtSlot(slot: fulu.Slot) fulu.Epoch {
    return slot / SLOTS_PER_EPOCH;
}

pub fn getCurrentEpoch(state: *const fulu.BeaconState) fulu.Epoch {
    return computeEpochAtSlot(state.slot);
}

pub fn computePreviousEpoch(epoch: fulu.Epoch) fulu.Epoch {
    return epoch -| EPOCH_OFFSET;
}

pub fn computeStartSlotAtEpoch(epoch: fulu.Epoch) error{Overflow}!fulu.Slot {
    return std.math.mul(fulu.Slot, epoch, SLOTS_PER_EPOCH) catch error.Overflow;
}

pub fn computeActivationExitEpoch(epoch: fulu.Epoch) error{Overflow}!fulu.Epoch {
    return std.math.add(fulu.Epoch, epoch, EPOCH_OFFSET + MAX_SEED_LOOKAHEAD) catch error.Overflow;
}

pub fn isActiveValidator(validator: fulu.Validator, epoch: fulu.Epoch) bool {
    return validator.activation_epoch <= epoch and epoch < validator.exit_epoch;
}

pub fn isEligibleForActivationQueue(validator: fulu.Validator) bool {
    return validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH and
        validator.effective_balance >= MIN_ACTIVATION_BALANCE;
}

pub fn isEligibleForActivation(validator: fulu.Validator, finalized_epoch: fulu.Epoch) bool {
    return validator.activation_eligibility_epoch <= finalized_epoch and
        validator.activation_epoch == FAR_FUTURE_EPOCH;
}

pub fn isSlashableValidator(validator: fulu.Validator, epoch: fulu.Epoch) bool {
    return !validator.slashed and validator.activation_epoch <= epoch and epoch < validator.withdrawable_epoch;
}

pub fn getTotalActiveBalance(validators: []const fulu.Validator, epoch: fulu.Epoch) error{BalanceOverflow}!fulu.Gwei {
    var balance: u128 = 0;
    for (validators) |validator| {
        if (isActiveValidator(validator, epoch)) balance += validator.effective_balance;
    }
    const total = @max(balance, EFFECTIVE_BALANCE_INCREMENT);
    if (total > std.math.maxInt(fulu.Gwei)) return error.BalanceOverflow;
    return @intCast(total);
}

pub fn computeWeakSubjectivityPeriod(state: *const fulu.BeaconState) error{ InvalidState, Overflow }!fulu.Epoch {
    const epoch = getCurrentEpoch(state);
    var active_count: u128 = 0;
    for (state.validators.data) |validator| {
        if (isActiveValidator(validator, epoch)) active_count += 1;
    }
    if (active_count == 0) return error.InvalidState;

    const total_balance = getTotalActiveBalance(state.validators.data, epoch) catch return error.InvalidState;
    const average_balance = @as(u128, total_balance) / active_count / ETH_TO_GWEI;
    const max_balance = MAX_EFFECTIVE_BALANCE_ELECTRA / ETH_TO_GWEI;
    if (average_balance > max_balance) return error.InvalidState;

    const raw_churn = @max(MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, total_balance / CHURN_LIMIT_QUOTIENT);
    const churn_gwei = raw_churn - raw_churn % EFFECTIVE_BALANCE_INCREMENT;
    const churn_eth = @max(@as(u128, 1), churn_gwei / ETH_TO_GWEI);
    const topups_per_epoch: u128 = MAX_DEPOSITS * SLOTS_PER_EPOCH;
    const n = active_count;
    const t = average_balance;
    const max = max_balance;
    const d: u128 = SAFETY_DECAY;
    var period: u128 = MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

    if (max * (200 + 3 * d) < t * (200 + 12 * d)) {
        const epochs_for_churn = n * (t * (200 + 12 * d) - max * (200 + 3 * d)) /
            (600 * churn_eth * (2 * t + max));
        const epochs_for_topups = n * (200 + 3 * d) / (600 * topups_per_epoch);
        period += @max(epochs_for_churn, epochs_for_topups);
    } else {
        period += 3 * n * d * t / (200 * topups_per_epoch * (max - t));
    }
    if (period > std.math.maxInt(fulu.Epoch)) return error.Overflow;
    return @intCast(period);
}

pub fn getActiveValidatorIndices(
    allocator: std.mem.Allocator,
    validators: []const fulu.Validator,
    epoch: fulu.Epoch,
) ![]fulu.ValidatorIndex {
    var indices = std.ArrayList(fulu.ValidatorIndex).empty;
    errdefer indices.deinit(allocator);
    for (validators, 0..) |validator, index| {
        if (isActiveValidator(validator, epoch)) try indices.append(allocator, @intCast(index));
    }
    return indices.toOwnedSlice(allocator);
}

pub fn computeShuffledIndex(index: usize, index_count: usize, seed: [32]u8) error{InvalidIndex}!usize {
    if (index >= index_count or index_count == 0) return error.InvalidIndex;

    var current = index;
    for (0..SHUFFLE_ROUND_COUNT) |round| {
        const round_byte: u8 = @intCast(round);
        var pivot_input: [33]u8 = undefined;
        @memcpy(pivot_input[0..32], &seed);
        pivot_input[32] = round_byte;
        var pivot_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&pivot_input, &pivot_hash, .{});
        const pivot = @as(usize, @intCast(std.mem.readInt(u64, pivot_hash[0..8], .little) % index_count));

        const flip = (pivot + index_count - current) % index_count;
        const position = @max(current, flip);
        var source_input: [37]u8 = undefined;
        @memcpy(source_input[0..32], &seed);
        source_input[32] = round_byte;
        std.mem.writeInt(u32, source_input[33..37], @intCast(position / 256), .little);
        var source: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&source_input, &source, .{});
        const bit = (source[(position % 256) / 8] >> @as(u3, @intCast(position % 8))) & 1;
        if (bit == 1) current = flip;
    }
    return current;
}

pub fn computeCommittee(
    allocator: std.mem.Allocator,
    indices: []const fulu.ValidatorIndex,
    seed: [32]u8,
    committee_index: usize,
    committee_count: usize,
) ![]fulu.ValidatorIndex {
    if (committee_count == 0 or committee_index >= committee_count) return error.InvalidCommittee;
    const start = indices.len * committee_index / committee_count;
    const end = indices.len * (committee_index + 1) / committee_count;
    const committee = try allocator.alloc(fulu.ValidatorIndex, end - start);
    errdefer allocator.free(committee);
    for (start..end, 0..) |position, output_index| {
        const shuffled = try computeShuffledIndex(position, indices.len, seed);
        committee[output_index] = indices[shuffled];
    }
    return committee;
}

pub fn getBeaconCommittee(
    allocator: std.mem.Allocator,
    state: *const fulu.BeaconState,
    slot: fulu.Slot,
    index: fulu.CommitteeIndex,
) ![]fulu.ValidatorIndex {
    const epoch = computeEpochAtSlot(slot);
    const active = try getActiveValidatorIndices(allocator, state.validators.data, epoch);
    defer allocator.free(active);
    const per_slot = @max(1, @min(MAX_COMMITTEES_PER_SLOT, active.len / SLOTS_PER_EPOCH / TARGET_COMMITTEE_SIZE));
    if (index >= per_slot) return error.InvalidCommittee;
    return computeCommittee(
        allocator,
        active,
        computeSeed(state.*, epoch, DOMAIN_BEACON_ATTESTER),
        @as(usize, @intCast(slot % SLOTS_PER_EPOCH)) * per_slot + @as(usize, @intCast(index)),
        per_slot * SLOTS_PER_EPOCH,
    );
}

pub fn computeProposerIndex(
    validators: []const fulu.Validator,
    indices: []const fulu.ValidatorIndex,
    seed: [32]u8,
) error{NoEligibleProposer}!fulu.ValidatorIndex {
    if (indices.len == 0) return error.NoEligibleProposer;
    var iteration: u64 = 0;
    while (iteration < std.math.maxInt(u64)) : (iteration += 1) {
        const shuffled = computeShuffledIndex(@intCast(iteration % indices.len), indices.len, seed) catch return error.NoEligibleProposer;
        const candidate_index = indices[shuffled];
        if (candidate_index >= validators.len) return error.NoEligibleProposer;

        var random_input: [40]u8 = undefined;
        @memcpy(random_input[0..32], &seed);
        std.mem.writeInt(u64, random_input[32..40], iteration / 16, .little);
        var random_bytes: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&random_input, &random_bytes, .{});
        const offset: usize = @intCast((iteration % 16) * 2);
        const random_value = @as(u16, random_bytes[offset]) | (@as(u16, random_bytes[offset + 1]) << 8);
        const effective_balance = validators[candidate_index].effective_balance;
        if (@as(u128, effective_balance) * std.math.maxInt(u16) >= @as(u128, MAX_EFFECTIVE_BALANCE_ELECTRA) * random_value) return candidate_index;
    }
    return error.NoEligibleProposer;
}

pub fn computeSeed(state: fulu.BeaconState, epoch: fulu.Epoch, domain_type: [4]u8) fulu.Root {
    const mix_index = (epoch % EPOCHS_PER_HISTORICAL_VECTOR + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1) % EPOCHS_PER_HISTORICAL_VECTOR;
    var input: [44]u8 = undefined;
    @memcpy(input[0..4], &domain_type);
    std.mem.writeInt(u64, input[4..12], epoch, .little);
    @memcpy(input[12..44], &state.randao_mixes[mix_index]);
    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &seed, .{});
    return seed;
}

pub fn computeProposerIndices(
    allocator: std.mem.Allocator,
    state: fulu.BeaconState,
    epoch: fulu.Epoch,
) ![SLOTS_PER_EPOCH]fulu.ValidatorIndex {
    const active = try getActiveValidatorIndices(allocator, state.validators.data, epoch);
    defer allocator.free(active);
    if (active.len == 0) return error.NoEligibleProposer;

    const epoch_seed = computeSeed(state, epoch, DOMAIN_BEACON_PROPOSER);
    const start_slot = try computeStartSlotAtEpoch(epoch);
    var indices: [SLOTS_PER_EPOCH]fulu.ValidatorIndex = undefined;
    for (&indices, 0..) |*proposer, slot_offset| {
        var input: [40]u8 = undefined;
        @memcpy(input[0..32], &epoch_seed);
        std.mem.writeInt(u64, input[32..40], start_slot + slot_offset, .little);
        var slot_seed: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&input, &slot_seed, .{});
        proposer.* = try computeProposerIndex(state.validators.data, active, slot_seed);
    }
    return indices;
}

test "slot and epoch helpers handle boundaries" {
    try std.testing.expectEqual(@as(u64, 0), computeEpochAtSlot(7));
    try std.testing.expectEqual(@as(u64, 1), computeEpochAtSlot(8));
    try std.testing.expectEqual(@as(u64, 0), computePreviousEpoch(0));
    try std.testing.expectEqual(@as(u64, 0), computePreviousEpoch(1));
    try std.testing.expectEqual(@as(u64, 1), computePreviousEpoch(2));
    try std.testing.expectEqual(@as(u64, 16), try computeStartSlotAtEpoch(2));
    try std.testing.expectError(error.Overflow, computeStartSlotAtEpoch(std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u64, 6), try computeActivationExitEpoch(1));
    try std.testing.expectError(error.Overflow, computeActivationExitEpoch(std.math.maxInt(u64)));
}

test "blob parameters use the latest scheduled epoch and Electra fallback" {
    const schedule = [_]BlobParameters{
        .{ .epoch = 10, .max_blobs_per_block = 15 },
        .{ .epoch = 20, .max_blobs_per_block = 21 },
    };
    try std.testing.expectEqual(BlobParameters{
        .epoch = ELECTRA_FORK_EPOCH,
        .max_blobs_per_block = MAX_BLOBS_PER_BLOCK_ELECTRA,
    }, getBlobParameters(9, &schedule));
    try std.testing.expectEqual(@as(u64, 15), getBlobParameters(10, &schedule).max_blobs_per_block);
    try std.testing.expectEqual(@as(u64, 15), getBlobParameters(19, &schedule).max_blobs_per_block);
    try std.testing.expectEqual(@as(u64, 21), getBlobParameters(20, &schedule).max_blobs_per_block);
    try std.testing.expectEqual(@as(u64, 21), getBlobParameters(21, &schedule).max_blobs_per_block);
}

test "Fulu fork digest mixes the active blob parameters" {
    const root = [_]u8{2} ** 32;
    const schedule = [_]BlobParameters{
        .{ .epoch = 10, .max_blobs_per_block = 15 },
    };
    try std.testing.expectEqual(
        [_]u8{ 0x87, 0xdf, 0xb9, 0x7f },
        computeForkDigest(.{ 1, 2, 3, 4 }, root, 9, &schedule),
    );
    try std.testing.expectEqual(
        [_]u8{ 0x34, 0xce, 0xf7, 0xc7 },
        computeForkDigest(.{ 1, 2, 3, 4 }, root, 10, &schedule),
    );
}

test "active validator range is inclusive at activation and exclusive at exit" {
    const validator = fulu.Validator{
        .pubkey = [_]u8{0} ** 48,
        .withdrawal_credentials = [_]u8{0} ** 32,
        .effective_balance = 32_000_000_000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 3,
        .exit_epoch = 5,
        .withdrawable_epoch = 6,
    };
    try std.testing.expect(!isActiveValidator(validator, 2));
    try std.testing.expect(isActiveValidator(validator, 3));
    try std.testing.expect(isActiveValidator(validator, 4));
    try std.testing.expect(!isActiveValidator(validator, 5));
    try std.testing.expect(!isEligibleForActivationQueue(validator));
    try std.testing.expect(!isEligibleForActivation(validator, 2));
    try std.testing.expect(isSlashableValidator(validator, 3));
    try std.testing.expect(!isSlashableValidator(validator, 6));
    var activation_candidate = validator;
    activation_candidate.activation_eligibility_epoch = 3;
    activation_candidate.activation_epoch = FAR_FUTURE_EPOCH;
    try std.testing.expect(!isEligibleForActivation(activation_candidate, 2));
    try std.testing.expect(isEligibleForActivation(activation_candidate, 3));
    var far_future = validator;
    far_future.activation_eligibility_epoch = FAR_FUTURE_EPOCH;
    far_future.activation_epoch = FAR_FUTURE_EPOCH;
    far_future.exit_epoch = FAR_FUTURE_EPOCH;
    far_future.withdrawable_epoch = FAR_FUTURE_EPOCH;
    try std.testing.expect(isEligibleForActivationQueue(far_future));
    try std.testing.expect(!isEligibleForActivation(far_future, FAR_FUTURE_EPOCH - 1));
    far_future.activation_eligibility_epoch = 4;
    try std.testing.expect(isEligibleForActivation(far_future, 4));
    far_future.slashed = true;
    try std.testing.expect(!isSlashableValidator(far_future, 5));
}

test "total active balance floors empty sets at one increment" {
    try std.testing.expectEqual(EFFECTIVE_BALANCE_INCREMENT, try getTotalActiveBalance(&.{}, 0));
    const validators = [_]fulu.Validator{
        .{
            .pubkey = [_]u8{0} ** 48,
            .withdrawal_credentials = [_]u8{0} ** 32,
            .effective_balance = 32_000_000_000,
            .slashed = false,
            .activation_eligibility_epoch = 0,
            .activation_epoch = 1,
            .exit_epoch = 3,
            .withdrawable_epoch = 4,
        },
        .{
            .pubkey = [_]u8{0} ** 48,
            .withdrawal_credentials = [_]u8{0} ** 32,
            .effective_balance = 16_000_000_000,
            .slashed = false,
            .activation_eligibility_epoch = 0,
            .activation_epoch = 0,
            .exit_epoch = 2,
            .withdrawable_epoch = 3,
        },
    };
    try std.testing.expectEqual(@as(u64, 48_000_000_000), try getTotalActiveBalance(&validators, 1));
    var oversized = [_]fulu.Validator{ validators[1], validators[1] };
    oversized[0].effective_balance = std.math.maxInt(u64);
    oversized[1].effective_balance = 1;
    try std.testing.expectError(error.BalanceOverflow, getTotalActiveBalance(&oversized, 1));
}

test "weak subjectivity period uses Fulu balance cap and validator churn" {
    var state: fulu.BeaconState = undefined;
    const validators = [_]fulu.Validator{
        .{
            .pubkey = [_]u8{0} ** 48,
            .withdrawal_credentials = [_]u8{0} ** 32,
            .effective_balance = MAX_EFFECTIVE_BALANCE,
            .slashed = false,
            .activation_eligibility_epoch = 0,
            .activation_epoch = 0,
            .exit_epoch = FAR_FUTURE_EPOCH,
            .withdrawable_epoch = FAR_FUTURE_EPOCH,
        },
    };
    state.slot = 0;
    state.validators = .{ .data = &validators };
    try std.testing.expectEqual(@as(u64, MIN_VALIDATOR_WITHDRAWABILITY_DELAY), try computeWeakSubjectivityPeriod(&state));
    state.validators.data = &.{};
    try std.testing.expectError(error.InvalidState, computeWeakSubjectivityPeriod(&state));
}

test "weak subjectivity period accounts for compounding validator top-ups" {
    const allocator = std.testing.allocator;
    const validators = try allocator.alloc(fulu.Validator, 32_768);
    defer allocator.free(validators);
    @memset(validators, .{
        .pubkey = [_]u8{0} ** 48,
        .withdrawal_credentials = [_]u8{0} ** 32,
        .effective_balance = MAX_EFFECTIVE_BALANCE_ELECTRA,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = FAR_FUTURE_EPOCH,
        .withdrawable_epoch = FAR_FUTURE_EPOCH,
    });
    var state: fulu.BeaconState = undefined;
    state.slot = 0;
    state.validators = .{ .data = validators };
    try std.testing.expectEqual(@as(u64, 354), try computeWeakSubjectivityPeriod(&state));
}

test "shuffle matches pinned minimal phase0 mappings" {
    // consensus-specs v1.6.1: phase0/shuffling/core/shuffle, counts 10 and 33.
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "994fed15c5b2fdaeeff317f157e1e0978c3f5fd5df3d34f8c08262b03750894f");
    const mapping_10 = [_]usize{ 4, 1, 3, 0, 5, 9, 8, 6, 7, 2 };
    for (mapping_10, 0..) |expected, index| try std.testing.expectEqual(expected, try computeShuffledIndex(index, 10, seed));
    _ = try std.fmt.hexToBytes(&seed, "2e31cccbbba9308b6447b2ba8ef714ee15d90d6438985c87db5195fc232764af");
    const mapping_33 = [_]usize{ 7, 21, 14, 31, 25, 22, 6, 26, 11, 0, 18, 5, 1, 8, 16, 4, 24, 27, 30, 10, 20, 15, 2, 17, 32, 9, 28, 12, 23, 13, 29, 19, 3 };
    for (mapping_33, 0..) |expected, index| try std.testing.expectEqual(expected, try computeShuffledIndex(index, 33, seed));
    try std.testing.expectError(error.InvalidIndex, computeShuffledIndex(0, 0, seed));
    try std.testing.expectError(error.InvalidIndex, computeShuffledIndex(33, 33, seed));
}

test "committee partitions pinned shuffle mapping" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "994fed15c5b2fdaeeff317f157e1e0978c3f5fd5df3d34f8c08262b03750894f");
    const first = try computeCommittee(allocator, &indices, seed, 0, 2);
    defer allocator.free(first);
    const second = try computeCommittee(allocator, &indices, seed, 1, 2);
    defer allocator.free(second);
    try std.testing.expectEqualSlices(u64, &.{ 4, 1, 3, 0, 5 }, first);
    try std.testing.expectEqualSlices(u64, &.{ 9, 8, 6, 7, 2 }, second);
    try std.testing.expectError(error.InvalidCommittee, computeCommittee(allocator, &indices, seed, 2, 2));
    try std.testing.expectError(error.InvalidCommittee, computeCommittee(allocator, &indices, seed, 0, 0));
}

test "seed and beacon committees use minimal preset boundaries" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, fixtures.find("proposer_lookahead_in_state_matches_computed_lookahead").?.pre_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);

    state.randao_mixes[62] = [_]u8{0x42} ** 32;
    state.randao_mixes[0] = [_]u8{0x42} ** 32;
    // Expected hashes follow the pinned get_seed rule with a fixed RANDAO mix.
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "dc8544120a92782420b5d51597243f5990ee1c32d843bd7b8428fa8fc3ef57d0");
    try std.testing.expectEqual(expected, computeSeed(state, 0, DOMAIN_BEACON_ATTESTER));
    _ = try std.fmt.hexToBytes(&expected, "b80bc97afb8a03b4ad532d8974493cb1016080485803dc29acbb2fe01822ded6");
    try std.testing.expectEqual(expected, computeSeed(state, 2, DOMAIN_BEACON_ATTESTER));
    _ = try std.fmt.hexToBytes(&expected, "3c227d02cad6fd8918b15170f523898262f46b36a7b3a678d718364455bb68c4");
    try std.testing.expectEqual(expected, computeSeed(state, 64, DOMAIN_BEACON_ATTESTER));
    _ = computeSeed(state, std.math.maxInt(u64), DOMAIN_BEACON_ATTESTER);

    const validators = @constCast(state.validators.data);
    try std.testing.expect(validators.len >= 64);
    for (validators, 0..) |*validator, index| {
        validator.activation_epoch = if (index < 8) 0 else FAR_FUTURE_EPOCH;
        validator.exit_epoch = FAR_FUTURE_EPOCH;
    }
    const first = try getBeaconCommittee(allocator, &state, 0, 0);
    defer allocator.free(first);
    const second = try getBeaconCommittee(allocator, &state, 1, 0);
    defer allocator.free(second);
    try std.testing.expectEqualSlices(u64, &.{1}, first);
    try std.testing.expectEqualSlices(u64, &.{0}, second);
    try std.testing.expectError(error.InvalidCommittee, getBeaconCommittee(allocator, &state, 0, 1));

    for (validators[8..64]) |*validator| validator.activation_epoch = 0;
    const second_committee = try getBeaconCommittee(allocator, &state, 0, 1);
    defer allocator.free(second_committee);
    try std.testing.expectEqualSlices(u64, &.{ 58, 61, 46, 19 }, second_committee);
    try std.testing.expectError(error.InvalidCommittee, getBeaconCommittee(allocator, &state, 0, 2));

    for (validators) |*validator| validator.activation_epoch = FAR_FUTURE_EPOCH;
    const empty = try getBeaconCommittee(allocator, &state, 0, 0);
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "proposer indices use the sole eligible validator" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, fixtures.find("proposer_lookahead_in_state_matches_computed_lookahead").?.pre_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);

    for (@constCast(state.validators.data), 0..) |*validator, index| {
        validator.activation_epoch = if (index == 0) 0 else FAR_FUTURE_EPOCH;
        validator.exit_epoch = FAR_FUTURE_EPOCH;
    }
    const indices = try computeProposerIndices(allocator, state, 2);
    try std.testing.expectEqualSlices(u64, &([_]u64{0} ** SLOTS_PER_EPOCH), &indices);
}

test "Electra proposer weighting retries a low-balance candidate" {
    const low = fulu.Validator{
        .pubkey = [_]u8{0} ** 48,
        .withdrawal_credentials = [_]u8{0} ** 32,
        .effective_balance = MAX_EFFECTIVE_BALANCE,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = FAR_FUTURE_EPOCH,
        .withdrawable_epoch = FAR_FUTURE_EPOCH,
    };
    var high = low;
    high.effective_balance = MAX_EFFECTIVE_BALANCE_ELECTRA;
    const validators = [_]fulu.Validator{ low, high };
    const seed = [_]u8{1} ** 32;
    try std.testing.expectEqual(@as(u64, 1), try computeProposerIndex(&validators, &.{ 0, 1 }, seed));
    try std.testing.expectEqual(@as(u64, 1), try computeProposerIndex(&validators, &.{1}, seed));
    try std.testing.expectError(error.NoEligibleProposer, computeProposerIndex(&validators, &.{}, seed));
    try std.testing.expectError(error.NoEligibleProposer, computeProposerIndex(&validators, &.{2}, seed));
}

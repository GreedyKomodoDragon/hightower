// An epoch groups SLOTS_PER_EPOCH slots; slot-to-epoch arithmetic determines
// validator eligibility and the ring-buffer position used by consensus state.
// Seed, shuffle, and balance rules must use the same epoch and preset values
// because proposer selection depends on both ordering and exact integer math.
// This file currently uses Fulu's minimal-preset constants.
//
//   slot -> epoch -> active validators -> seeded shuffle -> proposer indices
const std = @import("std");
const fulu = @import("fulu");

pub const SLOTS_PER_EPOCH: u64 = 8;
pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 64;
pub const EPOCHS_PER_HISTORICAL_VECTOR: u64 = 64;
pub const EPOCHS_PER_SLASHINGS_VECTOR: u64 = 64;
pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 4;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 8;
pub const EPOCHS_PER_HISTORICAL_SUMMARY: u64 = SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH;
pub const EPOCH_OFFSET: u64 = 1;
pub const MIN_SEED_LOOKAHEAD: u64 = 1;
pub const MAX_SEED_LOOKAHEAD: u64 = 4;
pub const SHUFFLE_ROUND_COUNT: u8 = 10;
pub const JUSTIFICATION_BITS_LENGTH: usize = 4;
pub const JUSTIFICATION_SUPERMAJORITY_NUMERATOR: u64 = 2;
pub const JUSTIFICATION_SUPERMAJORITY_DENOMINATOR: u64 = 3;
pub const INACTIVITY_LEAK_EPOCH_THRESHOLD: u64 = 4;

// Effective balances are rounded in increments; Electra raises the cap only
// for compounding validators while keeping activation at 32 ETH.
pub const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
pub const EFFECTIVE_BALANCE_HYSTERESIS_DOWNWARD: u64 = 250_000_000;
pub const EFFECTIVE_BALANCE_HYSTERESIS_UPWARD: u64 = 1_250_000_000;
pub const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;
pub const MAX_EFFECTIVE_BALANCE_ELECTRA: u64 = 2_048_000_000_000;
pub const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
pub const EJECTION_BALANCE: u64 = 16_000_000_000;
pub const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: u64 = 64_000_000_000;
pub const MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: u64 = 128_000_000_000;
pub const CHURN_LIMIT_QUOTIENT: u64 = 32;
pub const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;

// Inactivity scores and participation weights are shared by Altair reward
// accounting and the inherited Fulu epoch transition.
pub const INACTIVITY_SCORE_BIAS: u64 = 4;
pub const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;
pub const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64 = 50_331_648;
pub const BASE_REWARD_FACTOR: u64 = 64;
pub const BASE_REWARDS_PER_EPOCH: u64 = 4;
pub const WEIGHT_DENOMINATOR: u64 = 64;
pub const PROPOSER_WEIGHT: u64 = 8;
pub const PARTICIPATION_FLAG_WEIGHTS = [_]u64{ 14, 26, 14 };
pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;
pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;
pub const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;
pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64 = 4096;
pub const FAR_FUTURE_EPOCH: u64 = std.math.maxInt(u64);

pub const DOMAIN_BEACON_PROPOSER = [_]u8{ 0, 0, 0, 0 };
pub const DOMAIN_RANDAO = [_]u8{ 2, 0, 0, 0 };
pub const DOMAIN_SYNC_COMMITTEE = [_]u8{ 7, 0, 0, 0 };

pub fn computeEpochAtSlot(slot: fulu.Slot) fulu.Epoch {
    return slot / SLOTS_PER_EPOCH;
}

pub fn computeStartSlotAtEpoch(epoch: fulu.Epoch) error{Overflow}!fulu.Slot {
    return std.math.mul(fulu.Slot, epoch, SLOTS_PER_EPOCH) catch error.Overflow;
}

pub fn isActiveValidator(validator: fulu.Validator, epoch: fulu.Epoch) bool {
    return validator.activation_epoch <= epoch and epoch < validator.exit_epoch;
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
    const mix_index = (epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1) % EPOCHS_PER_HISTORICAL_VECTOR;
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
    try std.testing.expectEqual(@as(u64, 16), try computeStartSlotAtEpoch(2));
    try std.testing.expectError(error.Overflow, computeStartSlotAtEpoch(std.math.maxInt(u64)));
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
}

test "shuffle is deterministic and rejects out-of-range inputs" {
    const seed = [_]u8{0x42} ** 32;
    const first = try computeShuffledIndex(2, 16, seed);
    try std.testing.expectEqual(first, try computeShuffledIndex(2, 16, seed));
    try std.testing.expectError(error.InvalidIndex, computeShuffledIndex(16, 16, seed));
}

test "committee assigns every index once across partitions" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const seed = [_]u8{0} ** 32;
    const first = try computeCommittee(allocator, &indices, seed, 0, 2);
    defer allocator.free(first);
    const second = try computeCommittee(allocator, &indices, seed, 1, 2);
    defer allocator.free(second);
    try std.testing.expectEqual(@as(usize, 4), first.len);
    try std.testing.expectEqual(@as(usize, 4), second.len);
    var seen = [_]bool{false} ** 8;
    for (first) |index| seen[index] = true;
    for (second) |index| seen[index] = true;
    for (seen) |value| try std.testing.expect(value);
}

// An epoch groups slots for validator accounting and scheduled state updates.
// This handler applies the supported quiet-epoch penalties, Fulu pending
// queues, effective balances, randomness rollover, and proposer lookahead.
const std = @import("std");
const fulu = @import("fulu");
const helpers = @import("helpers.zig");
const lookahead = @import("lookahead.zig");
const deposits = @import("pending_deposits.zig");
const consolidations = @import("pending_consolidations.zig");

// shortcut: supports quiet epochs 0 and 1; add full Fulu finality, rewards,
// registry, and slashings handlers before accepting later epochs.
pub fn processEpoch(allocator: std.mem.Allocator, state: *fulu.BeaconState) !void {
    if ((state.slot + 1) % helpers.SLOTS_PER_EPOCH != 0) return error.NotEpochBoundary;
    const current_epoch = helpers.computeEpochAtSlot(state.slot);
    if (current_epoch > 1) return error.UnsupportedEpochState;
    if (state.pending_partial_withdrawals.data.len != 0)
        return error.UnsupportedEpochState;
    if (state.eth1_data_votes.data.len != 0 or state.historical_summaries.data.len != 0)
        return error.UnsupportedEpochState;
    if (state.validators.data.len != state.balances.data.len or
        state.validators.data.len != state.current_epoch_participation.data.len or
        state.validators.data.len != state.previous_epoch_participation.data.len or
        state.validators.data.len != state.inactivity_scores.data.len)
        return error.InvalidState;
    for (state.validators.data, state.balances.data, state.current_epoch_participation.data, state.previous_epoch_participation.data, state.inactivity_scores.data) |validator, balance, current_flags, previous_flags, inactivity_score| {
        if (!helpers.isActiveValidator(validator, current_epoch) or validator.slashed or
            validator.effective_balance != balance or current_flags != 0 or
            previous_flags != 0 or inactivity_score != 0)
            return error.UnsupportedEpochState;
    }
    for (state.slashings) |value| if (value != 0) return error.UnsupportedEpochState;

    if (current_epoch == 1) {
        var total_active_balance: u128 = 0;
        for (state.validators.data) |validator| total_active_balance += validator.effective_balance;
        if (total_active_balance == 0) return error.InvalidState;
        const base_reward_per_increment = 1_000_000_000 * 64 / std.math.sqrt(total_active_balance);
        for (state.validators.data, 0..) |validator, index| {
            const base_reward = validator.effective_balance / 1_000_000_000 * base_reward_per_increment;
            const penalty: u64 = @intCast(base_reward * 14 / 64 + base_reward * 26 / 64);
            @constCast(state.balances.data)[index] -|= penalty;
        }
    }
    try deposits.processPendingDeposits(allocator, state);
    try consolidations.processPendingConsolidations(allocator, state);
    processEffectiveBalanceUpdates(state);
    try lookahead.processProposerLookahead(allocator, state);
    state.randao_mixes[(current_epoch + 1) % helpers.EPOCHS_PER_HISTORICAL_VECTOR] =
        state.randao_mixes[current_epoch % helpers.EPOCHS_PER_HISTORICAL_VECTOR];
}

pub fn processEffectiveBalanceUpdates(state: *fulu.BeaconState) void {
    const downward_threshold: u64 = 250_000_000;
    const upward_threshold: u64 = 1_250_000_000;
    for (state.validators.data, state.balances.data, 0..) |validator, balance, index| {
        const effective = validator.effective_balance;
        if (@as(u128, balance) + downward_threshold < effective or
            @as(u128, effective) + upward_threshold < balance)
        {
            const max_balance = if (validator.withdrawal_credentials[0] == 0x02)
                helpers.MAX_EFFECTIVE_BALANCE_ELECTRA
            else
                helpers.MAX_EFFECTIVE_BALANCE;
            @constCast(state.validators.data)[index].effective_balance =
                @min(balance - balance % 1_000_000_000, max_balance);
        }
    }
}

test "genesis pending deposits match the pinned full epoch result" {
    const fixtures = @import("fixture_runner.zig");
    const merkle = @import("merkle");
    const allocator = std.testing.allocator;
    const case = fixtures.find("process_pending_deposits_multiple_pending_deposits_below_churn").?;
    var state = try fixtures.decodeState(allocator, case.pre_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    const expected = try fixtures.decodeState(allocator, case.post_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, expected);
    try processEpoch(allocator, &state);
    const actual_root = try merkle.HashTreeRoot(allocator, state);
    const expected_root = try merkle.HashTreeRoot(allocator, expected);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "effective balance hysteresis respects thresholds and compounding cap" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("slots_1").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    @constCast(state.balances.data)[0] = 31_750_000_000;
    @constCast(state.balances.data)[1] = 31_749_999_999;
    @constCast(state.balances.data)[2] = 34_000_000_000;
    @constCast(state.validators.data)[2].withdrawal_credentials[0] = 0x02;
    processEffectiveBalanceUpdates(&state);
    try std.testing.expectEqual(@as(u64, 32_000_000_000), state.validators.data[0].effective_balance);
    try std.testing.expectEqual(@as(u64, 31_000_000_000), state.validators.data[1].effective_balance);
    try std.testing.expectEqual(@as(u64, 34_000_000_000), state.validators.data[2].effective_balance);
}

test "epoch handler rejects unsupported later epochs" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("over_epoch_boundary").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    state.slot = helpers.SLOTS_PER_EPOCH * 3 - 1;
    try std.testing.expectError(error.UnsupportedEpochState, processEpoch(allocator, &state));
}

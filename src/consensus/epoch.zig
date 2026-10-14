// An epoch groups eight slots in the minimal preset. Its final slot applies
// participation rewards, finality, validator registry changes, and Fulu queues
// before the next slot begins. Order matters because later handlers consume
// state changed by earlier ones:
//
//   justification/finality -> inactivity -> rewards -> registry/slashings
//     -> deposits -> consolidations -> effective balances -> resets/history
//       -> participation rotation -> sync committees -> proposer lookahead
//
// Rewards read the old participation flags, while registry changes read the
// finalized checkpoint. Deposits and consolidations change balances before
// effective balances are rounded; the final lookahead uses the updated registry.
// Effective balance is the rounded, capped weight used for validator selection.
// RANDAO and historical rings carry consensus data across epoch boundaries.
// This implementation supports the pinned Fulu minimal preset.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const helpers = @import("helpers.zig");
const lookahead = @import("lookahead.zig");
const deposits = @import("pending_deposits.zig");
const consolidations = @import("pending_consolidations.zig");
const blst = @import("blst");

pub fn processEpoch(allocator: std.mem.Allocator, state: *fulu.BeaconState) !void {
    if ((state.slot + 1) % helpers.SLOTS_PER_EPOCH != 0) return error.NotEpochBoundary;
    const current_epoch = helpers.getCurrentEpoch(state);
    if (state.validators.data.len != state.balances.data.len or
        state.validators.data.len != state.current_epoch_participation.data.len or
        state.validators.data.len != state.previous_epoch_participation.data.len or
        state.validators.data.len != state.inactivity_scores.data.len)
        return error.InvalidState;

    try processJustificationAndFinalization(state, current_epoch);
    processInactivityUpdates(state, current_epoch);
    try processRewardsAndPenalties(allocator, state, current_epoch);
    try processRegistryUpdates(state, current_epoch);
    processSlashings(state, current_epoch);
    processEth1DataReset(allocator, state, current_epoch);
    try deposits.processPendingDeposits(allocator, state);
    try consolidations.processPendingConsolidations(allocator, state);
    processEffectiveBalanceUpdates(state);
    processSlashingsReset(state, current_epoch);
    processRandaoMixesReset(state, current_epoch);
    try processHistoricalSummariesUpdate(allocator, state, current_epoch);
    try processParticipationFlagUpdates(allocator, state);
    try processSyncCommitteeUpdates(allocator, state, current_epoch);
    try lookahead.processProposerLookahead(allocator, state);
}

pub fn processJustificationAndFinalization(state: *fulu.BeaconState, current_epoch: fulu.Epoch) !void {
    // Genesis and epoch 1 have no complete pair of prior epochs to justify.
    if (current_epoch <= helpers.EPOCH_OFFSET) return;
    const previous_epoch = helpers.computePreviousEpoch(current_epoch);
    const total_active_balance = totalBalance(state, null, current_epoch);
    const previous_target_balance = totalBalance(state, helpers.TIMELY_TARGET_FLAG_INDEX, previous_epoch);
    const current_target_balance = totalBalance(state, helpers.TIMELY_TARGET_FLAG_INDEX, current_epoch);
    const old_previous = state.previous_justified_checkpoint;
    const old_current = state.current_justified_checkpoint;

    // Preserve the old checkpoints for finalization tests, then shift the
    // four-bit history before adding this epoch's two-thirds support results.
    state.previous_justified_checkpoint = state.current_justified_checkpoint;
    for (0..(helpers.JUSTIFICATION_BITS_LENGTH - 1)) |i| {
        state.justification_bits.data[helpers.JUSTIFICATION_BITS_LENGTH - 1 - i] =
            state.justification_bits.data[helpers.JUSTIFICATION_BITS_LENGTH - 2 - i];
    }
    state.justification_bits.data[0] = false;
    // Two-thirds support is checked by cross-multiplying, avoiding division
    // and rounding in this consensus decision.
    if (@as(u128, previous_target_balance) * helpers.JUSTIFICATION_SUPERMAJORITY_DENOMINATOR >=
        @as(u128, total_active_balance) * helpers.JUSTIFICATION_SUPERMAJORITY_NUMERATOR)
    {
        state.current_justified_checkpoint = .{ .epoch = previous_epoch, .root = try blockRootAtEpoch(state, previous_epoch) };
        state.justification_bits.data[1] = true;
    }
    if (@as(u128, current_target_balance) * helpers.JUSTIFICATION_SUPERMAJORITY_DENOMINATOR >=
        @as(u128, total_active_balance) * helpers.JUSTIFICATION_SUPERMAJORITY_NUMERATOR)
    {
        state.current_justified_checkpoint = .{ .epoch = current_epoch, .root = try blockRootAtEpoch(state, current_epoch) };
        state.justification_bits.data[0] = true;
    }
    const bits = state.justification_bits.data;
    if (bits[1] and bits[2] and bits[3] and old_previous.epoch + 3 == current_epoch) state.finalized_checkpoint = old_previous;
    if (bits[1] and bits[2] and old_previous.epoch + 2 == current_epoch) state.finalized_checkpoint = old_previous;
    if (bits[0] and bits[1] and bits[2] and old_current.epoch + 2 == current_epoch) state.finalized_checkpoint = old_current;
    if (bits[0] and bits[1] and old_current.epoch + 1 == current_epoch) state.finalized_checkpoint = old_current;
}

fn blockRootAtEpoch(state: *const fulu.BeaconState, epoch_number: fulu.Epoch) !fulu.Root {
    const slot = try helpers.computeStartSlotAtEpoch(epoch_number);
    return state.block_roots[slot % state.block_roots.len];
}

fn totalBalance(state: *const fulu.BeaconState, flag_index: ?usize, epoch_number: fulu.Epoch) u64 {
    var balance: u128 = 0;
    for (state.validators.data, 0..) |validator, index| {
        if (flag_index) |flag| {
            if (!helpers.isActiveValidator(validator, epoch_number)) continue;
            const flags = if (epoch_number == helpers.computeEpochAtSlot(state.slot))
                state.current_epoch_participation.data[index]
            else
                state.previous_epoch_participation.data[index];
            // Participation rewards count only active, unslashed validators.
            if (validator.slashed or flags & (@as(u8, 1) << @as(u3, @intCast(flag))) == 0) continue;
        } else if (!helpers.isActiveValidator(validator, epoch_number)) continue;
        balance += validator.effective_balance;
    }
    // SSZ consensus totals use one increment as the denominator floor, even
    // when no validator participated.
    return @intCast(@max(balance, helpers.EFFECTIVE_BALANCE_INCREMENT));
}

fn isEligibleForRewards(validator: fulu.Validator, previous_epoch: fulu.Epoch) bool {
    return helpers.isActiveValidator(validator, previous_epoch) or
        (validator.slashed and previous_epoch + 1 < validator.withdrawable_epoch);
}

fn isInInactivityLeak(state: *const fulu.BeaconState, current_epoch: fulu.Epoch) bool {
    return current_epoch -| helpers.EPOCH_OFFSET -| state.finalized_checkpoint.epoch > helpers.INACTIVITY_LEAK_EPOCH_THRESHOLD;
}

pub fn processInactivityUpdates(state: *fulu.BeaconState, current_epoch: fulu.Epoch) void {
    if (current_epoch == 0) return;
    const leaking = isInInactivityLeak(state, current_epoch);
    for (state.validators.data, 0..) |validator, index| {
        if (!isEligibleForRewards(validator, current_epoch - 1)) continue;
        const flags = state.previous_epoch_participation.data[index];
        const target = !validator.slashed and flags & (@as(u8, 1) << helpers.TIMELY_TARGET_FLAG_INDEX) != 0;
        const score = &@constCast(state.inactivity_scores.data)[index];
        if (target) score.* -|= 1 else score.* +|= helpers.INACTIVITY_SCORE_BIAS;
        if (!leaking) score.* -|= helpers.INACTIVITY_SCORE_RECOVERY_RATE;
    }
}

pub fn processRewardsAndPenalties(allocator: std.mem.Allocator, state: *fulu.BeaconState, current_epoch: fulu.Epoch) !void {
    // There are no previous-epoch attestations to reward at genesis.
    if (current_epoch == 0) return;
    const count = state.validators.data.len;
    const rewards = try allocator.alloc(u64, count);
    defer allocator.free(rewards);
    const penalties = try allocator.alloc(u64, count);
    defer allocator.free(penalties);
    @memset(rewards, 0);
    @memset(penalties, 0);

    const total_active = totalBalance(state, null, current_epoch);
    const active_increments = @max(total_active / helpers.EFFECTIVE_BALANCE_INCREMENT, 1);
    const leaking = isInInactivityLeak(state, current_epoch);
    const previous_epoch = helpers.computePreviousEpoch(current_epoch);
    // Each flag has its own weight and participating balance; head misses do
    // not incur a penalty because timely-head rewards are intentionally small.
    for (0..helpers.PARTICIPATION_FLAG_WEIGHTS.len) |flag_index| {
        const participating_balance = totalBalance(state, flag_index, previous_epoch);
        const participating_increments = participating_balance / helpers.EFFECTIVE_BALANCE_INCREMENT;
        for (state.validators.data, 0..) |validator, index| {
            if (!isEligibleForRewards(validator, previous_epoch)) continue;
            const base = baseReward(validator.effective_balance, total_active);
            const flags = state.previous_epoch_participation.data[index];
            const participated = !validator.slashed and flags & (@as(u8, 1) << @as(u3, @intCast(flag_index))) != 0;
            if (participated) {
                if (!leaking) rewards[index] += base * helpers.PARTICIPATION_FLAG_WEIGHTS[flag_index] * participating_increments / (active_increments * helpers.WEIGHT_DENOMINATOR);
            } else if (flag_index != helpers.TIMELY_HEAD_FLAG_INDEX) {
                penalties[index] += base * helpers.PARTICIPATION_FLAG_WEIGHTS[flag_index] / helpers.WEIGHT_DENOMINATOR;
            }
        }
    }
    for (state.validators.data, 0..) |validator, index| {
        if (!isEligibleForRewards(validator, previous_epoch)) continue;
        const flags = state.previous_epoch_participation.data[index];
        const target = !validator.slashed and flags & (@as(u8, 1) << helpers.TIMELY_TARGET_FLAG_INDEX) != 0;
        if (!target) penalties[index] += validator.effective_balance * state.inactivity_scores.data[index] /
            (helpers.INACTIVITY_SCORE_BIAS * helpers.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX);
    }
    for (0..count) |index| {
        @constCast(state.balances.data)[index] = std.math.add(u64, state.balances.data[index], rewards[index]) catch return error.BalanceOverflow;
        @constCast(state.balances.data)[index] -|= penalties[index];
    }
}

fn baseReward(effective_balance: u64, total_active_balance: u64) u64 {
    // The spec rounds per increment first; combining these divisions changes
    // rewards by a few Gwei and breaks state-root agreement.
    const per_increment = helpers.EFFECTIVE_BALANCE_INCREMENT * helpers.BASE_REWARD_FACTOR / std.math.sqrt(total_active_balance);
    return per_increment * (effective_balance / helpers.EFFECTIVE_BALANCE_INCREMENT);
}

pub fn processRegistryUpdates(state: *fulu.BeaconState, current_epoch: fulu.Epoch) !void {
    for (state.validators.data, 0..) |validator, index| {
        // These conditions are mutually exclusive and ordered: first join the
        // activation queue, then eject active validators, then activate finalized entries.
        if (helpers.isEligibleForActivationQueue(validator)) {
            @constCast(state.validators.data)[index].activation_eligibility_epoch = current_epoch + 1;
        } else if (helpers.isActiveValidator(validator, current_epoch) and validator.effective_balance <= helpers.EJECTION_BALANCE) {
            try initiateValidatorExit(state, index, current_epoch);
        } else if (helpers.isEligibleForActivation(validator, state.finalized_checkpoint.epoch)) {
            // Eligibility is inclusive: an entry at the finalized epoch may activate.
            @constCast(state.validators.data)[index].activation_epoch = helpers.computeActivationExitEpoch(current_epoch) catch return error.InvalidState;
        }
    }
}

fn initiateValidatorExit(state: *fulu.BeaconState, index: usize, current_epoch: fulu.Epoch) !void {
    const validator = state.validators.data[index];
    if (validator.exit_epoch != helpers.FAR_FUTURE_EPOCH) return;
    const active_total = totalBalance(state, null, current_epoch);
    const balance_churn = @max(helpers.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, active_total / helpers.CHURN_LIMIT_QUOTIENT);
    const churn = @min(helpers.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, balance_churn);
    if (churn == 0) return error.InvalidState;
    // Electra schedules exits by balance churn, so one large exit can advance
    // the queue by several epochs while sharing the remaining epoch allowance.
    var earliest = @max(state.earliest_exit_epoch, helpers.computeActivationExitEpoch(current_epoch) catch return error.InvalidState);
    var consume = if (state.earliest_exit_epoch < earliest) churn else state.exit_balance_to_consume;
    if (validator.effective_balance > consume) {
        const additional = (validator.effective_balance - consume - 1) / churn + 1;
        earliest = std.math.add(u64, earliest, additional) catch return error.InvalidState;
        consume = std.math.add(u64, consume, additional * churn) catch return error.InvalidState;
    }
    state.exit_balance_to_consume = consume - validator.effective_balance;
    state.earliest_exit_epoch = earliest;
    @constCast(state.validators.data)[index].exit_epoch = earliest;
    @constCast(state.validators.data)[index].withdrawable_epoch = std.math.add(u64, earliest, helpers.MIN_VALIDATOR_WITHDRAWABILITY_DELAY) catch return error.InvalidState;
}

pub fn processSlashings(state: *fulu.BeaconState, current_epoch: fulu.Epoch) void {
    const active_balance = totalBalance(state, null, current_epoch);
    const total_slashings: u128 = @min(@as(u128, std.math.maxInt(u64)), blk: {
        var sum: u128 = 0;
        for (state.slashings) |amount| sum += amount;
        break :blk sum;
    });
    // Cap the correlated slash amount at active balance before scaling each
    // slashed validator's effective-balance increments.
    const adjusted = @min(total_slashings * helpers.PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX, active_balance);
    const per_increment = adjusted / (active_balance / helpers.EFFECTIVE_BALANCE_INCREMENT);
    for (state.validators.data, 0..) |validator, index| {
        if (validator.slashed and current_epoch + helpers.EPOCHS_PER_SLASHINGS_VECTOR / 2 == validator.withdrawable_epoch) {
            const penalty = per_increment * (validator.effective_balance / helpers.EFFECTIVE_BALANCE_INCREMENT);
            @constCast(state.balances.data)[index] -|= @intCast(penalty);
        }
    }
}

pub fn processEth1DataReset(allocator: std.mem.Allocator, state: *fulu.BeaconState, current_epoch: fulu.Epoch) void {
    // Votes are scoped to a voting period; retaining old votes would skew the
    // next period's majority calculation.
    if ((current_epoch + 1) % helpers.EPOCHS_PER_ETH1_VOTING_PERIOD == 0) {
        if (state.eth1_data_votes.data.len != 0) allocator.free(@constCast(state.eth1_data_votes.data));
        state.eth1_data_votes.data = &.{};
    }
}

pub fn processSlashingsReset(state: *fulu.BeaconState, current_epoch: fulu.Epoch) void {
    // The next epoch starts writing to this position in the slashings ring.
    state.slashings[(current_epoch + 1) % helpers.EPOCHS_PER_SLASHINGS_VECTOR] = 0;
}

pub fn processRandaoMixesReset(state: *fulu.BeaconState, current_epoch: fulu.Epoch) void {
    // Keep the ring-buffer index aligned with the next epoch before it begins.
    state.randao_mixes[(current_epoch + 1) % helpers.EPOCHS_PER_HISTORICAL_VECTOR] =
        state.randao_mixes[current_epoch % helpers.EPOCHS_PER_HISTORICAL_VECTOR];
}

pub fn processHistoricalSummariesUpdate(allocator: std.mem.Allocator, state: *fulu.BeaconState, current_epoch: fulu.Epoch) !void {
    // A historical root covers eight minimal-preset epochs; append its pair of
    // ring roots only when that window closes.
    if ((current_epoch + helpers.EPOCH_OFFSET) % helpers.EPOCHS_PER_HISTORICAL_SUMMARY != 0) return;
    const summary = fulu.HistoricalSummary{
        .block_summary_root = try merkle.HashTreeRoot(allocator, state.block_roots),
        .state_summary_root = try merkle.HashTreeRoot(allocator, state.state_roots),
    };
    const old = state.historical_summaries.data;
    const updated = try allocator.alloc(fulu.HistoricalSummary, old.len + 1);
    @memcpy(updated[0..old.len], old);
    updated[old.len] = summary;
    if (old.len != 0) allocator.free(@constCast(old));
    state.historical_summaries.data = updated;
}

pub fn processParticipationFlagUpdates(allocator: std.mem.Allocator, state: *fulu.BeaconState) !void {
    // Rewards have consumed the previous/current lists by this point: retain
    // current as next epoch's previous flags and allocate a clean current list.
    const old_previous = state.previous_epoch_participation.data;
    const next_current = try allocator.alloc(u8, state.current_epoch_participation.data.len);
    @memset(next_current, 0);
    state.previous_epoch_participation.data = state.current_epoch_participation.data;
    state.current_epoch_participation.data = next_current;
    if (old_previous.len != 0) allocator.free(@constCast(old_previous));
}

pub fn processSyncCommitteeUpdates(allocator: std.mem.Allocator, state: *fulu.BeaconState, current_epoch: fulu.Epoch) !void {
    const next_epoch = current_epoch + 1;
    if (next_epoch % helpers.EPOCHS_PER_SYNC_COMMITTEE_PERIOD != 0) return;
    // Promote the committee already used for this period before sampling its successor.
    state.current_sync_committee = state.next_sync_committee;
    state.next_sync_committee = try computeNextSyncCommittee(allocator, state, next_epoch);
}

fn computeNextSyncCommittee(allocator: std.mem.Allocator, state: *const fulu.BeaconState, epoch_number: fulu.Epoch) !fulu.SyncCommittee {
    const active = try helpers.getActiveValidatorIndices(allocator, state.validators.data, epoch_number);
    defer allocator.free(active);
    if (active.len == 0) return error.NoEligibleProposer;
    const seed = helpers.computeSeed(state.*, epoch_number, helpers.DOMAIN_SYNC_COMMITTEE);
    var pubkeys: [32]fulu.BLSPubkey = undefined;
    var index: u64 = 0;
    var filled: usize = 0;
    // Rejection sampling preserves effective-balance weighting while allowing
    // duplicate validator indices, as required by the sync committee spec.
    while (filled < pubkeys.len) : (index += 1) {
        const candidate = active[try helpers.computeShuffledIndex(index % active.len, active.len, seed)];
        var input: [40]u8 = undefined;
        @memcpy(input[0..32], &seed);
        std.mem.writeInt(u64, input[32..40], index / 16, .little);
        var random: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&input, &random, .{});
        const offset: usize = @intCast((index % 16) * 2);
        const random_value = @as(u16, random[offset]) | (@as(u16, random[offset + 1]) << 8);
        if (@as(u128, state.validators.data[candidate].effective_balance) * std.math.maxInt(u16) < @as(u128, helpers.MAX_EFFECTIVE_BALANCE_ELECTRA) * random_value) continue;
        pubkeys[filled] = state.validators.data[candidate].pubkey;
        filled += 1;
        if (index == std.math.maxInt(u64)) return error.NoEligibleProposer;
    }
    var aggregate: ?blst.P1 = null;
    for (pubkeys) |pubkey| {
        const point = try blst.P1_Affine.from(&pubkey);
        if (aggregate) |*accumulator| try accumulator.aggregate(&point) else aggregate = point.to_jacobian();
    }
    return .{ .pubkeys = pubkeys, .aggregate_pubkey = aggregate.?.to_affine().compress() };
}

pub fn processEffectiveBalanceUpdates(state: *fulu.BeaconState) void {
    const downward_threshold = helpers.EFFECTIVE_BALANCE_HYSTERESIS_DOWNWARD;
    const upward_threshold = helpers.EFFECTIVE_BALANCE_HYSTERESIS_UPWARD;
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
                @min(balance - balance % helpers.EFFECTIVE_BALANCE_INCREMENT, max_balance);
        }
    }
}

test "genesis pending deposits match the pinned full epoch result" {
    const fixtures = @import("fixture_runner.zig");
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

test "epoch handler processes epochs after genesis" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("over_epoch_boundary").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    state.slot = helpers.SLOTS_PER_EPOCH * 3 - 1;
    try processEpoch(allocator, &state);
}

test "slashed target voter gains inactivity score during a leak" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("slots_1").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    state.slot = 10 * helpers.SLOTS_PER_EPOCH;
    state.finalized_checkpoint.epoch = 0;
    @constCast(state.validators.data)[0].slashed = true;
    @constCast(state.validators.data)[0].withdrawable_epoch = helpers.FAR_FUTURE_EPOCH;
    @constCast(state.previous_epoch_participation.data)[0] = @as(u8, 1) << helpers.TIMELY_TARGET_FLAG_INDEX;
    @constCast(state.inactivity_scores.data)[0] = 10;

    processInactivityUpdates(&state, 10);
    try std.testing.expectEqual(@as(u64, 14), state.inactivity_scores.data[0]);
}

test "leak rewards use only flag misses and Bellatrix inactivity penalty" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("slots_1").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    state.slot = 10 * helpers.SLOTS_PER_EPOCH;
    state.finalized_checkpoint.epoch = 0;
    @constCast(state.validators.data)[0].slashed = false;
    @constCast(state.validators.data)[0].activation_epoch = 0;
    @constCast(state.validators.data)[0].exit_epoch = helpers.FAR_FUTURE_EPOCH;
    const initial_balance = state.balances.data[0];
    @constCast(state.previous_epoch_participation.data)[0] = 0b111;
    @constCast(state.inactivity_scores.data)[0] = 4;

    try processRewardsAndPenalties(allocator, &state, 10);
    try std.testing.expectEqual(initial_balance, state.balances.data[0]);

    @constCast(state.previous_epoch_participation.data)[0] = 0;
    const effective = state.validators.data[0].effective_balance;
    const base = baseReward(effective, totalBalance(&state, null, 10));
    const flag_penalty = base * helpers.PARTICIPATION_FLAG_WEIGHTS[0] / helpers.WEIGHT_DENOMINATOR +
        base * helpers.PARTICIPATION_FLAG_WEIGHTS[1] / helpers.WEIGHT_DENOMINATOR;
    const inactivity_penalty = effective * 4 / (helpers.INACTIVITY_SCORE_BIAS * helpers.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX);
    try processRewardsAndPenalties(allocator, &state, 10);
    try std.testing.expectEqual(initial_balance - flag_penalty - inactivity_penalty, state.balances.data[0]);
}

test "Electra slashing rounds before scaling by validator increments" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("slots_1").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    state.slot = 10 * helpers.SLOTS_PER_EPOCH;
    @constCast(state.validators.data)[0].slashed = true;
    @constCast(state.validators.data)[0].withdrawable_epoch = 10 + helpers.EPOCHS_PER_SLASHINGS_VECTOR / 2;
    @memset(&state.slashings, 0);
    state.slashings[0] = 1_000_000_001;
    const initial_balance = state.balances.data[0];
    const active_increments = totalBalance(&state, null, 10) / helpers.EFFECTIVE_BALANCE_INCREMENT;
    const validator_increments = state.validators.data[0].effective_balance / helpers.EFFECTIVE_BALANCE_INCREMENT;
    const expected_penalty = (3_000_000_003 / active_increments) * validator_increments;

    processSlashings(&state, 10);
    try std.testing.expectEqual(initial_balance -| expected_penalty, state.balances.data[0]);
    try std.testing.expect(expected_penalty != 3_000_000_003 * validator_increments / active_increments);
}

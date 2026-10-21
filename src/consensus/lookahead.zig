// A block proposer is the validator assigned to propose a block for one slot.
// Fulu stores two epochs of proposer indices in BeaconState so the schedule is
// already known when a slot starts. At each epoch boundary, this file rolls
// that fixed-size window forward:
//
//   [older epoch | newer epoch]
//                -> [newer epoch | newly computed epoch]
//
// The new indices are selected for current_epoch + 2 using the validator set,
// effective balances, shuffling seed, and RANDAO history in helpers.zig. The
// slot lookup reads the first half at the slot's offset within its epoch.
const std = @import("std");
const fulu = @import("fulu");
const helpers = @import("helpers.zig");

pub fn getBeaconProposerIndex(state: fulu.BeaconState) fulu.ValidatorIndex {
    return state.proposer_lookahead[state.slot % helpers.SLOTS_PER_EPOCH];
}

pub fn processProposerLookahead(allocator: std.mem.Allocator, state: *fulu.BeaconState) !void {
    const epoch_proposers = try helpers.computeProposerIndices(
        allocator,
        state.*,
        helpers.computeEpochAtSlot(state.slot) + helpers.MIN_SEED_LOOKAHEAD + 1,
    );
    @memmove(state.proposer_lookahead[0..helpers.SLOTS_PER_EPOCH], state.proposer_lookahead[helpers.SLOTS_PER_EPOCH..]);
    @memcpy(state.proposer_lookahead[helpers.SLOTS_PER_EPOCH..], &epoch_proposers);
}

test "Fulu proposer lookahead matches both pinned epoch fixtures" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "proposer_lookahead_in_state_matches_computed_lookahead",
        "proposer_lookahead_does_not_contain_exited_validators",
    }) |name| {
        const case = fixtures.find(name).?;
        var state = try fixtures.decodeState(allocator, case.pre_epoch.?);
        defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
        const expected = try fixtures.decodeState(allocator, case.post_epoch.?);
        defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, expected);
        try processProposerLookahead(allocator, &state);
        try std.testing.expectEqualSlices(u64, &expected.proposer_lookahead, &state.proposer_lookahead);
    }
}

test "proposer lookahead rolls over at the minimal epoch boundary" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, fixtures.find("proposer_lookahead_in_state_matches_computed_lookahead").?.pre_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);

    state.slot = helpers.SLOTS_PER_EPOCH;
    const previous = state.proposer_lookahead;
    const next = try helpers.computeProposerIndices(allocator, state, 3);
    try processProposerLookahead(allocator, &state);
    try std.testing.expectEqualSlices(u64, previous[helpers.SLOTS_PER_EPOCH..], state.proposer_lookahead[0..helpers.SLOTS_PER_EPOCH]);
    try std.testing.expectEqualSlices(u64, &next, state.proposer_lookahead[helpers.SLOTS_PER_EPOCH..]);
}

test "failed proposer lookahead computation leaves the window unchanged" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, fixtures.find("proposer_lookahead_in_state_matches_computed_lookahead").?.pre_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);

    for (@constCast(state.validators.data)) |*validator| {
        validator.activation_epoch = helpers.FAR_FUTURE_EPOCH;
        validator.exit_epoch = helpers.FAR_FUTURE_EPOCH;
    }
    state.proposer_lookahead = [_]u64{7} ** 16;
    const previous = state.proposer_lookahead;
    try std.testing.expectError(error.NoEligibleProposer, processProposerLookahead(allocator, &state));
    try std.testing.expectEqualSlices(u64, &previous, &state.proposer_lookahead);
}

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

// Electra and Fulu share every state field except Fulu's two-epoch proposer
// window. At the first slot of the fork epoch, copy the Electra snapshot,
// change the fork version, then compute proposer assignments in slot order.
//
//   Electra boundary state -> owned Fulu state -> epoch 0 | epoch 1 proposers
//
// The selected preset fixes vector sizes and fork versions. The caller owns
// the returned state and releases it with ssz.freeDecoded.
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const helpers = @import("helpers.zig");
const preset = @import("consensus_preset").Config;
const pool = @import("operation_pool.zig");
const engine_api = @import("execution_engine.zig");

/// Upgrade a valid Electra boundary state, leaving the input and its allocations untouched.
pub fn upgradeToFulu(allocator: std.mem.Allocator, pre: *const fulu.ElectraBeaconState) !fulu.BeaconState {
    if (pre.slot % helpers.SLOTS_PER_EPOCH != 0 or
        !std.mem.eql(u8, &pre.fork.current_version, &preset.ELECTRA_FORK_VERSION) or
        pre.validators.data.len != pre.balances.data.len or
        pre.validators.data.len != pre.previous_epoch_participation.data.len or
        pre.validators.data.len != pre.current_epoch_participation.data.len or
        pre.validators.data.len != pre.inactivity_scores.data.len)
        return error.InvalidPreState;

    var borrowed: fulu.BeaconState = undefined;
    inline for (@typeInfo(fulu.ElectraBeaconState).@"struct".fields) |field| {
        @field(borrowed, field.name) = @field(pre.*, field.name);
    }
    const epoch = helpers.computeEpochAtSlot(pre.slot);
    borrowed.fork = .{
        .previous_version = pre.fork.current_version,
        .current_version = preset.FULU_FORK_VERSION,
        .epoch = epoch,
    };
    borrowed.proposer_lookahead = undefined;
    for (0..2) |offset| {
        const target_epoch = std.math.add(u64, epoch, offset) catch return error.InvalidPreState;
        const indices = try helpers.computeProposerIndices(allocator, borrowed, target_epoch);
        @memcpy(borrowed.proposer_lookahead[offset * helpers.SLOTS_PER_EPOCH ..][0..helpers.SLOTS_PER_EPOCH], &indices);
    }
    return pool.copyValue(allocator, fulu.BeaconState, borrowed);
}

/// Activate Fulu at its configured epoch and apply the first signed Fulu block.
pub fn stateTransitionFromElectra(
    allocator: std.mem.Allocator,
    pre: *const fulu.ElectraBeaconState,
    signed: fulu.SignedBeaconBlock,
    engine: engine_api.ExecutionEngine,
) !fulu.BeaconState {
    if (helpers.computeEpochAtSlot(pre.slot) != preset.FULU_FORK_EPOCH) return error.NotFuluBoundary;
    var state = try upgradeToFulu(allocator, pre);
    errdefer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    try @import("block.zig").stateTransition(allocator, &state, signed, engine);
    return state;
}

test "upgrade rejects invalid boundary without changing the input" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const compressed = @embedFile("fixtures/fulu_fork/fork_base_state/pre.ssz_snappy");
    const bytes = try @import("snappy.zig").decompress(allocator, compressed);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    var pre = try ssz.deserialize(allocator, fulu.ElectraBeaconState, &reader);
    defer ssz.freeDecoded(allocator, fulu.ElectraBeaconState, pre);
    const original = try @import("merkle").HashTreeRoot(allocator, pre);
    pre.slot += 1;
    try std.testing.expectError(error.InvalidPreState, upgradeToFulu(allocator, &pre));
    pre.slot -= 1;
    try std.testing.expectEqual(original, try @import("merkle").HashTreeRoot(allocator, pre));
    var fake_engine: engine_api.TestEngine = .{ .status = .valid };
    try std.testing.expectError(error.NotFuluBoundary, stateTransitionFromElectra(allocator, &pre, std.mem.zeroes(fulu.SignedBeaconBlock), fake_engine.interface()));
    _ = fixtures;
}

test "pinned Electra fork fixtures match complete Fulu roots and proposer windows" {
    const allocator = std.testing.allocator;
    const merkle = @import("merkle");
    const snappy = @import("snappy.zig");
    inline for (.{ "fork_base_state", "lookahead_consistency_at_fork" }) |name| {
        const pre_bytes = try snappy.decompress(allocator, @embedFile("fixtures/fulu_fork/" ++ name ++ "/pre.ssz_snappy"));
        defer allocator.free(pre_bytes);
        var pre_reader: std.Io.Reader = .fixed(pre_bytes);
        const pre = try ssz.deserialize(allocator, fulu.ElectraBeaconState, &pre_reader);
        defer ssz.freeDecoded(allocator, fulu.ElectraBeaconState, pre);
        const post_bytes = try snappy.decompress(allocator, @embedFile("fixtures/fulu_fork/" ++ name ++ "/post.ssz_snappy"));
        defer allocator.free(post_bytes);
        var post_reader: std.Io.Reader = .fixed(post_bytes);
        const expected = try ssz.deserialize(allocator, fulu.BeaconState, &post_reader);
        defer ssz.freeDecoded(allocator, fulu.BeaconState, expected);
        const actual = try upgradeToFulu(allocator, &pre);
        defer ssz.freeDecoded(allocator, fulu.BeaconState, actual);
        try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, expected), try merkle.HashTreeRoot(allocator, actual));
        try std.testing.expectEqual(expected.proposer_lookahead, actual.proposer_lookahead);
        var boundary = actual;
        try @import("transition.zig").processSlots(allocator, &boundary, actual.slot + 1, null);
        try std.testing.expectEqual(actual.slot + 1, boundary.slot);
    }
}

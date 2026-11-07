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

    // SAFETY: This value is fully initialized before any read.
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
    // SAFETY: This value is fully initialized before any read.
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
    pre.slot += helpers.SLOTS_PER_EPOCH;
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

test "first Fulu block transitions from the pinned Electra boundary without changing it" {
    const allocator = std.testing.allocator;
    const merkle = @import("merkle");
    const blst = @import("blst");
    const bls = @import("bls.zig");
    const proposer = @import("proposer.zig");
    const operations = @import("block_operations.zig");
    const fixtures = @import("fixture_runner.zig");
    const compressed = @embedFile("fixtures/fulu_fork/fork_base_state/pre.ssz_snappy");
    const bytes = try @import("snappy.zig").decompress(allocator, compressed);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    var pre = try ssz.deserialize(allocator, fulu.ElectraBeaconState, &reader);
    defer ssz.freeDecoded(allocator, fulu.ElectraBeaconState, pre);
    const slot = pre.slot + 1;
    const initial = try upgradeToFulu(allocator, &pre);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, initial);
    const proposer_index = initial.proposer_lookahead[slot % helpers.SLOTS_PER_EPOCH];
    var key = blst.SecretKey{};
    key.keygen(&([_]u8{0x65} ** 32), null);
    defer key.deinit();
    const old_key = pre.validators.data[proposer_index].pubkey;
    const new_key = try bls.publicKey(&key);
    @constCast(pre.validators.data)[proposer_index].pubkey = new_key;
    for (&pre.current_sync_committee.pubkeys) |*pubkey| {
        if (std.mem.eql(u8, pubkey, &old_key)) pubkey.* = new_key;
    }
    for (&pre.next_sync_committee.pubkeys) |*pubkey| {
        if (std.mem.eql(u8, pubkey, &old_key)) pubkey.* = new_key;
    }
    const before = try merkle.HashTreeRoot(allocator, pre);
    const parent = try upgradeToFulu(allocator, &pre);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, parent);
    var advanced = try pool.copyValue(allocator, fulu.BeaconState, parent);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, advanced);
    try @import("transition.zig").processSlots(allocator, &advanced, slot, @import("epoch.zig").processEpoch);
    const template = try fixtures.decodeBlock(allocator, fixtures.find("empty_block_transition").?.input.?);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, template);
    var payload = template.message.body.execution_payload;
    payload.parent_hash = parent.latest_execution_payload_header.block_hash;
    payload.prev_randao = advanced.randao_mixes[helpers.computeEpochAtSlot(slot) % helpers.EPOCHS_PER_HISTORICAL_VECTOR];
    payload.timestamp = parent.genesis_time + slot * preset.SECONDS_PER_SLOT;
    payload.withdrawals.data = try operations.expectedWithdrawals(allocator, &advanced);
    defer allocator.free(payload.withdrawals.data);
    var test_engine: engine_api.TestEngine = .{ .status = .valid, .built = .{
        .payload = payload,
        .commitments = &.{},
        .requests = .{ .deposits = .{ .data = &.{} }, .withdrawals = .{ .data = &.{} }, .consolidations = .{ .data = &.{} } },
    } };
    const head = parent.latest_execution_payload_header.block_hash;
    const choice: engine_api.ForkchoiceState = .{ .head_block_hash = head, .safe_block_hash = head, .finalized_block_hash = head };
    var operation_pool = pool.Pool.init(allocator);
    defer operation_pool.deinit();
    var infinity = [_]u8{0} ** 96;
    infinity[0] = 0xc0;
    const sync: fulu.SyncAggregate = .{ .sync_committee_bits = .{ .data = [_]bool{false} ** preset.SYNC_COMMITTEE_SIZE }, .sync_committee_signature = infinity };
    const signed = try proposer.propose(allocator, &parent, slot, &key, &operation_pool, test_engine.interface(), choice, sync, [_]u8{0} ** 20, [_]u8{0} ** 32);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    const post = try stateTransitionFromElectra(allocator, &pre, signed, test_engine.interface());
    defer ssz.freeDecoded(allocator, fulu.BeaconState, post);
    try std.testing.expectEqual(signed.message.state_root, try merkle.HashTreeRoot(allocator, post));
    var expected_post_root: fulu.Root = undefined;
    _ = try std.fmt.hexToBytes(&expected_post_root, "2df9c36ac4c333437692bf3452c618a65af1aff453c0e74f4916fa6da33eee65");
    try std.testing.expectEqual(expected_post_root, try merkle.HashTreeRoot(allocator, post));
    try std.testing.expectEqual(before, try merkle.HashTreeRoot(allocator, pre));
}

const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const helpers = @import("helpers.zig");

pub const EpochProcessor = *const fn (std.mem.Allocator, *fulu.BeaconState) anyerror!void;

pub fn processSlot(allocator: std.mem.Allocator, state: *fulu.BeaconState) !void {
    const state_root = try merkle.HashTreeRoot(allocator, state.*);
    const slot_index: usize = @intCast(state.slot % state.block_roots.len);
    state.state_roots[slot_index] = state_root;

    if (std.mem.allEqual(u8, &state.latest_block_header.state_root, 0)) {
        state.latest_block_header.state_root = state_root;
    }
    state.block_roots[slot_index] = try merkle.HashTreeRoot(allocator, state.latest_block_header);
}

pub fn processSlots(
    allocator: std.mem.Allocator,
    state: *fulu.BeaconState,
    target_slot: fulu.Slot,
    process_epoch: ?EpochProcessor,
) anyerror!void {
    if (target_slot < state.slot) return error.SlotRegression;
    if (process_epoch == null) {
        var check_slot = state.slot;
        while (check_slot < target_slot) : (check_slot += 1) {
            if ((check_slot + 1) % helpers.SLOTS_PER_EPOCH == 0) return error.EpochProcessorRequired;
        }
    }
    while (state.slot < target_slot) {
        try processSlot(allocator, state);
        if ((state.slot + 1) % helpers.SLOTS_PER_EPOCH == 0) {
            try process_epoch.?(allocator, state);
        }
        state.slot += 1;
    }
}

test "process one slot matches the pinned slots_1 post-state" {
    const fixtures = @import("fixture_runner.zig");
    const case = fixtures.find("slots_1").?;
    const allocator = std.testing.allocator;
    var pre = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, pre);
    const expected = try fixtures.decodeState(allocator, case.post.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, expected);

    const target = try fixtures.parseSlotCount(case.metadata.?);
    try processSlots(allocator, &pre, target, null);
    const actual_root = try merkle.HashTreeRoot(allocator, pre);
    const expected_root = try merkle.HashTreeRoot(allocator, expected);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "processSlots rejects backwards movement and requires epoch handler" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const case = fixtures.find("slots_1").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);

    state.slot = 1;
    try std.testing.expectError(error.SlotRegression, processSlots(allocator, &state, 0, null));
    const original_state_roots = state.state_roots;
    try std.testing.expectError(error.EpochProcessorRequired, processSlots(allocator, &state, 8, null));
    try std.testing.expectEqual(@as(u64, 1), state.slot);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(&original_state_roots), std.mem.sliceAsBytes(&state.state_roots));
}

fn testEpochProcessor(_: std.mem.Allocator, state: *fulu.BeaconState) anyerror!void {
    state.genesis_time += 1;
}

test "processSlots invokes the epoch processor before incrementing across the boundary" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const case = fixtures.find("slots_1").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);

    const initial_genesis_time = state.genesis_time;
    try processSlots(allocator, &state, 8, testEpochProcessor);
    try std.testing.expectEqual(@as(u64, 8), state.slot);
    try std.testing.expectEqual(initial_genesis_time + 1, state.genesis_time);
}

test "process epoch boundary matches the pinned slots fixture" {
    const fixtures = @import("fixture_runner.zig");
    const epoch = @import("epoch.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("over_epoch_boundary").?;
    var pre = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, pre);
    const expected = try fixtures.decodeState(allocator, case.post.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, expected);

    try processSlots(allocator, &pre, pre.slot + try fixtures.parseSlotCount(case.metadata.?), epoch.processEpoch);
    const actual_root = try merkle.HashTreeRoot(allocator, pre);
    const expected_root = try merkle.HashTreeRoot(allocator, expected);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "two quiet epochs match the pinned double-empty-epoch fixture" {
    const fixtures = @import("fixture_runner.zig");
    const epoch = @import("epoch.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("double_empty_epoch").?;
    var pre = try fixtures.decodeState(allocator, case.pre.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, pre);
    const post = try fixtures.decodeState(allocator, case.post.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, post);
    try processSlots(allocator, &pre, pre.slot + try fixtures.parseSlotCount(case.metadata.?), epoch.processEpoch);
    const actual_root = try merkle.HashTreeRoot(allocator, pre);
    const expected_root = try merkle.HashTreeRoot(allocator, post);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

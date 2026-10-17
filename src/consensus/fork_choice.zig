// Fork choice is the rule for selecting one chain head when valid branches
// compete. A checkpoint is an epoch/root pair used for justification and
// finality; an unrealized checkpoint is known before epoch processing makes it
// part of the on-chain state. Proposer boost is temporary weight for the first
// timely block in a slot. Ticks advance in order: clear boost at each slot,
// then promote newer checkpoints at epoch starts. Fulu keeps these rules and
// adds data-availability validation during block import. This code targets the
// minimal preset: six seconds per slot and eight slots per epoch.
//
//   tick -> slot boundary -> clear proposer boost -> epoch boundary? -> promote checkpoints
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const ssz = @import("ssz");
const helpers = @import("helpers.zig");

// shortcut: the minimal preset fixes six seconds per slot, extract this when adding another preset.
const SECONDS_PER_SLOT: u64 = 6;

pub const LatestMessage = struct {
    epoch: fulu.Epoch,
    root: fulu.Root,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    time: u64,
    genesis_time: u64,
    justified_checkpoint: fulu.Checkpoint,
    finalized_checkpoint: fulu.Checkpoint,
    unrealized_justified_checkpoint: fulu.Checkpoint,
    unrealized_finalized_checkpoint: fulu.Checkpoint,
    proposer_boost_root: fulu.Root,
    equivocating_indices: std.AutoHashMap(fulu.ValidatorIndex, void),
    blocks: std.AutoHashMap(fulu.Root, fulu.BeaconBlock),
    block_states: std.AutoHashMap(fulu.Root, fulu.BeaconState),
    block_timeliness: std.AutoHashMap(fulu.Root, bool),
    checkpoint_states: std.AutoHashMap(fulu.Checkpoint, fulu.BeaconState),
    latest_messages: std.AutoHashMap(fulu.ValidatorIndex, LatestMessage),
    unrealized_justifications: std.AutoHashMap(fulu.Root, fulu.Checkpoint),

    pub fn deinit(self: *Store) void {
        const allocator = self.allocator;
        var blocks = self.blocks.valueIterator();
        while (blocks.next()) |block| ssz.freeDecoded(allocator, fulu.BeaconBlock, block.*);
        var states = self.block_states.valueIterator();
        while (states.next()) |state| ssz.freeDecoded(allocator, fulu.BeaconState, state.*);
        var checkpoint_states = self.checkpoint_states.valueIterator();
        while (checkpoint_states.next()) |state| ssz.freeDecoded(allocator, fulu.BeaconState, state.*);
        self.equivocating_indices.deinit();
        self.blocks.deinit();
        self.block_states.deinit();
        self.block_timeliness.deinit();
        self.checkpoint_states.deinit();
        self.latest_messages.deinit();
        self.unrealized_justifications.deinit();
    }

    pub fn currentSlot(self: *const Store) u64 {
        return (self.time - self.genesis_time) / SECONDS_PER_SLOT;
    }
};

pub fn initStore(
    allocator: std.mem.Allocator,
    anchor_state: *const fulu.BeaconState,
    anchor_block: *const fulu.BeaconBlock,
) !Store {
    const state_root = try merkle.HashTreeRoot(allocator, anchor_state.*);
    if (!std.mem.eql(u8, &anchor_block.state_root, &state_root)) return error.InvalidAnchor;
    const anchor_root = try merkle.HashTreeRoot(allocator, anchor_block.*);
    const anchor_epoch = helpers.computeEpochAtSlot(anchor_state.slot);
    const checkpoint = fulu.Checkpoint{ .epoch = anchor_epoch, .root = anchor_root };
    const elapsed = try std.math.mul(u64, anchor_state.slot, SECONDS_PER_SLOT);
    const time = try std.math.add(u64, anchor_state.genesis_time, elapsed);

    var store = Store{
        .allocator = allocator,
        .time = time,
        .genesis_time = anchor_state.genesis_time,
        .justified_checkpoint = checkpoint,
        .finalized_checkpoint = checkpoint,
        .unrealized_justified_checkpoint = checkpoint,
        .unrealized_finalized_checkpoint = checkpoint,
        .proposer_boost_root = [_]u8{0} ** 32,
        .equivocating_indices = .init(allocator),
        .blocks = .init(allocator),
        .block_states = .init(allocator),
        .block_timeliness = .init(allocator),
        .checkpoint_states = .init(allocator),
        .latest_messages = .init(allocator),
        .unrealized_justifications = .init(allocator),
    };
    errdefer store.deinit();

    try putBlock(&store, anchor_root, anchor_block.*);
    try putState(&store, anchor_root, anchor_state.*);
    try putCheckpointState(&store, checkpoint, anchor_state.*);
    try store.unrealized_justifications.put(anchor_root, checkpoint);
    return store;
}

pub fn onTick(store: *Store, time: u64) !void {
    if (time < store.time) return error.TimeRegression;
    if (time == store.time) return;

    const target_slot = (time - store.genesis_time) / SECONDS_PER_SLOT;
    while (store.currentSlot() < target_slot) {
        const next_slot = store.currentSlot() + 1;
        const elapsed = try std.math.mul(u64, next_slot, SECONDS_PER_SLOT);
        store.time = try std.math.add(u64, store.genesis_time, elapsed);
        store.proposer_boost_root = [_]u8{0} ** 32;
        if (next_slot % helpers.SLOTS_PER_EPOCH == 0) updateCheckpoints(store);
    }
    store.time = time;
}

fn updateCheckpoints(store: *Store) void {
    if (store.unrealized_justified_checkpoint.epoch > store.justified_checkpoint.epoch) {
        store.justified_checkpoint = store.unrealized_justified_checkpoint;
    }
    if (store.unrealized_finalized_checkpoint.epoch > store.finalized_checkpoint.epoch) {
        store.finalized_checkpoint = store.unrealized_finalized_checkpoint;
    }
}

fn cloneSSZ(allocator: std.mem.Allocator, comptime T: type, value: T) !T {
    const bytes = try ssz.serializeAlloc(allocator, value);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, T, &reader);
}

fn putBlock(store: *Store, root: fulu.Root, block: fulu.BeaconBlock) !void {
    const copy = try cloneSSZ(store.allocator, fulu.BeaconBlock, block);
    store.blocks.put(root, copy) catch |err| {
        ssz.freeDecoded(store.allocator, fulu.BeaconBlock, copy);
        return err;
    };
}

fn putState(store: *Store, root: fulu.Root, state: fulu.BeaconState) !void {
    const copy = try cloneSSZ(store.allocator, fulu.BeaconState, state);
    store.block_states.put(root, copy) catch |err| {
        ssz.freeDecoded(store.allocator, fulu.BeaconState, copy);
        return err;
    };
}

fn putCheckpointState(store: *Store, checkpoint: fulu.Checkpoint, state: fulu.BeaconState) !void {
    const copy = try cloneSSZ(store.allocator, fulu.BeaconState, state);
    store.checkpoint_states.put(checkpoint, copy) catch |err| {
        ssz.freeDecoded(store.allocator, fulu.BeaconState, copy);
        return err;
    };
}

test "fork-choice store initializes from the pinned Fulu anchor fixture" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var anchor_state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, anchor_state);
    const compressed_block = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(compressed_block);
    var reader: std.Io.Reader = .fixed(compressed_block);
    const anchor_block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor_block);

    var store = try initStore(allocator, &anchor_state, &anchor_block);
    defer store.deinit();
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, "eb7ad3d90729a187da87dcf467eace66b12331f9fcbd38c26e9d94c1c5cbc26f");
    const expected_checkpoint = fulu.Checkpoint{ .epoch = 0, .root = expected_root };
    try std.testing.expectEqual(@as(u64, 0), store.time);
    try std.testing.expectEqual(anchor_state.genesis_time, store.genesis_time);
    try std.testing.expectEqual(expected_checkpoint, store.justified_checkpoint);
    try std.testing.expectEqual(expected_checkpoint, store.finalized_checkpoint);
    try std.testing.expectEqual(expected_checkpoint, store.unrealized_justified_checkpoint);
    try std.testing.expectEqual(expected_checkpoint, store.unrealized_finalized_checkpoint);
    try std.testing.expectEqual(@as(usize, 1), store.blocks.count());
    try std.testing.expectEqual(@as(usize, 1), store.block_states.count());
    try std.testing.expectEqual(@as(usize, 1), store.checkpoint_states.count());
    try std.testing.expectEqual(@as(usize, 1), store.unrealized_justifications.count());
    try std.testing.expectEqual(@as(usize, 0), store.block_timeliness.count());
    try std.testing.expectEqual(@as(usize, 0), store.latest_messages.count());
    try std.testing.expectEqual(@as(usize, 0), store.equivocating_indices.count());

    anchor_state.genesis_time += 1;
    try std.testing.expectError(error.InvalidAnchor, initStore(allocator, &anchor_state, &anchor_block));
}

test "fork-choice ticks clear proposer boost, promote checkpoints, and reject regression" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var anchor_state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, anchor_state);
    const compressed_block = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(compressed_block);
    var reader: std.Io.Reader = .fixed(compressed_block);
    const anchor_block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor_block);

    var store = try initStore(allocator, &anchor_state, &anchor_block);
    defer store.deinit();
    const next_checkpoint = fulu.Checkpoint{ .epoch = 1, .root = [_]u8{0x11} ** 32 };
    store.unrealized_justified_checkpoint = next_checkpoint;
    store.unrealized_finalized_checkpoint = next_checkpoint;
    store.proposer_boost_root = [_]u8{0xaa} ** 32;

    try onTick(&store, 6);
    try std.testing.expectEqual(@as(u64, 1), store.currentSlot());
    try std.testing.expectEqual([_]u8{0} ** 32, store.proposer_boost_root);
    try std.testing.expectEqual(@as(u64, 0), store.justified_checkpoint.epoch);

    store.proposer_boost_root = [_]u8{0xbb} ** 32;
    try onTick(&store, 48);
    try std.testing.expectEqual(@as(u64, 8), store.currentSlot());
    try std.testing.expectEqual([_]u8{0} ** 32, store.proposer_boost_root);
    try std.testing.expectEqual(next_checkpoint, store.justified_checkpoint);
    try std.testing.expectEqual(next_checkpoint, store.finalized_checkpoint);

    store.proposer_boost_root = [_]u8{0xcc} ** 32;
    try onTick(&store, 48);
    try std.testing.expectEqual([_]u8{0xcc} ** 32, store.proposer_boost_root);
    try std.testing.expectError(error.TimeRegression, onTick(&store, 47));
    try std.testing.expectEqual(@as(u64, 48), store.time);
    try std.testing.expectEqual([_]u8{0xcc} ** 32, store.proposer_boost_root);
}

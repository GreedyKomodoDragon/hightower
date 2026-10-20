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
const block_transition = @import("block.zig");
const engine_api = @import("execution_engine.zig");

// shortcut: the minimal preset fixes six seconds per slot, extract this when adding another preset.
const SECONDS_PER_SLOT: u64 = 6;

pub const LatestMessage = struct {
    epoch: fulu.Epoch,
    root: fulu.Root,
};

pub const DataAvailabilityCheck = struct {
    context: *anyopaque,
    is_available: *const fn (*anyopaque, fulu.Root) anyerror!bool,

    pub fn check(self: DataAvailabilityCheck, root: fulu.Root) anyerror!bool {
        return self.is_available(self.context, root);
    }
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

fn checkpointBlock(store: *const Store, root: fulu.Root, epoch: fulu.Epoch) !fulu.Root {
    const start_slot = try helpers.computeStartSlotAtEpoch(epoch);
    var current_root = root;
    while (true) {
        const block = store.blocks.get(current_root) orelse return error.UnknownParent;
        if (block.slot <= start_slot) return current_root;
        current_root = block.parent_root;
    }
}

pub fn isWithinWeakSubjectivityPeriod(store: *const Store, state: *const fulu.BeaconState, checkpoint: fulu.Checkpoint) !bool {
    if (helpers.computeEpochAtSlot(state.slot) != checkpoint.epoch) return error.InvalidWeakSubjectivityCheckpoint;
    const start_slot = try helpers.computeStartSlotAtEpoch(checkpoint.epoch);
    const state_root = state.block_roots[@intCast(start_slot % state.block_roots.len)];
    if (!std.mem.eql(u8, &state_root, &checkpoint.root)) return error.InvalidWeakSubjectivityCheckpoint;

    if (checkpoint.epoch <= store.finalized_checkpoint.epoch) {
        const canonical_root = try checkpointBlock(store, store.finalized_checkpoint.root, checkpoint.epoch);
        if (!std.mem.eql(u8, &canonical_root, &checkpoint.root)) return error.InvalidWeakSubjectivityCheckpoint;
    }

    const period = try helpers.computeWeakSubjectivityPeriod(state);
    const current_epoch = helpers.computeEpochAtSlot(store.currentSlot());
    return current_epoch <= checkpoint.epoch or current_epoch - checkpoint.epoch <= period;
}

pub fn onBlock(store: *Store, signed_block: fulu.SignedBeaconBlock, engine: engine_api.ExecutionEngine, availability: DataAvailabilityCheck) !void {
    const block = signed_block.message;
    const parent_state = store.block_states.getPtr(block.parent_root) orelse return error.UnknownParent;
    if (block.slot > store.currentSlot()) return error.FutureBlock;
    const finalized_slot = try helpers.computeStartSlotAtEpoch(store.finalized_checkpoint.epoch);
    if (block.slot <= finalized_slot) return error.BeforeFinalized;
    if (!std.mem.eql(u8, &store.finalized_checkpoint.root, &(try checkpointBlock(store, block.parent_root, store.finalized_checkpoint.epoch)))) return error.NotDescendantOfFinalized;

    const block_root = try merkle.HashTreeRoot(store.allocator, block);
    if (store.blocks.contains(block_root)) return error.DuplicateBlock;
    if (!try availability.check(block_root)) return error.DataUnavailable;

    var state = try cloneSSZ(store.allocator, fulu.BeaconState, parent_state.*);
    defer ssz.freeDecoded(store.allocator, fulu.BeaconState, state);
    try block_transition.stateTransition(store.allocator, &state, signed_block, engine);

    try putBlock(store, block_root, block);
    try putState(store, block_root, state);
    const seconds_into_slot = (store.time - store.genesis_time) % SECONDS_PER_SLOT;
    const timely = store.currentSlot() == block.slot and seconds_into_slot < 2;
    try store.block_timeliness.put(block_root, timely);
    if (timely and std.mem.eql(u8, &store.proposer_boost_root, &([_]u8{0} ** 32))) {
        store.proposer_boost_root = block_root;
    }
    if (state.current_justified_checkpoint.epoch > store.unrealized_justified_checkpoint.epoch) {
        store.unrealized_justified_checkpoint = state.current_justified_checkpoint;
    }
    if (state.finalized_checkpoint.epoch > store.unrealized_finalized_checkpoint.epoch) {
        store.unrealized_finalized_checkpoint = state.finalized_checkpoint;
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

test "weak subjectivity validates checkpoint state and accepts the inclusive period boundary" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const compressed_block = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(compressed_block);
    var reader: std.Io.Reader = .fixed(compressed_block);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    var store = try initStore(allocator, &state, &block);
    defer store.deinit();

    state.slot = helpers.SLOTS_PER_EPOCH;
    const checkpoint = fulu.Checkpoint{ .epoch = 1, .root = [_]u8{0x11} ** 32 };
    state.block_roots[helpers.SLOTS_PER_EPOCH] = checkpoint.root;
    const period = try helpers.computeWeakSubjectivityPeriod(&state);
    store.time = store.genesis_time + (checkpoint.epoch + period) * helpers.SLOTS_PER_EPOCH * SECONDS_PER_SLOT;
    try std.testing.expect(try isWithinWeakSubjectivityPeriod(&store, &state, checkpoint));

    try std.testing.expectError(error.InvalidWeakSubjectivityCheckpoint, isWithinWeakSubjectivityPeriod(&store, &state, .{
        .epoch = checkpoint.epoch,
        .root = [_]u8{0x22} ** 32,
    }));

    store.time += helpers.SLOTS_PER_EPOCH * SECONDS_PER_SLOT;
    try std.testing.expect(!try isWithinWeakSubjectivityPeriod(&store, &state, checkpoint));
    try std.testing.expectError(error.InvalidWeakSubjectivityCheckpoint, isWithinWeakSubjectivityPeriod(&store, &state, .{
        .epoch = checkpoint.epoch + 1,
        .root = checkpoint.root,
    }));

    state.slot = 0;
    state.block_roots[0] = [_]u8{0x33} ** 32;
    try std.testing.expectError(error.InvalidWeakSubjectivityCheckpoint, isWithinWeakSubjectivityPeriod(&store, &state, .{
        .epoch = 0,
        .root = state.block_roots[0],
    }));
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

const AvailabilityTestContext = struct {
    available: bool,
    calls: usize = 0,

    fn check(context: *anyopaque, _: fulu.Root) anyerror!bool {
        const self: *AvailabilityTestContext = @ptrCast(@alignCast(context));
        self.calls += 1;
        return self.available;
    }
};

fn loadAvailabilityFixture(allocator: std.mem.Allocator) !struct { fulu.BeaconState, fulu.BeaconBlock, fulu.SignedBeaconBlock } {
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_state.ssz_snappy"));
    errdefer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const compressed_block = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_block.ssz_snappy"));
    defer allocator.free(compressed_block);
    var block_reader: std.Io.Reader = .fixed(compressed_block);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &block_reader);
    errdefer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    const signed = try fixtures.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    return .{ state, block, signed };
}

test "fork-choice rejects unavailable block without changing the store" {
    const allocator = std.testing.allocator;
    var fixture = try loadAvailabilityFixture(allocator);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, fixture[0]);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, fixture[1]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, fixture[2]);
    var store = try initStore(allocator, &fixture[0], &fixture[1]);
    defer store.deinit();
    try onTick(&store, fixture[2].message.slot * SECONDS_PER_SLOT);
    var availability = AvailabilityTestContext{ .available = false };
    var engine: engine_api.TestEngine = .{ .status = .valid };

    try std.testing.expectError(error.DataUnavailable, onBlock(&store, fixture[2], engine.interface(), .{
        .context = &availability,
        .is_available = AvailabilityTestContext.check,
    }));
    try std.testing.expectEqual(@as(usize, 1), availability.calls);
    try std.testing.expectEqual(@as(usize, 1), store.blocks.count());
    try std.testing.expectEqual(@as(usize, 1), store.block_states.count());
    try std.testing.expectEqual(@as(usize, 0), store.block_timeliness.count());
    try std.testing.expectEqual([_]u8{0} ** 32, store.proposer_boost_root);
}

test "fork-choice stores an available block and assigns timely proposer boost" {
    const allocator = std.testing.allocator;
    var fixture = try loadAvailabilityFixture(allocator);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, fixture[0]);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, fixture[1]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, fixture[2]);
    var store = try initStore(allocator, &fixture[0], &fixture[1]);
    defer store.deinit();
    const imported_checkpoint = fulu.Checkpoint{ .epoch = 1, .root = [_]u8{0x11} ** 32 };
    const parent_root = try merkle.HashTreeRoot(allocator, fixture[1]);
    store.block_states.getPtr(parent_root).?.current_justified_checkpoint = imported_checkpoint;
    store.block_states.getPtr(parent_root).?.finalized_checkpoint = imported_checkpoint;
    try onTick(&store, fixture[2].message.slot * SECONDS_PER_SLOT);
    var availability = AvailabilityTestContext{ .available = true };
    var engine: engine_api.TestEngine = .{ .status = .valid };

    try onBlock(&store, fixture[2], engine.interface(), .{
        .context = &availability,
        .is_available = AvailabilityTestContext.check,
    });
    try std.testing.expectEqual(@as(usize, 1), availability.calls);
    try std.testing.expectEqual(@as(usize, 2), store.blocks.count());
    try std.testing.expectEqual(@as(usize, 2), store.block_states.count());
    try std.testing.expectEqual(@as(usize, 1), store.block_timeliness.count());
    const block_root = try merkle.HashTreeRoot(allocator, fixture[2].message);
    try std.testing.expectEqual(block_root, store.proposer_boost_root);
    try std.testing.expectEqual(@as(u64, 0), store.justified_checkpoint.epoch);
    try std.testing.expectEqual(@as(u64, 0), store.finalized_checkpoint.epoch);
    try std.testing.expectEqual(imported_checkpoint, store.unrealized_justified_checkpoint);
    try std.testing.expectEqual(imported_checkpoint, store.unrealized_finalized_checkpoint);
}

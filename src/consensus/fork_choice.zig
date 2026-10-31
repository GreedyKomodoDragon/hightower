// Fork choice is the rule for selecting one chain head when valid branches
// compete. A checkpoint is an epoch/root pair used for justification and
// finality; an unrealized checkpoint is known before epoch processing makes it
// part of the on-chain state. Proposer boost is temporary weight for the first
// timely block in a slot. Ticks advance in order: clear boost at each slot,
// then promote newer checkpoints at epoch starts. Fulu keeps these rules and
// adds data-availability validation during block import. Slot timing and
// epoch boundaries come from the selected compile-time preset.
//
//   tick -> slot boundary -> clear proposer boost -> epoch boundary? -> promote checkpoints
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const ssz = @import("ssz");
const helpers = @import("helpers.zig");
const preset = @import("consensus_preset").Config;
const block_transition = @import("block.zig");
const operations = @import("block_operations.zig");
const epoch_transition = @import("epoch.zig");
const transition = @import("transition.zig");
const engine_api = @import("execution_engine.zig");
const PROPOSER_SCORE_BOOST: u64 = 40;

pub const LatestMessage = struct {
    epoch: fulu.Epoch,
    root: fulu.Root,
};

pub const DataAvailabilityCheck = struct {
    context: *anyopaque,
    is_available: *const fn (*anyopaque, fulu.Root, *const fulu.BeaconBlock) anyerror!bool,

    /// Check whether all required data for a block root is available.
    pub fn check(self: DataAvailabilityCheck, root: fulu.Root, block: *const fulu.BeaconBlock) anyerror!bool {
        if (block.body.blob_kzg_commitments.data.len == 0) return true;
        return self.is_available(self.context, root, block);
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
    signed_block_signatures: std.AutoHashMap(fulu.Root, fulu.BLSSignature),
    block_states: std.AutoHashMap(fulu.Root, fulu.BeaconState),
    block_timeliness: std.AutoHashMap(fulu.Root, bool),
    checkpoint_states: std.AutoHashMap(fulu.Checkpoint, fulu.BeaconState),
    latest_messages: std.AutoHashMap(fulu.ValidatorIndex, LatestMessage),
    unrealized_justifications: std.AutoHashMap(fulu.Root, fulu.Checkpoint),

    /// Free all owned blocks and states in the fork-choice store.
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
        self.signed_block_signatures.deinit();
        self.block_states.deinit();
        self.block_timeliness.deinit();
        self.checkpoint_states.deinit();
        self.latest_messages.deinit();
        self.unrealized_justifications.deinit();
    }

    /// Return the slot represented by the store's explicit timestamp.
    pub fn currentSlot(self: *const Store) u64 {
        return (self.time - self.genesis_time) / preset.SECONDS_PER_SLOT;
    }

    /// Return the stored block with its signature when it was imported from a peer.
    pub fn signedBlock(self: *const Store, root: fulu.Root) ?fulu.SignedBeaconBlock {
        const block = self.blocks.get(root) orelse return null;
        const signature = self.signed_block_signatures.get(root) orelse return null;
        return .{ .message = block, .signature = signature };
    }
};

/// Build a fork-choice store from a trusted anchor whose state root matches.
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
    const elapsed = try std.math.mul(u64, anchor_state.slot, preset.SECONDS_PER_SLOT);
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
        .signed_block_signatures = .init(allocator),
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

/// Advance explicit time, processing every crossed slot and epoch boundary.
pub fn onTick(store: *Store, time: u64) !void {
    if (time < store.time) return error.TimeRegression;
    if (time == store.time) return;

    const target_slot = (time - store.genesis_time) / preset.SECONDS_PER_SLOT;
    while (store.currentSlot() < target_slot) {
        const next_slot = store.currentSlot() + 1;
        const elapsed = try std.math.mul(u64, next_slot, preset.SECONDS_PER_SLOT);
        const next_time = try std.math.add(u64, store.genesis_time, elapsed);
        if (next_slot % helpers.SLOTS_PER_EPOCH == 0) try ensureCheckpointState(store, store.unrealized_justified_checkpoint);
        store.time = next_time;
        store.proposer_boost_root = [_]u8{0} ** 32;
        if (next_slot % helpers.SLOTS_PER_EPOCH == 0) {
            const prior_finalized_epoch = store.finalized_checkpoint.epoch;
            updateCheckpoints(store);
            if (store.finalized_checkpoint.epoch > prior_finalized_epoch) pruneToFinalized(store);
        }
    }
    store.time = time;
}

/// Promote unrealized checkpoints when an epoch starts.
fn updateCheckpoints(store: *Store) void {
    if (store.unrealized_justified_checkpoint.epoch > store.justified_checkpoint.epoch) {
        store.justified_checkpoint = store.unrealized_justified_checkpoint;
    }
    if (store.unrealized_finalized_checkpoint.epoch > store.finalized_checkpoint.epoch) {
        store.finalized_checkpoint = store.unrealized_finalized_checkpoint;
    }
}

/// Drop blocks, states, and votes that cannot contain the finalized checkpoint.
/// Only the finalized root and its descendants remain available for head choice.
fn pruneToFinalized(store: *Store) void {
    const finalized = store.finalized_checkpoint.root;
    if (!store.blocks.contains(finalized)) return;
    var children = buildChildMap(store) catch return;
    defer deinitChildMap(&children, store.allocator);
    var keep = std.AutoHashMap(fulu.Root, void).init(store.allocator);
    defer keep.deinit();
    var pending = std.ArrayListUnmanaged(fulu.Root).empty;
    defer pending.deinit(store.allocator);
    keep.put(finalized, {}) catch return;
    pending.append(store.allocator, finalized) catch return;
    while (pending.pop()) |root| {
        const kids = children.get(root) orelse continue;
        for (kids.items) |child| {
            const entry = keep.getOrPut(child) catch return;
            if (entry.found_existing) continue;
            pending.append(store.allocator, child) catch return;
        }
    }
    var removed = std.ArrayListUnmanaged(fulu.Root).empty;
    defer removed.deinit(store.allocator);
    var blocks = store.blocks.iterator();
    while (blocks.next()) |entry| {
        if (keep.contains(entry.key_ptr.*)) continue;
        removed.append(store.allocator, entry.key_ptr.*) catch return;
    }
    for (removed.items) |root| {
        if (store.blocks.fetchRemove(root)) |entry| ssz.freeDecoded(store.allocator, fulu.BeaconBlock, entry.value);
        if (store.block_states.fetchRemove(root)) |entry| ssz.freeDecoded(store.allocator, fulu.BeaconState, entry.value);
        _ = store.signed_block_signatures.remove(root);
        _ = store.block_timeliness.remove(root);
        _ = store.unrealized_justifications.remove(root);
    }
    var checkpoints = std.ArrayListUnmanaged(fulu.Checkpoint).empty;
    defer checkpoints.deinit(store.allocator);
    var checkpoint_states = store.checkpoint_states.keyIterator();
    while (checkpoint_states.next()) |checkpoint| {
        if (!store.blocks.contains(checkpoint.root)) checkpoints.append(store.allocator, checkpoint.*) catch return;
    }
    for (checkpoints.items) |checkpoint| {
        if (store.checkpoint_states.fetchRemove(checkpoint)) |entry| ssz.freeDecoded(store.allocator, fulu.BeaconState, entry.value);
    }
    var messages = std.ArrayListUnmanaged(fulu.ValidatorIndex).empty;
    defer messages.deinit(store.allocator);
    var latest_messages = store.latest_messages.iterator();
    while (latest_messages.next()) |entry| {
        if (!store.blocks.contains(entry.value_ptr.root)) messages.append(store.allocator, entry.key_ptr.*) catch return;
    }
    for (messages.items) |index| _ = store.latest_messages.remove(index);
}

/// Return the ancestor at or before the first slot of an epoch.
fn checkpointBlock(store: *const Store, root: fulu.Root, epoch: fulu.Epoch) !fulu.Root {
    const start_slot = try helpers.computeStartSlotAtEpoch(epoch);
    var current_root = root;
    while (true) {
        const block = store.blocks.get(current_root) orelse return error.UnknownParent;
        if (block.slot <= start_slot) return current_root;
        current_root = block.parent_root;
    }
}

// A weak subjectivity checkpoint must match its supplied state and, when it is
// already finalized locally, the canonical chain. The period is the maximum
// safe checkpoint age in epochs, derived from active validator balances.
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

/// Import a validated, available block without changing the store on rejection.
pub fn onBlock(store: *Store, signed_block: fulu.SignedBeaconBlock, engine: engine_api.ExecutionEngine, availability: DataAvailabilityCheck) !void {
    const prior_finalized_epoch = store.finalized_checkpoint.epoch;
    const block = signed_block.message;
    const parent_state = store.block_states.getPtr(block.parent_root) orelse return error.UnknownParent;
    if (block.slot > store.currentSlot()) return error.FutureBlock;
    const finalized_slot = try helpers.computeStartSlotAtEpoch(store.finalized_checkpoint.epoch);
    if (block.slot <= finalized_slot) return error.BeforeFinalized;
    if (!std.mem.eql(u8, &store.finalized_checkpoint.root, &(try checkpointBlock(store, block.parent_root, store.finalized_checkpoint.epoch)))) return error.NotDescendantOfFinalized;

    const block_root = try merkle.HashTreeRoot(store.allocator, block);
    if (store.blocks.contains(block_root)) return error.DuplicateBlock;
    if (!try availability.check(block_root, &block)) return error.DataUnavailable;

    var state = try cloneSSZ(store.allocator, fulu.BeaconState, parent_state.*);
    defer ssz.freeDecoded(store.allocator, fulu.BeaconState, state);
    try block_transition.stateTransition(store.allocator, &state, signed_block, engine);

    var pulled = try cloneSSZ(store.allocator, fulu.BeaconState, state);
    defer ssz.freeDecoded(store.allocator, fulu.BeaconState, pulled);
    try epoch_transition.processJustificationAndFinalization(&pulled, helpers.getCurrentEpoch(&pulled));

    // Roll back each owned insertion if a later allocation fails.
    try putBlock(store, block_root, block);
    errdefer if (store.blocks.fetchRemove(block_root)) |entry| ssz.freeDecoded(store.allocator, fulu.BeaconBlock, entry.value);
    try store.signed_block_signatures.put(block_root, signed_block.signature);
    errdefer _ = store.signed_block_signatures.remove(block_root);
    try putState(store, block_root, state);
    errdefer if (store.block_states.fetchRemove(block_root)) |entry| ssz.freeDecoded(store.allocator, fulu.BeaconState, entry.value);
    const seconds_into_slot = (store.time - store.genesis_time) % preset.SECONDS_PER_SLOT;
    const timely = store.currentSlot() == block.slot and seconds_into_slot < preset.PROPOSER_BOOST_WINDOW_SECONDS;
    try store.block_timeliness.put(block_root, timely);
    errdefer _ = store.block_timeliness.remove(block_root);
    try store.unrealized_justifications.put(block_root, pulled.current_justified_checkpoint);
    errdefer _ = store.unrealized_justifications.remove(block_root);
    const past_epoch = helpers.computeEpochAtSlot(block.slot) < helpers.computeEpochAtSlot(store.currentSlot());
    const next_justified = if (past_epoch and pulled.current_justified_checkpoint.epoch > state.current_justified_checkpoint.epoch)
        pulled.current_justified_checkpoint
    else
        state.current_justified_checkpoint;
    if (next_justified.epoch > store.justified_checkpoint.epoch) try ensureCheckpointState(store, next_justified);

    if (timely and std.mem.eql(u8, &store.proposer_boost_root, &([_]u8{0} ** 32))) {
        store.proposer_boost_root = block_root;
    }
    if (state.current_justified_checkpoint.epoch > store.justified_checkpoint.epoch) store.justified_checkpoint = state.current_justified_checkpoint;
    if (state.finalized_checkpoint.epoch > store.finalized_checkpoint.epoch) store.finalized_checkpoint = state.finalized_checkpoint;
    if (pulled.current_justified_checkpoint.epoch > store.unrealized_justified_checkpoint.epoch) {
        store.unrealized_justified_checkpoint = pulled.current_justified_checkpoint;
    }
    if (pulled.finalized_checkpoint.epoch > store.unrealized_finalized_checkpoint.epoch) {
        store.unrealized_finalized_checkpoint = pulled.finalized_checkpoint;
    }
    if (past_epoch) updateCheckpoints(store);
    if (store.finalized_checkpoint.epoch > prior_finalized_epoch) pruneToFinalized(store);
}

/// Deep-copy an SSZ value so store ownership is independent of caller memory.
fn cloneSSZ(allocator: std.mem.Allocator, comptime T: type, value: T) !T {
    const bytes = try ssz.serializeAlloc(allocator, value);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, T, &reader);
}

/// Insert an owned copy of a validated block under its root.
fn putBlock(store: *Store, root: fulu.Root, block: fulu.BeaconBlock) !void {
    const copy = try cloneSSZ(store.allocator, fulu.BeaconBlock, block);
    store.blocks.put(root, copy) catch |err| {
        ssz.freeDecoded(store.allocator, fulu.BeaconBlock, copy);
        return err;
    };
}

/// Insert an owned copy of a block's post-state.
fn putState(store: *Store, root: fulu.Root, state: fulu.BeaconState) !void {
    const copy = try cloneSSZ(store.allocator, fulu.BeaconState, state);
    store.block_states.put(root, copy) catch |err| {
        ssz.freeDecoded(store.allocator, fulu.BeaconState, copy);
        return err;
    };
}

/// Insert an owned state snapshot for a checkpoint.
fn putCheckpointState(store: *Store, checkpoint: fulu.Checkpoint, state: fulu.BeaconState) !void {
    const copy = try cloneSSZ(store.allocator, fulu.BeaconState, state);
    store.checkpoint_states.put(checkpoint, copy) catch |err| {
        ssz.freeDecoded(store.allocator, fulu.BeaconState, copy);
        return err;
    };
}

/// Cache a checkpoint's state at its epoch boundary before it becomes justified.
fn ensureCheckpointState(store: *Store, checkpoint: fulu.Checkpoint) !void {
    if (store.checkpoint_states.contains(checkpoint)) return;
    const source = store.block_states.get(checkpoint.root) orelse return error.UnknownCheckpoint;
    var state = try cloneSSZ(store.allocator, fulu.BeaconState, source);
    defer ssz.freeDecoded(store.allocator, fulu.BeaconState, state);
    const slot = try helpers.computeStartSlotAtEpoch(checkpoint.epoch);
    if (state.slot > slot) return error.InvalidCheckpoint;
    if (state.slot < slot) try transition.processSlots(store.allocator, &state, slot, epoch_transition.processEpoch);
    try putCheckpointState(store, checkpoint, state);
}

/// Import a valid attestation after timing and ancestry checks; block attestations may be older.
pub fn onAttestation(store: *Store, attestation: fulu.Attestation, is_from_block: bool) !void {
    const data = attestation.data;
    const current_epoch = helpers.computeEpochAtSlot(store.currentSlot());
    if (!is_from_block and data.target.epoch != current_epoch and data.target.epoch != current_epoch -| 1) return error.InvalidAttestationTime;
    if (data.target.epoch != helpers.computeEpochAtSlot(data.slot)) return error.InvalidAttestation;
    if (!store.blocks.contains(data.target.root)) return error.UnknownTarget;
    const vote_block = store.blocks.get(data.beacon_block_root) orelse return error.UnknownBlock;
    if (vote_block.slot > data.slot or
        !std.mem.eql(u8, &data.target.root, &(try checkpointBlock(store, data.beacon_block_root, data.target.epoch)))) return error.InvalidAttestationAncestry;
    if (data.slot >= store.currentSlot()) return error.EarlyAttestation;

    var target_state = try cloneSSZ(store.allocator, fulu.BeaconState, (store.checkpoint_states.get(data.target) orelse
        store.block_states.get(data.target.root) orelse return error.UnknownTarget));
    defer ssz.freeDecoded(store.allocator, fulu.BeaconState, target_state);
    const start_slot = try helpers.computeStartSlotAtEpoch(data.target.epoch);
    if (target_state.slot < start_slot) try transition.processSlots(store.allocator, &target_state, start_slot, epoch_transition.processEpoch);
    const indices = try operations.getAttestingIndices(store.allocator, &target_state, attestation);
    defer store.allocator.free(indices);
    try operations.validateIndexedAttestation(store.allocator, &target_state, .{
        .attesting_indices = .{ .data = indices },
        .data = data,
        .signature = attestation.signature,
    });

    try store.latest_messages.ensureUnusedCapacity(@intCast(indices.len));
    if (!store.checkpoint_states.contains(data.target)) try putCheckpointState(store, data.target, target_state);
    for (indices) |index| {
        if (store.equivocating_indices.contains(index)) continue;
        if (store.latest_messages.get(index)) |old| if (old.epoch >= data.target.epoch) continue;
        store.latest_messages.putAssumeCapacity(index, .{ .epoch = data.target.epoch, .root = data.beacon_block_root });
    }
}

/// Record validators proven to have made conflicting signed attestations.
pub fn onAttesterSlashing(store: *Store, slashing: fulu.AttesterSlashing) !void {
    const first = slashing.attestation_1;
    const second = slashing.attestation_2;
    if (!operations.isSlashableAttestationData(first.data, second.data)) return error.InvalidAttesterSlashing;
    const state = store.block_states.getPtr(store.justified_checkpoint.root) orelse return error.UnknownCheckpoint;
    try operations.validateIndexedAttestation(store.allocator, state, first);
    try operations.validateIndexedAttestation(store.allocator, state, second);
    try store.equivocating_indices.ensureUnusedCapacity(@intCast(@min(first.attesting_indices.data.len, second.attesting_indices.data.len)));
    var i: usize = 0;
    var j: usize = 0;
    while (i < first.attesting_indices.data.len and j < second.attesting_indices.data.len) {
        const a = first.attesting_indices.data[i];
        const b = second.attesting_indices.data[j];
        if (a < b) {
            i += 1;
        } else if (b < a) {
            j += 1;
        } else {
            store.equivocating_indices.putAssumeCapacity(a, {});
            i += 1;
            j += 1;
        }
    }
}

/// Sum active, unslashed latest votes on a block's branch and its current proposer boost.
pub fn getWeight(store: *const Store, root: fulu.Root) !u64 {
    const block = store.blocks.get(root) orelse return error.UnknownBlock;
    const state = store.checkpoint_states.get(store.justified_checkpoint) orelse return error.UnknownCheckpoint;
    const epoch_number = helpers.getCurrentEpoch(&state);
    var weight: u128 = 0;
    for (state.validators.data, 0..) |validator, index| {
        if (!helpers.isActiveValidator(validator, epoch_number) or validator.slashed or store.equivocating_indices.contains(index)) continue;
        const message = store.latest_messages.get(index) orelse continue;
        if (std.mem.eql(u8, &(try checkpointBlockAtSlot(store, message.root, block.slot)), &root)) weight += validator.effective_balance;
    }
    if (!std.mem.eql(u8, &store.proposer_boost_root, &([_]u8{0} ** 32)) and
        std.mem.eql(u8, &(try checkpointBlockAtSlot(store, store.proposer_boost_root, block.slot)), &root))
    {
        const balance = try helpers.getTotalActiveBalance(state.validators.data, epoch_number);
        weight += (@as(u128, balance) / helpers.SLOTS_PER_EPOCH) * PROPOSER_SCORE_BOOST / 100;
    }
    return std.math.cast(u64, weight) orelse error.WeightOverflow;
}

/// Return the ancestor at or before a slot, rejecting unknown roots.
fn checkpointBlockAtSlot(store: *const Store, root: fulu.Root, slot: fulu.Slot) !fulu.Root {
    var current = root;
    while (true) {
        const block = store.blocks.get(current) orelse return error.UnknownBlock;
        if (block.slot <= slot) return current;
        current = block.parent_root;
    }
}

const ChildMap = std.AutoHashMap(fulu.Root, std.ArrayListUnmanaged(fulu.Root));

/// Group block roots by parent once so head selection visits each edge once.
fn buildChildMap(store: *const Store) !ChildMap {
    var children = ChildMap.init(store.allocator);
    errdefer deinitChildMap(&children, store.allocator);
    var iter = store.blocks.iterator();
    while (iter.next()) |entry| {
        const slot = try children.getOrPut(entry.value_ptr.parent_root);
        if (!slot.found_existing) slot.value_ptr.* = .empty;
        try slot.value_ptr.append(store.allocator, entry.key_ptr.*);
    }
    return children;
}

/// Release the adjacency lists built for one head selection.
fn deinitChildMap(children: *ChildMap, allocator: std.mem.Allocator) void {
    var values = children.valueIterator();
    while (values.next()) |list| list.deinit(allocator);
    children.deinit();
}

/// Add one validator's balance to every ancestor of its latest vote.
fn addAncestorWeight(store: *const Store, weights: *std.AutoHashMap(fulu.Root, u128), root: fulu.Root, amount: u128) !void {
    var current = root;
    while (store.blocks.get(current)) |block| {
        const entry = try weights.getOrPut(current);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* +|= amount;
        current = block.parent_root;
    }
}

/// Precompute latest-message and proposer-boost weight for every stored block.
fn computeWeights(store: *const Store) !std.AutoHashMap(fulu.Root, u128) {
    const state = store.checkpoint_states.get(store.justified_checkpoint) orelse return error.UnknownCheckpoint;
    const epoch = helpers.getCurrentEpoch(&state);
    var weights = std.AutoHashMap(fulu.Root, u128).init(store.allocator);
    errdefer weights.deinit();
    for (state.validators.data, 0..) |validator, index| {
        if (!helpers.isActiveValidator(validator, epoch) or validator.slashed or store.equivocating_indices.contains(index)) continue;
        const message = store.latest_messages.get(index) orelse continue;
        if (!store.blocks.contains(message.root)) return error.UnknownBlock;
        try addAncestorWeight(store, &weights, message.root, validator.effective_balance);
    }
    if (!std.mem.eql(u8, &store.proposer_boost_root, &([_]u8{0} ** 32))) {
        if (!store.blocks.contains(store.proposer_boost_root)) return error.UnknownBlock;
        const balance = try helpers.getTotalActiveBalance(state.validators.data, epoch);
        const boost = (@as(u128, balance) / helpers.SLOTS_PER_EPOCH) * PROPOSER_SCORE_BOOST / 100;
        try addAncestorWeight(store, &weights, store.proposer_boost_root, boost);
    }
    return weights;
}

/// Select the viable descendant with the highest latest-message weight at each fork.
pub fn getHead(store: *const Store) !fulu.Root {
    var head = store.justified_checkpoint.root;
    if (!store.blocks.contains(head)) return error.UnknownCheckpoint;
    var children = try buildChildMap(store);
    defer deinitChildMap(&children, store.allocator);
    var weights = try computeWeights(store);
    defer weights.deinit();
    var viable = std.AutoHashMap(fulu.Root, bool).init(store.allocator);
    defer viable.deinit();
    var visiting = std.AutoHashMap(fulu.Root, void).init(store.allocator);
    defer visiting.deinit();
    while (true) {
        const candidates = children.get(head) orelse return head;
        var best: ?fulu.Root = null;
        var best_weight: u128 = 0;
        for (candidates.items) |root| {
            if (!try viableBranch(store, &children, root, &viable, &visiting)) continue;
            const weight = weights.get(root) orelse 0;
            if (best == null or weight > best_weight or (weight == best_weight and std.mem.order(u8, &root, &best.?) == .gt)) {
                best = root;
                best_weight = weight;
            }
        }
        head = best orelse return head;
    }
}

/// A branch is viable when a leaf below it has compatible justification and finality.
fn viableBranch(store: *const Store, children: *const ChildMap, root: fulu.Root, cache: *std.AutoHashMap(fulu.Root, bool), visiting: *std.AutoHashMap(fulu.Root, void)) !bool {
    if (cache.get(root)) |known| return known;
    if (visiting.contains(root)) return false;
    try visiting.put(root, {});
    defer _ = visiting.remove(root);
    var result = false;
    if (children.get(root)) |kids| {
        for (kids.items) |child| {
            if (try viableBranch(store, children, child, cache, visiting)) {
                result = true;
                break;
            }
        }
    } else {
        result = try leafIsViable(store, root);
    }
    try cache.put(root, result);
    return result;
}

/// Check the justification and finality snapshot carried by a branch leaf.
fn leafIsViable(store: *const Store, root: fulu.Root) !bool {
    const block = store.blocks.get(root) orelse return error.UnknownBlock;
    const current_epoch = helpers.computeEpochAtSlot(store.currentSlot());
    const source = if (current_epoch > helpers.computeEpochAtSlot(block.slot))
        store.unrealized_justifications.get(root) orelse return error.UnknownCheckpoint
    else
        (store.block_states.get(root) orelse return error.UnknownBlock).current_justified_checkpoint;
    const justified = store.justified_checkpoint.epoch == 0 or source.epoch == store.justified_checkpoint.epoch or source.epoch + 2 >= current_epoch;
    const finalized = store.finalized_checkpoint.epoch == 0 or std.mem.eql(u8, &store.finalized_checkpoint.root, &(try checkpointBlock(store, root, store.finalized_checkpoint.epoch)));
    return justified and finalized;
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
    store.time = store.genesis_time + (checkpoint.epoch + period) * helpers.SLOTS_PER_EPOCH * preset.SECONDS_PER_SLOT;
    try std.testing.expect(try isWithinWeakSubjectivityPeriod(&store, &state, checkpoint));

    try std.testing.expectError(error.InvalidWeakSubjectivityCheckpoint, isWithinWeakSubjectivityPeriod(&store, &state, .{
        .epoch = checkpoint.epoch,
        .root = [_]u8{0x22} ** 32,
    }));

    store.time += helpers.SLOTS_PER_EPOCH * preset.SECONDS_PER_SLOT;
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
    const next_checkpoint = fulu.Checkpoint{ .epoch = 1, .root = store.justified_checkpoint.root };
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

    /// Return the configured availability result and count checks.
    fn check(context: *anyopaque, _: fulu.Root, _: *const fulu.BeaconBlock) anyerror!bool {
        const self: *AvailabilityTestContext = @ptrCast(@alignCast(context));
        self.calls += 1;
        return self.available;
    }
};

/// Decode the shared official anchor and data-availability block fixture.
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
    try onTick(&store, fixture[2].message.slot * preset.SECONDS_PER_SLOT);
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
    try std.testing.expectEqual(store.justified_checkpoint.root, try getHead(&store));
}

test "blobless blocks need no availability callback" {
    const allocator = std.testing.allocator;
    const fixture = try loadAvailabilityFixture(allocator);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, fixture[0]);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, fixture[1]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, fixture[2]);
    var block = fixture[2].message;
    block.body.blob_kzg_commitments = .{ .data = &.{} };
    var context = AvailabilityTestContext{ .available = false };
    const check = DataAvailabilityCheck{ .context = &context, .is_available = AvailabilityTestContext.check };
    try std.testing.expect(try check.check([_]u8{0} ** 32, &block));
    try std.testing.expectEqual(@as(usize, 0), context.calls);
}

test "fork-choice stores an available block and assigns timely proposer boost" {
    const allocator = std.testing.allocator;
    var fixture = try loadAvailabilityFixture(allocator);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, fixture[0]);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, fixture[1]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, fixture[2]);
    var store = try initStore(allocator, &fixture[0], &fixture[1]);
    defer store.deinit();
    try onTick(&store, fixture[2].message.slot * preset.SECONDS_PER_SLOT);
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
    const served_signed = store.signedBlock(block_root).?;
    try std.testing.expectEqualSlices(u8, &fixture[2].signature, &served_signed.signature);
    try std.testing.expectEqual(block_root, store.proposer_boost_root);
    try std.testing.expectEqual(@as(u64, 0), store.justified_checkpoint.epoch);
    try std.testing.expectEqual(@as(u64, 0), store.finalized_checkpoint.epoch);
    try std.testing.expectEqual(store.justified_checkpoint, store.unrealized_justified_checkpoint);
    try std.testing.expectEqual(store.finalized_checkpoint, store.unrealized_finalized_checkpoint);
    try std.testing.expectEqual(@as(usize, 2), store.unrealized_justifications.count());
    try std.testing.expectEqual(block_root, try getHead(&store));
    try std.testing.expect((try getWeight(&store, block_root)) > 0);
}

test "fork-choice votes, proposer boost, expiry, and invalid events" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    var store = try initStore(allocator, &state, &anchor);
    defer store.deinit();

    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    var child = anchor;
    child.slot = 1;
    child.parent_root = store.justified_checkpoint.root;
    try putBlock(&store, a, child);
    try putBlock(&store, b, child);
    try putState(&store, a, state);
    try putState(&store, b, state);
    try store.unrealized_justifications.put(a, store.justified_checkpoint);
    try store.unrealized_justifications.put(b, store.justified_checkpoint);
    try store.latest_messages.put(0, .{ .epoch = 0, .root = a });
    try std.testing.expectEqual(state.validators.data[0].effective_balance, try getWeight(&store, a));
    try std.testing.expectEqual(a, try getHead(&store));

    store.proposer_boost_root = b;
    try std.testing.expectEqual(b, try getHead(&store));
    try onTick(&store, preset.SECONDS_PER_SLOT);
    try std.testing.expectEqual(a, try getHead(&store));

    try store.equivocating_indices.put(0, {});
    try std.testing.expectEqual(@as(u64, 0), try getWeight(&store, a));
    try std.testing.expectEqual(b, try getHead(&store));
    store.finalized_checkpoint = .{ .epoch = 1, .root = a };
    try std.testing.expectEqual(a, try getHead(&store));

    try std.testing.expectError(error.UnknownTarget, onAttestation(&store, std.mem.zeroes(fulu.Attestation), false));
    try std.testing.expectError(error.InvalidAttesterSlashing, onAttesterSlashing(&store, std.mem.zeroes(fulu.AttesterSlashing)));
    try std.testing.expectEqual(@as(usize, 1), store.latest_messages.count());
    try std.testing.expectEqual(@as(usize, 1), store.equivocating_indices.count());
}

test "fork-choice rejects an unknown parent and records late blocks without boost" {
    const allocator = std.testing.allocator;
    var fixture = try loadAvailabilityFixture(allocator);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, fixture[0]);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, fixture[1]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, fixture[2]);
    var store = try initStore(allocator, &fixture[0], &fixture[1]);
    defer store.deinit();
    var availability = AvailabilityTestContext{ .available = true };
    var engine: engine_api.TestEngine = .{ .status = .valid };
    const check = DataAvailabilityCheck{ .context = &availability, .is_available = AvailabilityTestContext.check };
    var bad = fixture[2];
    bad.message.parent_root = [_]u8{0xff} ** 32;
    try std.testing.expectError(error.UnknownParent, onBlock(&store, bad, engine.interface(), check));
    try std.testing.expectEqual(@as(usize, 1), store.blocks.count());
    try std.testing.expectEqual(@as(usize, 0), availability.calls);

    try onTick(&store, (fixture[2].message.slot + 1) * preset.SECONDS_PER_SLOT);
    try onBlock(&store, fixture[2], engine.interface(), check);
    const root = try merkle.HashTreeRoot(allocator, fixture[2].message);
    try std.testing.expectEqual(false, store.block_timeliness.get(root).?);
    try std.testing.expectEqual([_]u8{0} ** 32, store.proposer_boost_root);
}

test "official Fulu heavier-branch fixture changes head after attestation" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const dir = "fixtures/fulu_fork_choice/heavier_branch/";
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    var store = try initStore(allocator, &state, &anchor);
    defer store.deinit();
    var engine: engine_api.TestEngine = .{ .status = .valid };
    var availability = AvailabilityTestContext{ .available = true };
    const check = DataAvailabilityCheck{ .context = &availability, .is_available = AvailabilityTestContext.check };
    const bad_parent = try fixtures.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/bad_parent/block_0xa5667dda587576392d5ce9396751b4761abe367219f379b58333d0017eda3970.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, bad_parent);
    if (onBlock(&store, bad_parent, engine.interface(), check)) |_| return error.ExpectedRejection else |_| {}
    try std.testing.expectEqual(@as(usize, 1), store.blocks.count());
    try std.testing.expectEqual(@as(usize, 1), store.block_states.count());
    try std.testing.expectEqual(@as(usize, 0), store.block_timeliness.count());
    try std.testing.expectEqual(@as(usize, 1), store.unrealized_justifications.count());
    const compressed = [_][]const u8{
        @embedFile(dir ++ "block_0xbc8706b8945c619414fb557decb7cb893c5e240ea95ec8a0e9d97c6f56532cff.ssz_snappy"),
        @embedFile(dir ++ "block_0xc44a335c2ae08ad57a68b81affd6b22d79427b4c755214eebcc74351d2b29347.ssz_snappy"),
        @embedFile(dir ++ "block_0x1db47324a6822813b02b053d39930e385d1fbfe474e4ad3d0b4ee89748c857b8.ssz_snappy"),
        @embedFile(dir ++ "block_0x0ae189fc2d624f5c04b4f1075245ba3a0b9aaa0bfeacacc9df6e7d58a9f035c7.ssz_snappy"),
    };
    const times = [_]u64{ 6, 12, 18, 18 };
    for (compressed, times) |input, time| {
        try onTick(&store, time);
        const signed = try fixtures.decodeBlock(allocator, input);
        defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
        try onBlock(&store, signed, engine.interface(), check);
    }
    var expected: fulu.Root = undefined;
    _ = try std.fmt.hexToBytes(&expected, "f2597784a2d11269a56a61e256c4830c3ba3c467fd178f11146a8bdf9be198df");
    try std.testing.expectEqual(expected, try getHead(&store));
    const attestation_bytes = try fixtures.decode(allocator, @embedFile(dir ++ "attestation_0xfd7837e56b89c2042febfa3e790e8e4f12177170bcb7a6abcfc08b37474f20ba.ssz_snappy"));
    defer allocator.free(attestation_bytes);
    var attestation_reader: std.Io.Reader = .fixed(attestation_bytes);
    const attestation = try ssz.deserialize(allocator, fulu.Attestation, &attestation_reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, attestation);
    var wrong_target = attestation;
    wrong_target.data.target.root = expected;
    try std.testing.expectError(error.InvalidAttestationAncestry, onAttestation(&store, wrong_target, false));
    var bad_signature = attestation;
    bad_signature.signature = [_]u8{0} ** 96;
    if (onAttestation(&store, bad_signature, false)) |_| return error.ExpectedRejection else |_| {}
    try std.testing.expectEqual(@as(usize, 0), store.latest_messages.count());
    try onAttestation(&store, attestation, false);
    _ = try std.fmt.hexToBytes(&expected, "c892833adc0fff2de4366886a5eaecfaa6228dfddc6dc0a9c44d2fda4518d5e5");
    try std.testing.expectEqual(expected, try getHead(&store));
}

test "official Fulu slashing fixture excludes equivocating votes" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const anchor_dir = "fixtures/fulu_fork_choice/basic/";
    const dir = "fixtures/fulu_fork_choice/slashing/";
    var state = try fixtures.decodeState(allocator, @embedFile(anchor_dir ++ "anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const anchor_bytes = try fixtures.decode(allocator, @embedFile(anchor_dir ++ "anchor_block.ssz_snappy"));
    defer allocator.free(anchor_bytes);
    var anchor_reader: std.Io.Reader = .fixed(anchor_bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &anchor_reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    var store = try initStore(allocator, &state, &anchor);
    defer store.deinit();
    try onTick(&store, 36);
    var engine: engine_api.TestEngine = .{ .status = .valid };
    var availability = AvailabilityTestContext{ .available = true };
    const check = DataAvailabilityCheck{ .context = &availability, .is_available = AvailabilityTestContext.check };
    for ([_][]const u8{
        @embedFile(dir ++ "block_0x2c1cbf2a02a84caf257b074dfac21f7b549b741fd815dcd29de52308a4cd477d.ssz_snappy"),
        @embedFile(dir ++ "block_0x267dad33839d51d5cebd0f400aface00fb9852dc30bfd1f5eee92a2f655d91dc.ssz_snappy"),
    }) |input| {
        const signed = try fixtures.decodeBlock(allocator, input);
        defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
        try onBlock(&store, signed, engine.interface(), check);
    }
    const attestation_bytes = try fixtures.decode(allocator, @embedFile(dir ++ "attestation_0x5172be6898efefa589c2182765c8e7a74272ed2b0004d0577921a4808b364fcf.ssz_snappy"));
    defer allocator.free(attestation_bytes);
    var reader: std.Io.Reader = .fixed(attestation_bytes);
    const attestation = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, attestation);
    try onAttestation(&store, attestation, false);
    const message_count = store.latest_messages.count();
    try std.testing.expect(message_count > 0);
    const slashing_bytes = try fixtures.decode(allocator, @embedFile(dir ++ "attester_slashing_0x37f647afd2845d3e479b0f3a7fface55f4aca82464d477681094d1950e5923c5.ssz_snappy"));
    defer allocator.free(slashing_bytes);
    var slashing_reader: std.Io.Reader = .fixed(slashing_bytes);
    const slashing = try ssz.deserialize(allocator, fulu.AttesterSlashing, &slashing_reader);
    defer ssz.freeDecoded(allocator, fulu.AttesterSlashing, slashing);
    var bad_signature = slashing;
    bad_signature.attestation_1.signature = [_]u8{0} ** 96;
    if (onAttesterSlashing(&store, bad_signature)) |_| return error.ExpectedRejection else |_| {}
    try std.testing.expectEqual(@as(usize, 0), store.equivocating_indices.count());
    try onAttesterSlashing(&store, slashing);
    try std.testing.expect(store.equivocating_indices.count() > 0);
    try std.testing.expectEqual(message_count, store.latest_messages.count());
    var expected: fulu.Root = undefined;
    _ = try std.fmt.hexToBytes(&expected, "738b28897c8ca84f0b800f5847dc5fdfc009d289fc226d047cf8d660af9342dc");
    try std.testing.expectEqual(expected, try getHead(&store));
}

test "finality prunes non-descendant blocks, states, checkpoints, and votes" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    var store = try initStore(allocator, &state, &anchor);
    defer store.deinit();

    const finalized = [_]u8{0x11} ** 32;
    const descendant = [_]u8{0x22} ** 32;
    const stale = [_]u8{0x33} ** 32;
    var child = anchor;
    child.slot = 1;
    child.parent_root = store.justified_checkpoint.root;
    try putBlock(&store, finalized, child);
    child.slot = 2;
    child.parent_root = finalized;
    try putBlock(&store, descendant, child);
    child.slot = 1;
    child.parent_root = store.justified_checkpoint.root;
    try putBlock(&store, stale, child);
    try putState(&store, finalized, state);
    try putState(&store, descendant, state);
    try putState(&store, stale, state);
    try store.unrealized_justifications.put(finalized, store.justified_checkpoint);
    try store.unrealized_justifications.put(descendant, store.justified_checkpoint);
    try store.unrealized_justifications.put(stale, store.justified_checkpoint);
    const stale_checkpoint = fulu.Checkpoint{ .epoch = 1, .root = stale };
    try putCheckpointState(&store, stale_checkpoint, state);
    try store.latest_messages.put(0, .{ .epoch = 0, .root = stale });
    try store.latest_messages.put(1, .{ .epoch = 0, .root = descendant });

    store.justified_checkpoint = .{ .epoch = 1, .root = finalized };
    store.finalized_checkpoint = .{ .epoch = 1, .root = finalized };
    pruneToFinalized(&store);

    try std.testing.expectEqual(@as(usize, 2), store.blocks.count());
    try std.testing.expectEqual(@as(usize, 2), store.block_states.count());
    try std.testing.expect(store.blocks.contains(finalized));
    try std.testing.expect(store.blocks.contains(descendant));
    try std.testing.expect(!store.blocks.contains(stale));
    try std.testing.expect(!store.checkpoint_states.contains(stale_checkpoint));
    try std.testing.expect(!store.latest_messages.contains(0));
    try std.testing.expect(store.latest_messages.contains(1));
}

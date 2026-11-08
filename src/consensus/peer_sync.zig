// Peer sync imports one ordered range from the active peer. A block names its
// parent by root, and fork choice stores the post-state only after transition
// and data availability checks pass. The snapshot is replaced after each
// accepted block, so recovery starts from the last durable head.
//
//   parent head -> range -> verified columns -> transition -> snapshot
// Requests are capped at 128 slots. This single-chain importer stops at a
// conflicting parent; branch reconciliation needs a later fork sync protocol.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const fork_choice = @import("fork_choice.zig");
const columns = @import("data_columns.zig");
const peer = @import("p2p_peer.zig");
const ingress = @import("p2p_ingress.zig");
const requests = @import("p2p_requests.zig");
const snapshot = @import("fork_choice_snapshot.zig");
const engine_api = @import("execution_engine.zig");
const kzg = @import("execution").kzg;

pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    store: *fork_choice.Store,
    columns: *columns.Store,
    settings: *const kzg.Settings,
    engine: engine_api.ExecutionEngine,
    head: fulu.Root,
    next_slot: u64,
    cancelled: ?*const std.atomic.Value(bool) = null,
    const ColumnContext = struct { block: *const fulu.BeaconBlock, parent_state: *const fulu.BeaconState };

    /// Fetch at most 128 slots after the retained head and import their chain.
    pub fn step(self: *Coordinator, remote: *peer.Peer, count: u64) !usize {
        if (self.cancelled) |flag| if (flag.load(.acquire)) return error.Canceled;
        if (count == 0 or count > columns.max_request_blocks) return error.InvalidRequest;
        const start = self.next_slot;
        var fetched = try remote.fetchBlocksByRange(start, count, 1);
        defer fetched.deinit();
        const imported = try self.importBlocks(remote, fetched.items.items, start, count);
        self.next_slot = try std.math.add(u64, start, count);
        return imported;
    }

    /// Check parent, order, availability, and transition before saving progress.
    pub fn importBlocks(self: *Coordinator, remote: ?*peer.Peer, blocks: []const fulu.SignedBeaconBlock, start: u64, count: u64) !usize {
        if (count == 0 or count > columns.max_request_blocks) return error.InvalidRequest;
        const end = try std.math.add(u64, start, count);
        var prior_slot = start -| 1;
        var imported: usize = 0;
        for (blocks) |*signed| {
            if (self.cancelled) |flag| if (flag.load(.acquire)) return error.Canceled;
            const block = signed.message;
            if (block.slot < start or block.slot >= end or block.slot <= prior_slot) return error.InvalidResponseOrder;
            if (!std.mem.eql(u8, &block.parent_root, &self.head)) return error.ConflictingParent;
            const parent_state = self.store.block_states.getPtr(self.head) orelse return error.UnknownParent;
            const root = try merkle.HashTreeRoot(self.allocator, block);
            if (block.body.blob_kzg_commitments.data.len != 0) {
                const active = remote orelse return error.MissingPeer;
                var column_context = ColumnContext{ .block = &block, .parent_state = parent_state };
                const lookup = ingress.ColumnLookup{ .context = &column_context, .resolve = resolveColumn };
                var sampled: [columns.column_count]u64 = undefined;
                for (self.columns.samples.values[0..self.columns.samples.len], 0..) |index, i| sampled[i] = index;
                const identifier = requests.ByRootIdentifier{ .block_root = root, .columns = .{ .data = sampled[0..self.columns.samples.len] } };
                _ = try active.fetchColumnsByRoot(&.{identifier}, self.columns, self.settings, lookup);
                if (!try self.columns.available(root, &block)) return error.DataUnavailable;
            }
            const at_slot = try std.math.add(u64, self.store.genesis_time, try std.math.mul(u64, block.slot, @import("consensus_preset").Config.SECONDS_PER_SLOT));
            try fork_choice.onTick(self.store, at_slot);
            try fork_choice.onBlock(self.store, signed.*, self.engine, .{ .context = self.columns, .is_available = columns.Store.check });
            self.head = fork_choice.getHead(self.store) catch return error.ImportCommitFailed;
            if (!std.mem.eql(u8, &self.head, &root)) return error.ImportCommitFailed;
            const head_state = self.store.block_states.get(self.head) orelse return error.ImportCommitFailed;
            const safe_state = self.store.block_states.get(self.store.justified_checkpoint.root) orelse return error.ImportCommitFailed;
            const finalized_state = self.store.block_states.get(self.store.finalized_checkpoint.root) orelse return error.ImportCommitFailed;
            const choice = self.engine.forkchoiceUpdated(.{ .head_block_hash = head_state.latest_execution_payload_header.block_hash, .safe_block_hash = safe_state.latest_execution_payload_header.block_hash, .finalized_block_hash = finalized_state.latest_execution_payload_header.block_hash }, null) catch return error.ForkchoiceUpdateFailed;
            if (choice.verdict.status != .valid) return error.ForkchoiceUpdateFailed;
            snapshot.saveForkChoiceStore(self.allocator, self.io, self.dir, "fork-choice.bin", self.store) catch return error.ImportCommitFailed;
            self.next_slot = try std.math.add(u64, block.slot, 1);
            prior_slot = block.slot;
            imported += 1;
        }
        return imported;
    }

    /// Serve a retained signed block by its message root.
    pub fn byRoot(context: *anyopaque, root: fulu.Root) ?fulu.SignedBeaconBlock {
        const self: *Coordinator = @ptrCast(@alignCast(context));
        return self.store.signedBlock(root);
    }

    /// Walk the selected chain to find the block at an exact slot.
    pub fn atSlot(context: *anyopaque, slot: u64) ?fulu.Root {
        const self: *Coordinator = @ptrCast(@alignCast(context));
        var root = self.head;
        while (self.store.blocks.get(root)) |block| {
            if (block.slot == slot) return root;
            if (block.slot < slot) return null;
            root = block.parent_root;
        }
        return null;
    }

    /// Match a column header to the requested block and its retained parent state.
    fn resolveColumn(context: *anyopaque, header: *const fulu.SignedBeaconBlockHeader) ?ingress.ColumnBlock {
        const source: *ColumnContext = @ptrCast(@alignCast(context));
        if (header.message.slot != source.block.slot or !std.mem.eql(u8, &header.message.parent_root, &source.block.parent_root)) return null;
        return .{ .block = source.block, .parent_state = source.parent_state };
    }
};

test "ordered import saves a valid head and rejects a conflicting replay" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = @import("fixture_runner.zig");
    const ssz = @import("ssz");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const anchor_bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(anchor_bytes);
    var reader: std.Io.Reader = .fixed(anchor_bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    var chain = try fork_choice.initStore(allocator, &state, &anchor);
    defer chain.deinit();
    const initial_root = try merkle.HashTreeRoot(allocator, anchor);
    var column_store = try columns.Store.open(allocator, io, tmp.dir, "columns", state.genesis_validators_root, [_]u8{1} ** 32, 128);
    defer column_store.deinit();
    var setup = kzg.Settings{};
    var engine = engine_api.TestEngine{ .status = .valid };
    var coordinator = Coordinator{ .allocator = allocator, .io = io, .dir = tmp.dir, .store = &chain, .columns = &column_store, .settings = &setup, .engine = engine.interface(), .head = initial_root, .next_slot = 1 };
    const first = try fixtures.decodeBlock(allocator, fixtures.fork_choice_heavier_blocks[0]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, first);
    try std.testing.expectEqual(@as(usize, 0), first.message.body.blob_kzg_commitments.data.len);
    try std.testing.expectEqual(@as(usize, 1), try coordinator.importBlocks(null, &.{first}, 1, 1));
    const accepted = coordinator.head;
    var restored = try snapshot.loadForkChoiceStore(allocator, io, tmp.dir, "fork-choice.bin");
    defer restored.deinit();
    try std.testing.expectEqual(accepted, try fork_choice.getHead(&restored));
    try std.testing.expectEqual(accepted, Coordinator.atSlot(&coordinator, 1).?);
    try std.testing.expectError(error.ConflictingParent, coordinator.importBlocks(null, &.{first}, 1, 1));
    try std.testing.expectEqual(accepted, coordinator.head);
    const second = try fixtures.decodeBlock(allocator, fixtures.fork_choice_heavier_blocks[1]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, second);
    var resumed = Coordinator{ .allocator = allocator, .io = io, .dir = tmp.dir, .store = &restored, .columns = &column_store, .settings = &setup, .engine = engine.interface(), .head = accepted, .next_slot = 2 };
    var cancel = std.atomic.Value(bool).init(true);
    resumed.cancelled = &cancel;
    try std.testing.expectError(error.Canceled, resumed.importBlocks(null, &.{second}, 2, 1));
    cancel.store(false, .release);
    var invalid = second;
    invalid.message.state_root[0] ^= 1;
    try std.testing.expectError(error.InvalidStateRoot, resumed.importBlocks(null, &.{invalid}, 2, 1));
    try std.testing.expectEqual(accepted, resumed.head);
    engine.forkchoice_status = .syncing;
    try std.testing.expectError(error.ForkchoiceUpdateFailed, resumed.importBlocks(null, &.{second}, 2, 1));
    var durable = try snapshot.loadForkChoiceStore(allocator, io, tmp.dir, "fork-choice.bin");
    defer durable.deinit();
    try std.testing.expectEqual(accepted, try fork_choice.getHead(&durable));
    const reloaded = try snapshot.loadForkChoiceStore(allocator, io, tmp.dir, "fork-choice.bin");
    restored.deinit();
    restored = reloaded;
    resumed.head = accepted;
    resumed.next_slot = 2;
    engine.forkchoice_status = null;
    try std.testing.expectEqual(@as(usize, 1), try resumed.importBlocks(null, &.{second}, 2, 1));
    const next = resumed.head;
    var recovered = try snapshot.loadForkChoiceStore(allocator, io, tmp.dir, "fork-choice.bin");
    defer recovered.deinit();
    try std.testing.expectEqual(next, try fork_choice.getHead(&recovered));
    try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, recovered.block_states.get(next).?), second.message.state_root);
}

test "two peers catch up from an anchor and resume after restart" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = @import("fixture_runner.zig");
    const ssz = @import("ssz");
    const gossip = @import("p2p_gossip.zig");
    const service = @import("p2p_service.zig");
    const control = @import("p2p_control.zig");
    const enr = @import("enr.zig");
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    var source_dir = std.testing.tmpDir(.{});
    defer source_dir.cleanup();
    var target_dir = std.testing.tmpDir(.{});
    defer target_dir.cleanup();
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    const anchor_root = try merkle.HashTreeRoot(allocator, anchor);
    var source_chain = try fork_choice.initStore(allocator, &state, &anchor);
    defer source_chain.deinit();
    var target_chain = try fork_choice.initStore(allocator, &state, &anchor);
    defer target_chain.deinit();
    var source_columns = try columns.Store.open(allocator, io, source_dir.dir, "columns", state.genesis_validators_root, [_]u8{1} ** 32, 128);
    defer source_columns.deinit();
    var target_columns = try columns.Store.open(allocator, io, target_dir.dir, "columns", state.genesis_validators_root, [_]u8{2} ** 32, 128);
    defer target_columns.deinit();
    var setup = kzg.Settings{};
    var source_engine = engine_api.TestEngine{ .status = .valid };
    var target_engine = engine_api.TestEngine{ .status = .valid };
    var source_sync = Coordinator{ .allocator = allocator, .io = io, .dir = source_dir.dir, .store = &source_chain, .columns = &source_columns, .settings = &setup, .engine = source_engine.interface(), .head = anchor_root, .next_slot = 1 };
    var target_sync = Coordinator{ .allocator = allocator, .io = io, .dir = target_dir.dir, .store = &target_chain, .columns = &target_columns, .settings = &setup, .engine = target_engine.interface(), .head = anchor_root, .next_slot = 1 };
    const first = try fixtures.decodeBlock(allocator, fixtures.fork_choice_heavier_blocks[0]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, first);
    const second = try fixtures.decodeBlock(allocator, fixtures.fork_choice_heavier_blocks[1]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, second);
    try std.testing.expectEqual(@as(usize, 2), try source_sync.importBlocks(null, &.{ first, second }, 1, 2));
    const ingress_config = ingress.Config{ .genesis_validators_root = state.genesis_validators_root, .fulu_version = state.fork.current_version, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    const digest = try ingress_config.digestAtSlot(0);
    const Gates = struct {
        /// Accept only after the transport and SSZ gates.
        fn block(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {}
        /// Accept only after the transport and SSZ gates.
        fn attestation(_: *anyopaque, _: *const fulu.Attestation) !void {}
        /// Accept only after the transport and SSZ gates.
        fn aggregate(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    };
    var marker: u8 = 0;
    const block_gate = ingress.BlockValidation{ .context = &marker, .validate = Gates.block };
    const attestation_gate = ingress.AttestationValidation{ .context = &marker, .validate = Gates.attestation };
    const aggregate_gate = ingress.AggregateValidation{ .context = &marker, .validate = Gates.aggregate };
    var source_gossip = try gossip.Service.init(allocator, ingress_config, digest, &.{}, 1, 3, block_gate, attestation_gate, aggregate_gate, null);
    defer source_gossip.deinit();
    var target_gossip = try gossip.Service.init(allocator, ingress_config, digest, &.{}, 1, 3, block_gate, attestation_gate, aggregate_gate, null);
    defer target_gossip.deinit();
    var fork_id = [_]u8{0} ** 16;
    @memcpy(fork_id[0..4], &digest);
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 0, .tcp_port = 0, .fork_id = fork_id, .next_fork_digest = .{0} ** 4, .custody_group_count = 128 };
    const metadata = control.MetaData{ .seq_number = 1, .attnets = .{ .data = [_]bool{false} ** 64 }, .syncnets = .{ .data = [_]bool{false} ** 4 }, .custody_group_count = 128 };
    const source_status = control.Status{ .fork_digest = digest, .finalized_root = anchor_root, .finalized_epoch = 0, .head_root = source_sync.head, .head_slot = 2, .earliest_available_slot = 1 };
    const target_status = control.Status{ .fork_digest = digest, .finalized_root = anchor_root, .finalized_epoch = 0, .head_root = anchor_root, .head_slot = 0, .earliest_available_slot = 0 };
    var source_service = try service.Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{131} ** 32), local, 2, &source_gossip, source_status, metadata);
    defer source_service.deinit();
    var target_service = try service.Service.init(allocator, io, try Ecdsa.KeyPair.generateDeterministic([_]u8{132} ** 32), local, 2, &target_gossip, target_status, metadata);
    defer target_service.deinit();
    source_service.setRoutes(.{ .blocks = .{ .context = &source_sync, .by_root = Coordinator.byRoot, .root_at_slot = Coordinator.atSlot }, .columns = &source_columns, .canonical = .{ .context = &source_sync, .root_at_slot = Coordinator.atSlot } });
    const uri = try source_service.localUri();
    defer allocator.free(uri);
    try target_service.addBootstrap(uri);
    const Worker = struct {
        source: *service.Service,
        stop: std.atomic.Value(bool) = .init(false),
        err: ?anyerror = null,
        /// Drive the serving peer while the target connects and requests blocks.
        fn run(self: *@This()) void {
            while (!self.stop.load(.acquire)) self.source.step(10) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var worker = Worker{ .source = &source_service };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    defer {
        worker.stop.store(true, .release);
        thread.join();
    }
    const deadline = std.Io.Clock.awake.now(io).nanoseconds + 20 * std.time.ns_per_s;
    while (!target_service.connected() and std.Io.Clock.awake.now(io).nanoseconds < deadline) try target_service.step(10);
    if (!target_service.connected()) return target_service.last_handshake_error orelse error.ConnectionTimeout;
    try std.testing.expectEqual(@as(usize, 1), try target_sync.step(try target_service.activePeer(), 1));
    var restored = try snapshot.loadForkChoiceStore(allocator, io, target_dir.dir, "fork-choice.bin");
    defer restored.deinit();
    var resumed = Coordinator{ .allocator = allocator, .io = io, .dir = target_dir.dir, .store = &restored, .columns = &target_columns, .settings = &setup, .engine = target_engine.interface(), .head = try fork_choice.getHead(&restored), .next_slot = 2 };
    try std.testing.expectEqual(@as(usize, 1), try resumed.step(try target_service.activePeer(), 1));
    try std.testing.expectEqual(source_sync.head, resumed.head);
    try std.testing.expectEqual(second.message.body.execution_payload.block_hash, target_engine.head.?);
    try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, source_chain.block_states.get(source_sync.head).?), try merkle.HashTreeRoot(allocator, restored.block_states.get(resumed.head).?));
    if (worker.err) |err| return err;
}

// Local microbenchmarks for the hot paths identified during the memory and
// performance review. Timings are wall-clock on the current machine and are
// intended for before/after comparisons, not as fixed budgets.
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const storage = @import("storage");
const consensus = @import("consensus");
const preset = @import("consensus_preset").Config;
const wire = consensus.P2PWire;

const fixtures = consensus.fixtureRunner;

const anchor_state_bytes = @embedFile("consensus/fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy");
const anchor_block_bytes = @embedFile("consensus/fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy");
const attestation_pre_bytes = @embedFile("consensus/fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy");
const attestation_bytes = @embedFile("consensus/fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy");
const heavier_blocks = [_][]const u8{
    @embedFile("consensus/fixtures/fulu_fork_choice/heavier_branch/block_0xbc8706b8945c619414fb557decb7cb893c5e240ea95ec8a0e9d97c6f56532cff.ssz_snappy"),
    @embedFile("consensus/fixtures/fulu_fork_choice/heavier_branch/block_0xc44a335c2ae08ad57a68b81affd6b22d79427b4c755214eebcc74351d2b29347.ssz_snappy"),
    @embedFile("consensus/fixtures/fulu_fork_choice/heavier_branch/block_0x1db47324a6822813b02b053d39930e385d1fbfe474e4ad3d0b4ee89748c857b8.ssz_snappy"),
    @embedFile("consensus/fixtures/fulu_fork_choice/heavier_branch/block_0x0ae189fc2d624f5c04b4f1075245ba3a0b9aaa0bfeacacc9df6e7d58a9f035c7.ssz_snappy"),
};
const heavier_times = [_]u64{ 6, 12, 18, 18 };

const Engine = struct {
    /// Accept every execution payload so the benchmark measures consensus work.
    fn verify(_: *anyopaque, _: consensus.NewPayloadRequest) anyerror!consensus.PayloadVerdict {
        return .{ .status = .valid };
    }
};

const Availability = struct {
    /// Treat every block as data-available.
    fn check(_: *anyopaque, _: fulu.Root, _: *const fulu.BeaconBlock) anyerror!bool {
        return true;
    }
};

var engine_context: u8 = 0;
var availability_context: u8 = 0;

fn engine() consensus.ExecutionEngine {
    return .{ .context = &engine_context, .verify_and_notify_new_payload = Engine.verify };
}

fn availability() consensus.DataAvailabilityCheck {
    return .{ .context = &availability_context, .is_available = Availability.check };
}

fn bench(io: std.Io, allocator: std.mem.Allocator, label: []const u8, iterations: usize, context: anytype) !void {
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var i: usize = 0;
    while (i < iterations) : (i += 1) try context.run();
    const end = std.Io.Clock.awake.now(io).nanoseconds;
    const elapsed: f64 = @floatFromInt(end - start);
    const per: f64 = elapsed / @as(f64, @floatFromInt(iterations));
    const text = try std.fmt.allocPrint(allocator, "{s:<42} {d:>12.3} us/op  ({d} iters)\n", .{ label, per / std.time.ns_per_us, iterations });
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(io, text);
}

fn loadAnchor(allocator: std.mem.Allocator) !struct { fulu.BeaconState, fulu.BeaconBlock } {
    const state = try fixtures.decodeState(allocator, anchor_state_bytes);
    errdefer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const raw = try fixtures.decode(allocator, anchor_block_bytes);
    defer allocator.free(raw);
    var reader: std.Io.Reader = .fixed(raw);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    return .{ state, block };
}

fn loadHeavyStore(allocator: std.mem.Allocator) !consensus.ForkChoiceStore {
    const anchor = try loadAnchor(allocator);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, anchor[0]);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor[1]);
    var store = try consensus.initForkChoiceStore(allocator, &anchor[0], &anchor[1]);
    errdefer store.deinit();
    for (heavier_blocks, heavier_times) |input, time| {
        try consensus.onForkChoiceTick(&store, time);
        const signed = try fixtures.decodeBlock(allocator, input);
        defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
        try consensus.onForkChoiceBlock(&store, signed, engine(), availability());
    }
    return store;
}

const CloneContext = struct {
    allocator: std.mem.Allocator,
    state: *const fulu.BeaconState,

    /// Serialize and deserialize one BeaconState, matching fork-choice cloning.
    fn run(self: @This()) !void {
        const bytes = try ssz.serializeAlloc(self.allocator, self.state.*);
        defer self.allocator.free(bytes);
        var reader: std.Io.Reader = .fixed(bytes);
        const copy = try ssz.deserialize(self.allocator, fulu.BeaconState, &reader);
        ssz.freeDecoded(self.allocator, fulu.BeaconState, copy);
    }
};

const RootContext = struct {
    allocator: std.mem.Allocator,
    state: *const fulu.BeaconState,

    /// Hash one BeaconState without retaining the result.
    fn run(self: @This()) !void {
        const root = try merkle.HashTreeRoot(self.allocator, self.state.*);
        std.mem.doNotOptimizeAway(root);
    }
};

const InitStoreContext = struct {
    allocator: std.mem.Allocator,
    state: *const fulu.BeaconState,
    block: *const fulu.BeaconBlock,

    /// Build and tear down one anchor fork-choice store.
    fn run(self: @This()) !void {
        var store = try consensus.initForkChoiceStore(self.allocator, self.state, self.block);
        store.deinit();
    }
};

const ImportBlockContext = struct {
    allocator: std.mem.Allocator,
    state: *const fulu.BeaconState,
    block: *const fulu.BeaconBlock,

    /// Import the first heavier-branch block into a fresh anchor store.
    fn run(self: @This()) !void {
        var store = try consensus.initForkChoiceStore(self.allocator, self.state, self.block);
        defer store.deinit();
        try consensus.onForkChoiceTick(&store, heavier_times[0]);
        const signed = try fixtures.decodeBlock(self.allocator, heavier_blocks[0]);
        defer ssz.freeDecoded(self.allocator, fulu.SignedBeaconBlock, signed);
        try consensus.onForkChoiceBlock(&store, signed, engine(), availability());
    }
};

fn cloneValue(allocator: std.mem.Allocator, comptime T: type, value: T) !T {
    const bytes = try ssz.serializeAlloc(allocator, value);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, T, &reader);
}

/// Build a synthetic single-child chain to expose head-selection scaling.
fn buildSyntheticStore(allocator: std.mem.Allocator, state: *const fulu.BeaconState, anchor: *const fulu.BeaconBlock, count: usize) !consensus.ForkChoiceStore {
    var store = try consensus.initForkChoiceStore(allocator, state, anchor);
    errdefer store.deinit();
    var parent = store.justified_checkpoint.root;
    var slot = anchor.slot;
    for (0..count) |_| {
        slot += 1;
        var child = anchor.*;
        child.slot = slot;
        child.parent_root = parent;
        const root = try merkle.HashTreeRoot(allocator, child);
        const block_copy = try cloneValue(allocator, fulu.BeaconBlock, child);
        store.blocks.put(root, block_copy) catch |err| {
            ssz.freeDecoded(allocator, fulu.BeaconBlock, block_copy);
            return err;
        };
        const state_copy = try cloneValue(allocator, fulu.BeaconState, state.*);
        store.block_states.put(root, state_copy) catch |err| {
            ssz.freeDecoded(allocator, fulu.BeaconState, state_copy);
            return err;
        };
        try store.unrealized_justifications.put(root, store.justified_checkpoint);
        parent = root;
    }
    store.time = store.genesis_time + slot * preset.SECONDS_PER_SLOT;
    return store;
}

const HeadContext = struct {
    store: *const consensus.ForkChoiceStore,

    /// Select the head from a store with one fork and four imported blocks.
    fn run(self: @This()) !void {
        const head = try consensus.getForkChoiceHead(self.store);
        std.mem.doNotOptimizeAway(head);
    }
};

const AdmitAttestationContext = struct {
    allocator: std.mem.Allocator,
    state: *const fulu.BeaconState,
    attestation: *const fulu.Attestation,

    /// Admit one valid attestation into a fresh operation pool.
    fn run(self: @This()) !void {
        var pool = consensus.OperationPool.init(self.allocator);
        defer pool.deinit();
        try pool.addAttestation(self.state, self.attestation.*);
    }
};

const SelectContext = struct {
    allocator: std.mem.Allocator,
    pool: *const consensus.OperationPool,
    state: *const fulu.BeaconState,

    /// Select operations from a pool holding one attestation.
    fn run(self: @This()) !void {
        const selected = try self.pool.select(self.allocator, self.state);
        defer {
            self.allocator.free(selected.proposer_slashings);
            self.allocator.free(selected.attester_slashings);
            self.allocator.free(selected.attestations);
            self.allocator.free(selected.voluntary_exits);
            self.allocator.free(selected.bls_changes);
        }
        std.mem.doNotOptimizeAway(selected.attestations.len);
    }
};

const PutContext = struct {
    db: *storage.Database,
    counter: *u64,

    /// Durably write one distinct key, exercising the per-put WAL sync.
    fn run(self: @This()) !void {
        var key_buffer: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buffer, "bench/key/{d}", .{self.counter.*});
        self.counter.* += 1;
        try self.db.put(key, "value");
    }
};

const BatchPutContext = struct {
    db: *storage.Database,
    operations: []const storage.Operation,

    /// Durably write one prebuilt batch of 64 keys.
    fn run(self: @This()) !void {
        try self.db.write(self.operations);
    }
};

const GetContext = struct {
    allocator: std.mem.Allocator,
    db: *storage.Database,
    key: []const u8,
    expected: []const u8,

    /// Read one key and compare its value.
    fn run(self: @This()) !void {
        const value = (try self.db.get(self.allocator, self.key)).?;
        defer self.allocator.free(value);
        if (!std.mem.eql(u8, value, self.expected)) return error.UnexpectedValue;
    }
};

const ScanContext = struct {
    allocator: std.mem.Allocator,
    db: *storage.Database,

    /// Scan the first 64 keys in the benchmark range.
    fn run(self: @This()) !void {
        const rows = try self.db.scan(self.allocator, "bench/key/", "bench/kez", null, 64, 1024 * 1024);
        defer {
            for (rows) |row| {
                self.allocator.free(row.key);
                self.allocator.free(row.value);
            }
            self.allocator.free(rows);
        }
        std.mem.doNotOptimizeAway(rows.len);
    }
};

const SnappyDecompressContext = struct {
    allocator: std.mem.Allocator,
    input: []const u8,

    /// Decompress one bound Snappy block.
    fn run(self: @This()) !void {
        const output = try wire.decodeGossip(self.allocator, self.input, self.input.len);
        defer self.allocator.free(output);
        std.mem.doNotOptimizeAway(output.len);
    }
};

const SnappyCompressContext = struct {
    allocator: std.mem.Allocator,
    input: []const u8,

    /// Compress one raw block with the literal-only encoder.
    fn run(self: @This()) !void {
        const output = try wire.encodeGossip(self.allocator, self.input, self.input.len * 2);
        defer self.allocator.free(output);
        std.mem.doNotOptimizeAway(output.len);
    }
};

/// Run local microbenchmarks against the reviewed hot paths.
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    const anchor = try loadAnchor(allocator);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, anchor[0]);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor[1]);
    const serialized = try ssz.serializeAlloc(allocator, anchor[0]);
    defer allocator.free(serialized);
    const size_text = try std.fmt.allocPrint(allocator, "serialized BeaconState: {d} bytes\n\n", .{serialized.len});
    defer allocator.free(size_text);
    try std.Io.File.stdout().writeStreamingAll(io, size_text);

    try bench(io, allocator, "ssz.clone_beacon_state", 20, CloneContext{ .allocator = allocator, .state = &anchor[0] });
    try bench(io, allocator, "merkle.hash_tree_root_beacon_state", 20, RootContext{ .allocator = allocator, .state = &anchor[0] });
    try bench(io, allocator, "fork_choice.init_store", 10, InitStoreContext{ .allocator = allocator, .state = &anchor[0], .block = &anchor[1] });
    try bench(io, allocator, "fork_choice.import_block", 5, ImportBlockContext{ .allocator = allocator, .state = &anchor[0], .block = &anchor[1] });

    var store = try loadHeavyStore(allocator);
    defer store.deinit();
    try bench(io, allocator, "fork_choice.get_head", 1000, HeadContext{ .store = &store });

    const chain_lengths = [_]usize{ 64, 128, 256, 512 };
    for (chain_lengths) |length| {
        var synthetic = try buildSyntheticStore(allocator, &anchor[0], &anchor[1], length);
        defer synthetic.deinit();
        const label = try std.fmt.allocPrint(allocator, "fork_choice.get_head_chain_{d}", .{length});
        defer allocator.free(label);
        try bench(io, allocator, label, 100, HeadContext{ .store = &synthetic });
        const retained_text = try std.fmt.allocPrint(allocator, "  retains ~{d} KiB of block states for {d} imported blocks\n", .{ length * serialized.len / 1024, length });
        defer allocator.free(retained_text);
        try std.Io.File.stdout().writeStreamingAll(io, retained_text);
    }

    const op_state = try fixtures.decodeState(allocator, attestation_pre_bytes);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, op_state);
    const op_raw = try fixtures.decode(allocator, attestation_bytes);
    defer allocator.free(op_raw);
    var op_reader: std.Io.Reader = .fixed(op_raw);
    const attestation = try ssz.deserialize(allocator, fulu.Attestation, &op_reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, attestation);
    var pool = consensus.OperationPool.init(allocator);
    defer pool.deinit();
    try pool.addAttestation(&op_state, attestation);
    try bench(io, allocator, "operation_pool.admit_attestation", 10, AdmitAttestationContext{ .allocator = allocator, .state = &op_state, .attestation = &attestation });
    try bench(io, allocator, "operation_pool.select", 20, SelectContext{ .allocator = allocator, .pool = &pool, .state = &op_state });

    const dir = std.Io.Dir.cwd();
    const path = ".zig-cache/bench-lsm";
    dir.deleteTree(io, path) catch {};
    defer dir.deleteTree(io, path) catch {};
    var db = try storage.Database.open(allocator, io, dir, path);
    defer db.close();
    var counter: u64 = 0;
    try bench(io, allocator, "lsm.put_single_synced", 20, PutContext{ .db = &db, .counter = &counter });
    const keys = try allocator.alloc([32]u8, 64);
    defer allocator.free(keys);
    const operations = try allocator.alloc(storage.Operation, 64);
    defer allocator.free(operations);
    for (keys, 0..) |*key_buffer, i| {
        const key = try std.fmt.bufPrint(key_buffer, "bench/batch/{d:0>4}", .{i});
        operations[i] = .{ .put = .{ .key = key, .value = "value" } };
    }
    try bench(io, allocator, "lsm.write_batch_64_synced", 10, BatchPutContext{ .db = &db, .operations = operations });
    try db.put("bench/key/read", "value");
    try bench(io, allocator, "lsm.get", 2000, GetContext{ .allocator = allocator, .db = &db, .key = "bench/key/read", .expected = "value" });
    try bench(io, allocator, "lsm.scan_64", 100, ScanContext{ .allocator = allocator, .db = &db });

    try bench(io, allocator, "snappy.decompress_anchor_state", 50, SnappyDecompressContext{ .allocator = allocator, .input = anchor_state_bytes });
    try bench(io, allocator, "snappy.compress_anchor_state", 50, SnappyCompressContext{ .allocator = allocator, .input = serialized });
}

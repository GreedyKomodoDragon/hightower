// A fork-choice snapshot preserves the blocks, post-states, votes, checkpoints,
// and slot timing that determine the next head. A checkpoint names an epoch and
// block root; proposer boost is temporary weight that expires at a slot boundary.
// The complete replacement is synced before it becomes visible, so recovery
// observes either the old store or the new store, never a partial transition.
// shortcut: snapshots are limited to 256 MiB and 4096 records per map; raise
// these bounds when archival storage or a production database is introduced.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const ssz = @import("ssz");
const fork_choice = @import("fork_choice.zig");

const magic = "HTFC0002";
const legacy_magic = "HTFC0001";
const max_bytes = 256 * 1024 * 1024;
const max_records = 4096;
const header_len = magic.len + 8 + 32;
const zero_root: fulu.Root = [_]u8{0} ** 32;

/// Atomically replace a snapshot after syncing its complete contents.
/// Payload bytes stream into the temporary file while a running digest is
/// computed; only the fixed-size header is retained in memory.
pub fn saveForkChoiceStore(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, store: *const fork_choice.Store) !void {
    var atomic = try dir.createFileAtomic(io, path, .{ .replace = true });
    defer atomic.deinit(io);
    var header: [header_len]u8 = [_]u8{0} ** header_len;
    @memcpy(header[0..magic.len], magic);
    try atomic.file.writeStreamingAll(io, &header);
    var writer = SnapshotWriter{
        .file = atomic.file,
        .io = io,
        .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
    };
    try writer.number(store.time);
    try writer.number(store.genesis_time);
    try writer.checkpoint(store.justified_checkpoint);
    try writer.checkpoint(store.finalized_checkpoint);
    try writer.checkpoint(store.unrealized_justified_checkpoint);
    try writer.checkpoint(store.unrealized_finalized_checkpoint);
    try writer.append(&store.proposer_boost_root);
    const head = try fork_choice.getHead(store);
    try writer.append(&head);

    try writer.count(store.blocks.count());
    var blocks = store.blocks.iterator();
    while (blocks.next()) |entry| {
        try writer.append(entry.key_ptr);
        try writer.value(allocator, entry.value_ptr.*);
    }
    try writer.count(store.signed_block_signatures.count());
    var signatures = store.signed_block_signatures.iterator();
    while (signatures.next()) |entry| {
        try writer.append(entry.key_ptr);
        try writer.append(&entry.value_ptr.*);
    }
    try writer.count(store.block_states.count());
    var states = store.block_states.iterator();
    while (states.next()) |entry| {
        try writer.append(entry.key_ptr);
        try writer.value(allocator, entry.value_ptr.*);
    }
    try writer.count(store.checkpoint_states.count());
    var checkpoint_states = store.checkpoint_states.iterator();
    while (checkpoint_states.next()) |entry| {
        try writer.checkpoint(entry.key_ptr.*);
        try writer.value(allocator, entry.value_ptr.*);
    }
    try writer.count(store.block_timeliness.count());
    var timeliness = store.block_timeliness.iterator();
    while (timeliness.next()) |entry| {
        try writer.append(entry.key_ptr);
        try writer.append(&.{@intFromBool(entry.value_ptr.*)});
    }
    try writer.count(store.latest_messages.count());
    var messages = store.latest_messages.iterator();
    while (messages.next()) |entry| {
        try writer.number(entry.key_ptr.*);
        try writer.number(entry.value_ptr.epoch);
        try writer.append(&entry.value_ptr.root);
    }
    try writer.count(store.equivocating_indices.count());
    var equivocators = store.equivocating_indices.keyIterator();
    while (equivocators.next()) |index| try writer.number(index.*);
    try writer.count(store.unrealized_justifications.count());
    var justifications = store.unrealized_justifications.iterator();
    while (justifications.next()) |entry| {
        try writer.append(entry.key_ptr);
        try writer.checkpoint(entry.value_ptr.*);
    }
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, writer.written, .little);
    @memcpy(header[magic.len..][0..8], &length);
    writer.hasher.final(header[magic.len + 8 ..][0..32]);
    try atomic.file.writePositionalAll(io, &header, 0);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Load a bounded, checksummed snapshot into an independently owned store.
pub fn loadForkChoiceStore(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !fork_choice.Store {
    const bytes = dir.readFileAlloc(io, path, allocator, .limited(max_bytes + 1)) catch |err| switch (err) {
        error.StreamTooLong => return error.SnapshotTooLarge,
        else => return err,
    };
    defer allocator.free(bytes);
    if (bytes.len < header_len) return error.TruncatedSnapshot;
    const has_signatures = std.mem.eql(u8, bytes[0..magic.len], magic);
    if (!has_signatures and !std.mem.eql(u8, bytes[0..magic.len], legacy_magic)) return error.UnsupportedSnapshotVersion;
    const length = std.mem.readInt(u64, bytes[magic.len..][0..8], .little);
    if (length > max_bytes - header_len) return error.SnapshotTooLarge;
    if (length != bytes.len - header_len) return error.TruncatedSnapshot;
    const payload = bytes[header_len..];
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    if (!std.mem.eql(u8, &digest, bytes[magic.len + 8 .. header_len])) return error.CorruptSnapshot;

    var cursor = Cursor{ .bytes = payload };
    var store = fork_choice.Store{
        .allocator = allocator,
        .time = try cursor.number(),
        .genesis_time = try cursor.number(),
        .justified_checkpoint = try cursor.checkpoint(),
        .finalized_checkpoint = try cursor.checkpoint(),
        .unrealized_justified_checkpoint = try cursor.checkpoint(),
        .unrealized_finalized_checkpoint = try cursor.checkpoint(),
        .proposer_boost_root = try cursor.root(),
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
    const expected_head = try cursor.root();
    for (0..try cursor.count()) |_| {
        const root = try cursor.root();
        if (store.blocks.contains(root)) return error.InconsistentSnapshot;
        const block = try cursor.value(allocator, fulu.BeaconBlock);
        store.blocks.put(root, block) catch |err| {
            ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
            return err;
        };
    }
    if (has_signatures) {
        for (0..try cursor.count()) |_| {
            const root = try cursor.root();
            if (store.signed_block_signatures.contains(root) or !store.blocks.contains(root)) return error.InconsistentSnapshot;
            try store.signed_block_signatures.put(root, try cursor.signature());
        }
    }
    for (0..try cursor.count()) |_| {
        const root = try cursor.root();
        if (store.block_states.contains(root)) return error.InconsistentSnapshot;
        const state = try cursor.value(allocator, fulu.BeaconState);
        store.block_states.put(root, state) catch |err| {
            ssz.freeDecoded(allocator, fulu.BeaconState, state);
            return err;
        };
    }
    for (0..try cursor.count()) |_| {
        const cp = try cursor.checkpoint();
        if (store.checkpoint_states.contains(cp)) return error.InconsistentSnapshot;
        const state = try cursor.value(allocator, fulu.BeaconState);
        store.checkpoint_states.put(cp, state) catch |err| {
            ssz.freeDecoded(allocator, fulu.BeaconState, state);
            return err;
        };
    }
    for (0..try cursor.count()) |_| {
        const root = try cursor.root();
        const bit = (try cursor.take(1))[0];
        if (bit > 1 or store.block_timeliness.contains(root)) return error.InconsistentSnapshot;
        try store.block_timeliness.put(root, bit == 1);
    }
    for (0..try cursor.count()) |_| {
        const index = try cursor.number();
        const message = fork_choice.LatestMessage{ .epoch = try cursor.number(), .root = try cursor.root() };
        if (store.latest_messages.contains(index)) return error.InconsistentSnapshot;
        try store.latest_messages.put(index, message);
    }
    for (0..try cursor.count()) |_| {
        const index = try cursor.number();
        if (store.equivocating_indices.contains(index)) return error.InconsistentSnapshot;
        try store.equivocating_indices.put(index, {});
    }
    for (0..try cursor.count()) |_| {
        const root = try cursor.root();
        const cp = try cursor.checkpoint();
        if (store.unrealized_justifications.contains(root)) return error.InconsistentSnapshot;
        try store.unrealized_justifications.put(root, cp);
    }
    if (cursor.offset != payload.len) return error.InconsistentSnapshot;
    try validate(allocator, &store, expected_head);
    return store;
}

/// Verify roots and every relationship needed to safely derive the chain head.
fn validate(allocator: std.mem.Allocator, store: *const fork_choice.Store, expected_head: fulu.Root) !void {
    if (store.time < store.genesis_time or store.blocks.count() == 0 or store.blocks.count() != store.block_states.count()) return error.InconsistentSnapshot;
    const checkpoints = [_]fulu.Checkpoint{ store.justified_checkpoint, store.finalized_checkpoint, store.unrealized_justified_checkpoint, store.unrealized_finalized_checkpoint };
    for (checkpoints) |cp| if (!store.blocks.contains(cp.root)) return error.InconsistentSnapshot;
    if (!std.mem.eql(u8, &store.proposer_boost_root, &zero_root) and !store.blocks.contains(store.proposer_boost_root)) return error.InconsistentSnapshot;
    var roots = store.blocks.iterator();
    var anchors: usize = 0;
    while (roots.next()) |entry| {
        const root = entry.key_ptr.*;
        if (!std.mem.eql(u8, &root, &(try merkle.HashTreeRoot(allocator, entry.value_ptr.*)))) return error.InconsistentSnapshot;
        const state = store.block_states.get(root) orelse return error.InconsistentSnapshot;
        if (!std.mem.eql(u8, &entry.value_ptr.state_root, &(try merkle.HashTreeRoot(allocator, state)))) return error.InconsistentSnapshot;
        if (store.blocks.contains(entry.value_ptr.parent_root)) {
            var current = root;
            for (0..store.blocks.count()) |_| {
                const block = store.blocks.get(current) orelse return error.InconsistentSnapshot;
                if (!store.blocks.contains(block.parent_root)) break;
                const parent = store.blocks.get(block.parent_root).?;
                if (parent.slot >= block.slot) return error.InconsistentSnapshot;
                current = block.parent_root;
            } else return error.InconsistentSnapshot;
        } else anchors += 1;
        if (!store.unrealized_justifications.contains(root)) return error.InconsistentSnapshot;
    }
    var signed_roots = store.signed_block_signatures.keyIterator();
    while (signed_roots.next()) |root| if (!store.blocks.contains(root.*)) return error.InconsistentSnapshot;
    if (anchors != 1) return error.InconsistentSnapshot;
    var states = store.checkpoint_states.iterator();
    while (states.next()) |entry| if (!store.blocks.contains(entry.key_ptr.root)) return error.InconsistentSnapshot;
    var times = store.block_timeliness.keyIterator();
    while (times.next()) |root| if (!store.blocks.contains(root.*)) return error.InconsistentSnapshot;
    var votes = store.latest_messages.valueIterator();
    while (votes.next()) |vote| if (!store.blocks.contains(vote.root)) return error.InconsistentSnapshot;
    var justifications = store.unrealized_justifications.iterator();
    while (justifications.next()) |entry| if (!store.blocks.contains(entry.key_ptr.*) or (!store.blocks.contains(entry.value_ptr.root) and !std.mem.eql(u8, &entry.value_ptr.root, &zero_root))) return error.InconsistentSnapshot;
    const head = fork_choice.getHead(store) catch return error.InconsistentSnapshot;
    if (!std.mem.eql(u8, &head, &expected_head)) return error.InconsistentSnapshot;
}

const SnapshotWriter = struct {
    file: std.Io.File,
    io: std.Io,
    hasher: std.crypto.hash.sha2.Sha256,
    written: usize = 0,

    /// Append bytes while advancing the running checksum and size cap.
    fn append(self: *SnapshotWriter, bytes: []const u8) !void {
        if (self.written > max_bytes - header_len or bytes.len > max_bytes - header_len - self.written) return error.SnapshotTooLarge;
        try self.file.writeStreamingAll(self.io, bytes);
        self.hasher.update(bytes);
        self.written += bytes.len;
    }

    /// Append a little-endian integer to the snapshot body.
    fn number(self: *SnapshotWriter, n: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        try self.append(&bytes);
    }

    /// Append a bounded map count.
    fn count(self: *SnapshotWriter, n: usize) !void {
        if (n > max_records) return error.SnapshotTooLarge;
        try self.number(n);
    }

    /// Append an epoch and block root.
    fn checkpoint(self: *SnapshotWriter, cp: fulu.Checkpoint) !void {
        try self.number(cp.epoch);
        try self.append(&cp.root);
    }

    /// Append one SSZ value with an explicit byte length.
    fn value(self: *SnapshotWriter, allocator: std.mem.Allocator, item: anytype) !void {
        const bytes = try ssz.serializeAlloc(allocator, item);
        defer allocator.free(bytes);
        try self.number(bytes.len);
        try self.append(bytes);
    }
};

const Cursor = struct {
    bytes: []const u8,
    offset: usize = 0,

    /// Consume exactly n bytes or report a truncated record.
    fn take(self: *Cursor, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.offset) return error.TruncatedSnapshot;
        defer self.offset += n;
        return self.bytes[self.offset..][0..n];
    }

    /// Decode a little-endian integer.
    fn number(self: *Cursor) !u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    /// Decode a bounded map count.
    fn count(self: *Cursor) !usize {
        const n = try self.number();
        if (n > max_records) return error.SnapshotTooLarge;
        return @intCast(n);
    }

    /// Decode a fixed-size root.
    fn root(self: *Cursor) !fulu.Root {
        return (try self.take(32))[0..32].*;
    }

    /// Read a fixed-width proposer signature from the bounded snapshot.
    fn signature(self: *Cursor) !fulu.BLSSignature {
        return (try self.take(@sizeOf(fulu.BLSSignature)))[0..@sizeOf(fulu.BLSSignature)].*;
    }

    /// Decode a checkpoint record.
    fn checkpoint(self: *Cursor) !fulu.Checkpoint {
        return .{ .epoch = try self.number(), .root = try self.root() };
    }

    /// Decode a bounded SSZ value; the caller owns the result.
    fn value(self: *Cursor, allocator: std.mem.Allocator, comptime T: type) !T {
        const n = try self.number();
        if (n > max_bytes) return error.SnapshotTooLarge;
        const bytes = try self.take(@intCast(n));
        var reader: std.Io.Reader = .fixed(bytes);
        return ssz.deserialize(allocator, T, &reader) catch return error.InconsistentSnapshot;
    }
};

test "snapshot round trip and recovery errors" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = @import("fixture_runner.zig");
    const anchor_state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, anchor_state);
    const block_bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const anchor_block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor_block);
    var store = try fork_choice.initStore(allocator, &anchor_state, &anchor_block);
    defer store.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(error.FileNotFound, loadForkChoiceStore(allocator, io, tmp.dir, "store.bin"));
    try saveForkChoiceStore(allocator, io, tmp.dir, "store.bin", &store);
    var restored = try loadForkChoiceStore(allocator, io, tmp.dir, "store.bin");
    defer restored.deinit();
    try std.testing.expectEqual(try fork_choice.getHead(&store), try fork_choice.getHead(&restored));
    try std.testing.expectEqual(store.justified_checkpoint, restored.justified_checkpoint);
    try std.testing.expectEqual(store.finalized_checkpoint, restored.finalized_checkpoint);
    try std.testing.expectEqual(store.latest_messages.count(), restored.latest_messages.count());
    const original = try tmp.dir.readFileAlloc(io, "store.bin", allocator, .limited(max_bytes));
    defer allocator.free(original);
    try tmp.dir.writeFile(io, .{ .sub_path = "interrupted.tmp", .data = original[0..8] });
    var recovered = try loadForkChoiceStore(allocator, io, tmp.dir, "store.bin");
    recovered.deinit();
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.bin", .data = original[0..7] });
    try std.testing.expectError(error.TruncatedSnapshot, loadForkChoiceStore(allocator, io, tmp.dir, "bad.bin"));
    const corrupt = try allocator.dupe(u8, original);
    defer allocator.free(corrupt);
    corrupt[header_len] ^= 1;
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.bin", .data = corrupt });
    try std.testing.expectError(error.CorruptSnapshot, loadForkChoiceStore(allocator, io, tmp.dir, "bad.bin"));
    std.mem.writeInt(u64, corrupt[magic.len..][0..8], max_bytes, .little);
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.bin", .data = corrupt });
    try std.testing.expectError(error.SnapshotTooLarge, loadForkChoiceStore(allocator, io, tmp.dir, "bad.bin"));
    @memcpy(corrupt, original);
    corrupt[header_len + 16 + 4 * 40 + 32 + 32 + 8] ^= 1;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(corrupt[header_len..], &digest, .{});
    @memcpy(corrupt[magic.len + 8 .. header_len], &digest);
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.bin", .data = corrupt });
    try std.testing.expectError(error.InconsistentSnapshot, loadForkChoiceStore(allocator, io, tmp.dir, "bad.bin"));
}

/// Accept fixture blocks whose availability has already been established.
fn fixtureAvailable(_: *anyopaque, _: fulu.Root, _: *const fulu.BeaconBlock) anyerror!bool {
    return true;
}

test "forked chain restores head votes and post-state roots" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = @import("fixture_runner.zig");
    const engine_api = @import("execution_engine.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const anchor_bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(anchor_bytes);
    var reader: std.Io.Reader = .fixed(anchor_bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    var store = try fork_choice.initStore(allocator, &state, &anchor);
    defer store.deinit();
    var engine: engine_api.TestEngine = .{ .status = .valid };
    var context: u8 = 0;
    const availability = fork_choice.DataAvailabilityCheck{ .context = &context, .is_available = fixtureAvailable };
    const dir = "fixtures/fulu_fork_choice/heavier_branch/";
    const blocks = [_][]const u8{
        @embedFile(dir ++ "block_0xbc8706b8945c619414fb557decb7cb893c5e240ea95ec8a0e9d97c6f56532cff.ssz_snappy"),
        @embedFile(dir ++ "block_0xc44a335c2ae08ad57a68b81affd6b22d79427b4c755214eebcc74351d2b29347.ssz_snappy"),
        @embedFile(dir ++ "block_0x1db47324a6822813b02b053d39930e385d1fbfe474e4ad3d0b4ee89748c857b8.ssz_snappy"),
        @embedFile(dir ++ "block_0x0ae189fc2d624f5c04b4f1075245ba3a0b9aaa0bfeacacc9df6e7d58a9f035c7.ssz_snappy"),
    };
    for (blocks, [_]u64{ 6, 12, 18, 18 }) |bytes, time| {
        try fork_choice.onTick(&store, time);
        const signed = try fixtures.decodeBlock(allocator, bytes);
        defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
        try fork_choice.onBlock(&store, signed, engine.interface(), availability);
    }
    const vote_bytes = try fixtures.decode(allocator, @embedFile(dir ++ "attestation_0xfd7837e56b89c2042febfa3e790e8e4f12177170bcb7a6abcfc08b37474f20ba.ssz_snappy"));
    defer allocator.free(vote_bytes);
    var vote_reader: std.Io.Reader = .fixed(vote_bytes);
    const vote = try ssz.deserialize(allocator, fulu.Attestation, &vote_reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, vote);
    try fork_choice.onAttestation(&store, vote, false);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try saveForkChoiceStore(allocator, io, tmp.dir, "fork.bin", &store);
    var restored = try loadForkChoiceStore(allocator, io, tmp.dir, "fork.bin");
    defer restored.deinit();
    try std.testing.expectEqual(try fork_choice.getHead(&store), try fork_choice.getHead(&restored));
    try std.testing.expectEqual(store.justified_checkpoint, restored.justified_checkpoint);
    try std.testing.expectEqual(store.finalized_checkpoint, restored.finalized_checkpoint);
    try std.testing.expectEqual(store.proposer_boost_root, restored.proposer_boost_root);
    try std.testing.expectEqual(store.signed_block_signatures.count(), restored.signed_block_signatures.count());
    try std.testing.expectEqual(store.latest_messages.count(), restored.latest_messages.count());
    var votes = store.latest_messages.iterator();
    while (votes.next()) |entry| try std.testing.expectEqual(entry.value_ptr.*, restored.latest_messages.get(entry.key_ptr.*).?);
    var states = store.block_states.iterator();
    while (states.next()) |entry| try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, entry.value_ptr.*), try merkle.HashTreeRoot(allocator, restored.block_states.get(entry.key_ptr.*).?));
    var signatures = store.signed_block_signatures.iterator();
    while (signatures.next()) |entry| try std.testing.expectEqualSlices(u8, &entry.value_ptr.*, &restored.signed_block_signatures.get(entry.key_ptr.*).?);
}

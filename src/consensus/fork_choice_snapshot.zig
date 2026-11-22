// Fork choice stores blocks, post-states, votes, and checkpoints to select a
// head. Checkpoints name an epoch and block root; proposer boost expires at a
// slot boundary. Persistence retains the finalized anchor and descendants, so
// recovery must apply ordered, checksummed updates before exposing a store.
//
//   synced snapshot -> checksummed deltas -> validate and replay -> compact snapshot
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const ssz = @import("ssz");
const fork_choice = @import("fork_choice.zig");

const magic = "HTFC0003";
const log_magic = "HTFLOG01";
const frame_magic = "HTFREC01";
const max_bytes = 8 * 1024 * 1024 * 1024;
const header_len = magic.len + 8 + 32;
const log_header_len = log_magic.len + 32 + 32;
const frame_header_len = frame_magic.len + 8 + 8 + 32;
const max_log_bytes = max_bytes;
const compact_log_bytes = 256 * 1024 * 1024;
const zero_root: fulu.Root = [_]u8{0} ** 32;

/// Select the current head and durably persist the store.
pub fn saveForkChoiceStore(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, store: *fork_choice.Store) !void {
    const head = try fork_choice.getHead(store);
    return saveForkChoiceStoreAt(allocator, io, dir, path, store, head);
}

/// Atomically replace a snapshot after syncing its streamed contents.
fn writeSnapshotAt(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, store: *const fork_choice.Store, head: fulu.Root) !void {
    var atomic = try dir.createFileAtomic(io, path, .{ .replace = true });
    defer atomic.deinit(io);
    const buffer = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(buffer);
    var header: [header_len]u8 = [_]u8{0} ** header_len;
    @memcpy(header[0..magic.len], magic);
    try atomic.file.writeStreamingAll(io, &header);
    var writer = SnapshotWriter{
        .file = atomic.file,
        .io = io,
        .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
        .buffer = buffer,
    };
    try writer.number(store.time);
    try writer.number(store.genesis_time);
    try writer.checkpoint(store.justified_checkpoint);
    try writer.checkpoint(store.finalized_checkpoint);
    try writer.checkpoint(store.unrealized_justified_checkpoint);
    try writer.checkpoint(store.unrealized_finalized_checkpoint);
    try writer.append(&store.proposer_boost_root);
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
    try writer.flush();
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, writer.written, .little);
    @memcpy(header[magic.len..][0..8], &length);
    writer.hasher.final(header[magic.len + 8 ..][0..32]);
    try atomic.file.writePositionalAll(io, &header, 0);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Persist a store whose head was already selected by the caller.
pub fn saveForkChoiceStoreAt(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, store: *fork_choice.Store, head: fulu.Root) !void {
    const log_path = try std.fmt.allocPrint(allocator, "{s}.log", .{path});
    defer allocator.free(log_path);
    const snapshot_hash = snapshotChecksum(io, dir, path) catch |err| switch (err) {
        error.FileNotFound => {
            try writeSnapshotAt(allocator, io, dir, path, store, head);
            try resetLog(io, dir, path, log_path);
            store.persistence_changes.clear();
            return;
        },
        else => return err,
    };
    var log = inspectLog(io, dir, log_path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (log) |info| {
        if (!std.mem.eql(u8, &info.snapshot_hash, &snapshot_hash)) {
            try compact(allocator, io, dir, path, log_path, store, head);
            return;
        }
    } else {
        try resetLog(io, dir, path, log_path);
        log = try inspectLog(io, dir, log_path);
    }
    const log_info = log.?;
    if (!store.persistence_changes.complete or log_info.size > compact_log_bytes) {
        try compact(allocator, io, dir, path, log_path, store, head);
        return;
    }
    const payload = try encodeDelta(allocator, store, head);
    defer allocator.free(payload);
    if (payload.len > max_log_bytes - frame_header_len or log_info.size > max_log_bytes - frame_header_len - payload.len) return error.LogTooLarge;
    const sequence = log_info.frame_count;
    var frame_header: [frame_header_len]u8 = undefined;
    @memcpy(frame_header[0..frame_magic.len], frame_magic);
    std.mem.writeInt(u64, frame_header[frame_magic.len..][0..8], sequence + 1, .little);
    std.mem.writeInt(u64, frame_header[frame_magic.len + 8 ..][0..8], payload.len, .little);
    hashFrame(sequence + 1, payload, frame_header[frame_magic.len + 16 ..][0..32]);
    var file = try dir.openFile(io, log_path, .{ .mode = .read_write });
    defer file.close(io);
    var offset = log_info.size;
    try file.writePositionalAll(io, &frame_header, offset);
    offset += frame_header.len;
    try file.writePositionalAll(io, payload, offset);
    try file.sync(io);
    store.persistence_changes.clear();
    if (log_info.size + frame_header.len + payload.len >= compact_log_bytes) {
        try compact(allocator, io, dir, path, log_path, store, head);
    }
}

/// Compact the committed state, then atomically start a log tied to its checksum.
fn compact(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, log_path: []const u8, store: *fork_choice.Store, head: fulu.Root) !void {
    try writeSnapshotAt(allocator, io, dir, path, store, head);
    try resetLog(io, dir, path, log_path);
    store.persistence_changes.clear();
}

/// Load a snapshot and replay its bounded, checksummed update log.
fn readSnapshot(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !fork_choice.Store {
    const bytes = dir.readFileAlloc(io, path, allocator, .limited(max_bytes + 1)) catch |err| switch (err) {
        error.StreamTooLong => return error.SnapshotTooLarge,
        else => return err,
    };
    defer allocator.free(bytes);
    if (bytes.len < header_len) return error.TruncatedSnapshot;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.UnsupportedSnapshotVersion;
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
    for (0..try cursor.count()) |_| {
        const root = try cursor.root();
        if (store.signed_block_signatures.contains(root) or !store.blocks.contains(root)) return error.InconsistentSnapshot;
        try store.signed_block_signatures.put(root, try cursor.signature());
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

/// Load an independently owned fork-choice snapshot.
pub fn loadForkChoiceStore(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !fork_choice.Store {
    var store = try readSnapshot(allocator, io, dir, path);
    errdefer store.deinit();
    const log_path = try std.fmt.allocPrint(allocator, "{s}.log", .{path});
    defer allocator.free(log_path);
    const bytes = dir.readFileAlloc(io, log_path, allocator, .limited(max_log_bytes + 1)) catch |err| switch (err) {
        error.FileNotFound => return store,
        error.StreamTooLong => return error.LogTooLarge,
        else => return err,
    };
    defer allocator.free(bytes);
    if (bytes.len < log_header_len or !std.mem.eql(u8, bytes[0..log_magic.len], log_magic)) return error.CorruptLog;
    var log_header_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes[0 .. log_magic.len + 32], &log_header_digest, .{});
    if (!std.mem.eql(u8, &log_header_digest, bytes[log_magic.len + 32 .. log_header_len])) return error.CorruptLog;
    const base_hash = try snapshotChecksum(io, dir, path);
    if (!std.mem.eql(u8, bytes[log_magic.len..log_header_len], &base_hash)) return store;
    var offset: usize = log_header_len;
    var expected_head = try fork_choice.getHead(&store);
    var expected_sequence: u64 = 1;
    while (offset < bytes.len) {
        if (bytes.len - offset < frame_header_len) return error.TruncatedLog;
        const header = bytes[offset..][0..frame_header_len];
        if (!std.mem.eql(u8, header[0..frame_magic.len], frame_magic)) return error.CorruptLog;
        const sequence = std.mem.readInt(u64, header[frame_magic.len..][0..8], .little);
        if (sequence != expected_sequence) return error.InconsistentLog;
        const length = std.mem.readInt(u64, header[frame_magic.len + 8 ..][0..8], .little);
        if (length > max_bytes) return error.LogTooLarge;
        offset += frame_header_len;
        if (length > bytes.len - offset) return error.TruncatedLog;
        const payload = bytes[offset..][0..@intCast(length)];
        var digest: [32]u8 = undefined;
        hashFrame(sequence, payload, &digest);
        if (!std.mem.eql(u8, &digest, header[frame_magic.len + 16 ..][0..32])) return error.CorruptLog;
        expected_head = try applyDelta(allocator, &store, payload);
        try validate(allocator, &store, expected_head);
        offset += payload.len;
        expected_sequence += 1;
    }
    store.persistence_changes.clear();
    return store;
}

/// Read the checksum that identifies the snapshot generation without loading its payload.
fn snapshotChecksum(io: std.Io, dir: std.Io.Dir, path: []const u8) ![32]u8 {
    var file = try dir.openFile(io, path, .{});
    defer file.close(io);
    const file_size = (try file.stat(io)).size;
    var header: [header_len]u8 = undefined;
    if (try file.readPositionalAll(io, &header, 0) != header.len) return error.TruncatedSnapshot;
    if (!std.mem.eql(u8, header[0..magic.len], magic)) return error.UnsupportedSnapshotVersion;
    const payload_len = std.mem.readInt(u64, header[magic.len..][0..8], .little);
    if (payload_len > max_bytes - header_len) return error.SnapshotTooLarge;
    if (file_size != header_len + payload_len) return error.TruncatedSnapshot;
    return header[magic.len + 8 ..][0..32].*;
}

/// Atomically establish a fresh log generation tied to the current snapshot checksum.
fn resetLog(io: std.Io, dir: std.Io.Dir, snapshot_path: []const u8, log_path: []const u8) !void {
    const digest = try snapshotChecksum(io, dir, snapshot_path);
    var atomic = try dir.createFileAtomic(io, log_path, .{ .replace = true });
    defer atomic.deinit(io);
    var header: [log_header_len]u8 = undefined;
    @memcpy(header[0..log_magic.len], log_magic);
    @memcpy(header[log_magic.len..][0..32], &digest);
    std.crypto.hash.sha2.Sha256.hash(header[0 .. log_magic.len + 32], header[log_magic.len + 32 ..][0..32], .{});
    try atomic.file.writeStreamingAll(io, &header);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Return the current append log size.
fn logSize(io: std.Io, dir: std.Io.Dir, path: []const u8) !u64 {
    var file = try dir.openFile(io, path, .{});
    defer file.close(io);
    return (try file.stat(io)).size;
}

const LogInfo = struct { size: u64, frame_count: u64, snapshot_hash: [32]u8 };

/// Inspect frame headers without rereading their potentially large state payloads.
fn inspectLog(io: std.Io, dir: std.Io.Dir, path: []const u8) !LogInfo {
    var file = try dir.openFile(io, path, .{});
    defer file.close(io);
    const size = (try file.stat(io)).size;
    if (size > max_log_bytes) return error.LogTooLarge;
    if (size < log_header_len) return error.TruncatedLog;
    var header: [log_header_len]u8 = undefined;
    if (try file.readPositionalAll(io, &header, 0) != header.len) return error.TruncatedLog;
    if (!std.mem.eql(u8, header[0..log_magic.len], log_magic)) return error.CorruptLog;
    var header_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(header[0 .. log_magic.len + 32], &header_digest, .{});
    if (!std.mem.eql(u8, &header_digest, header[log_magic.len + 32 ..])) return error.CorruptLog;
    const snapshot_hash = header[log_magic.len..][0..32].*;
    var offset: u64 = log_header_len;
    var count: u64 = 0;
    while (offset < size) {
        if (size - offset < frame_header_len) return error.TruncatedLog;
        var frame: [frame_header_len]u8 = undefined;
        if (try file.readPositionalAll(io, &frame, offset) != frame.len) return error.TruncatedLog;
        if (!std.mem.eql(u8, frame[0..frame_magic.len], frame_magic)) return error.CorruptLog;
        const sequence = std.mem.readInt(u64, frame[frame_magic.len..][0..8], .little);
        if (sequence != count + 1) return error.InconsistentLog;
        const length = std.mem.readInt(u64, frame[frame_magic.len + 8 ..][0..8], .little);
        if (length > max_bytes) return error.LogTooLarge;
        if (length > size - offset - frame_header_len) return error.TruncatedLog;
        offset += frame_header_len + length;
        if (count == std.math.maxInt(u64)) return error.LogTooLarge;
        count += 1;
    }
    return .{ .size = size, .frame_count = count, .snapshot_hash = snapshot_hash };
}

/// Hash a frame's sequence and payload so records cannot be reordered silently.
fn hashFrame(sequence: u64, payload: []const u8, digest: *[32]u8) void {
    var sequence_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_bytes, sequence, .little);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&sequence_bytes);
    hasher.update(payload);
    hasher.final(digest);
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

/// Encode only keys touched by fork choice since the preceding durable commit.
fn encodeDelta(allocator: std.mem.Allocator, store: *const fork_choice.Store, head: fulu.Root) ![]u8 {
    if (!store.persistence_changes.complete) return error.IncompleteChangeSet;
    var writer = DeltaWriter{ .allocator = allocator };
    errdefer writer.items.deinit(allocator);
    try writer.number(store.time);
    try writer.number(store.genesis_time);
    try writer.checkpoint(store.justified_checkpoint);
    try writer.checkpoint(store.finalized_checkpoint);
    try writer.checkpoint(store.unrealized_justified_checkpoint);
    try writer.checkpoint(store.unrealized_finalized_checkpoint);
    try writer.append(&store.proposer_boost_root);
    try writer.append(&head);

    try writer.section(store.persistence_changes.blocks.count());
    var blocks = store.persistence_changes.blocks.keyIterator();
    while (blocks.next()) |key| {
        const value = store.blocks.get(key.*);
        try writer.op(value != null);
        try writer.append(&key.*);
        if (value) |item| try writer.value(allocator, item);
    }
    try writer.section(store.persistence_changes.signatures.count());
    var signatures = store.persistence_changes.signatures.keyIterator();
    while (signatures.next()) |key| {
        const value = store.signed_block_signatures.get(key.*);
        try writer.op(value != null);
        try writer.append(&key.*);
        if (value) |item| try writer.append(&item);
    }
    try writer.section(store.persistence_changes.states.count());
    var states = store.persistence_changes.states.keyIterator();
    while (states.next()) |key| {
        const value = store.block_states.get(key.*);
        try writer.op(value != null);
        try writer.append(&key.*);
        if (value) |item| try writer.value(allocator, item);
    }
    try writer.section(store.persistence_changes.checkpoint_states.count());
    var checkpoint_states = store.persistence_changes.checkpoint_states.keyIterator();
    while (checkpoint_states.next()) |key| {
        const value = store.checkpoint_states.get(key.*);
        try writer.op(value != null);
        try writer.checkpoint(key.*);
        if (value) |item| try writer.value(allocator, item);
    }
    try writer.section(store.persistence_changes.timeliness.count());
    var timeliness = store.persistence_changes.timeliness.keyIterator();
    while (timeliness.next()) |key| {
        const value = store.block_timeliness.get(key.*);
        try writer.op(value != null);
        try writer.append(&key.*);
        if (value) |item| try writer.op(item);
    }
    try writer.section(store.persistence_changes.messages.count());
    var messages = store.persistence_changes.messages.keyIterator();
    while (messages.next()) |key| {
        const value = store.latest_messages.get(key.*);
        try writer.op(value != null);
        try writer.number(key.*);
        if (value) |item| {
            try writer.number(item.epoch);
            try writer.append(&item.root);
        }
    }
    try writer.section(store.persistence_changes.equivocators.count());
    var equivocators = store.persistence_changes.equivocators.keyIterator();
    while (equivocators.next()) |key| {
        try writer.op(store.equivocating_indices.contains(key.*));
        try writer.number(key.*);
    }
    try writer.section(store.persistence_changes.justifications.count());
    var justifications = store.persistence_changes.justifications.keyIterator();
    while (justifications.next()) |key| {
        const value = store.unrealized_justifications.get(key.*);
        try writer.op(value != null);
        try writer.append(&key.*);
        if (value) |item| try writer.checkpoint(item);
    }
    return writer.items.toOwnedSlice(allocator);
}

/// Apply one complete delta. The caller validates the resulting store before exposing it.
fn applyDelta(allocator: std.mem.Allocator, store: *fork_choice.Store, payload: []const u8) !fulu.Root {
    var cursor = Cursor{ .bytes = payload };
    store.time = try cursor.number();
    store.genesis_time = try cursor.number();
    store.justified_checkpoint = try cursor.checkpoint();
    store.finalized_checkpoint = try cursor.checkpoint();
    store.unrealized_justified_checkpoint = try cursor.checkpoint();
    store.unrealized_finalized_checkpoint = try cursor.checkpoint();
    store.proposer_boost_root = try cursor.root();
    const head = try cursor.root();

    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const root = try cursor.root();
        if (put) {
            const block = try cursor.value(allocator, fulu.BeaconBlock);
            const old = store.blocks.fetchPut(root, block) catch |err| {
                ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
                return err;
            };
            if (old) |entry| ssz.freeDecoded(allocator, fulu.BeaconBlock, entry.value);
        } else if (store.blocks.fetchRemove(root)) |old| ssz.freeDecoded(allocator, fulu.BeaconBlock, old.value);
    }
    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const root = try cursor.root();
        if (put) try store.signed_block_signatures.put(root, try cursor.signature()) else _ = store.signed_block_signatures.remove(root);
    }
    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const root = try cursor.root();
        if (put) {
            const state = try cursor.value(allocator, fulu.BeaconState);
            const old = store.block_states.fetchPut(root, state) catch |err| {
                ssz.freeDecoded(allocator, fulu.BeaconState, state);
                return err;
            };
            if (old) |entry| ssz.freeDecoded(allocator, fulu.BeaconState, entry.value);
        } else if (store.block_states.fetchRemove(root)) |old| ssz.freeDecoded(allocator, fulu.BeaconState, old.value);
    }
    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const checkpoint = try cursor.checkpoint();
        if (put) {
            const state = try cursor.value(allocator, fulu.BeaconState);
            const old = store.checkpoint_states.fetchPut(checkpoint, state) catch |err| {
                ssz.freeDecoded(allocator, fulu.BeaconState, state);
                return err;
            };
            if (old) |entry| ssz.freeDecoded(allocator, fulu.BeaconState, entry.value);
        } else if (store.checkpoint_states.fetchRemove(checkpoint)) |old| ssz.freeDecoded(allocator, fulu.BeaconState, old.value);
    }
    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const root = try cursor.root();
        if (put) try store.block_timeliness.put(root, try cursor.bit()) else _ = store.block_timeliness.remove(root);
    }
    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const index = try cursor.number();
        if (put) try store.latest_messages.put(index, .{ .epoch = try cursor.number(), .root = try cursor.root() }) else _ = store.latest_messages.remove(index);
    }
    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const index = try cursor.number();
        if (put) try store.equivocating_indices.put(index, {}) else _ = store.equivocating_indices.remove(index);
    }
    for (0..try cursor.count()) |_| {
        const put = try cursor.bit();
        const root = try cursor.root();
        if (put) try store.unrealized_justifications.put(root, try cursor.checkpoint()) else _ = store.unrealized_justifications.remove(root);
    }
    if (cursor.offset != payload.len) return error.InconsistentLog;
    store.persistence_changes.clear();
    store.markDirty();
    return head;
}

const SnapshotWriter = struct {
    file: std.Io.File,
    io: std.Io,
    hasher: std.crypto.hash.sha2.Sha256,
    buffer: []u8,
    buffered: usize = 0,
    written: usize = 0,

    /// Append bytes while advancing the running checksum and size cap.
    fn append(self: *SnapshotWriter, bytes: []const u8) !void {
        if (self.written > max_bytes - header_len or bytes.len > max_bytes - header_len - self.written) return error.SnapshotTooLarge;
        self.hasher.update(bytes);
        self.written += bytes.len;
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (self.buffered == self.buffer.len) try self.flush();
            const n = @min(bytes.len - offset, self.buffer.len - self.buffered);
            @memcpy(self.buffer[self.buffered..][0..n], bytes[offset..][0..n]);
            self.buffered += n;
            offset += n;
        }
    }

    /// Write buffered payload bytes before the header and directory sync.
    fn flush(self: *SnapshotWriter) !void {
        if (self.buffered == 0) return;
        try self.file.writeStreamingAll(self.io, self.buffer[0..self.buffered]);
        self.buffered = 0;
    }

    /// Append a little-endian integer to the snapshot body.
    fn number(self: *SnapshotWriter, n: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        try self.append(&bytes);
    }

    /// Append a bounded map count.
    fn count(self: *SnapshotWriter, n: usize) !void {
        if (n > max_bytes / 8) return error.SnapshotTooLarge;
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

const DeltaWriter = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(u8) = .empty,

    /// Append bytes while enforcing the record size limit.
    fn append(self: *DeltaWriter, bytes: []const u8) !void {
        if (bytes.len > max_bytes or self.items.items.len > max_bytes - bytes.len) return error.LogTooLarge;
        try self.items.appendSlice(self.allocator, bytes);
    }

    /// Append a little-endian integer.
    fn number(self: *DeltaWriter, number_value: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, number_value, .little);
        try self.append(&bytes);
    }

    /// Append an epoch and root pair.
    fn checkpoint(self: *DeltaWriter, checkpoint_value: fulu.Checkpoint) !void {
        try self.number(checkpoint_value.epoch);
        try self.append(&checkpoint_value.root);
    }

    /// Append a canonical put or delete marker.
    fn op(self: *DeltaWriter, put: bool) !void {
        try self.append(&.{@intFromBool(put)});
    }

    /// Start a counted key-change section.
    fn section(self: *DeltaWriter, count: usize) !void {
        try self.number(count);
    }

    /// Append a length-prefixed SSZ value.
    fn value(self: *DeltaWriter, allocator: std.mem.Allocator, item: anytype) !void {
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

    /// Decode a canonical boolean byte.
    fn bit(self: *Cursor) !bool {
        const bit_value = (try self.take(1))[0];
        if (bit_value > 1) return error.InconsistentLog;
        return bit_value == 1;
    }

    /// Decode a bounded map count.
    fn count(self: *Cursor) !usize {
        const n = try self.number();
        if (n > max_bytes / 8) return error.SnapshotTooLarge;
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
    const old_version = try allocator.dupe(u8, original);
    defer allocator.free(old_version);
    @memcpy(old_version[0..magic.len], "HTFC0002");
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.bin", .data = old_version });
    try std.testing.expectError(error.UnsupportedSnapshotVersion, loadForkChoiceStore(allocator, io, tmp.dir, "bad.bin"));
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
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try saveForkChoiceStore(allocator, io, tmp.dir, "fork.bin", &store);
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
    const times = [_]u64{ 6, 12, 18, 18 };
    for (blocks[0..3], times[0..3]) |bytes, time| {
        try fork_choice.onTick(&store, time);
        const signed = try fixtures.decodeBlock(allocator, bytes);
        defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
        try fork_choice.onBlock(&store, signed, engine.interface(), availability);
    }
    try saveForkChoiceStore(allocator, io, tmp.dir, "fork.bin", &store);
    try fork_choice.onTick(&store, times[3]);
    const last_block = try fixtures.decodeBlock(allocator, blocks[3]);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, last_block);
    try fork_choice.onBlock(&store, last_block, engine.interface(), availability);
    const vote_bytes = try fixtures.decode(allocator, @embedFile(dir ++ "attestation_0xfd7837e56b89c2042febfa3e790e8e4f12177170bcb7a6abcfc08b37474f20ba.ssz_snappy"));
    defer allocator.free(vote_bytes);
    var vote_reader: std.Io.Reader = .fixed(vote_bytes);
    const vote = try ssz.deserialize(allocator, fulu.Attestation, &vote_reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, vote);
    try fork_choice.onAttestation(&store, vote, false);
    try saveForkChoiceStore(allocator, io, tmp.dir, "fork.bin", &store);
    const snapshot_bytes = try tmp.dir.readFileAlloc(io, "fork.bin", allocator, .limited(max_bytes));
    defer allocator.free(snapshot_bytes);
    const log_bytes = try tmp.dir.readFileAlloc(io, "fork.bin.log", allocator, .limited(max_log_bytes));
    defer allocator.free(log_bytes);
    try std.testing.expect(log_bytes.len < snapshot_bytes.len);
    var journal_restored = try loadForkChoiceStore(allocator, io, tmp.dir, "fork.bin");
    defer journal_restored.deinit();
    try std.testing.expectEqual(try fork_choice.getHead(&store), try fork_choice.getHead(&journal_restored));
    try std.testing.expectEqual(store.justified_checkpoint, journal_restored.justified_checkpoint);
    try std.testing.expectEqual(store.finalized_checkpoint, journal_restored.finalized_checkpoint);
    try std.testing.expectEqual(store.latest_messages.count(), journal_restored.latest_messages.count());
    try std.testing.expectEqual(store.signed_block_signatures.count(), journal_restored.signed_block_signatures.count());
    try std.testing.expectEqual(store.checkpoint_states.count(), journal_restored.checkpoint_states.count());
    var journal_votes = store.latest_messages.iterator();
    while (journal_votes.next()) |entry| try std.testing.expectEqual(entry.value_ptr.*, journal_restored.latest_messages.get(entry.key_ptr.*).?);
    var journal_signatures = store.signed_block_signatures.iterator();
    while (journal_signatures.next()) |entry| try std.testing.expectEqualSlices(u8, &entry.value_ptr.*, &journal_restored.signed_block_signatures.get(entry.key_ptr.*).?);
    var journal_states = store.block_states.iterator();
    while (journal_states.next()) |entry| try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, entry.value_ptr.*), try merkle.HashTreeRoot(allocator, journal_restored.block_states.get(entry.key_ptr.*).?));
    var journal_checkpoint_states = store.checkpoint_states.iterator();
    while (journal_checkpoint_states.next()) |entry| try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, entry.value_ptr.*), try merkle.HashTreeRoot(allocator, journal_restored.checkpoint_states.get(entry.key_ptr.*).?));
    try tmp.dir.writeFile(io, .{ .sub_path = "corrupt.bin", .data = snapshot_bytes });
    const corrupt_log = try allocator.dupe(u8, log_bytes);
    defer allocator.free(corrupt_log);
    corrupt_log[log_header_len + frame_header_len] ^= 1;
    try tmp.dir.writeFile(io, .{ .sub_path = "corrupt.bin.log", .data = corrupt_log });
    try std.testing.expectError(error.CorruptLog, loadForkChoiceStore(allocator, io, tmp.dir, "corrupt.bin"));
    try tmp.dir.writeFile(io, .{ .sub_path = "truncated.bin", .data = snapshot_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "truncated.bin.log", .data = log_bytes[0 .. log_bytes.len - 1] });
    try std.testing.expectError(error.TruncatedLog, loadForkChoiceStore(allocator, io, tmp.dir, "truncated.bin"));
    const oversized_log = try allocator.dupe(u8, log_bytes);
    defer allocator.free(oversized_log);
    std.mem.writeInt(u64, oversized_log[log_header_len + frame_magic.len + 8 ..][0..8], max_bytes + 1, .little);
    try tmp.dir.writeFile(io, .{ .sub_path = "oversized.bin", .data = snapshot_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "oversized.bin.log", .data = oversized_log });
    try std.testing.expectError(error.LogTooLarge, loadForkChoiceStore(allocator, io, tmp.dir, "oversized.bin"));
    const inconsistent_log = try allocator.dupe(u8, log_bytes);
    defer allocator.free(inconsistent_log);
    const payload_offset = log_header_len + frame_header_len;
    std.mem.writeInt(u64, inconsistent_log[payload_offset + 8 ..][0..8], std.math.maxInt(u64), .little);
    const first_sequence = std.mem.readInt(u64, inconsistent_log[log_header_len + frame_magic.len ..][0..8], .little);
    const first_payload_len = std.mem.readInt(u64, inconsistent_log[log_header_len + frame_magic.len + 8 ..][0..8], .little);
    hashFrame(first_sequence, inconsistent_log[payload_offset..][0..@intCast(first_payload_len)], inconsistent_log[log_header_len + frame_magic.len + 16 ..][0..32]);
    try tmp.dir.writeFile(io, .{ .sub_path = "inconsistent.bin", .data = snapshot_bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "inconsistent.bin.log", .data = inconsistent_log });
    try std.testing.expectError(error.InconsistentSnapshot, loadForkChoiceStore(allocator, io, tmp.dir, "inconsistent.bin"));
    try writeSnapshotAt(allocator, io, tmp.dir, "fork.bin", &store, try fork_choice.getHead(&store));
    var after_interrupted_compaction = try loadForkChoiceStore(allocator, io, tmp.dir, "fork.bin");
    defer after_interrupted_compaction.deinit();
    try std.testing.expectEqual(try fork_choice.getHead(&store), try fork_choice.getHead(&after_interrupted_compaction));
    try compact(allocator, io, tmp.dir, "fork.bin", "fork.bin.log", &store, try fork_choice.getHead(&store));
    try std.testing.expectEqual(@as(u64, log_header_len), try logSize(io, tmp.dir, "fork.bin.log"));
    var restored = try loadForkChoiceStore(allocator, io, tmp.dir, "fork.bin");
    defer restored.deinit();
    try std.testing.expectEqual(store.time, restored.time);
    try std.testing.expectEqual(store.block_timeliness.count(), restored.block_timeliness.count());
    try std.testing.expectEqual(try fork_choice.getHead(&store), try fork_choice.getHead(&restored));
    try std.testing.expectEqual(store.justified_checkpoint, restored.justified_checkpoint);
    try std.testing.expectEqual(store.finalized_checkpoint, restored.finalized_checkpoint);
    try std.testing.expectEqual(store.proposer_boost_root, restored.proposer_boost_root);
    try fork_choice.onTick(&restored, store.time + @import("consensus_preset").Config.SECONDS_PER_SLOT);
    try std.testing.expectEqual([_]u8{0} ** 32, restored.proposer_boost_root);
    try std.testing.expectEqual(store.signed_block_signatures.count(), restored.signed_block_signatures.count());
    try std.testing.expectEqual(store.latest_messages.count(), restored.latest_messages.count());
    var votes = store.latest_messages.iterator();
    while (votes.next()) |entry| try std.testing.expectEqual(entry.value_ptr.*, restored.latest_messages.get(entry.key_ptr.*).?);
    var states = store.block_states.iterator();
    while (states.next()) |entry| try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, entry.value_ptr.*), try merkle.HashTreeRoot(allocator, restored.block_states.get(entry.key_ptr.*).?));
    var signatures = store.signed_block_signatures.iterator();
    while (signatures.next()) |entry| try std.testing.expectEqualSlices(u8, &entry.value_ptr.*, &restored.signed_block_signatures.get(entry.key_ptr.*).?);
}

test "one vote update writes the same delta with ten thousand retained votes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    const root = try merkle.HashTreeRoot(allocator, block);
    var small = try fork_choice.initStore(allocator, &state, &block);
    defer small.deinit();
    var large = try fork_choice.initStore(allocator, &state, &block);
    defer large.deinit();
    for (2..10_002) |index| try large.latest_messages.put(@intCast(index), .{ .epoch = 0, .root = root });
    var small_dir = std.testing.tmpDir(.{});
    defer small_dir.cleanup();
    var large_dir = std.testing.tmpDir(.{});
    defer large_dir.cleanup();
    try saveForkChoiceStore(allocator, io, small_dir.dir, "fork.bin", &small);
    try saveForkChoiceStore(allocator, io, large_dir.dir, "fork.bin", &large);
    const small_snapshot = try small_dir.dir.readFileAlloc(io, "fork.bin", allocator, .limited(max_bytes));
    defer allocator.free(small_snapshot);
    const large_snapshot = try large_dir.dir.readFileAlloc(io, "fork.bin", allocator, .limited(max_bytes));
    defer allocator.free(large_snapshot);
    try std.testing.expect(large_snapshot.len > small_snapshot.len);
    for ([_]*fork_choice.Store{ &small, &large }) |store| {
        try store.latest_messages.put(1, .{ .epoch = 1, .root = root });
        store.trackChange(&store.persistence_changes.messages, 1);
        try saveForkChoiceStore(allocator, io, if (store == &small) small_dir.dir else large_dir.dir, "fork.bin", store);
    }
    const small_log = try small_dir.dir.readFileAlloc(io, "fork.bin.log", allocator, .limited(max_log_bytes));
    defer allocator.free(small_log);
    const large_log = try large_dir.dir.readFileAlloc(io, "fork.bin.log", allocator, .limited(max_log_bytes));
    defer allocator.free(large_log);
    try std.testing.expectEqual(small_log.len, large_log.len);
}

test "one block import writes the same delta as the retained store grows" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = @import("fixture_runner.zig");
    const engine_api = @import("execution_engine.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const anchor_bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(anchor_bytes);
    var anchor_reader: std.Io.Reader = .fixed(anchor_bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &anchor_reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    const anchor_root = try merkle.HashTreeRoot(allocator, anchor);
    var small = try fork_choice.initStore(allocator, &state, &anchor);
    defer small.deinit();
    var large = try fork_choice.initStore(allocator, &state, &anchor);
    defer large.deinit();
    for (2..10_002) |index| try large.latest_messages.put(@intCast(index), .{ .epoch = 0, .root = anchor_root });
    var small_dir = std.testing.tmpDir(.{});
    defer small_dir.cleanup();
    var large_dir = std.testing.tmpDir(.{});
    defer large_dir.cleanup();
    try saveForkChoiceStore(allocator, io, small_dir.dir, "fork.bin", &small);
    try saveForkChoiceStore(allocator, io, large_dir.dir, "fork.bin", &large);

    const block_bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/heavier_branch/block_0xbc8706b8945c619414fb557decb7cb893c5e240ea95ec8a0e9d97c6f56532cff.ssz_snappy"));
    defer allocator.free(block_bytes);
    var block_reader: std.Io.Reader = .fixed(block_bytes);
    const signed = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &block_reader);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    var engine: engine_api.TestEngine = .{ .status = .valid };
    var context: u8 = 0;
    const availability = fork_choice.DataAvailabilityCheck{ .context = &context, .is_available = fixtureAvailable };
    for ([_]*fork_choice.Store{ &small, &large }) |store| {
        try fork_choice.onTick(store, 6);
        try fork_choice.onBlock(store, signed, engine.interface(), availability);
    }
    try saveForkChoiceStore(allocator, io, small_dir.dir, "fork.bin", &small);
    try saveForkChoiceStore(allocator, io, large_dir.dir, "fork.bin", &large);
    const small_log = try small_dir.dir.readFileAlloc(io, "fork.bin.log", allocator, .limited(max_log_bytes));
    defer allocator.free(small_log);
    const large_log = try large_dir.dir.readFileAlloc(io, "fork.bin.log", allocator, .limited(max_log_bytes));
    defer allocator.free(large_log);
    try std.testing.expectEqual(small_log.len, large_log.len);
}

test "mainnet preset block and checkpoint states survive snapshot recovery" {
    if (@import("consensus_preset").name != .mainnet) return;
    var failure: ?anyerror = null;
    const worker = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 * 1024 }, struct {
        /// Run the mainnet state recovery check with room for fixed-size SSZ arrays.
        fn run(result: *?anyerror) void {
            checkMainnetSnapshotRecovery() catch |err| {
                result.* = err;
            };
        }
    }.run, .{&failure});
    worker.join();
    if (failure) |err| return err;
}

/// Round-trip an official mainnet Fulu state as both a block and checkpoint state.
fn checkMainnetSnapshotRecovery() !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const state = try @import("fixture_runner.zig").decodeState(allocator, @embedFile("fixtures/fulu_block_operations_mainnet/correct_attestation_included_at_one_epoch_delay/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var block = std.mem.zeroes(fulu.BeaconBlock);
    block.state_root = try merkle.HashTreeRoot(allocator, state);
    var store = try fork_choice.initStore(allocator, &state, &block);
    defer store.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try saveForkChoiceStore(allocator, io, dir.dir, "mainnet.bin", &store);
    var recovered = try loadForkChoiceStore(allocator, io, dir.dir, "mainnet.bin");
    defer recovered.deinit();
    try std.testing.expectEqual(try fork_choice.getHead(&store), try fork_choice.getHead(&recovered));
    try std.testing.expectEqual(store.justified_checkpoint, recovered.justified_checkpoint);
    try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, state), try merkle.HashTreeRoot(allocator, recovered.block_states.get(store.justified_checkpoint.root).?));
    try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, state), try merkle.HashTreeRoot(allocator, recovered.checkpoint_states.get(store.justified_checkpoint).?));
}

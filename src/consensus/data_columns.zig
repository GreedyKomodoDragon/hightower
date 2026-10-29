// Fulu splits each blob into 128 erasure-coded cells, one per column. A column
// sidecar binds all cells at one index to a signed block and its commitments.
// Validation precedes storage; eight distinct, matching columns make a
// blob-carrying block available to fork choice. Four selected groups are kept
// for custody, while all eight sampled columns are retained for availability.
//
// signed header -> commitment branch -> batched cell proofs -> store -> sample gate
// The pinned v1.6.1 limits are 128 columns, at most nine blobs in the minimal
// preset, and 4096 epochs of column request retention.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const ssz = @import("ssz");
const preset = @import("consensus_preset").Config;
const kzg = @import("execution").kzg;
const ckzg = @import("ckzg");
const bls = @import("bls.zig");
const domains = @import("domains.zig");
const helpers = @import("helpers.zig");

pub const column_count: usize = 128;
pub const custody_requirement: usize = 4;
pub const samples_per_slot: usize = 8;
pub const retention_epochs: u64 = 4096;
pub const max_request_blocks: usize = 128;
pub const max_request_columns: usize = max_request_blocks * column_count;

pub const ByRoot = struct {
    block_root: fulu.Root,
    columns: []const u64,
};

pub const ServedColumn = struct {
    block_root: fulu.Root,
    slot: u64,
    index: u8,
    /// Borrowed from Store; callers must finish encoding before pruning it.
    bytes: []const u8,
};

pub const CanonicalRoots = struct {
    context: *anyopaque,
    /// Return the block root selected by one fork-choice snapshot at this slot.
    root_at_slot: *const fn (*anyopaque, u64) ?fulu.Root,
};

pub const Groups = struct {
    values: [column_count]u8 = undefined,
    len: usize,

    /// Tell whether a column is in this group selection.
    pub fn contains(self: *const Groups, column: u64) bool {
        if (column >= column_count) return false;
        for (self.values[0..self.len]) |group| if (group == column) return true;
        return false;
    }
};

/// Select the pinned deterministic custody groups from a discv5 node ID.
pub fn selectGroups(node_id: [32]u8, count: usize) !Groups {
    if (count > column_count) return error.InvalidCustodyCount;
    var result = Groups{ .len = count };
    if (count == column_count) {
        for (0..column_count) |i| result.values[i] = @intCast(i);
        return result;
    }
    var current = std.mem.readInt(u256, &node_id, .little);
    var found: usize = 0;
    while (found < count) : (current +%= 1) {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, current, .little);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&bytes, &digest, .{});
        const group: u8 = @intCast(std.mem.readInt(u64, digest[0..8], .little) % column_count);
        var duplicate = false;
        for (result.values[0..found]) |existing| if (existing == group) {
            duplicate = true;
            break;
        };
        if (!duplicate) {
            result.values[found] = group;
            found += 1;
        }
    }
    std.mem.sort(u8, result.values[0..count], {}, std.sort.asc(u8));
    return result;
}

/// Verify a sidecar against the known block and parent state before storage.
pub fn verify(allocator: std.mem.Allocator, settings: *const kzg.Settings, sidecar: *const fulu.DataColumnSidecar, block: *const fulu.BeaconBlock, parent_state: *const fulu.BeaconState) !fulu.Root {
    const commitments = sidecar.kzg_commitments.data;
    const cells = sidecar.column.data;
    const proofs = sidecar.kzg_proofs.data;
    if (sidecar.index >= column_count or commitments.len == 0 or
        commitments.len > helpers.getBlobParameters(helpers.computeEpochAtSlot(block.slot), &helpers.BLOB_SCHEDULE).max_blobs_per_block or
        cells.len != commitments.len or proofs.len != commitments.len or
        !std.mem.eql(fulu.KZGCommitment, commitments, block.body.blob_kzg_commitments.data)) return error.InvalidDataColumn;

    const header = sidecar.signed_block_header.message;
    const body_root = try merkle.HashTreeRoot(allocator, block.body);
    if (header.slot != block.slot or header.proposer_index != block.proposer_index or
        !std.mem.eql(u8, &header.parent_root, &block.parent_root) or
        !std.mem.eql(u8, &header.state_root, &block.state_root) or
        !std.mem.eql(u8, &header.body_root, &body_root)) return error.WrongBlock;
    if (header.proposer_index >= parent_state.validators.data.len) return error.InvalidProposer;
    const block_root = try merkle.HashTreeRoot(allocator, block.*);
    const header_root = try merkle.HashTreeRoot(allocator, header);
    if (!std.mem.eql(u8, &block_root, &header_root)) return error.WrongBlock;
    const domain = domains.getDomain(parent_state.*, helpers.DOMAIN_BEACON_PROPOSER, helpers.computeEpochAtSlot(block.slot));
    try bls.verify(parent_state.validators.data[header.proposer_index].pubkey, domains.computeSigningRoot(header_root, domain), sidecar.signed_block_header.signature);
    const commitments_root = try merkle.HashTreeRoot(allocator, sidecar.kzg_commitments);
    if (!merkle.verifyMerkleProof(commitments_root, &sidecar.kzg_commitments_inclusion_proof, 27, body_root)) return error.InvalidCommitmentProof;

    const c_commitments = try allocator.alloc(ckzg.Bytes48, commitments.len);
    defer allocator.free(c_commitments);
    const c_cells = try allocator.alloc(ckzg.Cell, cells.len);
    defer allocator.free(c_cells);
    const c_proofs = try allocator.alloc(ckzg.Bytes48, proofs.len);
    defer allocator.free(c_proofs);
    const indices = try allocator.alloc(u64, cells.len);
    defer allocator.free(indices);
    for (commitments, cells, proofs, 0..) |commitment, cell, proof, i| {
        c_commitments[i] = .{ .bytes = commitment };
        c_cells[i] = .{ .bytes = cell };
        c_proofs[i] = .{ .bytes = proof };
        indices[i] = sidecar.index;
    }
    if (!(settings.verifyCellKzgProofBatch(c_commitments, indices, c_cells, c_proofs) catch false)) return error.InvalidCellProof;
    return block_root;
}

const Key = struct { root: fulu.Root, index: u8 };
const Entry = struct { slot: u64, bytes: []u8 };

pub const Store = struct {
    allocator: std.mem.Allocator,
    custody: Groups,
    samples: Groups,
    columns: std.AutoHashMap(Key, Entry),

    /// Initialize the custody and sampling selections for a node identity.
    pub fn init(allocator: std.mem.Allocator, node_id: [32]u8, custody_count: usize) !Store {
        if (custody_count < custody_requirement) return error.InvalidCustodyCount;
        return .{
            .allocator = allocator,
            .custody = try selectGroups(node_id, custody_count),
            .samples = try selectGroups(node_id, @max(samples_per_slot, custody_count)),
            .columns = .init(allocator),
        };
    }

    /// Release retained, serialized sidecars.
    pub fn deinit(self: *Store) void {
        var entries = self.columns.valueIterator();
        while (entries.next()) |entry| self.allocator.free(entry.bytes);
        self.columns.deinit();
    }

    /// Validate and retain one sampled column, rejecting duplicate roots and indices.
    pub fn put(self: *Store, settings: *const kzg.Settings, sidecar: *const fulu.DataColumnSidecar, block: *const fulu.BeaconBlock, parent_state: *const fulu.BeaconState) !void {
        if (!self.samples.contains(sidecar.index)) return error.UnselectedColumn;
        const root = try verify(self.allocator, settings, sidecar, block, parent_state);
        const key = Key{ .root = root, .index = @intCast(sidecar.index) };
        if (self.columns.contains(key)) return error.DuplicateColumn;
        const bytes = try ssz.serializeAlloc(self.allocator, sidecar.*);
        errdefer self.allocator.free(bytes);
        try self.columns.put(key, .{ .slot = block.slot, .bytes = bytes });
    }

    /// Report whether every selected sample for a blob-carrying block exists.
    pub fn available(self: *const Store, root: fulu.Root, block: *const fulu.BeaconBlock) bool {
        if (block.body.blob_kzg_commitments.data.len == 0) return true;
        for (self.samples.values[0..self.samples.len]) |index| {
            if (!self.columns.contains(.{ .root = root, .index = index })) return false;
        }
        return true;
    }

    /// Adapt the store to fork choice's block-aware availability callback.
    pub fn check(context: *anyopaque, root: fulu.Root, block: *const fulu.BeaconBlock) anyerror!bool {
        const self: *Store = @ptrCast(@alignCast(context));
        return self.available(root, block);
    }

    /// Return a borrowed encoded sidecar only for a custodied column.
    pub fn get(self: *const Store, root: fulu.Root, index: u64) ?[]const u8 {
        if (!self.custody.contains(index)) return null;
        const entry = self.columns.get(.{ .root = root, .index = @intCast(index) }) orelse return null;
        return entry.bytes;
    }

    /// Select verified custodied columns in request order, bounded by the Fulu limit.
    pub fn serveByRoot(self: *const Store, allocator: std.mem.Allocator, requests: []const ByRoot) ![]ServedColumn {
        if (requests.len > max_request_blocks) return error.InvalidRequest;
        var total: usize = 0;
        var result: std.ArrayList(ServedColumn) = .empty;
        errdefer result.deinit(allocator);
        for (requests) |request| {
            if (request.columns.len > column_count or request.columns.len > max_request_columns - total) return error.InvalidRequest;
            total += request.columns.len;
            var seen = [_]bool{false} ** column_count;
            for (request.columns) |index| {
                if (index >= column_count or seen[index]) return error.InvalidRequest;
                seen[index] = true;
                if (!self.custody.contains(index)) continue;
                const entry = self.columns.get(.{ .root = request.block_root, .index = @intCast(index) }) orelse continue;
                try result.append(allocator, .{ .block_root = request.block_root, .slot = entry.slot, .index = @intCast(index), .bytes = entry.bytes });
            }
        }
        return result.toOwnedSlice(allocator);
    }

    /// Serve a canonical slot range in (slot, column_index) order, skipping empty slots.
    pub fn serveByRange(self: *const Store, allocator: std.mem.Allocator, start_slot: u64, count: u64, columns: []const u64, canonical: CanonicalRoots) ![]ServedColumn {
        if (count > max_request_blocks or start_slot > std.math.maxInt(u64) - count or columns.len > column_count) return error.InvalidRequest;
        var requested = [_]bool{false} ** column_count;
        for (columns) |index| {
            if (index >= column_count or requested[index]) return error.InvalidRequest;
            requested[index] = true;
        }
        var result: std.ArrayList(ServedColumn) = .empty;
        errdefer result.deinit(allocator);
        for (start_slot..start_slot + count) |slot| {
            const root = canonical.root_at_slot(canonical.context, slot) orelse continue;
            for (requested, 0..) |want, index| {
                if (!want or !self.custody.contains(index)) continue;
                const entry = self.columns.get(.{ .root = root, .index = @intCast(index) }) orelse continue;
                if (entry.slot != slot) return error.InconsistentStore;
                try result.append(allocator, .{ .block_root = root, .slot = slot, .index = @intCast(index), .bytes = entry.bytes });
            }
        }
        return result.toOwnedSlice(allocator);
    }

    /// Drop columns older than the required request retention window.
    pub fn prune(self: *Store, current_slot: u64) !void {
        const window = retention_epochs * preset.SLOTS_PER_EPOCH;
        var expired: std.ArrayList(Key) = .empty;
        defer expired.deinit(self.allocator);
        var it = self.columns.iterator();
        while (it.next()) |item| {
            if (item.value_ptr.slot < current_slot -| window) try expired.append(self.allocator, item.key_ptr.*);
        }
        for (expired.items) |key| {
            const entry = self.columns.fetchRemove(key).?;
            self.allocator.free(entry.value.bytes);
        }
    }
};

test "custody selection is deterministic, distinct, and nested in sampling" {
    const id = [_]u8{0x42} ** 32;
    const custody = try selectGroups(id, custody_requirement);
    const samples = try selectGroups(id, samples_per_slot);
    try std.testing.expectEqual(@as(usize, 4), custody.len);
    for (custody.values[0..custody.len]) |group| try std.testing.expect(samples.contains(group));
    for (samples.values[1..samples.len], samples.values[0 .. samples.len - 1]) |right, left| try std.testing.expect(left < right);
    try std.testing.expectError(error.InvalidCustodyCount, selectGroups(id, 129));
    const official = try selectGroups([_]u8{0xff} ** 32, 4);
    try std.testing.expectEqualSlices(u8, &.{ 1, 47, 87, 102 }, official.values[0..official.len]);
}

test "column serving enforces custody, request bounds, canonical order and retention" {
    const allocator = std.testing.allocator;
    const root_a = [_]u8{1} ** 32;
    const root_b = [_]u8{2} ** 32;
    var store = try Store.init(allocator, [_]u8{0} ** 32, custody_requirement);
    defer store.deinit();
    const first = store.custody.values[0];
    const second = store.custody.values[1];
    try store.columns.put(.{ .root = root_a, .index = first }, .{ .slot = 10, .bytes = try allocator.dupe(u8, "a0") });
    try store.columns.put(.{ .root = root_a, .index = second }, .{ .slot = 10, .bytes = try allocator.dupe(u8, "a1") });
    try store.columns.put(.{ .root = root_b, .index = first }, .{ .slot = 12, .bytes = try allocator.dupe(u8, "b0") });
    var uncustodied: u64 = 0;
    while (store.custody.contains(uncustodied)) : (uncustodied += 1) {}
    const requested = [_]u64{ uncustodied, second, first };
    const by_root = try store.serveByRoot(allocator, &.{.{ .block_root = root_a, .columns = &requested }});
    defer allocator.free(by_root);
    try std.testing.expectEqual(@as(usize, 2), by_root.len);
    try std.testing.expectEqual(second, by_root[0].index);
    try std.testing.expectEqual(first, by_root[1].index);
    try std.testing.expectError(error.InvalidRequest, store.serveByRoot(allocator, &.{.{ .block_root = root_a, .columns = &.{ first, first } }}));
    try std.testing.expectError(error.InvalidRequest, store.serveByRoot(allocator, &.{.{ .block_root = root_a, .columns = &.{128} }}));

    const roots = struct {
        fn at(_: *anyopaque, slot: u64) ?fulu.Root {
            return switch (slot) {
                10 => root_a,
                12 => root_b,
                else => null,
            };
        }
    };
    const canonical = CanonicalRoots{ .context = &store, .root_at_slot = roots.at };
    const by_range = try store.serveByRange(allocator, 10, 3, &requested, canonical);
    defer allocator.free(by_range);
    try std.testing.expectEqual(@as(usize, 3), by_range.len);
    try std.testing.expectEqual(first, by_range[0].index);
    try std.testing.expectEqual(second, by_range[1].index);
    try std.testing.expectEqual(@as(u64, 12), by_range[2].slot);
    try std.testing.expectError(error.InvalidRequest, store.serveByRange(allocator, 10, 129, &requested, canonical));
    try std.testing.expectError(error.InvalidRequest, store.serveByRange(allocator, 10, 1, &.{ second, second }, canonical));
    try store.prune(10 + retention_epochs * preset.SLOTS_PER_EPOCH);
    try std.testing.expect(store.get(root_a, first) != null);
    try store.prune(10 + retention_epochs * preset.SLOTS_PER_EPOCH + 1);
    try std.testing.expect(store.get(root_a, first) == null);
    try std.testing.expect(store.get(root_b, first) != null);
}

test "availability needs eight matching selected columns" {
    const allocator = std.testing.allocator;
    const fixture = @import("fixture_runner.zig");
    var signed = try fixture.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    const root = try merkle.HashTreeRoot(allocator, signed.message);
    var store = try Store.init(allocator, [_]u8{0} ** 32, custody_requirement);
    defer store.deinit();
    try std.testing.expectEqual(@as(usize, samples_per_slot), store.samples.len);
    for (store.samples.values[0 .. samples_per_slot - 1]) |index| {
        try store.columns.put(.{ .root = root, .index = index }, .{ .slot = signed.message.slot, .bytes = try allocator.alloc(u8, 0) });
    }
    try std.testing.expect(!store.available(root, &signed.message));
    const last = store.samples.values[samples_per_slot - 1];
    try store.columns.put(.{ .root = [_]u8{0} ** 32, .index = last }, .{ .slot = signed.message.slot, .bytes = try allocator.alloc(u8, 0) });
    try std.testing.expect(!store.available(root, &signed.message));
    try store.columns.put(.{ .root = root, .index = last }, .{ .slot = signed.message.slot, .bytes = try allocator.alloc(u8, 0) });
    try std.testing.expect(store.available(root, &signed.message));
}

test "official PeerDAS columns complete the eight-sample availability gate" {
    const fixture = @import("fixture_runner.zig");
    const fork_choice = @import("fork_choice.zig");
    const engine_api = @import("execution_engine.zig");
    const allocator = std.testing.allocator;
    var state = try fixture.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var signed = try fixture.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    var settings = try kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var store = try Store.init(allocator, [_]u8{0} ** 32, custody_requirement);
    defer store.deinit();
    const root = try merkle.HashTreeRoot(allocator, signed.message);
    const anchor_bytes = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_block.ssz_snappy"));
    defer allocator.free(anchor_bytes);
    var anchor_reader: std.Io.Reader = .fixed(anchor_bytes);
    const anchor = try ssz.deserialize(allocator, fulu.BeaconBlock, &anchor_reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, anchor);
    var choice = try fork_choice.initStore(allocator, &state, &anchor);
    defer choice.deinit();
    try fork_choice.onTick(&choice, signed.message.slot * preset.SECONDS_PER_SLOT);
    var engine: engine_api.TestEngine = .{ .status = .valid };
    const availability = fork_choice.DataAvailabilityCheck{ .context = &store, .is_available = Store.check };
    try std.testing.expectError(error.DataUnavailable, fork_choice.onBlock(&choice, signed, engine.interface(), availability));
    try std.testing.expectEqual(@as(usize, 1), choice.blocks.count());
    const inputs = [_][]const u8{
        @embedFile("fixtures/fulu_data_columns/sample_01.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_17.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_19.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_42.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_75.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_87.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_102.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_117.ssz_snappy"),
    };
    for (inputs, 0..) |compressed, i| {
        const bytes = try fixture.decode(allocator, compressed);
        defer allocator.free(bytes);
        var reader: std.Io.Reader = .fixed(bytes);
        const sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &reader);
        defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, sidecar);
        try store.put(&settings, &sidecar, &signed.message, &state);
        try std.testing.expectEqual(i == inputs.len - 1, store.available(root, &signed.message));
    }
    var custody_indices: [custody_requirement]u64 = undefined;
    for (&custody_indices, store.custody.values[0..custody_requirement]) |*target, index| target.* = index;
    const served = try store.serveByRoot(allocator, &.{.{ .block_root = root, .columns = &custody_indices }});
    defer allocator.free(served);
    try std.testing.expectEqual(custody_requirement, served.len);
    for (served) |column| try std.testing.expectEqualSlices(u8, store.get(root, column.index).?, column.bytes);
    var canonical_context = struct { slot: u64, root: fulu.Root }{ .slot = signed.message.slot, .root = root };
    const canonical = CanonicalRoots{ .context = &canonical_context, .root_at_slot = struct {
        fn at(context: *anyopaque, slot: u64) ?fulu.Root {
            const snapshot: *@TypeOf(canonical_context) = @ptrCast(@alignCast(context));
            return if (slot == snapshot.slot) snapshot.root else null;
        }
    }.at };
    const range = try store.serveByRange(allocator, signed.message.slot, 1, &custody_indices, canonical);
    defer allocator.free(range);
    try std.testing.expectEqual(custody_requirement, range.len);
    for (range, 0..) |column, i| try std.testing.expectEqual(store.custody.values[i], column.index);
    try fork_choice.onBlock(&choice, signed, engine.interface(), availability);
    try std.testing.expectEqual(@as(usize, 2), choice.blocks.count());
}

test "official Fulu column verifies against its block and rejects tampering" {
    const fixture = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    var state = try fixture.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var signed = try fixture.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    const bytes = try fixture.decode(allocator, @embedFile("fixtures/fulu_data_columns/valid.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    var sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &reader);
    defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, sidecar);
    var settings = try kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    const root = try verify(allocator, &settings, &sidecar, &signed.message, &state);
    try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, signed.message), root);
    var store = try Store.init(allocator, [_]u8{0} ** 32, custody_requirement);
    defer store.deinit();
    try std.testing.expect(!store.available(root, &signed.message));
    store.samples.len = 1;
    store.samples.values[0] = @intCast(sidecar.index);
    store.custody.values[0] = @intCast(sidecar.index);
    try store.put(&settings, &sidecar, &signed.message, &state);
    try std.testing.expect(store.available(root, &signed.message));
    try std.testing.expect(store.get(root, sidecar.index) != null);
    try std.testing.expectError(error.DuplicateColumn, store.put(&settings, &sidecar, &signed.message, &state));
    try store.prune(signed.message.slot + retention_epochs * preset.SLOTS_PER_EPOCH);
    try std.testing.expect(store.available(root, &signed.message));
    try store.prune(signed.message.slot + retention_epochs * preset.SLOTS_PER_EPOCH + 1);
    try std.testing.expect(!store.available(root, &signed.message));
    sidecar.kzg_commitments_inclusion_proof[0][0] ^= 1;
    try std.testing.expectError(error.InvalidCommitmentProof, verify(allocator, &settings, &sidecar, &signed.message, &state));
    sidecar.kzg_commitments_inclusion_proof[0][0] ^= 1;
    var wrong_block = signed.message;
    wrong_block.parent_root[0] ^= 1;
    try std.testing.expectError(error.WrongBlock, verify(allocator, &settings, &sidecar, &wrong_block, &state));
    var bad_commitment = [1]fulu.KZGCommitment{sidecar.kzg_commitments.data[0]};
    bad_commitment[0][0] ^= 1;
    var altered = sidecar;
    altered.kzg_commitments = .{ .data = &bad_commitment };
    try std.testing.expectError(error.InvalidDataColumn, verify(allocator, &settings, &altered, &signed.message, &state));
    sidecar.index = (sidecar.index + 1) % column_count;
    try std.testing.expectError(error.InvalidCellProof, verify(allocator, &settings, &sidecar, &signed.message, &state));
    sidecar.index = column_count;
    try std.testing.expectError(error.InvalidDataColumn, verify(allocator, &settings, &sidecar, &signed.message, &state));
}

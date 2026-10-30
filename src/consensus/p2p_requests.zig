// A Fulu sidecar request names either block roots or a canonical slot range,
// then asks for selected data columns. The store serves only columns this node
// retained for custody, and each response chunk binds one encoded sidecar to
// the fork active at that sidecar's slot. Request bounds are checked before
// any sidecar bytes are loaded.
//
// SSZ+Snappy request -> bounded store lookup -> fork-scoped response chunks
// The protocol permits at most 128 blocks and 128 column indices per block.
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");
const columns = @import("data_columns.zig");
const ingress = @import("p2p_ingress.zig");
const wire = @import("p2p_wire.zig");

pub const ByRootIdentifier = struct {
    block_root: fulu.Root,
    columns: types.List(u64, columns.column_count),
};

pub const ByRootRequest = types.List(ByRootIdentifier, columns.max_request_blocks);

pub const BlockRootsRequest = types.List(fulu.Root, columns.max_request_blocks);

pub const BlockRangeRequest = struct {
    start_slot: u64,
    count: u64,
    step: u64,
};

pub const ByRangeRequest = struct {
    start_slot: u64,
    count: u64,
    columns: types.List(u64, columns.column_count),
};

pub const EncodedChunks = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList([]u8) = .empty,

    /// Free every response chunk and the list that owns them.
    pub fn deinit(self: *EncodedChunks) void {
        for (self.items.items) |item| self.allocator.free(item);
        self.items.deinit(self.allocator);
    }
};

pub const BlockLookup = struct {
    context: *anyopaque,
    /// Return a borrowed signed block by message root, if it is retained.
    by_root: *const fn (*anyopaque, fulu.Root) ?fulu.SignedBeaconBlock,
    /// Return the root at one slot from a single fork-choice snapshot.
    root_at_slot: *const fn (*anyopaque, u64) ?fulu.Root,
};

/// Decode and serve one SSZ+Snappy beacon-blocks-by-root request.
pub fn serveBlocksByRoot(allocator: std.mem.Allocator, config: ingress.Config, encoded_request: []const u8, lookup: BlockLookup) !EncodedChunks {
    const request_bytes = try wire.decodePayload(allocator, encoded_request, wire.max_payload_size);
    defer allocator.free(request_bytes);
    var reader: std.Io.Reader = .fixed(request_bytes);
    const request = try ssz.deserialize(allocator, BlockRootsRequest, &reader);
    defer ssz.freeDecoded(allocator, BlockRootsRequest, request);
    if (request.data.len > columns.max_request_blocks) return error.InvalidRequest;
    var result = EncodedChunks{ .allocator = allocator };
    errdefer result.deinit();
    for (request.data) |root| {
        const block = lookup.by_root(lookup.context, root) orelse continue;
        try appendBlock(allocator, config, &result, .blocks_by_root, root, block);
    }
    return result;
}

/// Decode and serve one SSZ+Snappy beacon-blocks-by-range request.
pub fn serveBlocksByRange(allocator: std.mem.Allocator, config: ingress.Config, encoded_request: []const u8, lookup: BlockLookup) !EncodedChunks {
    const request_bytes = try wire.decodePayload(allocator, encoded_request, wire.max_payload_size);
    defer allocator.free(request_bytes);
    var reader: std.Io.Reader = .fixed(request_bytes);
    const request = try ssz.deserialize(allocator, BlockRangeRequest, &reader);
    if (request.count > columns.max_request_blocks or request.step == 0) return error.InvalidRequest;
    if (request.count != 0) {
        const last_step = try std.math.mul(u64, request.count - 1, request.step);
        _ = try std.math.add(u64, request.start_slot, last_step);
    }
    var result = EncodedChunks{ .allocator = allocator };
    errdefer result.deinit();
    for (0..request.count) |offset| {
        const slot = request.start_slot + @as(u64, @intCast(offset)) * request.step;
        const root = lookup.root_at_slot(lookup.context, slot) orelse continue;
        const block = lookup.by_root(lookup.context, root) orelse continue;
        if (block.message.slot != slot) return error.InconsistentStore;
        try appendBlock(allocator, config, &result, .blocks_by_range, root, block);
    }
    return result;
}

/// Decode and serve one SSZ+Snappy columns-by-root request.
pub fn serveColumnsByRoot(allocator: std.mem.Allocator, config: ingress.Config, encoded_request: []const u8, store: *columns.Store) !EncodedChunks {
    const request_bytes = try wire.decodePayload(allocator, encoded_request, wire.max_payload_size);
    defer allocator.free(request_bytes);
    var reader: std.Io.Reader = .fixed(request_bytes);
    const request = try ssz.deserialize(allocator, ByRootRequest, &reader);
    defer ssz.freeDecoded(allocator, ByRootRequest, request);
    if (request.data.len > columns.max_request_blocks) return error.InvalidRequest;

    const lookups = try allocator.alloc(columns.ByRoot, request.data.len);
    defer allocator.free(lookups);
    for (request.data, 0..) |identifier, i| {
        lookups[i] = .{ .block_root = identifier.block_root, .columns = identifier.columns.data };
    }
    const served = try store.serveByRoot(allocator, lookups);
    defer columns.Store.freeServed(allocator, served);
    return encodeServed(allocator, config, .columns_by_root, served);
}

/// Decode and serve one SSZ+Snappy columns-by-range request from a fork-choice view.
pub fn serveColumnsByRange(allocator: std.mem.Allocator, config: ingress.Config, encoded_request: []const u8, store: *columns.Store, canonical: columns.CanonicalRoots) !EncodedChunks {
    const request_bytes = try wire.decodePayload(allocator, encoded_request, wire.max_payload_size);
    defer allocator.free(request_bytes);
    var reader: std.Io.Reader = .fixed(request_bytes);
    const request = try ssz.deserialize(allocator, ByRangeRequest, &reader);
    defer ssz.freeDecoded(allocator, ByRangeRequest, request);
    const served = try store.serveByRange(allocator, request.start_slot, request.count, request.columns.data, canonical);
    defer columns.Store.freeServed(allocator, served);
    return encodeServed(allocator, config, .columns_by_range, served);
}

/// Encode served sidecars as independent response chunks in store order.
fn encodeServed(allocator: std.mem.Allocator, config: ingress.Config, protocol: wire.Protocol, served: []const columns.ServedColumn) !EncodedChunks {
    var result = EncodedChunks{ .allocator = allocator };
    errdefer result.deinit();
    for (served) |item| {
        const digest = try config.digestAtSlot(item.slot);
        const chunk = try wire.encodeResponseChunk(allocator, protocol, .success, digest, item.bytes, wire.max_payload_size);
        errdefer allocator.free(chunk);
        try result.items.append(allocator, chunk);
    }
    return result;
}

/// Verify a retained block root and append its fork-scoped response chunk.
fn appendBlock(allocator: std.mem.Allocator, config: ingress.Config, result: *EncodedChunks, protocol: wire.Protocol, root: fulu.Root, block: fulu.SignedBeaconBlock) !void {
    if (!std.mem.eql(u8, &(try merkle.HashTreeRoot(allocator, block.message)), &root)) return error.InconsistentStore;
    const bytes = try ssz.serializeAlloc(allocator, block);
    defer allocator.free(bytes);
    const digest = try config.digestAtSlot(block.message.slot);
    const chunk = try wire.encodeResponseChunk(allocator, protocol, .success, digest, bytes, wire.max_payload_size);
    errdefer allocator.free(chunk);
    try result.items.append(allocator, chunk);
}

test "column request schemas round trip through SSZ Snappy framing" {
    const allocator = std.testing.allocator;
    const request = ByRootRequest{ .data = &.{.{
        .block_root = [_]u8{0x42} ** 32,
        .columns = .{ .data = &.{ 3, 8, 127 } },
    }} };
    const serialized = try ssz.serializeAlloc(allocator, request);
    defer allocator.free(serialized);
    const encoded = try wire.encodePayload(allocator, serialized, wire.max_payload_size);
    defer allocator.free(encoded);
    const decoded = try wire.decodePayload(allocator, encoded, wire.max_payload_size);
    defer allocator.free(decoded);
    var reader: std.Io.Reader = .fixed(decoded);
    const roundtrip = try ssz.deserialize(allocator, ByRootRequest, &reader);
    defer ssz.freeDecoded(allocator, ByRootRequest, roundtrip);
    try std.testing.expectEqualSlices(u8, &request.data[0].block_root, &roundtrip.data[0].block_root);
    try std.testing.expectEqualSlices(u64, request.data[0].columns.data, roundtrip.data[0].columns.data);
}

test "blocks by root returns only a matching retained signed block" {
    const fixture = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    var signed = try fixture.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    const root = try merkle.HashTreeRoot(allocator, signed.message);
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    const request = BlockRootsRequest{ .data = &.{root} };
    const request_ssz = try ssz.serializeAlloc(allocator, request);
    defer allocator.free(request_ssz);
    const request_wire = try wire.encodePayload(allocator, request_ssz, wire.max_payload_size);
    defer allocator.free(request_wire);
    const LookupContext = struct {
        block: *fulu.SignedBeaconBlock,
        root: fulu.Root,
    };
    var lookup_context = LookupContext{ .block = &signed, .root = root };
    const lookup = BlockLookup{
        .context = &lookup_context,
        .by_root = struct {
            fn get(context: *anyopaque, requested: fulu.Root) ?fulu.SignedBeaconBlock {
                const source: *LookupContext = @ptrCast(@alignCast(context));
                return if (std.mem.eql(u8, &source.root, &requested)) source.block.* else null;
            }
        }.get,
        .root_at_slot = struct {
            fn at(_: *anyopaque, _: u64) ?fulu.Root {
                return null;
            }
        }.at,
    };
    var chunks = try serveBlocksByRoot(allocator, config, request_wire, lookup);
    defer chunks.deinit();
    try std.testing.expectEqual(@as(usize, 1), chunks.items.items.len);
    const decoded = try wire.decodeResponseChunk(allocator, .blocks_by_root, chunks.items.items[0], try config.digestAtSlot(signed.message.slot), wire.max_payload_size);
    defer allocator.free(decoded.payload);
    const expected = try ssz.serializeAlloc(allocator, signed);
    defer allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, decoded.payload);
}

test "columns by root serves only verified custodied sidecars" {
    const fixture = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const raw_sidecar = try fixture.decode(allocator, @embedFile("fixtures/fulu_data_columns/sample_01.ssz_snappy"));
    defer allocator.free(raw_sidecar);
    var reader: std.Io.Reader = .fixed(raw_sidecar);
    const sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &reader);
    defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, sidecar);
    var state = try fixture.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var signed = try fixture.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    var settings = try @import("execution").kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var store = try columns.Store.open(allocator, std.testing.io, tmp.dir, "columns", [_]u8{9} ** 32, [_]u8{0} ** 32, columns.custody_requirement);
    defer store.deinit();
    try store.put(&settings, &sidecar, &signed.message, &state);

    const root = try @import("merkle").HashTreeRoot(allocator, signed.message);
    const request = ByRootRequest{ .data = &.{.{ .block_root = root, .columns = .{ .data = &.{1} } }} };
    const request_ssz = try ssz.serializeAlloc(allocator, request);
    defer allocator.free(request_ssz);
    const request_wire = try wire.encodePayload(allocator, request_ssz, wire.max_payload_size);
    defer allocator.free(request_wire);
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    var chunks = try serveColumnsByRoot(allocator, config, request_wire, &store);
    defer chunks.deinit();
    try std.testing.expectEqual(@as(usize, 1), chunks.items.items.len);
    const decoded = try wire.decodeResponseChunk(allocator, .columns_by_root, chunks.items.items[0], try config.digestAtSlot(sidecar.signed_block_header.message.slot), wire.max_payload_size);
    defer allocator.free(decoded.payload);
    try std.testing.expectEqual(wire.ResponseCode.success, decoded.code);
    try std.testing.expectEqualSlices(u8, raw_sidecar, decoded.payload);

    const missing = ByRootRequest{ .data = &.{.{ .block_root = [_]u8{0xff} ** 32, .columns = .{ .data = &.{1} } }} };
    const missing_ssz = try ssz.serializeAlloc(allocator, missing);
    defer allocator.free(missing_ssz);
    const missing_wire = try wire.encodePayload(allocator, missing_ssz, wire.max_payload_size);
    defer allocator.free(missing_wire);
    var missing_chunks = try serveColumnsByRoot(allocator, config, missing_wire, &store);
    defer missing_chunks.deinit();
    try std.testing.expectEqual(@as(usize, 0), missing_chunks.items.items.len);
}

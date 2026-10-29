// Fulu gossip and block responses carry SSZ objects scoped to the fork at
// their slot. The four-byte fork digest must match that slot before an object
// reaches a consensus callback. Column gossip also binds its subnet index to
// the verified sidecar and known block before storage. The caller owns block
// and attestation consensus validation; the column store verifies KZG proofs.
//
// Snappy -> SSZ -> slot digest -> consensus validation -> callback/store
// Each uncompressed message is limited to 10 MiB by the wire decoder.
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const kzg = @import("execution").kzg;
const columns = @import("data_columns.zig");
const helpers = @import("helpers.zig");
const wire = @import("p2p_wire.zig");

pub const Config = struct {
    genesis_validators_root: fulu.Root,
    fulu_version: fulu.Version,
    fulu_epoch: u64,
    blob_schedule: []const helpers.BlobParameters,
    max_encoded_size: usize = wire.max_payload_size,

    /// Compute a Fulu digest only for slots at or after the configured fork.
    pub fn digestAtSlot(self: Config, slot: u64) ![4]u8 {
        const epoch = helpers.computeEpochAtSlot(slot);
        if (epoch < self.fulu_epoch) return error.UnsupportedFork;
        return helpers.computeForkDigest(self.fulu_version, self.genesis_validators_root, epoch, self.blob_schedule);
    }
};

pub const BlockValidation = struct {
    context: *anyopaque,
    validate: *const fn (*anyopaque, *const fulu.SignedBeaconBlock) anyerror!void,
};

pub const AttestationValidation = struct {
    context: *anyopaque,
    validate: *const fn (*anyopaque, *const fulu.Attestation) anyerror!void,
};

/// Decode and validate block gossip before invoking the caller's consensus gate.
pub fn receiveBlockGossip(allocator: std.mem.Allocator, config: Config, topic_digest: [4]u8, encoded: []const u8, validation: BlockValidation) !void {
    const bytes = try wire.decodeGossip(allocator, encoded, config.max_encoded_size);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const block = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
    const expected = try config.digestAtSlot(block.message.slot);
    if (!std.mem.eql(u8, &topic_digest, &expected)) return error.InvalidForkContext;
    try validation.validate(validation.context, &block);
}

/// Decode and validate attestation gossip before invoking the caller's consensus gate.
pub fn receiveAttestationGossip(allocator: std.mem.Allocator, config: Config, topic_digest: [4]u8, encoded: []const u8, validation: AttestationValidation) !void {
    const bytes = try wire.decodeGossip(allocator, encoded, config.max_encoded_size);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const attestation = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, attestation);
    const expected = try config.digestAtSlot(attestation.data.slot);
    if (!std.mem.eql(u8, &topic_digest, &expected)) return error.InvalidForkContext;
    try validation.validate(validation.context, &attestation);
}

/// Verify column gossip against the known block and parent state before retention.
pub fn receiveColumnGossip(allocator: std.mem.Allocator, config: Config, topic_digest: [4]u8, subnet: u8, encoded: []const u8, store: *columns.Store, settings: *const kzg.Settings, block: *const fulu.BeaconBlock, parent_state: *const fulu.BeaconState) !void {
    const bytes = try wire.decodeGossip(allocator, encoded, config.max_encoded_size);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &reader);
    defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, sidecar);
    if (sidecar.index != subnet or sidecar.signed_block_header.message.slot != block.slot) return error.InvalidDataColumn;
    const expected = try config.digestAtSlot(block.slot);
    if (!std.mem.eql(u8, &topic_digest, &expected)) return error.InvalidForkContext;
    try store.put(settings, &sidecar, block, parent_state);
}

/// Decode a successful block response, checking its unknown slot against the wire digest.
pub fn decodeBlockResponse(allocator: std.mem.Allocator, config: Config, chunk: *const wire.ResponseChunk) !fulu.SignedBeaconBlock {
    if (chunk.code != .success or chunk.fork_digest == null) return error.InvalidResponseCode;
    var reader: std.Io.Reader = .fixed(chunk.payload);
    const block = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &reader);
    errdefer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
    const expected = try config.digestAtSlot(block.message.slot);
    const got = chunk.fork_digest.?;
    if (!std.mem.eql(u8, &got, &expected)) return error.InvalidForkContext;
    return block;
}

test "gossip and response gates reject wrong fork before callbacks" {
    const fixture = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const raw = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer allocator.free(raw);
    const config = Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &helpers.BLOB_SCHEDULE };
    var reader: std.Io.Reader = .fixed(raw);
    const block = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
    const digest = try config.digestAtSlot(block.message.slot);
    const gossip = try wire.encodeGossip(allocator, raw, config.max_encoded_size);
    defer allocator.free(gossip);
    var calls: usize = 0;
    const validator = BlockValidation{ .context = &calls, .validate = struct {
        fn check(context: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
        }
    }.check };
    try receiveBlockGossip(allocator, config, digest, gossip, validator);
    try std.testing.expectEqual(@as(usize, 1), calls);
    var wrong = digest;
    wrong[0] ^= 1;
    try std.testing.expectError(error.InvalidForkContext, receiveBlockGossip(allocator, config, wrong, gossip, validator));
    try std.testing.expectError(error.MalformedBlock, receiveBlockGossip(allocator, config, digest, &.{ 0xff, 0xff }, validator));
    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expectError(error.InvalidForkContext, decodeBlockResponse(allocator, config, &.{ .code = .success, .fork_digest = wrong, .payload = raw }));
    const decoded = try decodeBlockResponse(allocator, config, &.{ .code = .success, .fork_digest = digest, .payload = raw });
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, decoded);
    try std.testing.expectEqual(block.message.slot, decoded.message.slot);
}

test "attestation gossip and official column sidecar cross validation gates" {
    const fixture = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config = Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &helpers.BLOB_SCHEDULE };
    const attestation_bytes = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/slashing/attestation_0x5172be6898efefa589c2182765c8e7a74272ed2b0004d0577921a4808b364fcf.ssz_snappy"));
    defer allocator.free(attestation_bytes);
    var att_reader: std.Io.Reader = .fixed(attestation_bytes);
    const attestation = try ssz.deserialize(allocator, fulu.Attestation, &att_reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, attestation);
    const att_digest = try config.digestAtSlot(attestation.data.slot);
    const att_gossip = try wire.encodeGossip(allocator, attestation_bytes, config.max_encoded_size);
    defer allocator.free(att_gossip);
    var calls: usize = 0;
    const validation = AttestationValidation{ .context = &calls, .validate = struct {
        fn check(context: *anyopaque, _: *const fulu.Attestation) !void {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
        }
    }.check };
    try receiveAttestationGossip(allocator, config, att_digest, att_gossip, validation);
    try std.testing.expectEqual(@as(usize, 1), calls);
    var wrong = att_digest;
    wrong[0] ^= 1;
    try std.testing.expectError(error.InvalidForkContext, receiveAttestationGossip(allocator, config, wrong, att_gossip, validation));
    try std.testing.expectEqual(@as(usize, 1), calls);

    var state = try fixture.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var signed = try fixture.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    const column_bytes = try fixture.decode(allocator, @embedFile("fixtures/fulu_data_columns/sample_01.ssz_snappy"));
    defer allocator.free(column_bytes);
    const column_gossip = try wire.encodeGossip(allocator, column_bytes, config.max_encoded_size);
    defer allocator.free(column_gossip);
    var settings = try kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var store = try columns.Store.open(allocator, std.testing.io, tmp.dir, "columns", [_]u8{9} ** 32, [_]u8{0} ** 32, columns.custody_requirement);
    defer store.deinit();
    const root = try @import("merkle").HashTreeRoot(allocator, signed.message);
    const block_digest = try config.digestAtSlot(signed.message.slot);
    try std.testing.expectError(error.InvalidDataColumn, receiveColumnGossip(allocator, config, block_digest, 2, column_gossip, &store, &settings, &signed.message, &state));
    try std.testing.expect((try store.get(root, 1)) == null);
    try receiveColumnGossip(allocator, config, block_digest, 1, column_gossip, &store, &settings, &signed.message, &state);
    const stored = (try store.get(root, 1)).?;
    defer allocator.free(stored);
    try std.testing.expectError(error.DuplicateColumn, receiveColumnGossip(allocator, config, block_digest, 1, column_gossip, &store, &settings, &signed.message, &state));
}

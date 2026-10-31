// Gossipsub publishes arrive as protobuf RPCs from authenticated peers. Parse
// the complete bounded envelope before delivering any SSZ object, then check
// its fork topic and consensus rules. Valid duplicates are suppressed; invalid
// messages count toward the existing peer ban threshold.
//
//   peer RPC -> bounded protobuf -> topic -> SSZ/consensus gate -> delivery
// This module handles publish envelopes only. Connection security, mesh
// control, and stream framing are separate parts of the peer transport.
const std = @import("std");
const ingress = @import("p2p_ingress.zig");
const admission = @import("p2p_admission.zig");
const wire = @import("p2p_wire.zig");

pub const max_rpc_size: usize = 16 * 1024 * 1024;
const max_publishes: usize = 16;
const seen_capacity: usize = 1024;

const Publish = struct { topic: []const u8, data: []const u8 };
const Parsed = struct { items: [max_publishes]Publish = undefined, len: usize = 0 };

pub const Service = struct {
    allocator: std.mem.Allocator,
    digest: [4]u8,
    block_topic: []u8,
    attestation_topics: [64]?[]u8,
    block_validation: ingress.BlockValidation,
    attestation_validation: ingress.AttestationValidation,
    peers: admission.Admission,
    seen: std.AutoHashMap([32]u8, void),
    seen_order: [seen_capacity][32]u8 = undefined,
    seen_len: usize = 0,
    seen_next: usize = 0,

    /// Subscribe to one Fulu digest and selected attestation subnets. Callback
    /// contexts and the config's blob schedule must outlive the service.
    pub fn init(allocator: std.mem.Allocator, config: ingress.Config, digest: [4]u8, subnets: []const u8, max_peers: usize, invalid_limit: u8, block_validation: ingress.BlockValidation, attestation_validation: ingress.AttestationValidation) !Service {
        if (subnets.len > 64) return error.InvalidSubnet;
        var peers = try admission.Admission.init(allocator, config, max_peers, invalid_limit);
        errdefer peers.deinit();
        const block_topic = try wire.topicName(allocator, digest, .block, null);
        errdefer allocator.free(block_topic);
        var attestation_topics: [64]?[]u8 = .{null} ** 64;
        errdefer for (attestation_topics) |name| if (name) |owned| allocator.free(owned);
        for (subnets) |subnet| {
            if (subnet >= 64) return error.InvalidSubnet;
            if (attestation_topics[subnet] != null) continue;
            attestation_topics[subnet] = try wire.topicName(allocator, digest, .attestation, subnet);
        }
        var seen = std.AutoHashMap([32]u8, void).init(allocator);
        errdefer seen.deinit();
        try seen.ensureTotalCapacity(seen_capacity);
        return .{ .allocator = allocator, .digest = digest, .block_topic = block_topic, .attestation_topics = attestation_topics, .block_validation = block_validation, .attestation_validation = attestation_validation, .peers = peers, .seen = seen };
    }

    /// Release topic names, the bounded duplicate cache, and peer scores.
    pub fn deinit(self: *Service) void {
        self.seen.deinit();
        self.peers.deinit();
        for (self.attestation_topics) |name| if (name) |owned| self.allocator.free(owned);
        self.allocator.free(self.block_topic);
    }

    /// Admit a transport-authenticated peer within the configured table limit.
    pub fn connect(self: *Service, peer_id: [32]u8) !void {
        return self.peers.connect(peer_id);
    }

    /// Retain a peer's invalid-message count when its stream closes.
    pub fn disconnect(self: *Service, peer_id: [32]u8) void {
        self.peers.disconnect(peer_id);
    }

    /// Decode one complete RPC, then deliver only subscribed, valid publishes.
    /// The caller owns the frame and supplies a transport-authenticated peer ID.
    pub fn receive(self: *Service, peer_id: [32]u8, frame: []const u8) !void {
        try self.peers.requirePeer(peer_id);
        const parsed = decodeRpc(frame, self.peers.config.max_encoded_size) catch |err| {
            self.peers.noteInvalid(peer_id);
            return err;
        };
        for (parsed.items[0..parsed.len]) |publish| {
            const kind: wire.Topic = if (std.mem.eql(u8, publish.topic, self.block_topic)) .block else blk: {
                for (self.attestation_topics) |maybe_name| {
                    const name = maybe_name orelse continue;
                    if (std.mem.eql(u8, publish.topic, name)) break :blk .attestation;
                }
                continue;
            };
            const hash = messageHash(publish);
            if (self.seen.contains(hash)) continue;
            switch (kind) {
                .block => try self.peers.receiveBlock(peer_id, self.digest, publish.data, self.block_validation),
                .attestation => try self.peers.receiveAttestation(peer_id, self.digest, publish.data, self.attestation_validation),
                else => unreachable,
            }
            if (self.seen_len == seen_capacity) {
                _ = self.seen.remove(self.seen_order[self.seen_next]);
            } else {
                self.seen_len += 1;
            }
            self.seen.putAssumeCapacity(hash, {});
            self.seen_order[self.seen_next] = hash;
            self.seen_next = (self.seen_next + 1) % seen_capacity;
        }
    }
};

/// Encode a StrictNoSign publish as one libp2p Gossipsub protobuf RPC.
pub fn encodePublish(allocator: std.mem.Allocator, topic: []const u8, data: []const u8) ![]u8 {
    if (topic.len == 0 or topic.len > 128 or data.len > wire.max_payload_size) return error.PayloadTooLarge;
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try appendBytes(allocator, &message, 2, data);
    try appendBytes(allocator, &message, 4, topic);
    var rpc: std.ArrayList(u8) = .empty;
    errdefer rpc.deinit(allocator);
    try appendBytes(allocator, &rpc, 2, message.items);
    return rpc.toOwnedSlice(allocator);
}

/// Parse all publish fields before allowing any consensus callback to run.
fn decodeRpc(bytes: []const u8, max_data: usize) !Parsed {
    if (bytes.len > max_rpc_size) return error.PayloadTooLarge;
    var result = Parsed{};
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const key = try readVarint(bytes, &cursor);
        if (key >> 3 == 0) return error.InvalidGossipRpc;
        if (key >> 3 != 2) {
            try skipField(bytes, &cursor, @truncate(key & 7));
            continue;
        }
        if (key & 7 != 2 or result.len == max_publishes) return error.InvalidGossipRpc;
        result.items[result.len] = try decodeMessage(try readBytes(bytes, &cursor), max_data);
        result.len += 1;
    }
    return result;
}

/// Require one topic and data field, with Ethereum's unsigned gossip policy.
fn decodeMessage(bytes: []const u8, max_data: usize) !Publish {
    var cursor: usize = 0;
    var topic: ?[]const u8 = null;
    var data: ?[]const u8 = null;
    while (cursor < bytes.len) {
        const key = try readVarint(bytes, &cursor);
        const field = key >> 3;
        if (field == 0) return error.InvalidGossipRpc;
        switch (field) {
            2 => {
                if (key & 7 != 2 or data != null) return error.InvalidGossipRpc;
                data = try readBytes(bytes, &cursor);
                if (data.?.len > max_data) return error.PayloadTooLarge;
            },
            4 => {
                if (key & 7 != 2 or topic != null) return error.InvalidGossipRpc;
                topic = try readBytes(bytes, &cursor);
                if (topic.?.len == 0 or topic.?.len > 128) return error.InvalidGossipRpc;
            },
            1, 3, 5, 6 => return error.InvalidSignaturePolicy,
            else => try skipField(bytes, &cursor, @truncate(key & 7)),
        }
    }
    return .{ .topic = topic orelse return error.InvalidGossipRpc, .data = data orelse return error.InvalidGossipRpc };
}

/// Read a canonical protobuf varint without overflowing u64.
fn readVarint(bytes: []const u8, cursor: *usize) !u64 {
    var value: u64 = 0;
    for (0..10) |index| {
        if (cursor.* >= bytes.len) return error.InvalidGossipRpc;
        const byte = bytes[cursor.*];
        cursor.* += 1;
        if (index == 9 and byte > 1) return error.InvalidGossipRpc;
        value |= @as(u64, byte & 0x7f) << @intCast(index * 7);
        if (byte & 0x80 != 0) continue;
        if (index > 0 and value < (@as(u64, 1) << @intCast(index * 7))) return error.InvalidGossipRpc;
        return value;
    }
    return error.InvalidGossipRpc;
}

/// Borrow a bounded length-delimited protobuf field from the input frame.
fn readBytes(bytes: []const u8, cursor: *usize) ![]const u8 {
    const length = try readVarint(bytes, cursor);
    if (length > bytes.len - cursor.*) return error.InvalidGossipRpc;
    const size: usize = @intCast(length);
    const result = bytes[cursor.*..][0..size];
    cursor.* += size;
    return result;
}

/// Skip a protobuf field outside the publish payload without allocating.
fn skipField(bytes: []const u8, cursor: *usize, wire_type: u3) !void {
    switch (wire_type) {
        0 => _ = try readVarint(bytes, cursor),
        1 => {
            if (bytes.len - cursor.* < 8) return error.InvalidGossipRpc;
            cursor.* += 8;
        },
        2 => _ = try readBytes(bytes, cursor),
        5 => {
            if (bytes.len - cursor.* < 4) return error.InvalidGossipRpc;
            cursor.* += 4;
        },
        else => return error.InvalidGossipRpc,
    }
}

/// Append one length-delimited protobuf field to the caller's list.
fn appendBytes(allocator: std.mem.Allocator, output: *std.ArrayList(u8), field: u8, bytes: []const u8) !void {
    try appendVarint(allocator, output, @as(u64, field) << 3 | 2);
    try appendVarint(allocator, output, bytes.len);
    try output.appendSlice(allocator, bytes);
}

/// Append a canonical unsigned protobuf varint.
fn appendVarint(allocator: std.mem.Allocator, output: *std.ArrayList(u8), value: u64) !void {
    var remaining = value;
    while (remaining >= 128) : (remaining >>= 7) try output.append(allocator, @as(u8, @truncate(remaining)) | 0x80);
    try output.append(allocator, @intCast(remaining));
}

/// Hash a topic and payload with a separator for bounded duplicate tracking.
fn messageHash(publish: Publish) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(publish.topic);
    hasher.update(&.{0});
    hasher.update(publish.data);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

test "publish RPC accepts canonical unsigned fields and rejects malformed envelopes" {
    const allocator = std.testing.allocator;
    const encoded = try encodePublish(allocator, "topic", "data");
    defer allocator.free(encoded);
    const parsed = try decodeRpc(encoded, 16);
    try std.testing.expectEqual(@as(usize, 1), parsed.len);
    try std.testing.expectEqualStrings("topic", parsed.items[0].topic);
    try std.testing.expectEqualStrings("data", parsed.items[0].data);
    try std.testing.expectError(error.InvalidGossipRpc, decodeRpc(&.{ 0x12, 0x80 }, 16));
    try std.testing.expectError(error.InvalidGossipRpc, decodeRpc(&.{ 0x12, 0x80, 0x00 }, 16));
    try std.testing.expectError(error.PayloadTooLarge, decodeRpc(encoded, 3));
    var signed_message: std.ArrayList(u8) = .empty;
    defer signed_message.deinit(allocator);
    try appendBytes(allocator, &signed_message, 1, "sender");
    try appendBytes(allocator, &signed_message, 2, "data");
    try appendBytes(allocator, &signed_message, 4, "topic");
    var signed_rpc: std.ArrayList(u8) = .empty;
    defer signed_rpc.deinit(allocator);
    try appendBytes(allocator, &signed_rpc, 2, signed_message.items);
    try std.testing.expectError(error.InvalidSignaturePolicy, decodeRpc(signed_rpc.items, 16));
}

test "gossip RPC validates blocks and attestations before delivery and retains peer scores" {
    const fixture = @import("fixture_runner.zig");
    const fulu = @import("fulu");
    const ssz = @import("ssz");
    const helpers = @import("helpers.zig");
    const allocator = std.testing.allocator;
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &helpers.BLOB_SCHEDULE };
    const raw_block = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer allocator.free(raw_block);
    var block_reader: std.Io.Reader = .fixed(raw_block);
    const block = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &block_reader);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
    const digest = try config.digestAtSlot(block.message.slot);
    const raw_attestation = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/slashing/attestation_0x5172be6898efefa589c2182765c8e7a74272ed2b0004d0577921a4808b364fcf.ssz_snappy"));
    defer allocator.free(raw_attestation);
    var att_reader: std.Io.Reader = .fixed(raw_attestation);
    const attestation = try ssz.deserialize(allocator, fulu.Attestation, &att_reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, attestation);
    try std.testing.expectEqual(digest, try config.digestAtSlot(attestation.data.slot));
    const Counts = struct { blocks: usize = 0, attestations: usize = 0 };
    var counts = Counts{};
    const block_gate = ingress.BlockValidation{ .context = &counts, .validate = struct {
        /// Count a block only after it passes the ingress checks.
        fn check(context: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            const state: *Counts = @ptrCast(@alignCast(context));
            state.blocks += 1;
        }
    }.check };
    const att_gate = ingress.AttestationValidation{ .context = &counts, .validate = struct {
        /// Count an attestation only after it passes the ingress checks.
        fn check(context: *anyopaque, _: *const fulu.Attestation) !void {
            const state: *Counts = @ptrCast(@alignCast(context));
            state.attestations += 1;
        }
    }.check };
    const bad_peer = [_]u8{1} ** 32;
    const good_peer = [_]u8{2} ** 32;
    try std.testing.expectError(error.InvalidSubnet, Service.init(allocator, config, digest, &.{64}, 2, 3, block_gate, att_gate));
    var service = try Service.init(allocator, config, digest, &.{3}, 2, 3, block_gate, att_gate);
    defer service.deinit();
    try service.connect(bad_peer);
    try service.connect(good_peer);
    const block_data = try wire.encodeGossip(allocator, raw_block, config.max_encoded_size);
    defer allocator.free(block_data);
    const block_rpc = try encodePublish(allocator, service.block_topic, block_data);
    defer allocator.free(block_rpc);
    try service.receive(good_peer, block_rpc);
    try service.receive(good_peer, block_rpc);
    try std.testing.expectEqual(@as(usize, 1), counts.blocks);
    const att_data = try wire.encodeGossip(allocator, raw_attestation, config.max_encoded_size);
    defer allocator.free(att_data);
    const att_rpc = try encodePublish(allocator, service.attestation_topics[3].?, att_data);
    defer allocator.free(att_rpc);
    try service.receive(good_peer, att_rpc);
    try std.testing.expectEqual(@as(usize, 1), counts.attestations);
    const other_topic = try wire.topicName(allocator, digest, .attestation, 4);
    defer allocator.free(other_topic);
    const other_rpc = try encodePublish(allocator, other_topic, att_data);
    defer allocator.free(other_rpc);
    try service.receive(good_peer, other_rpc);
    try std.testing.expectEqual(@as(usize, 1), counts.attestations);
    const malformed_rpc = try encodePublish(allocator, service.block_topic, &.{ 0xff, 0xff });
    defer allocator.free(malformed_rpc);
    try std.testing.expectError(error.MalformedBlock, service.receive(bad_peer, malformed_rpc));
    var malformed_batch: std.ArrayList(u8) = .empty;
    defer malformed_batch.deinit(allocator);
    try malformed_batch.appendSlice(allocator, block_rpc);
    try malformed_batch.appendSlice(allocator, &.{ 0x12, 0x80 });
    service.seen.clearRetainingCapacity();
    service.seen_len = 0;
    service.seen_next = 0;
    try std.testing.expectError(error.InvalidGossipRpc, service.receive(bad_peer, malformed_batch.items));
    try std.testing.expectEqual(@as(usize, 1), counts.blocks);
    try std.testing.expectError(error.MalformedBlock, service.receive(bad_peer, malformed_rpc));
    try std.testing.expectEqual(@as(u8, 3), service.peers.state(bad_peer).?.invalid_messages);
    try std.testing.expectError(error.PeerBanned, service.receive(bad_peer, block_rpc));
    try std.testing.expectEqual(@as(usize, 1), counts.blocks);
    service.disconnect(good_peer);
    try std.testing.expectError(error.PeerDisconnected, service.receive(good_peer, att_rpc));
    try service.connect(good_peer);
    try std.testing.expectEqual(@as(u8, 0), service.peers.state(good_peer).?.invalid_messages);
    try service.receive(good_peer, block_rpc);
    try std.testing.expectEqual(@as(usize, 2), counts.blocks);

    var wrong_digest = digest;
    wrong_digest[0] ^= 1;
    var wrong = try Service.init(allocator, config, wrong_digest, &.{}, 1, 3, block_gate, att_gate);
    defer wrong.deinit();
    try wrong.connect(bad_peer);
    const wrong_rpc = try encodePublish(allocator, wrong.block_topic, block_data);
    defer allocator.free(wrong_rpc);
    try std.testing.expectError(error.InvalidForkContext, wrong.receive(bad_peer, wrong_rpc));
    try std.testing.expectEqual(@as(u8, 1), wrong.peers.state(bad_peer).?.invalid_messages);
    try std.testing.expectEqual(@as(usize, 2), counts.blocks);

    var small_config = config;
    small_config.max_encoded_size = 1;
    var bounded = try Service.init(allocator, small_config, digest, &.{}, 1, 3, block_gate, att_gate);
    defer bounded.deinit();
    try bounded.connect(bad_peer);
    try std.testing.expectError(error.PayloadTooLarge, bounded.receive(bad_peer, block_rpc));
    try std.testing.expectEqual(@as(u8, 1), bounded.peers.state(bad_peer).?.invalid_messages);
    try std.testing.expectEqual(@as(usize, 2), counts.blocks);

    const local_gate = ingress.BlockValidation{ .context = &counts, .validate = struct {
        /// Simulate a local failure that must not penalize the sender.
        fn unavailable(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            return error.LocalUnavailable;
        }
    }.unavailable };
    var local_error = try Service.init(allocator, config, digest, &.{}, 1, 3, local_gate, att_gate);
    defer local_error.deinit();
    try local_error.connect(bad_peer);
    try std.testing.expectError(error.LocalUnavailable, local_error.receive(bad_peer, block_rpc));
    try std.testing.expectEqual(@as(u8, 0), local_error.peers.state(bad_peer).?.invalid_messages);
}

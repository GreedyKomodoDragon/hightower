// Gossipsub subscriptions and publishes arrive as protobuf RPCs from
// authenticated peers. Parse the complete bounded envelope before changing
// subscriptions or delivering SSZ objects. Valid duplicates are suppressed;
// invalid messages count toward the existing peer ban threshold.
//
//   peer RPC -> bounded protobuf -> topic -> SSZ/consensus gate -> delivery
// One RPC carries at most 128 subscription updates and 16 publishes in 16 MiB.
// A stream prefixes each RPC with its unsigned varint byte length. Connection
// security and mesh control are separate work.
const std = @import("std");
const ingress = @import("p2p_ingress.zig");
const admission = @import("p2p_admission.zig");
const wire = @import("p2p_wire.zig");

pub const max_rpc_size: usize = 16 * 1024 * 1024;
const max_publishes: usize = 16;
const max_subscriptions: usize = 128;
const seen_capacity: usize = 1024;
const max_topic_size: usize = 128;
const max_frame_prefix: usize = 4;
const field_shift = 3;
const wire_mask = 0b111;
const RpcField = struct {
    const subscription = 1;
    const publish = 2;
};
const SubscriptionField = struct {
    const subscribe = 1;
    const topic = 2;
};
const MessageField = struct {
    const from = 1;
    const data = 2;
    const seqno = 3;
    const topic = 4;
    const signature = 5;
    const key = 6;
};
const WireType = struct {
    const varint = 0;
    const fixed64 = 1;
    const bytes = 2;
    const fixed32 = 5;
};

const Publish = struct { topic: []const u8, data: []const u8 };
const Subscription = struct { topic: []const u8, subscribe: bool };
const RemoteSubscriptions = struct { block: bool = false, attestations: u64 = 0 };
const TopicSelection = union(enum) { block, attestation: u8 };
const Parsed = struct {
    publishes: [max_publishes]Publish = undefined,
    publish_len: usize = 0,
    subscriptions: [max_subscriptions]Subscription = undefined,
    subscription_len: usize = 0,
};

pub const Service = struct {
    allocator: std.mem.Allocator,
    digest: [4]u8,
    block_topic: []u8,
    attestation_topics: [64]?[]u8,
    block_validation: ingress.BlockValidation,
    attestation_validation: ingress.AttestationValidation,
    peers: admission.Admission,
    subscriptions: std.AutoHashMap([32]u8, RemoteSubscriptions),
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
        var subscriptions = std.AutoHashMap([32]u8, RemoteSubscriptions).init(allocator);
        errdefer subscriptions.deinit();
        try subscriptions.ensureTotalCapacity(@intCast(max_peers));
        return .{ .allocator = allocator, .digest = digest, .block_topic = block_topic, .attestation_topics = attestation_topics, .block_validation = block_validation, .attestation_validation = attestation_validation, .peers = peers, .subscriptions = subscriptions, .seen = seen };
    }

    /// Release topic names, the bounded duplicate cache, and peer scores.
    pub fn deinit(self: *Service) void {
        self.seen.deinit();
        self.subscriptions.deinit();
        self.peers.deinit();
        for (self.attestation_topics) |name| if (name) |owned| self.allocator.free(owned);
        self.allocator.free(self.block_topic);
    }

    /// Admit a transport-authenticated peer within the configured table limit.
    pub fn connect(self: *Service, peer_id: [32]u8) !void {
        const already_connected = if (self.peers.state(peer_id)) |state| state.connected else false;
        try self.peers.connect(peer_id);
        if (!already_connected) self.subscriptions.putAssumeCapacity(peer_id, .{});
    }

    /// Retain a peer's invalid-message count when its stream closes.
    pub fn disconnect(self: *Service, peer_id: [32]u8) void {
        self.peers.disconnect(peer_id);
        _ = self.subscriptions.remove(peer_id);
    }

    /// Copy connected peers subscribed to a local block or attestation topic.
    /// Returns BufferTooSmall without writing beyond the caller's output slice.
    pub fn recipients(self: *Service, name: []const u8, output: [][32]u8) !usize {
        const selected = self.classify(name) orelse return error.UnknownTopic;
        var count: usize = 0;
        var iterator = self.subscriptions.iterator();
        while (iterator.next()) |entry| {
            const interested = switch (selected) {
                .block => entry.value_ptr.block,
                .attestation => |subnet| entry.value_ptr.attestations & (@as(u64, 1) << @intCast(subnet)) != 0,
            };
            if (!interested or !self.peers.state(entry.key_ptr.*).?.connected) continue;
            if (count == output.len) return error.BufferTooSmall;
            output[count] = entry.key_ptr.*;
            count += 1;
        }
        return count;
    }

    /// Decode one complete RPC, then apply subscriptions and valid publishes.
    /// The caller owns the frame and supplies a transport-authenticated peer ID.
    pub fn receive(self: *Service, peer_id: [32]u8, frame: []const u8) !void {
        try self.peers.requirePeer(peer_id);
        const parsed = decodeRpc(frame, self.peers.config.max_encoded_size) catch |err| {
            self.peers.noteInvalid(peer_id);
            return err;
        };
        const remote = self.subscriptions.getPtr(peer_id).?;
        for (parsed.subscriptions[0..parsed.subscription_len]) |subscription| {
            const selected = self.classify(subscription.topic) orelse continue;
            switch (selected) {
                .block => remote.block = subscription.subscribe,
                .attestation => |subnet| {
                    const mask = @as(u64, 1) << @intCast(subnet);
                    if (subscription.subscribe) remote.attestations |= mask else remote.attestations &= ~mask;
                },
            }
        }
        for (parsed.publishes[0..parsed.publish_len]) |publish| {
            const selected = self.classify(publish.topic) orelse continue;
            const hash = messageHash(publish);
            if (self.seen.contains(hash)) continue;
            switch (selected) {
                .block => try self.peers.receiveBlock(peer_id, self.digest, publish.data, self.block_validation),
                .attestation => try self.peers.receiveAttestation(peer_id, self.digest, publish.data, self.attestation_validation),
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

    /// Match only topics this service follows at its configured fork digest.
    fn classify(self: *const Service, name: []const u8) ?TopicSelection {
        if (std.mem.eql(u8, name, self.block_topic)) return .block;
        for (self.attestation_topics, 0..) |maybe_name, subnet| {
            const topic_name = maybe_name orelse continue;
            if (std.mem.eql(u8, name, topic_name)) return .{ .attestation = @intCast(subnet) };
        }
        return null;
    }
};

/// Assemble varint-delimited RPCs from one authenticated peer's gossip stream.
/// The caller owns one Stream per connection and releases it on disconnect.
pub const Stream = struct {
    allocator: std.mem.Allocator,
    peer_id: [32]u8,
    pending: std.ArrayList(u8) = .empty,
    prefix_len: u8 = 0,
    declared: usize = 0,
    have_length: bool = false,

    /// Bind a new stream to the transport-authenticated peer identity.
    pub fn init(allocator: std.mem.Allocator, peer_id: [32]u8) Stream {
        return .{ .allocator = allocator, .peer_id = peer_id };
    }

    /// Release any incomplete RPC when the connection closes.
    pub fn deinit(self: *Stream) void {
        self.pending.deinit(self.allocator);
    }

    /// Decode complete RPCs from arbitrarily split or coalesced transport reads.
    /// Framing faults count against the peer; Service scores invalid RPC bodies.
    pub fn feed(self: *Stream, service: *Service, bytes: []const u8) !void {
        try service.peers.requirePeer(self.peer_id);
        errdefer self.reset();
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (!self.have_length) {
                const byte = bytes[offset];
                offset += 1;
                if (self.prefix_len == max_frame_prefix) {
                    service.peers.noteInvalid(self.peer_id);
                    return error.InvalidGossipFrame;
                }
                self.declared |= @as(usize, byte & 0x7f) << @intCast(self.prefix_len * 7);
                self.prefix_len += 1;
                if (byte & 0x80 != 0) {
                    if (self.prefix_len == max_frame_prefix) {
                        service.peers.noteInvalid(self.peer_id);
                        return error.InvalidGossipFrame;
                    }
                    continue;
                }
                if ((self.prefix_len > 1 and byte == 0) or self.declared > max_rpc_size) {
                    service.peers.noteInvalid(self.peer_id);
                    return error.InvalidGossipFrame;
                }
                self.have_length = true;
            }
            const take = @min(self.declared - self.pending.items.len, bytes.len - offset);
            try self.pending.appendSlice(self.allocator, bytes[offset..][0..take]);
            offset += take;
            if (self.pending.items.len != self.declared) continue;
            try service.receive(self.peer_id, self.pending.items);
            self.reset();
        }
    }

    /// Discard a partial frame after an error or connection loss.
    pub fn reset(self: *Stream) void {
        self.pending.clearRetainingCapacity();
        self.prefix_len = 0;
        self.declared = 0;
        self.have_length = false;
    }
};

/// Prefix one bounded protobuf RPC for a Gossipsub stream write.
pub fn encodeFrame(allocator: std.mem.Allocator, rpc: []const u8) ![]u8 {
    if (rpc.len > max_rpc_size) return error.PayloadTooLarge;
    var frame: std.ArrayList(u8) = .empty;
    errdefer frame.deinit(allocator);
    try appendVarint(allocator, &frame, rpc.len);
    try frame.appendSlice(allocator, rpc);
    return frame.toOwnedSlice(allocator);
}

/// Encode a StrictNoSign publish as one libp2p Gossipsub protobuf RPC.
pub fn encodePublish(allocator: std.mem.Allocator, topic: []const u8, data: []const u8) ![]u8 {
    if (topic.len == 0 or topic.len > max_topic_size or data.len > wire.max_payload_size) return error.PayloadTooLarge;
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try appendBytes(allocator, &message, MessageField.data, data);
    try appendBytes(allocator, &message, MessageField.topic, topic);
    var rpc: std.ArrayList(u8) = .empty;
    errdefer rpc.deinit(allocator);
    try appendBytes(allocator, &rpc, RpcField.publish, message.items);
    return rpc.toOwnedSlice(allocator);
}

/// Encode one subscription update in the libp2p Gossipsub RPC format.
pub fn encodeSubscription(allocator: std.mem.Allocator, topic: []const u8, subscribe: bool) ![]u8 {
    if (topic.len == 0 or topic.len > max_topic_size) return error.InvalidGossipRpc;
    var option: std.ArrayList(u8) = .empty;
    defer option.deinit(allocator);
    try appendVarint(allocator, &option, @as(u64, SubscriptionField.subscribe) << field_shift | WireType.varint);
    try appendVarint(allocator, &option, @intFromBool(subscribe));
    try appendBytes(allocator, &option, SubscriptionField.topic, topic);
    var rpc: std.ArrayList(u8) = .empty;
    errdefer rpc.deinit(allocator);
    try appendBytes(allocator, &rpc, RpcField.subscription, option.items);
    return rpc.toOwnedSlice(allocator);
}

/// Parse all subscription and publish fields before changing peer state.
fn decodeRpc(bytes: []const u8, max_data: usize) !Parsed {
    if (bytes.len > max_rpc_size) return error.PayloadTooLarge;
    var result = Parsed{};
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const key = try readVarint(bytes, &cursor);
        if (key >> field_shift == 0) return error.InvalidGossipRpc;
        switch (key >> field_shift) {
            RpcField.subscription => {
                if (key & wire_mask != WireType.bytes or result.subscription_len == max_subscriptions) return error.InvalidGossipRpc;
                result.subscriptions[result.subscription_len] = try decodeSubscription(try readBytes(bytes, &cursor));
                result.subscription_len += 1;
            },
            RpcField.publish => {
                if (key & wire_mask != WireType.bytes or result.publish_len == max_publishes) return error.InvalidGossipRpc;
                result.publishes[result.publish_len] = try decodeMessage(try readBytes(bytes, &cursor), max_data);
                result.publish_len += 1;
            },
            else => try skipField(bytes, &cursor, @truncate(key & wire_mask)),
        }
    }
    return result;
}

/// Read one subscription update with a canonical boolean and topic.
fn decodeSubscription(bytes: []const u8) !Subscription {
    var cursor: usize = 0;
    var subscribe: ?bool = null;
    var topic: ?[]const u8 = null;
    while (cursor < bytes.len) {
        const key = try readVarint(bytes, &cursor);
        switch (key >> field_shift) {
            SubscriptionField.subscribe => {
                if (key & wire_mask != WireType.varint or subscribe != null) return error.InvalidGossipRpc;
                const value = try readVarint(bytes, &cursor);
                if (value > 1) return error.InvalidGossipRpc;
                subscribe = value == 1;
            },
            SubscriptionField.topic => {
                if (key & wire_mask != WireType.bytes or topic != null) return error.InvalidGossipRpc;
                topic = try readBytes(bytes, &cursor);
                if (topic.?.len == 0 or topic.?.len > max_topic_size) return error.InvalidGossipRpc;
            },
            0 => return error.InvalidGossipRpc,
            else => try skipField(bytes, &cursor, @truncate(key & wire_mask)),
        }
    }
    return .{ .topic = topic orelse return error.InvalidGossipRpc, .subscribe = subscribe orelse return error.InvalidGossipRpc };
}

/// Require one topic and data field, with Ethereum's unsigned gossip policy.
fn decodeMessage(bytes: []const u8, max_data: usize) !Publish {
    var cursor: usize = 0;
    var topic: ?[]const u8 = null;
    var data: ?[]const u8 = null;
    while (cursor < bytes.len) {
        const key = try readVarint(bytes, &cursor);
        const field = key >> field_shift;
        if (field == 0) return error.InvalidGossipRpc;
        switch (field) {
            MessageField.data => {
                if (key & wire_mask != WireType.bytes or data != null) return error.InvalidGossipRpc;
                data = try readBytes(bytes, &cursor);
                if (data.?.len > max_data) return error.PayloadTooLarge;
            },
            MessageField.topic => {
                if (key & wire_mask != WireType.bytes or topic != null) return error.InvalidGossipRpc;
                topic = try readBytes(bytes, &cursor);
                if (topic.?.len == 0 or topic.?.len > max_topic_size) return error.InvalidGossipRpc;
            },
            MessageField.from, MessageField.seqno, MessageField.signature, MessageField.key => return error.InvalidSignaturePolicy,
            else => try skipField(bytes, &cursor, @truncate(key & wire_mask)),
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
        WireType.varint => _ = try readVarint(bytes, cursor),
        WireType.fixed64 => {
            const size = @sizeOf(u64);
            if (bytes.len - cursor.* < size) return error.InvalidGossipRpc;
            cursor.* += size;
        },
        WireType.bytes => _ = try readBytes(bytes, cursor),
        WireType.fixed32 => {
            const size = @sizeOf(u32);
            if (bytes.len - cursor.* < size) return error.InvalidGossipRpc;
            cursor.* += size;
        },
        else => return error.InvalidGossipRpc,
    }
}

/// Append one length-delimited protobuf field to the caller's list.
fn appendBytes(allocator: std.mem.Allocator, output: *std.ArrayList(u8), field: u8, bytes: []const u8) !void {
    try appendVarint(allocator, output, @as(u64, field) << field_shift | WireType.bytes);
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
    try std.testing.expectEqual(@as(usize, 1), parsed.publish_len);
    try std.testing.expectEqualStrings("topic", parsed.publishes[0].topic);
    try std.testing.expectEqualStrings("data", parsed.publishes[0].data);
    try std.testing.expectError(error.InvalidGossipRpc, decodeRpc(&.{ 0x12, 0x80 }, 16));
    try std.testing.expectError(error.InvalidGossipRpc, decodeRpc(&.{ 0x12, 0x80, 0x00 }, 16));
    try std.testing.expectError(error.PayloadTooLarge, decodeRpc(encoded, 3));
    var signed_message: std.ArrayList(u8) = .empty;
    defer signed_message.deinit(allocator);
    try appendBytes(allocator, &signed_message, MessageField.from, "sender");
    try appendBytes(allocator, &signed_message, MessageField.data, "data");
    try appendBytes(allocator, &signed_message, MessageField.topic, "topic");
    var signed_rpc: std.ArrayList(u8) = .empty;
    defer signed_rpc.deinit(allocator);
    try appendBytes(allocator, &signed_rpc, RpcField.publish, signed_message.items);
    try std.testing.expectError(error.InvalidSignaturePolicy, decodeRpc(signed_rpc.items, 16));

    const unknown_field: u8 = 7;
    var extended: std.ArrayList(u8) = .empty;
    defer extended.deinit(allocator);
    try appendVarint(allocator, &extended, @as(u64, unknown_field) << field_shift | WireType.varint);
    try appendVarint(allocator, &extended, 300);
    try appendVarint(allocator, &extended, @as(u64, unknown_field) << field_shift | WireType.fixed64);
    try extended.appendSlice(allocator, &([_]u8{0} ** @sizeOf(u64)));
    try appendVarint(allocator, &extended, @as(u64, unknown_field) << field_shift | WireType.fixed32);
    try extended.appendSlice(allocator, &([_]u8{0} ** @sizeOf(u32)));
    try appendBytes(allocator, &extended, unknown_field, "ignored");
    try extended.appendSlice(allocator, encoded);
    try std.testing.expectEqual(@as(usize, 1), (try decodeRpc(extended.items, 16)).publish_len);

    var extended_message: std.ArrayList(u8) = .empty;
    defer extended_message.deinit(allocator);
    try appendBytes(allocator, &extended_message, MessageField.data, "data");
    try appendBytes(allocator, &extended_message, MessageField.topic, "topic");
    try appendBytes(allocator, &extended_message, unknown_field, "ignored");
    var extended_rpc: std.ArrayList(u8) = .empty;
    defer extended_rpc.deinit(allocator);
    try appendBytes(allocator, &extended_rpc, RpcField.publish, extended_message.items);
    try std.testing.expectEqual(@as(usize, 1), (try decodeRpc(extended_rpc.items, 16)).publish_len);
}

test "subscription RPC requires a bounded topic and canonical boolean" {
    const allocator = std.testing.allocator;
    const encoded = try encodeSubscription(allocator, "topic", true);
    defer allocator.free(encoded);
    const parsed = try decodeRpc(encoded, 16);
    try std.testing.expectEqual(@as(usize, 1), parsed.subscription_len);
    try std.testing.expect(parsed.subscriptions[0].subscribe);
    try std.testing.expectEqualStrings("topic", parsed.subscriptions[0].topic);
    try std.testing.expectError(error.InvalidGossipRpc, encodeSubscription(allocator, "", true));

    var option: std.ArrayList(u8) = .empty;
    defer option.deinit(allocator);
    try appendVarint(allocator, &option, @as(u64, SubscriptionField.subscribe) << field_shift | WireType.varint);
    try appendVarint(allocator, &option, 2);
    try appendBytes(allocator, &option, SubscriptionField.topic, "topic");
    var malformed: std.ArrayList(u8) = .empty;
    defer malformed.deinit(allocator);
    try appendBytes(allocator, &malformed, RpcField.subscription, option.items);
    try std.testing.expectError(error.InvalidGossipRpc, decodeRpc(malformed.items, 16));

    var excessive: std.ArrayList(u8) = .empty;
    defer excessive.deinit(allocator);
    for (0..max_subscriptions + 1) |_| try excessive.appendSlice(allocator, encoded);
    try std.testing.expectError(error.InvalidGossipRpc, decodeRpc(excessive.items, 16));
}

test "gossip stream assembles split RPCs and rejects bad length prefixes" {
    const allocator = std.testing.allocator;
    const fulu = @import("fulu");
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    const peer_id = [_]u8{2} ** 32;
    var unused: u8 = 0;
    const block_gate = ingress.BlockValidation{ .context = &unused, .validate = struct {
        /// Reject unexpected block delivery in this framing test.
        fn reject(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            return error.UnexpectedBlock;
        }
    }.reject };
    const att_gate = ingress.AttestationValidation{ .context = &unused, .validate = struct {
        /// Reject unexpected attestation delivery in this framing test.
        fn reject(_: *anyopaque, _: *const fulu.Attestation) !void {
            return error.UnexpectedAttestation;
        }
    }.reject };
    var service = try Service.init(allocator, config, .{ 1, 2, 3, 4 }, &.{}, 1, 4, block_gate, att_gate);
    defer service.deinit();
    try service.connect(peer_id);
    var stream = Stream.init(allocator, peer_id);
    defer stream.deinit();
    const subscribe_rpc = try encodeSubscription(allocator, service.block_topic, true);
    defer allocator.free(subscribe_rpc);
    const subscribe_frame = try encodeFrame(allocator, subscribe_rpc);
    defer allocator.free(subscribe_frame);
    var recipients: [1][32]u8 = undefined;
    try stream.feed(&service, subscribe_frame[0..1]);
    try stream.feed(&service, subscribe_frame[1..3]);
    try std.testing.expectEqual(@as(usize, 0), try service.recipients(service.block_topic, &recipients));
    try stream.feed(&service, subscribe_frame[3..]);
    try std.testing.expectEqual(@as(usize, 1), try service.recipients(service.block_topic, &recipients));

    const unsubscribe_rpc = try encodeSubscription(allocator, service.block_topic, false);
    defer allocator.free(unsubscribe_rpc);
    const unsubscribe_frame = try encodeFrame(allocator, unsubscribe_rpc);
    defer allocator.free(unsubscribe_frame);
    var combined: std.ArrayList(u8) = .empty;
    defer combined.deinit(allocator);
    try combined.appendSlice(allocator, unsubscribe_frame);
    try combined.appendSlice(allocator, subscribe_frame);
    try stream.feed(&service, combined.items);
    try std.testing.expectEqual(@as(usize, 1), try service.recipients(service.block_topic, &recipients));

    const long_topic = [_]u8{'x'} ** max_topic_size;
    const long_rpc = try encodeSubscription(allocator, &long_topic, true);
    defer allocator.free(long_rpc);
    const long_frame = try encodeFrame(allocator, long_rpc);
    defer allocator.free(long_frame);
    try std.testing.expect(long_frame[0] & 0x80 != 0);
    try stream.feed(&service, long_frame[0..1]);
    try stream.feed(&service, long_frame[1..]);
    try std.testing.expectEqual(@as(usize, 1), try service.recipients(service.block_topic, &recipients));

    try std.testing.expectError(error.InvalidGossipFrame, stream.feed(&service, &.{ 0x80, 0x00 }));
    var oversized: std.ArrayList(u8) = .empty;
    defer oversized.deinit(allocator);
    try appendVarint(allocator, &oversized, max_rpc_size + 1);
    try std.testing.expectError(error.InvalidGossipFrame, stream.feed(&service, oversized.items));
    const malformed = try encodeFrame(allocator, &.{ 0x12, 0x80 });
    defer allocator.free(malformed);
    try std.testing.expectError(error.InvalidGossipRpc, stream.feed(&service, malformed));
    try std.testing.expectEqual(@as(u8, 3), service.peers.state(peer_id).?.invalid_messages);
    try stream.feed(&service, unsubscribe_frame);
    try std.testing.expectEqual(@as(usize, 0), try service.recipients(service.block_topic, &recipients));
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
    var publisher = try Service.init(allocator, config, digest, &.{3}, 1, 3, block_gate, att_gate);
    defer publisher.deinit();
    try publisher.connect(bad_peer);
    var recipients: [1][32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try publisher.recipients(publisher.block_topic, &recipients));
    const block_subscribe = try encodeSubscription(allocator, service.block_topic, true);
    defer allocator.free(block_subscribe);
    var malformed_subscription_batch: std.ArrayList(u8) = .empty;
    defer malformed_subscription_batch.deinit(allocator);
    try malformed_subscription_batch.appendSlice(allocator, block_subscribe);
    try malformed_subscription_batch.appendSlice(allocator, &.{ 0x12, 0x80 });
    try std.testing.expectError(error.InvalidGossipRpc, publisher.receive(bad_peer, malformed_subscription_batch.items));
    try std.testing.expectEqual(@as(usize, 0), try publisher.recipients(publisher.block_topic, &recipients));
    try publisher.receive(bad_peer, block_subscribe);
    try std.testing.expectEqual(@as(usize, 1), try publisher.recipients(publisher.block_topic, &recipients));
    try std.testing.expectEqual(bad_peer, recipients[0]);
    try std.testing.expectError(error.BufferTooSmall, publisher.recipients(publisher.block_topic, recipients[0..0]));
    const block_data = try wire.encodeGossip(allocator, raw_block, config.max_encoded_size);
    defer allocator.free(block_data);
    const block_rpc = try encodePublish(allocator, service.block_topic, block_data);
    defer allocator.free(block_rpc);
    const block_frame = try encodeFrame(allocator, block_rpc);
    defer allocator.free(block_frame);
    var block_stream = Stream.init(allocator, good_peer);
    defer block_stream.deinit();
    try block_stream.feed(&service, block_frame[0 .. block_frame.len / 2]);
    try std.testing.expectEqual(@as(usize, 0), counts.blocks);
    try block_stream.feed(&service, block_frame[block_frame.len / 2 ..]);
    try service.receive(good_peer, block_rpc);
    try std.testing.expectEqual(@as(usize, 1), counts.blocks);
    const att_data = try wire.encodeGossip(allocator, raw_attestation, config.max_encoded_size);
    defer allocator.free(att_data);
    const att_subscribe = try encodeSubscription(allocator, service.attestation_topics[3].?, true);
    defer allocator.free(att_subscribe);
    try publisher.receive(bad_peer, att_subscribe);
    try std.testing.expectEqual(@as(usize, 1), try publisher.recipients(publisher.attestation_topics[3].?, &recipients));
    const att_rpc = try encodePublish(allocator, service.attestation_topics[3].?, att_data);
    defer allocator.free(att_rpc);
    const att_frame = try encodeFrame(allocator, att_rpc);
    defer allocator.free(att_frame);
    try block_stream.feed(&service, att_frame);
    try std.testing.expectEqual(@as(usize, 1), counts.attestations);
    const other_topic = try wire.topicName(allocator, digest, .attestation, 4);
    defer allocator.free(other_topic);
    const other_rpc = try encodePublish(allocator, other_topic, att_data);
    defer allocator.free(other_rpc);
    try service.receive(good_peer, other_rpc);
    try std.testing.expectEqual(@as(usize, 1), counts.attestations);
    try std.testing.expectError(error.UnknownTopic, publisher.recipients(other_topic, &recipients));
    const att_unsubscribe = try encodeSubscription(allocator, service.attestation_topics[3].?, false);
    defer allocator.free(att_unsubscribe);
    try publisher.receive(bad_peer, att_unsubscribe);
    try std.testing.expectEqual(@as(usize, 0), try publisher.recipients(publisher.attestation_topics[3].?, &recipients));
    publisher.disconnect(bad_peer);
    try publisher.connect(bad_peer);
    try std.testing.expectEqual(@as(usize, 0), try publisher.recipients(publisher.block_topic, &recipients));
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

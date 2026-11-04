// Gossipsub subscriptions and publishes arrive as protobuf RPCs from
// authenticated peers. Announce our block, aggregate, selected attestation,
// and sampled data-column topics on each new stream, then parse envelopes before
// changing remote subscriptions or delivering SSZ objects. Valid duplicates
// are suppressed; invalid messages
// count toward the existing peer ban threshold.
//
//   peer RPC -> bounded protobuf -> topic -> SSZ/consensus gate -> delivery
// One RPC carries at most 256 subscription updates and 16 publishes in 16 MiB.
// A stream prefixes each RPC with its unsigned varint byte length. Connection
// security and mesh control are separate work.
const std = @import("std");
const ingress = @import("p2p_ingress.zig");
const admission = @import("p2p_admission.zig");
const wire = @import("p2p_wire.zig");
const columns = @import("data_columns.zig");
const kzg = @import("execution").kzg;

pub const max_rpc_size: usize = 16 * 1024 * 1024;
const max_publishes: usize = 16;
const max_subscriptions: usize = 256;
const seen_capacity: usize = 1024;
const max_topic_size: usize = 128;
const max_frame_prefix: usize = 4;
const field_shift = 3;
const wire_mask = 0b111;
const RpcField = struct {
    const subscription = 1;
    const publish = 2;
    const control = 3;
};
const ControlField = struct {
    const graft = 3;
};
const GraftField = struct {
    const topic = 1;
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
const RemoteSubscriptions = struct { block: bool = false, aggregate: bool = false, attestations: u64 = 0, columns: [2]u64 = .{ 0, 0 } };
const TopicSelection = union(enum) { block, aggregate, attestation: u8, column: u8 };
const Parsed = struct {
    publishes: [max_publishes]Publish = undefined,
    publish_len: usize = 0,
    subscriptions: [max_subscriptions]Subscription = undefined,
    subscription_len: usize = 0,
};

/// Borrow the verified store, KZG setup, and known-block lookup for selected columns.
pub const ColumnRoute = struct {
    store: *columns.Store,
    settings: *const kzg.Settings,
    lookup: ingress.ColumnLookup,
};

pub const Service = struct {
    allocator: std.mem.Allocator,
    digest: [4]u8,
    block_topic: []u8,
    aggregate_topic: []u8,
    attestation_topics: [64]?[]u8,
    column_topics: [columns.column_count]?[]u8,
    column_route: ?ColumnRoute,
    block_validation: ingress.BlockValidation,
    attestation_validation: ingress.AttestationValidation,
    aggregate_validation: ingress.AggregateValidation,
    peers: admission.Admission,
    subscriptions: std.AutoHashMap([32]u8, RemoteSubscriptions),
    connection_counts: std.AutoHashMap([32]u8, u32),
    seen: std.AutoHashMap([20]u8, void),
    seen_order: [seen_capacity][20]u8 = undefined,
    seen_len: usize = 0,
    seen_next: usize = 0,

    /// Subscribe to one Fulu digest, selected attestation subnets, and the
    /// optional store's sampled columns. Callbacks, store, settings, and blob
    /// schedule must outlive the service.
    pub fn init(allocator: std.mem.Allocator, config: ingress.Config, digest: [4]u8, subnets: []const u8, max_peers: usize, invalid_limit: u8, block_validation: ingress.BlockValidation, attestation_validation: ingress.AttestationValidation, aggregate_validation: ingress.AggregateValidation, column_route: ?ColumnRoute) !Service {
        if (subnets.len > 64) return error.InvalidSubnet;
        var peers = try admission.Admission.init(allocator, config, max_peers, invalid_limit);
        errdefer peers.deinit();
        const block_topic = try wire.topicName(allocator, digest, .block, null);
        errdefer allocator.free(block_topic);
        const aggregate_topic = try wire.topicName(allocator, digest, .aggregate_attestation, null);
        errdefer allocator.free(aggregate_topic);
        var attestation_topics: [64]?[]u8 = .{null} ** 64;
        errdefer for (attestation_topics) |name| if (name) |owned| allocator.free(owned);
        for (subnets) |subnet| {
            if (subnet >= 64) return error.InvalidSubnet;
            if (attestation_topics[subnet] != null) continue;
            attestation_topics[subnet] = try wire.topicName(allocator, digest, .attestation, subnet);
        }
        var column_topics: [columns.column_count]?[]u8 = .{null} ** columns.column_count;
        errdefer for (column_topics) |name| if (name) |owned| allocator.free(owned);
        if (column_route) |route| {
            for (route.store.samples.values[0..route.store.samples.len]) |subnet| {
                column_topics[subnet] = try wire.topicName(allocator, digest, .data_column, subnet);
            }
        }
        var seen = std.AutoHashMap([20]u8, void).init(allocator);
        errdefer seen.deinit();
        try seen.ensureTotalCapacity(seen_capacity);
        var subscriptions = std.AutoHashMap([32]u8, RemoteSubscriptions).init(allocator);
        errdefer subscriptions.deinit();
        try subscriptions.ensureTotalCapacity(@intCast(max_peers));
        var connection_counts = std.AutoHashMap([32]u8, u32).init(allocator);
        errdefer connection_counts.deinit();
        try connection_counts.ensureTotalCapacity(@intCast(max_peers));
        return .{ .allocator = allocator, .digest = digest, .block_topic = block_topic, .aggregate_topic = aggregate_topic, .attestation_topics = attestation_topics, .column_topics = column_topics, .column_route = column_route, .block_validation = block_validation, .attestation_validation = attestation_validation, .aggregate_validation = aggregate_validation, .peers = peers, .subscriptions = subscriptions, .connection_counts = connection_counts, .seen = seen };
    }

    /// Release topic names, the bounded duplicate cache, and peer scores.
    pub fn deinit(self: *Service) void {
        self.seen.deinit();
        self.connection_counts.deinit();
        self.subscriptions.deinit();
        self.peers.deinit();
        for (self.attestation_topics) |name| if (name) |owned| self.allocator.free(owned);
        for (self.column_topics) |name| if (name) |owned| self.allocator.free(owned);
        self.allocator.free(self.aggregate_topic);
        self.allocator.free(self.block_topic);
    }

    /// Admit a transport-authenticated peer and count this gossip stream.
    /// libp2p uses one outbound and one inbound stream per peer, so admission
    /// ends only when the last stream closes.
    pub fn connect(self: *Service, peer_id: [32]u8) !void {
        const entry = try self.connection_counts.getOrPut(peer_id);
        if (entry.found_existing) {
            entry.value_ptr.* += 1;
            return;
        }
        entry.value_ptr.* = 1;
        errdefer _ = self.connection_counts.remove(peer_id);
        try self.peers.connect(peer_id);
        self.subscriptions.putAssumeCapacity(peer_id, .{});
    }

    /// Drop one gossip stream while retaining the peer's score until the last
    /// stream closes.
    pub fn disconnect(self: *Service, peer_id: [32]u8) void {
        const entry = self.connection_counts.getPtr(peer_id) orelse return;
        if (entry.* > 1) {
            entry.* -= 1;
            return;
        }
        _ = self.connection_counts.remove(peer_id);
        self.peers.disconnect(peer_id);
        _ = self.subscriptions.remove(peer_id);
    }

    /// Copy connected, unbanned peers subscribed to a local gossip topic.
    /// Returns BufferTooSmall without writing beyond the caller's output slice.
    pub fn recipients(self: *Service, name: []const u8, output: [][32]u8) !usize {
        const selected = self.classify(name) orelse return error.UnknownTopic;
        var count: usize = 0;
        var iterator = self.subscriptions.iterator();
        while (iterator.next()) |entry| {
            const interested = switch (selected) {
                .block => entry.value_ptr.block,
                .aggregate => entry.value_ptr.aggregate,
                .attestation => |subnet| entry.value_ptr.attestations & (@as(u64, 1) << @intCast(subnet)) != 0,
                .column => |subnet| entry.value_ptr.columns[subnet / 64] & (@as(u64, 1) << @intCast(subnet % 64)) != 0,
            };
            if (!interested) continue;
            self.peers.requirePeer(entry.key_ptr.*) catch continue;
            if (count == output.len) return error.BufferTooSmall;
            output[count] = entry.key_ptr.*;
            count += 1;
        }
        return count;
    }

    /// Report whether one connected peer announced the Fulu block topic.
    pub fn remoteBlockSubscribed(self: *const Service, peer_id: [32]u8) bool {
        const remote = self.subscriptions.get(peer_id) orelse return false;
        return remote.block;
    }

    /// Return one connected peer's data-column subscription bits, if known.
    pub fn remoteColumnMask(self: *const Service, peer_id: [32]u8) ?[2]u64 {
        const remote = self.subscriptions.get(peer_id) orelse return null;
        return remote.columns;
    }

    /// Encode this node's block and selected attestation subscriptions as one
    /// framed RPC to send when a peer's gossip stream opens or reconnects.
    pub fn localSubscriptionFrame(self: *const Service) ![]u8 {
        var rpc: std.ArrayList(u8) = .empty;
        defer rpc.deinit(self.allocator);
        var control: std.ArrayList(u8) = .empty;
        defer control.deinit(self.allocator);
        try appendSubscription(self.allocator, &rpc, self.block_topic, true);
        try appendSubscription(self.allocator, &rpc, self.aggregate_topic, true);
        try appendGraft(self.allocator, &control, self.block_topic);
        try appendGraft(self.allocator, &control, self.aggregate_topic);
        for (self.attestation_topics) |maybe_name| {
            const name = maybe_name orelse continue;
            try appendSubscription(self.allocator, &rpc, name, true);
            try appendGraft(self.allocator, &control, name);
        }
        for (self.column_topics) |maybe_name| {
            const name = maybe_name orelse continue;
            try appendSubscription(self.allocator, &rpc, name, true);
            try appendGraft(self.allocator, &control, name);
        }
        try appendBytes(self.allocator, &rpc, RpcField.control, control.items);
        return encodeFrame(self.allocator, rpc.items);
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
                .aggregate => remote.aggregate = subscription.subscribe,
                .attestation => |subnet| {
                    const mask = @as(u64, 1) << @intCast(subnet);
                    if (subscription.subscribe) remote.attestations |= mask else remote.attestations &= ~mask;
                },
                .column => |subnet| {
                    const mask = @as(u64, 1) << @intCast(subnet % 64);
                    if (subscription.subscribe) remote.columns[subnet / 64] |= mask else remote.columns[subnet / 64] &= ~mask;
                },
            }
        }
        for (parsed.publishes[0..parsed.publish_len]) |publish| {
            const selected = self.classify(publish.topic) orelse continue;
            const hash = try messageHash(self, publish);
            if (self.seen.contains(hash)) continue;
            self.noteSeen(hash);
            switch (selected) {
                .block => try self.peers.receiveBlock(peer_id, self.digest, publish.data, self.block_validation),
                .aggregate => try self.peers.receiveAggregate(peer_id, self.digest, publish.data, self.aggregate_validation),
                .attestation => try self.peers.receiveAttestation(peer_id, self.digest, publish.data, self.attestation_validation),
                .column => |subnet| {
                    const route = self.column_route.?;
                    try self.peers.receiveColumn(peer_id, self.digest, subnet, publish.data, route.store, route.settings, route.lookup);
                },
            }
        }
    }

    /// Record a gossipsub message ID before validation so redelivery is ignored.
    fn noteSeen(self: *Service, hash: [20]u8) void {
        if (self.seen_len == seen_capacity) {
            _ = self.seen.remove(self.seen_order[self.seen_next]);
        } else {
            self.seen_len += 1;
        }
        self.seen.putAssumeCapacity(hash, {});
        self.seen_order[self.seen_next] = hash;
        self.seen_next = (self.seen_next + 1) % seen_capacity;
    }

    /// Match only topics this service follows at its configured fork digest.
    fn classify(self: *const Service, name: []const u8) ?TopicSelection {
        if (std.mem.eql(u8, name, self.block_topic)) return .block;
        if (std.mem.eql(u8, name, self.aggregate_topic)) return .aggregate;
        for (self.attestation_topics, 0..) |maybe_name, subnet| {
            const topic_name = maybe_name orelse continue;
            if (std.mem.eql(u8, name, topic_name)) return .{ .attestation = @intCast(subnet) };
        }
        for (self.column_topics, 0..) |maybe_name, subnet| {
            const topic_name = maybe_name orelse continue;
            if (std.mem.eql(u8, name, topic_name)) return .{ .column = @intCast(subnet) };
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
    var rpc: std.ArrayList(u8) = .empty;
    errdefer rpc.deinit(allocator);
    try appendSubscription(allocator, &rpc, topic, subscribe);
    return rpc.toOwnedSlice(allocator);
}

/// Append one bounded topic update to a protobuf RPC under construction.
fn appendSubscription(allocator: std.mem.Allocator, rpc: *std.ArrayList(u8), topic: []const u8, subscribe: bool) !void {
    if (topic.len == 0 or topic.len > max_topic_size) return error.InvalidGossipRpc;
    var option: std.ArrayList(u8) = .empty;
    defer option.deinit(allocator);
    try appendVarint(allocator, &option, @as(u64, SubscriptionField.subscribe) << field_shift | WireType.varint);
    try appendVarint(allocator, &option, @intFromBool(subscribe));
    try appendBytes(allocator, &option, SubscriptionField.topic, topic);
    try appendBytes(allocator, rpc, RpcField.subscription, option.items);
}

/// Append one GRAFT entry to a libp2p ControlMessage under construction.
fn appendGraft(allocator: std.mem.Allocator, control: *std.ArrayList(u8), topic: []const u8) !void {
    if (topic.len == 0 or topic.len > max_topic_size) return error.InvalidGossipRpc;
    var graft: std.ArrayList(u8) = .empty;
    defer graft.deinit(allocator);
    try appendBytes(allocator, &graft, GraftField.topic, topic);
    try appendBytes(allocator, control, ControlField.graft, graft.items);
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

/// Hash a gossipsub message with the post-Altair Ethereum message ID domain.
/// A valid Snappy block hashes its decompressed bytes; malformed data hashes
/// the raw wire bytes so duplicate suppression still matches libp2p.
fn messageHash(self: *Service, publish: Publish) ![20]u8 {
    const decoded = wire.decodeGossip(self.allocator, publish.data, self.peers.config.max_encoded_size) catch null;
    defer if (decoded) |bytes| self.allocator.free(bytes);
    const payload = decoded orelse publish.data;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    if (decoded == null) {
        hasher.update(&.{ 0, 0, 0, 0 });
    } else {
        hasher.update(&.{ 1, 0, 0, 0 });
    }
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, publish.topic.len, .little);
    hasher.update(&length);
    hasher.update(publish.topic);
    hasher.update(payload);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest[0..20].*;
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

/// Collect GRAFT topic IDs from a framed RPC so tests assert the wire nesting.
fn collectGraftTopics(allocator: std.mem.Allocator, frame: []const u8) ![][]const u8 {
    var cursor: usize = 0;
    _ = try readVarint(frame, &cursor);
    const rpc = frame[cursor..];
    cursor = 0;
    var topics: std.ArrayList([]const u8) = .empty;
    errdefer topics.deinit(allocator);
    while (cursor < rpc.len) {
        const key = try readVarint(rpc, &cursor);
        if (key >> field_shift != RpcField.control) {
            try skipField(rpc, &cursor, @truncate(key & wire_mask));
            continue;
        }
        if (key & wire_mask != WireType.bytes) return error.InvalidGossipRpc;
        const control = try readBytes(rpc, &cursor);
        var control_cursor: usize = 0;
        while (control_cursor < control.len) {
            const control_key = try readVarint(control, &control_cursor);
            if (control_key >> field_shift != ControlField.graft) {
                try skipField(control, &control_cursor, @truncate(control_key & wire_mask));
                continue;
            }
            if (control_key & wire_mask != WireType.bytes) return error.InvalidGossipRpc;
            const graft = try readBytes(control, &control_cursor);
            var graft_cursor: usize = 0;
            var topic: ?[]const u8 = null;
            while (graft_cursor < graft.len) {
                const graft_key = try readVarint(graft, &graft_cursor);
                if (graft_key >> field_shift != GraftField.topic) {
                    try skipField(graft, &graft_cursor, @truncate(graft_key & wire_mask));
                    continue;
                }
                if (graft_key & wire_mask != WireType.bytes or topic != null) return error.InvalidGossipRpc;
                topic = try readBytes(graft, &graft_cursor);
            }
            try topics.append(allocator, topic orelse return error.InvalidGossipRpc);
        }
    }
    return topics.toOwnedSlice(allocator);
}

test "local subscriptions announce GRAFT inside the control message" {
    const fulu = @import("fulu");
    const allocator = std.testing.allocator;
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    var unused: u8 = 0;
    const block_gate = ingress.BlockValidation{ .context = &unused, .validate = struct {
        /// Accept blocks in this wire-shape test.
        fn accept(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {}
    }.accept };
    const attestation_gate = ingress.AttestationValidation{ .context = &unused, .validate = struct {
        /// Accept attestations in this wire-shape test.
        fn accept(_: *anyopaque, _: *const fulu.Attestation) !void {}
    }.accept };
    const aggregate_gate = ingress.AggregateValidation{ .context = &unused, .validate = struct {
        /// Accept aggregates in this wire-shape test.
        fn accept(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    }.accept };
    var service = try Service.init(allocator, config, .{ 1, 2, 3, 4 }, &.{}, 1, 3, block_gate, attestation_gate, aggregate_gate, null);
    defer service.deinit();
    const frame = try service.localSubscriptionFrame();
    defer allocator.free(frame);
    const topics = try collectGraftTopics(allocator, frame);
    defer allocator.free(topics);
    try std.testing.expectEqual(@as(usize, 2), topics.len);
    try std.testing.expectEqualStrings(service.block_topic, topics[0]);
    try std.testing.expectEqualStrings(service.aggregate_topic, topics[1]);
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
    const aggregate_gate = ingress.AggregateValidation{ .context = &unused, .validate = struct {
        /// Reject unexpected aggregate delivery in this framing test.
        fn reject(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {
            return error.UnexpectedAggregate;
        }
    }.reject };
    var service = try Service.init(allocator, config, .{ 1, 2, 3, 4 }, &.{}, 1, 4, block_gate, att_gate, aggregate_gate, null);
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

test "duplicate invalid gossip is ignored before validation" {
    const fulu = @import("fulu");
    const allocator = std.testing.allocator;
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    var unused: u8 = 0;
    const block_gate = ingress.BlockValidation{ .context = &unused, .validate = struct {
        /// Accept blocks reaching the callback; malformed SSZ fails earlier.
        fn accept(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {}
    }.accept };
    const attestation_gate = ingress.AttestationValidation{ .context = &unused, .validate = struct {
        /// Accept attestations unused by this duplicate test.
        fn accept(_: *anyopaque, _: *const fulu.Attestation) !void {}
    }.accept };
    const aggregate_gate = ingress.AggregateValidation{ .context = &unused, .validate = struct {
        /// Accept aggregates unused by this duplicate test.
        fn accept(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    }.accept };
    var service = try Service.init(allocator, config, .{ 1, 2, 3, 4 }, &.{}, 1, 5, block_gate, attestation_gate, aggregate_gate, null);
    defer service.deinit();
    const peer = [_]u8{2} ** 32;
    try service.connect(peer);
    const malformed = try wire.encodeGossip(allocator, &.{0}, config.max_encoded_size);
    defer allocator.free(malformed);
    const rpc = try encodePublish(allocator, service.block_topic, malformed);
    defer allocator.free(rpc);
    try std.testing.expectError(error.EndOfStream, service.receive(peer, rpc));
    try std.testing.expectEqual(@as(u8, 1), service.peers.state(peer).?.invalid_messages);
    try service.receive(peer, rpc);
    try std.testing.expectEqual(@as(u8, 1), service.peers.state(peer).?.invalid_messages);
}

test "gossip RPC validates blocks attestations and aggregates before delivery" {
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
    const Counts = struct { blocks: usize = 0, attestations: usize = 0, aggregates: usize = 0 };
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
    const aggregate_gate = ingress.AggregateValidation{ .context = &counts, .validate = struct {
        /// Count a signed aggregate only after its ingress checks pass.
        fn check(context: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {
            const state: *Counts = @ptrCast(@alignCast(context));
            state.aggregates += 1;
        }
    }.check };
    const bad_peer = [_]u8{1} ** 32;
    const good_peer = [_]u8{2} ** 32;
    try std.testing.expectError(error.InvalidSubnet, Service.init(allocator, config, digest, &.{64}, 2, 3, block_gate, att_gate, aggregate_gate, null));
    var service = try Service.init(allocator, config, digest, &.{3}, 2, 3, block_gate, att_gate, aggregate_gate, null);
    defer service.deinit();
    try service.connect(bad_peer);
    try service.connect(good_peer);
    var publisher = try Service.init(allocator, config, digest, &.{3}, 1, 3, block_gate, att_gate, aggregate_gate, null);
    defer publisher.deinit();
    try publisher.connect(bad_peer);
    const publisher_frame = try publisher.localSubscriptionFrame();
    defer allocator.free(publisher_frame);
    var remote_stream = Stream.init(allocator, bad_peer);
    defer remote_stream.deinit();
    try remote_stream.feed(&service, publisher_frame);
    var recipients: [1][32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try service.recipients(service.block_topic, &recipients));
    try std.testing.expectEqual(bad_peer, recipients[0]);
    try std.testing.expectEqual(@as(usize, 0), try publisher.recipients(publisher.block_topic, &recipients));
    const block_subscribe = try encodeSubscription(allocator, service.block_topic, true);
    defer allocator.free(block_subscribe);
    var malformed_subscription_batch: std.ArrayList(u8) = .empty;
    defer malformed_subscription_batch.deinit(allocator);
    try malformed_subscription_batch.appendSlice(allocator, block_subscribe);
    try malformed_subscription_batch.appendSlice(allocator, &.{ 0x12, 0x80 });
    try std.testing.expectError(error.InvalidGossipRpc, publisher.receive(bad_peer, malformed_subscription_batch.items));
    try std.testing.expectEqual(@as(usize, 0), try publisher.recipients(publisher.block_topic, &recipients));
    const subscriptions_frame = try service.localSubscriptionFrame();
    defer allocator.free(subscriptions_frame);
    var subscription_stream = Stream.init(allocator, bad_peer);
    defer subscription_stream.deinit();
    try subscription_stream.feed(&publisher, subscriptions_frame[0 .. subscriptions_frame.len / 2]);
    try std.testing.expectEqual(@as(usize, 0), try publisher.recipients(publisher.block_topic, &recipients));
    try subscription_stream.feed(&publisher, subscriptions_frame[subscriptions_frame.len / 2 ..]);
    try std.testing.expectEqual(@as(usize, 1), try publisher.recipients(publisher.block_topic, &recipients));
    try std.testing.expectEqual(bad_peer, recipients[0]);
    try std.testing.expectEqual(@as(usize, 1), try publisher.recipients(publisher.aggregate_topic, &recipients));
    try std.testing.expectEqual(@as(usize, 1), try publisher.recipients(publisher.attestation_topics[3].?, &recipients));
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
    const att_rpc = try encodePublish(allocator, service.attestation_topics[3].?, att_data);
    defer allocator.free(att_rpc);
    const att_frame = try encodeFrame(allocator, att_rpc);
    defer allocator.free(att_frame);
    try block_stream.feed(&service, att_frame);
    try std.testing.expectEqual(@as(usize, 1), counts.attestations);
    const signed_aggregate = fulu.SignedAggregateAndProof{
        .message = .{ .aggregator_index = 1, .aggregate = attestation, .selection_proof = [_]u8{0} ** 96 },
        .signature = [_]u8{0} ** 96,
    };
    const aggregate_ssz = try ssz.serializeAlloc(allocator, signed_aggregate);
    defer allocator.free(aggregate_ssz);
    const aggregate_data = try wire.encodeGossip(allocator, aggregate_ssz, config.max_encoded_size);
    defer allocator.free(aggregate_data);
    const aggregate_rpc = try encodePublish(allocator, service.aggregate_topic, aggregate_data);
    defer allocator.free(aggregate_rpc);
    const aggregate_frame = try encodeFrame(allocator, aggregate_rpc);
    defer allocator.free(aggregate_frame);
    try block_stream.feed(&service, aggregate_frame);
    try block_stream.feed(&service, aggregate_frame);
    try std.testing.expectEqual(@as(usize, 1), counts.aggregates);
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
    var reconnected_stream = Stream.init(allocator, bad_peer);
    defer reconnected_stream.deinit();
    try reconnected_stream.feed(&publisher, subscriptions_frame);
    try std.testing.expectEqual(@as(usize, 1), try publisher.recipients(publisher.block_topic, &recipients));
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
    try std.testing.expectEqual(@as(usize, 0), try service.recipients(service.block_topic, &recipients));
    try std.testing.expectEqual(@as(usize, 1), counts.blocks);
    service.disconnect(good_peer);
    try std.testing.expectError(error.PeerDisconnected, service.receive(good_peer, att_rpc));
    try service.connect(good_peer);
    try std.testing.expectEqual(@as(u8, 0), service.peers.state(good_peer).?.invalid_messages);
    try service.receive(good_peer, block_rpc);
    try std.testing.expectEqual(@as(usize, 2), counts.blocks);

    var wrong_digest = digest;
    wrong_digest[0] ^= 1;
    var wrong = try Service.init(allocator, config, wrong_digest, &.{}, 1, 3, block_gate, att_gate, aggregate_gate, null);
    defer wrong.deinit();
    try wrong.connect(bad_peer);
    const wrong_rpc = try encodePublish(allocator, wrong.block_topic, block_data);
    defer allocator.free(wrong_rpc);
    try std.testing.expectError(error.InvalidForkContext, wrong.receive(bad_peer, wrong_rpc));
    try std.testing.expectEqual(@as(u8, 1), wrong.peers.state(bad_peer).?.invalid_messages);
    try std.testing.expectEqual(@as(usize, 2), counts.blocks);

    var small_config = config;
    small_config.max_encoded_size = 1;
    var bounded = try Service.init(allocator, small_config, digest, &.{}, 1, 3, block_gate, att_gate, aggregate_gate, null);
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
    var local_error = try Service.init(allocator, config, digest, &.{}, 1, 3, local_gate, att_gate, aggregate_gate, null);
    defer local_error.deinit();
    try local_error.connect(bad_peer);
    try std.testing.expectError(error.LocalUnavailable, local_error.receive(bad_peer, block_rpc));
    try std.testing.expectEqual(@as(u8, 0), local_error.peers.state(bad_peer).?.invalid_messages);
}

test "column gossip retains only verified selected sidecars" {
    const fixture = @import("fixture_runner.zig");
    const fulu = @import("fulu");
    const ssz = @import("ssz");
    const merkle = @import("merkle");
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    var state = try fixture.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var signed = try fixture.decodeBlock(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    const root = try merkle.HashTreeRoot(allocator, signed.message);
    const digest = try config.digestAtSlot(signed.message.slot);
    const sidecar_bytes = try fixture.decode(allocator, @embedFile("fixtures/fulu_data_columns/sample_01.ssz_snappy"));
    defer allocator.free(sidecar_bytes);
    const sidecar_data = try wire.encodeGossip(allocator, sidecar_bytes, config.max_encoded_size);
    defer allocator.free(sidecar_data);
    var settings = try kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    var store = try columns.Store.open(allocator, std.testing.io, tmp.dir, "columns", [_]u8{9} ** 32, [_]u8{0} ** 32, columns.custody_requirement);
    defer store.deinit();
    try std.testing.expect(store.samples.contains(1));
    const Known = struct { block: *const fulu.BeaconBlock, parent_state: *const fulu.BeaconState, present: bool = true };
    var known = Known{ .block = &signed.message, .parent_state = &state };
    const lookup = ingress.ColumnLookup{ .context = &known, .resolve = struct {
        /// Supply the borrowed block and parent state for this test's known header.
        fn resolve(context: *anyopaque, _: *const fulu.SignedBeaconBlockHeader) ?ingress.ColumnBlock {
            const source: *Known = @ptrCast(@alignCast(context));
            if (!source.present) return null;
            return .{ .block = source.block, .parent_state = source.parent_state };
        }
    }.resolve };
    var unused: u8 = 0;
    const block_gate = ingress.BlockValidation{ .context = &unused, .validate = struct {
        /// Reject unexpected block delivery in this column test.
        fn reject(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            return error.UnexpectedBlock;
        }
    }.reject };
    const att_gate = ingress.AttestationValidation{ .context = &unused, .validate = struct {
        /// Reject unexpected attestation delivery in this column test.
        fn reject(_: *anyopaque, _: *const fulu.Attestation) !void {
            return error.UnexpectedAttestation;
        }
    }.reject };
    const aggregate_gate = ingress.AggregateValidation{ .context = &unused, .validate = struct {
        /// Reject unexpected aggregate delivery in this column test.
        fn reject(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {
            return error.UnexpectedAggregate;
        }
    }.reject };
    const route = ColumnRoute{ .store = &store, .settings = &settings, .lookup = lookup };
    var service = try Service.init(allocator, config, digest, &.{}, 1, 5, block_gate, att_gate, aggregate_gate, route);
    defer service.deinit();
    const peer = [_]u8{2} ** 32;
    try service.connect(peer);
    const topic = service.column_topics[1].?;
    const rpc = try encodePublish(allocator, topic, sidecar_data);
    defer allocator.free(rpc);
    const frame = try encodeFrame(allocator, rpc);
    defer allocator.free(frame);
    var stream = Stream.init(allocator, peer);
    defer stream.deinit();
    var recipients: [1][32]u8 = undefined;
    const announcement = try service.localSubscriptionFrame();
    defer allocator.free(announcement);
    try stream.feed(&service, announcement);
    try std.testing.expectEqual(@as(usize, 1), try service.recipients(topic, &recipients));
    try std.testing.expectEqual(peer, recipients[0]);

    var wrong_digest = digest;
    wrong_digest[0] ^= 1;
    var wrong_fork = try Service.init(allocator, config, wrong_digest, &.{}, 1, 5, block_gate, att_gate, aggregate_gate, route);
    defer wrong_fork.deinit();
    try wrong_fork.connect(peer);
    const wrong_fork_rpc = try encodePublish(allocator, wrong_fork.column_topics[1].?, sidecar_data);
    defer allocator.free(wrong_fork_rpc);
    try std.testing.expectError(error.InvalidForkContext, wrong_fork.receive(peer, wrong_fork_rpc));
    try std.testing.expect((try store.get(root, 1)) == null);

    const other_subnet = if (store.samples.values[0] == 1) store.samples.values[1] else store.samples.values[0];
    const wrong_subnet_rpc = try encodePublish(allocator, service.column_topics[other_subnet].?, sidecar_data);
    defer allocator.free(wrong_subnet_rpc);
    try std.testing.expectError(error.InvalidDataColumn, service.receive(peer, wrong_subnet_rpc));
    const malformed_ssz = try wire.encodeGossip(allocator, &.{0}, config.max_encoded_size);
    defer allocator.free(malformed_ssz);
    const malformed_rpc = try encodePublish(allocator, topic, malformed_ssz);
    defer allocator.free(malformed_rpc);
    try std.testing.expectError(error.EndOfStream, service.receive(peer, malformed_rpc));
    try std.testing.expect((try store.get(root, 1)) == null);

    known.present = false;
    try std.testing.expectError(error.UnknownBlock, stream.feed(&service, frame));
    try std.testing.expectEqual(@as(u8, 2), service.peers.state(peer).?.invalid_messages);
    try std.testing.expect((try store.get(root, 1)) == null);
    known.present = true;
    service.seen.clearRetainingCapacity();
    service.seen_len = 0;
    service.seen_next = 0;
    var wrong_block = signed.message;
    wrong_block.parent_root[0] ^= 1;
    known.block = &wrong_block;
    try std.testing.expectError(error.WrongBlock, stream.feed(&service, frame));
    known.block = &signed.message;
    try std.testing.expect((try store.get(root, 1)) == null);

    var reader: std.Io.Reader = .fixed(sidecar_bytes);
    const sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &reader);
    defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, sidecar);
    var altered = sidecar;
    const bad_proofs = try allocator.dupe(fulu.KZGProof, sidecar.kzg_proofs.data);
    defer allocator.free(bad_proofs);
    bad_proofs[0][0] ^= 1;
    altered.kzg_proofs.data = bad_proofs;
    const altered_ssz = try ssz.serializeAlloc(allocator, altered);
    defer allocator.free(altered_ssz);
    const altered_data = try wire.encodeGossip(allocator, altered_ssz, config.max_encoded_size);
    defer allocator.free(altered_data);
    const altered_rpc = try encodePublish(allocator, topic, altered_data);
    defer allocator.free(altered_rpc);
    try std.testing.expectError(error.InvalidCellProof, service.receive(peer, altered_rpc));
    try std.testing.expect((try store.get(root, 1)) == null);
    try std.testing.expect(!(try store.available(root, &signed.message)));
    try std.testing.expectEqual(@as(u8, 4), service.peers.state(peer).?.invalid_messages);

    try stream.feed(&service, frame);
    try stream.feed(&service, frame);
    service.seen.clearRetainingCapacity();
    service.seen_len = 0;
    service.seen_next = 0;
    try stream.feed(&service, frame);
    const stored = (try store.get(root, 1)).?;
    defer allocator.free(stored);
    try std.testing.expect(!(try store.available(root, &signed.message)));
    try std.testing.expectEqual(@as(u8, 4), service.peers.state(peer).?.invalid_messages);
}

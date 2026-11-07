// A Gossipsub stream begins with multistream-select negotiation. After the
// exact gossip ID is echoed, both peers announce their selected Fulu topics;
// later framed publishes pass through the existing fork and consensus gates.
// One session owns one authenticated peer stream. Disconnect discards partial
// negotiation and RPC bytes, while the service retains that peer's score.
//
// authenticated stream -> negotiation -> subscriptions -> validated RPCs
// Negotiation lines are at most 128 bytes; RPCs are at most 16 MiB.
const std = @import("std");
const multistream = @import("p2p_multistream.zig");
const gossip = @import("p2p_gossip.zig");

pub const Role = enum { initiator, responder };

pub const Session = struct {
    allocator: std.mem.Allocator,
    service: *gossip.Service,
    peer_id: [32]u8,
    initiator: ?multistream.Initiator,
    responder: multistream.Responder = .{ .allowed = .gossip },
    stream: gossip.Stream,
    selected: bool = false,

    pub const Result = struct {
        consumed: usize,
        /// The caller owns and sends each non-null byte slice in order.
        reply: ?[]u8 = null,
        subscription: ?[]u8 = null,

        /// Release unsent output after the transport write or an error.
        pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
            if (self.reply) |bytes| allocator.free(bytes);
            if (self.subscription) |bytes| allocator.free(bytes);
        }
    };

    /// Bind one authenticated peer identity and admit this stream to the
    /// gossip service. A peer may have one initiator and one responder stream.
    pub fn init(allocator: std.mem.Allocator, service: *gossip.Service, peer_id: [32]u8, role: Role) !Session {
        try service.connect(peer_id);
        return .{
            .allocator = allocator,
            .service = service,
            .peer_id = peer_id,
            .initiator = if (role == .initiator) .{ .protocol = .gossip } else null,
            .stream = gossip.Stream.init(allocator, peer_id),
        };
    }

    /// Return the initiator's opening bytes; the caller frees them after write.
    pub fn opening(self: *const Session) ![]u8 {
        if (self.initiator == null or self.selected) return error.InvalidNegotiation;
        return multistream.offer(self.allocator, .gossip);
    }

    /// Read through one negotiation event, then route all later bytes as RPCs.
    /// Call again with input[result.consumed..] when bytes remain.
    pub fn feed(self: *Session, input: []const u8) !Result {
        try self.service.peers.requirePeer(self.peer_id);
        if (self.selected) {
            try self.stream.feed(self.service, input);
            return .{ .consumed = input.len };
        }
        if (self.initiator) |*state| {
            const parsed = state.feed(input) catch |err| {
                self.scoreNegotiation(err);
                return err;
            };
            if (!parsed.selected) return .{ .consumed = parsed.consumed };
            const subscription = try self.service.localSubscriptionFrame();
            self.selected = true;
            return .{ .consumed = parsed.consumed, .subscription = subscription };
        }
        const parsed = self.responder.feed(self.allocator, input) catch |err| {
            self.scoreNegotiation(err);
            return err;
        };
        if (parsed.selected == null) return .{ .consumed = parsed.consumed, .reply = parsed.response };
        errdefer self.allocator.free(parsed.response.?);
        const subscription = try self.service.localSubscriptionFrame();
        self.selected = true;
        return .{ .consumed = parsed.consumed, .reply = parsed.response, .subscription = subscription };
    }

    /// Drop partial bytes and remote subscriptions, keeping the peer's score.
    pub fn deinit(self: *Session) void {
        self.stream.deinit();
        self.service.disconnect(self.peer_id);
    }

    /// Penalize malformed negotiation bytes, not allocation or local failures.
    fn scoreNegotiation(self: *Session, err: anyerror) void {
        switch (err) {
            error.InvalidLength, error.InvalidLine, error.InvalidNegotiation => self.service.peers.noteInvalid(self.peer_id),
            else => {},
        }
    }
};

test "two authenticated gossip sessions negotiate, subscribe, and validate Fulu messages" {
    const allocator = std.testing.allocator;
    const fulu = @import("fulu");
    const ssz = @import("ssz");
    const fixture = @import("fixture_runner.zig");
    const ingress = @import("p2p_ingress.zig");
    const wire = @import("p2p_wire.zig");
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    const raw_block = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer allocator.free(raw_block);
    var reader: std.Io.Reader = .fixed(raw_block);
    const block = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
    const digest = try config.digestAtSlot(block.message.slot);
    const Counts = struct { blocks: usize = 0, attestations: usize = 0 };
    var counts = Counts{};
    const block_gate = ingress.BlockValidation{ .context = &counts, .validate = struct {
        /// Count only a decoded block that reached the consensus gate.
        fn accept(context: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            const state: *Counts = @ptrCast(@alignCast(context));
            state.blocks += 1;
        }
    }.accept };
    const att_gate = ingress.AttestationValidation{ .context = &counts, .validate = struct {
        /// Count only a decoded attestation that reached the consensus gate.
        fn accept(context: *anyopaque, _: *const fulu.Attestation) !void {
            const state: *Counts = @ptrCast(@alignCast(context));
            state.attestations += 1;
        }
    }.accept };
    const aggregate_gate = ingress.AggregateValidation{ .context = &counts, .validate = struct {
        /// Accept unused aggregate traffic in this stream test.
        fn accept(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    }.accept };
    var a = try gossip.Service.init(allocator, config, digest, &.{3}, 1, 3, block_gate, att_gate, aggregate_gate, null);
    defer a.deinit();
    var b = try gossip.Service.init(allocator, config, digest, &.{3}, 1, 3, block_gate, att_gate, aggregate_gate, null);
    defer b.deinit();
    const a_id = [_]u8{1} ** 32;
    const b_id = [_]u8{2} ** 32;
    var outgoing = try Session.init(allocator, &a, b_id, .initiator);
    defer outgoing.deinit();
    var incoming = try Session.init(allocator, &b, a_id, .responder);
    defer incoming.deinit();
    const opening = try outgoing.opening();
    defer allocator.free(opening);
    const partial = try incoming.feed(opening[0..1]);
    try std.testing.expectEqual(@as(?[]u8, null), partial.reply);
    const first = try incoming.feed(opening[1..]);
    defer first.deinit(allocator);
    const second = try incoming.feed(opening[1 + first.consumed ..]);
    defer second.deinit(allocator);
    try std.testing.expect(incoming.selected);
    const echo_header = try outgoing.feed(first.reply.?);
    defer echo_header.deinit(allocator);
    const echo_protocol = try outgoing.feed(second.reply.?);
    defer echo_protocol.deinit(allocator);
    try std.testing.expect(outgoing.selected);
    const a_subscription = try incoming.feed(echo_protocol.subscription.?);
    const b_subscription = try outgoing.feed(second.subscription.?);
    try std.testing.expectEqual(echo_protocol.subscription.?.len, a_subscription.consumed);
    try std.testing.expectEqual(second.subscription.?.len, b_subscription.consumed);
    try std.testing.expect(a.remoteBlockSubscribed(b_id));
    try std.testing.expect(b.remoteBlockSubscribed(a_id));
    try std.testing.expectEqual([2]u64{ 0, 0 }, a.remoteColumnMask(b_id).?);
    try std.testing.expect(!a.remoteBlockSubscribed([_]u8{9} ** 32));
    try std.testing.expectEqual(@as(?[2]u64, null), a.remoteColumnMask([_]u8{9} ** 32));
    var recipients: [1][32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try a.recipients(a.block_topic, &recipients));
    try std.testing.expectEqual(b_id, recipients[0]);
    try std.testing.expectEqual(@as(usize, 1), try b.recipients(b.block_topic, &recipients));
    try std.testing.expectEqual(a_id, recipients[0]);

    const encoded_block = try wire.encodeGossip(allocator, raw_block, config.max_encoded_size);
    defer allocator.free(encoded_block);
    const block_rpc = try gossip.encodePublish(allocator, b.block_topic, encoded_block);
    defer allocator.free(block_rpc);
    const block_frame = try gossip.encodeFrame(allocator, block_rpc);
    defer allocator.free(block_frame);
    _ = try incoming.feed(block_frame[0 .. block_frame.len / 2]);
    try std.testing.expectEqual(@as(usize, 0), counts.blocks);
    _ = try incoming.feed(block_frame[block_frame.len / 2 ..]);
    try std.testing.expectEqual(@as(usize, 1), counts.blocks);

    const raw_attestation = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/slashing/attestation_0x5172be6898efefa589c2182765c8e7a74272ed2b0004d0577921a4808b364fcf.ssz_snappy"));
    defer allocator.free(raw_attestation);
    const encoded_attestation = try wire.encodeGossip(allocator, raw_attestation, config.max_encoded_size);
    defer allocator.free(encoded_attestation);
    const att_rpc = try gossip.encodePublish(allocator, b.attestation_topics[3].?, encoded_attestation);
    defer allocator.free(att_rpc);
    const att_frame = try gossip.encodeFrame(allocator, att_rpc);
    defer allocator.free(att_frame);
    _ = try incoming.feed(att_frame);
    try std.testing.expectEqual(@as(usize, 1), counts.attestations);

    const bad_rpc = try gossip.encodePublish(allocator, b.block_topic, &.{ 0xff, 0xff });
    defer allocator.free(bad_rpc);
    const bad_frame = try gossip.encodeFrame(allocator, bad_rpc);
    defer allocator.free(bad_frame);
    try std.testing.expectError(error.MalformedBlock, incoming.feed(bad_frame));
    try std.testing.expectEqual(@as(usize, 1), counts.blocks);
    try std.testing.expectEqual(@as(u8, 1), b.peers.state(a_id).?.invalid_messages);
}

test "failed negotiation is scored and disconnect clears partial stream state" {
    const allocator = std.testing.allocator;
    const ingress = @import("p2p_ingress.zig");
    const fulu = @import("fulu");
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    var calls: usize = 0;
    const block_gate = ingress.BlockValidation{ .context = &calls, .validate = struct {
        /// Count blocks admitted by the stream.
        fn accept(context: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
        }
    }.accept };
    const att_gate = ingress.AttestationValidation{ .context = &calls, .validate = struct {
        /// Accept unused attestations in this negotiation test.
        fn accept(_: *anyopaque, _: *const fulu.Attestation) !void {}
    }.accept };
    const aggregate_gate = ingress.AggregateValidation{ .context = &calls, .validate = struct {
        /// Accept unused aggregates in this negotiation test.
        fn accept(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    }.accept };
    const digest = try config.digestAtSlot(0);
    var service = try gossip.Service.init(allocator, config, digest, &.{}, 1, 3, block_gate, att_gate, aggregate_gate, null);
    defer service.deinit();
    const peer_id = [_]u8{9} ** 32;
    var first = try Session.init(allocator, &service, peer_id, .responder);
    var second_stream = try Session.init(allocator, &service, peer_id, .responder);
    second_stream.deinit();
    try std.testing.expect(service.peers.state(peer_id).?.connected);
    try std.testing.expectError(error.InvalidLength, first.feed(&.{0}));
    try std.testing.expectEqual(@as(u8, 1), service.peers.state(peer_id).?.invalid_messages);
    first.deinit();
    try std.testing.expect(!service.peers.state(peer_id).?.connected);
    var second = try Session.init(allocator, &service, peer_id, .responder);
    defer second.deinit();
    try std.testing.expectEqual(@as(u8, 1), service.peers.state(peer_id).?.invalid_messages);
    const wrong_offer = try multistream.offer(allocator, .status);
    defer allocator.free(wrong_offer);
    const header = try second.feed(wrong_offer);
    defer header.deinit(allocator);
    const rejected = try second.feed(wrong_offer[header.consumed..]);
    defer rejected.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 3, 'n', 'a', '\n' }, rejected.reply.?);
    try std.testing.expect(!second.selected);
    const opening = try multistream.offer(allocator, .gossip);
    defer allocator.free(opening);
    const selected = try second.feed(opening[header.consumed..]);
    defer selected.deinit(allocator);
    try std.testing.expect(second.selected);
    try std.testing.expectEqual(@as(usize, 0), calls);
}

// Consensus gossip is untrusted until its Snappy and SSZ bytes, fork context,
// and caller's consensus rules pass. Track each connected peer separately so
// repeated invalid input cannot keep reaching validation callbacks. A peer
// that disconnects without violations can reconnect with its score intact.
//
//   peer bytes -> bounded decode -> fork check -> consensus gate -> delivery
// The table is bounded to 256 peers; the caller supplies peer identities.
const std = @import("std");
const fulu = @import("fulu");
const ingress = @import("p2p_ingress.zig");

pub const State = struct {
    connected: bool = true,
    invalid_messages: u8 = 0,
};

pub const Admission = struct {
    allocator: std.mem.Allocator,
    config: ingress.Config,
    max_peers: usize,
    invalid_limit: u8,
    peers: std.AutoHashMap([32]u8, State),

    /// Allocate a bounded peer table and a nonzero invalid-message limit.
    pub fn init(allocator: std.mem.Allocator, config: ingress.Config, max_peers: usize, invalid_limit: u8) !Admission {
        if (max_peers == 0 or max_peers > 256 or invalid_limit == 0) return error.InvalidPeerLimit;
        return .{ .allocator = allocator, .config = config, .max_peers = max_peers, .invalid_limit = invalid_limit, .peers = .init(allocator) };
    }

    /// Release the peer score table.
    pub fn deinit(self: *Admission) void {
        self.peers.deinit();
    }

    /// Mark a known peer connected, or admit a new peer within the table limit.
    pub fn connect(self: *Admission, peer_id: [32]u8) !void {
        if (self.peers.getPtr(peer_id)) |peer| {
            if (peer.invalid_messages >= self.invalid_limit) return error.PeerBanned;
            peer.connected = true;
            return;
        }
        if (self.peers.count() >= self.max_peers) return error.PeerLimitReached;
        try self.peers.put(peer_id, .{});
    }

    /// Mark a peer disconnected without discarding its invalid-message history.
    pub fn disconnect(self: *Admission, peer_id: [32]u8) void {
        if (self.peers.getPtr(peer_id)) |peer| peer.connected = false;
    }

    /// Decode and validate block gossip; callbacks use InvalidGossip for peer-rule rejection.
    pub fn receiveBlock(self: *Admission, peer_id: [32]u8, topic_digest: [4]u8, bytes: []const u8, validation: ingress.BlockValidation) !void {
        try self.requirePeer(peer_id);
        ingress.receiveBlockGossip(self.allocator, self.config, topic_digest, bytes, validation) catch |err| {
            if (isPeerFault(err)) self.noteInvalid(peer_id);
            return err;
        };
    }

    /// Decode and validate attestation gossip; callbacks use InvalidGossip for peer-rule rejection.
    pub fn receiveAttestation(self: *Admission, peer_id: [32]u8, topic_digest: [4]u8, bytes: []const u8, validation: ingress.AttestationValidation) !void {
        try self.requirePeer(peer_id);
        ingress.receiveAttestationGossip(self.allocator, self.config, topic_digest, bytes, validation) catch |err| {
            if (isPeerFault(err)) self.noteInvalid(peer_id);
            return err;
        };
    }

    /// Return the current peer score and connectivity, if the peer is tracked.
    pub fn state(self: *const Admission, peer_id: [32]u8) ?State {
        return self.peers.get(peer_id);
    }

    /// Reject missing, disconnected, and banned peers before any decoding work.
    fn requirePeer(self: *const Admission, peer_id: [32]u8) !void {
        const peer = self.peers.get(peer_id) orelse return error.UnknownPeer;
        if (!peer.connected) return error.PeerDisconnected;
        if (peer.invalid_messages >= self.invalid_limit) return error.PeerBanned;
    }

    /// Count one rejected remote message, saturating the score at the ban limit.
    fn noteInvalid(self: *Admission, peer_id: [32]u8) void {
        const peer = self.peers.getPtr(peer_id).?;
        if (peer.invalid_messages < self.invalid_limit) peer.invalid_messages += 1;
    }
};

/// Score only wire, SSZ, fork, or explicitly rejected consensus input.
fn isPeerFault(err: anyerror) bool {
    return switch (err) {
        error.InvalidGossip, error.InvalidForkContext, error.PayloadTooLarge, error.MalformedBlock, error.OutputTooLarge, error.InvalidBoolean, error.InvalidLength, error.InvalidOffset, error.TrailingBytes, error.EndOfStream, error.ListTooLong, error.BitListTooLong, error.ByteListTooLong, error.NoDelimiterBit, error.StreamTooLong, error.NonZeroPaddingBits => true,
        else => false,
    };
}

test "valid gossip reaches callbacks and repeated invalid input bans only its peer" {
    const fixture = @import("fixture_runner.zig");
    const ssz = @import("ssz");
    const wire = @import("p2p_wire.zig");
    const allocator = std.testing.allocator;
    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    var admission = try Admission.init(allocator, config, 2, 3);
    defer admission.deinit();
    const bad_peer = [_]u8{1} ** 32;
    const good_peer = [_]u8{2} ** 32;
    try admission.connect(bad_peer);
    try admission.connect(good_peer);
    const raw_block = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer allocator.free(raw_block);
    var reader: std.Io.Reader = .fixed(raw_block);
    const block = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
    const digest = try config.digestAtSlot(block.message.slot);
    const encoded_block = try wire.encodeGossip(allocator, raw_block, config.max_encoded_size);
    defer allocator.free(encoded_block);
    var calls: usize = 0;
    const block_validation = ingress.BlockValidation{ .context = &calls, .validate = struct {
        fn accept(context: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
        }
    }.accept };
    try admission.receiveBlock(good_peer, digest, encoded_block, block_validation);
    var wrong = digest;
    wrong[0] ^= 1;
    for (0..3) |_| try std.testing.expectError(error.InvalidForkContext, admission.receiveBlock(bad_peer, wrong, encoded_block, block_validation));
    try std.testing.expectError(error.PeerBanned, admission.receiveBlock(bad_peer, digest, encoded_block, block_validation));
    try std.testing.expectEqual(@as(usize, 1), calls);
    admission.disconnect(good_peer);
    try std.testing.expectError(error.PeerDisconnected, admission.receiveBlock(good_peer, digest, encoded_block, block_validation));
    try admission.connect(good_peer);
    try admission.receiveBlock(good_peer, digest, encoded_block, block_validation);
    try std.testing.expectEqual(@as(usize, 2), calls);
    const raw_attestation = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/slashing/attestation_0x5172be6898efefa589c2182765c8e7a74272ed2b0004d0577921a4808b364fcf.ssz_snappy"));
    defer allocator.free(raw_attestation);
    var att_reader: std.Io.Reader = .fixed(raw_attestation);
    const attestation = try ssz.deserialize(allocator, fulu.Attestation, &att_reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, attestation);
    const att_digest = try config.digestAtSlot(attestation.data.slot);
    const encoded_attestation = try wire.encodeGossip(allocator, raw_attestation, config.max_encoded_size);
    defer allocator.free(encoded_attestation);
    const att_validation = ingress.AttestationValidation{ .context = &calls, .validate = struct {
        fn accept(context: *anyopaque, _: *const fulu.Attestation) !void {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
        }
    }.accept };
    try admission.receiveAttestation(good_peer, att_digest, encoded_attestation, att_validation);
    try std.testing.expectEqual(@as(usize, 3), calls);
    const local_failure = ingress.BlockValidation{ .context = &calls, .validate = struct {
        fn fail(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            return error.LocalUnavailable;
        }
    }.fail };
    try std.testing.expectError(error.LocalUnavailable, admission.receiveBlock(good_peer, digest, encoded_block, local_failure));
    try std.testing.expectEqual(@as(u8, 0), admission.state(good_peer).?.invalid_messages);
    const invalid_consensus = ingress.BlockValidation{ .context = &calls, .validate = struct {
        fn reject(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            return error.InvalidGossip;
        }
    }.reject };
    try std.testing.expectError(error.InvalidGossip, admission.receiveBlock(good_peer, digest, encoded_block, invalid_consensus));
    try std.testing.expectEqual(@as(u8, 1), admission.state(good_peer).?.invalid_messages);
    try std.testing.expectEqual(@as(u8, 3), admission.state(bad_peer).?.invalid_messages);
}

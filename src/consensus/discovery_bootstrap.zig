// Bootstrap ENRs are untrusted claims about peer identity, fork, custody, and
// address. Verify each signed record before admitting it to a bounded peer
// table. A higher sequence replaces an earlier record for the same node ID;
// a conflicting record at the same sequence is rejected.
//
//   configured enr: URI -> signature/fork gate -> bounded candidates
// This table holds at most 256 candidates; discv5 packet exchange is separate.
const std = @import("std");
const enr = @import("enr.zig");

pub const Candidates = struct {
    allocator: std.mem.Allocator,
    fork_digest: [4]u8,
    max_peers: usize,
    items: std.ArrayList(enr.Record) = .empty,

    /// Create a candidate table with a limit no greater than 256 peers.
    pub fn init(allocator: std.mem.Allocator, fork_digest: [4]u8, max_peers: usize) !Candidates {
        if (max_peers == 0 or max_peers > 256) return error.InvalidPeerLimit;
        return .{ .allocator = allocator, .fork_digest = fork_digest, .max_peers = max_peers };
    }

    /// Free the candidate table; returned record values need no separate release.
    pub fn deinit(self: *Candidates) void {
        self.items.deinit(self.allocator);
    }

    /// Admit a configured `enr:` URI after checking its signature, fork, and sequence.
    pub fn add(self: *Candidates, uri: []const u8) !void {
        if (!std.mem.startsWith(u8, uri, "enr:")) return error.InvalidEnrUri;
        const encoded = uri[4..];
        if (encoded.len == 0 or encoded.len > std.base64.url_safe_no_pad.Encoder.calcSize(300)) return error.InvalidEnrUri;
        const length = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch return error.InvalidEnrUri;
        if (length > 300) return error.RecordTooLarge;
        const bytes = try self.allocator.alloc(u8, length);
        defer self.allocator.free(bytes);
        std.base64.url_safe_no_pad.Decoder.decode(bytes, encoded) catch return error.InvalidEnrUri;
        const record = try enr.decode(self.allocator, bytes);
        try enr.requireFork(record, self.fork_digest);
        for (self.items.items) |*existing| {
            if (!std.mem.eql(u8, &existing.node_id, &record.node_id)) continue;
            if (record.sequence < existing.sequence) return error.StaleEnr;
            if (record.sequence == existing.sequence) {
                if (!std.meta.eql(existing.*, record)) return error.ConflictingEnr;
                return;
            }
            existing.* = record;
            return;
        }
        if (self.items.items.len == self.max_peers) return error.PeerLimitReached;
        try self.items.append(self.allocator, record);
    }

    /// Return a copied candidate by discovery node ID.
    pub fn get(self: *const Candidates, node_id: [32]u8) ?enr.Record {
        for (self.items.items) |record| if (std.mem.eql(u8, &record.node_id, &node_id)) return record;
        return null;
    }
};

test "bootstrap table verifies signed ENRs and updates only newer records" {
    const allocator = std.testing.allocator;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const key = try Ecdsa.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const fork_digest = [4]u8{ 1, 2, 3, 4 };
    var local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 9000, .tcp_port = 9001, .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    var candidates = try Candidates.init(allocator, fork_digest, 1);
    defer candidates.deinit();
    const first = try enr.encode(allocator, key, local);
    defer allocator.free(first);
    const first_text = try uriFor(allocator, first);
    defer allocator.free(first_text);
    try candidates.add(first_text);
    try candidates.add(first_text);
    try std.testing.expectEqual(@as(usize, 1), candidates.items.items.len);
    const id = candidates.items.items[0].node_id;
    local.sequence = 2;
    local.udp_port = 9002;
    const newer = try enr.encode(allocator, key, local);
    defer allocator.free(newer);
    const newer_text = try uriFor(allocator, newer);
    defer allocator.free(newer_text);
    try candidates.add(newer_text);
    try std.testing.expectEqual(@as(u16, 9002), candidates.get(id).?.udp_port);
    try std.testing.expectError(error.StaleEnr, candidates.add(first_text));
    local.udp_port = 9003;
    const conflicting = try enr.encode(allocator, key, local);
    defer allocator.free(conflicting);
    const conflicting_text = try uriFor(allocator, conflicting);
    defer allocator.free(conflicting_text);
    try std.testing.expectError(error.ConflictingEnr, candidates.add(conflicting_text));
    try std.testing.expectEqual(@as(u16, 9002), candidates.get(id).?.udp_port);
    const other_key = try Ecdsa.KeyPair.generateDeterministic([_]u8{8} ** 32);
    const another_peer = try enr.encode(allocator, other_key, local);
    defer allocator.free(another_peer);
    const another_text = try uriFor(allocator, another_peer);
    defer allocator.free(another_text);
    try std.testing.expectError(error.PeerLimitReached, candidates.add(another_text));
    try std.testing.expectEqual(@as(usize, 1), candidates.items.items.len);
    var other_fork = try Candidates.init(allocator, .{ 9, 2, 3, 4 }, 1);
    defer other_fork.deinit();
    try std.testing.expectError(error.InvalidForkContext, other_fork.add(first_text));
}

/// Return an owned ENR URI for the test's signed bytes.
fn uriFor(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const body = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(bytes.len));
    defer allocator.free(body);
    _ = std.base64.url_safe_no_pad.Encoder.encode(body, bytes);
    return std.fmt.allocPrint(allocator, "enr:{s}", .{body});
}

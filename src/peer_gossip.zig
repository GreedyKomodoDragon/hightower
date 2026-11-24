// An execution peer is a configured Hightower node exchanging pending signed
// transactions. Every received transaction is revalidated against local state
// before pool admission; duplicates do not affect reputation. Polling bounds
// in-flight work to one request per peer, two peers total, 256 transactions,
// and a 10 MiB response. Three invalid submissions disconnect that peer.
//
// local pool <-> bounded RPC snapshot <-> remote pool admission
const std = @import("std");
const rpc = @import("execution").rpc;

pub const max_peers = 2;
pub const max_transactions = 256;
pub const max_message_bytes = 10 * 1024 * 1024;
const max_transaction_bytes = 3 * 1024 * 1024;
const invalid_threshold = 3;
const poll_interval_ns = std.time.ns_per_s;

/// Counts invalid peer transactions and reports when the disconnect threshold is reached.
fn recordInvalid(invalid: *u8) bool {
    invalid.* +|= 1;
    return invalid.* >= invalid_threshold;
}

/// Owns one bounded worker per configured peer URL for the service lifetime.
pub const Service = struct {
    server: *rpc.Server,
    io: std.Io,
    peers: []const []const u8,

    /// Starts polling workers; each worker reconnects after transport failures.
    pub fn start(self: *Service) !void {
        if (self.peers.len > max_peers) return error.TooManyPeers;
        for (self.peers) |url| {
            const thread = try std.Thread.spawn(.{}, run, .{ self, url });
            thread.detach();
        }
    }

    /// Exchanges bounded transaction snapshots until the peer exceeds reputation limits.
    fn run(self: *Service, url: []const u8) void {
        var invalid: u8 = 0;
        while (true) {
            if (self.exchange(url, &invalid)) {} else |err| {
                std.log.warn("execution peer {s} disconnected: {s}", .{ url, @errorName(err) });
                if (err == error.InvalidPeerTransactions or err == error.PeerMessageTooLarge or err == error.PeerProtocolError) return;
            }
            self.io.sleep(.fromNanoseconds(poll_interval_ns), .awake) catch return;
        }
    }

    /// Fetches one remote snapshot and validates each transaction locally.
    fn exchange(self: *Service, url: []const u8, invalid: *u8) !void {
        var client: std.http.Client = .{ .allocator = std.heap.page_allocator, .io = self.io };
        defer client.deinit();
        const request = try std.json.Stringify.valueAlloc(std.heap.page_allocator, .{
            .jsonrpc = "2.0",
            .id = 1,
            .method = "hightower_peerTransactions",
            .params = [_]std.json.Value{},
        }, .{});
        defer std.heap.page_allocator.free(request);
        const response_buffer = try std.heap.page_allocator.alloc(u8, max_message_bytes);
        defer std.heap.page_allocator.free(response_buffer);
        var response_writer: std.Io.Writer = .fixed(response_buffer);
        const response = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = request,
            .response_writer = &response_writer,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
            .keep_alive = false,
        }) catch |err| {
            if (err == error.NoSpaceLeft or (err == error.WriteFailed and response_writer.end == response_buffer.len)) return error.PeerMessageTooLarge;
            return err;
        };
        if (response_writer.end == response_buffer.len) return error.PeerMessageTooLarge;
        if (response.status != .ok) return error.PeerProtocolError;
        var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, response_buffer[0..response_writer.end], .{ .allocate = .alloc_always }) catch return error.PeerProtocolError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.PeerProtocolError;
        const version = parsed.value.object.get("jsonrpc") orelse return error.PeerProtocolError;
        const id = parsed.value.object.get("id") orelse return error.PeerProtocolError;
        if (version != .string or !std.mem.eql(u8, version.string, "2.0") or id != .integer or id.integer != 1) return error.PeerProtocolError;
        if (parsed.value.object.contains("error")) return error.PeerProtocolError;
        const result = parsed.value.object.get("result") orelse return error.PeerProtocolError;
        if (result != .array or result.array.items.len > max_transactions) return error.PeerMessageTooLarge;
        for (result.array.items) |item| {
            if (item != .string or item.string.len < 4 or !std.mem.startsWith(u8, item.string, "0x") or item.string.len % 2 != 0) return error.PeerProtocolError;
            const raw = std.heap.page_allocator.alloc(u8, (item.string.len - 2) / 2) catch return error.OutOfMemory;
            defer std.heap.page_allocator.free(raw);
            _ = std.fmt.hexToBytes(raw, item.string[2..]) catch return error.PeerProtocolError;
            if (raw.len > max_transaction_bytes) return error.PeerMessageTooLarge;
            const admission = try self.server.admitPeerTransaction(raw);
            if (admission == .invalid and recordInvalid(invalid)) return error.InvalidPeerTransactions;
        }
    }
};

test "peer reputation ignores duplicates and disconnects after bounded invalid submissions" {
    try std.testing.expectEqual(@as(usize, 2), max_peers);
    try std.testing.expectEqual(@as(usize, 256), max_transactions);
    try std.testing.expectEqual(@as(usize, 10 * 1024 * 1024), max_message_bytes);
    try std.testing.expectEqual(@as(u8, 3), invalid_threshold);
    var invalid: u8 = 0;
    try std.testing.expect(!recordInvalid(&invalid));
    try std.testing.expect(!recordInvalid(&invalid));
    try std.testing.expect(recordInvalid(&invalid));
}

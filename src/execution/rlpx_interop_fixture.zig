// The RLPx fixture dials a local Geth eth/69 server and exchanges one real
// pooled transaction. It tests the production Zig handshake, framing, Snappy,
// status, and announcement codecs against a separate implementation.
//
// Geth status -> Zig announcement -> Geth request -> Zig response
const std = @import("std");
const peer = @import("rlpx_peer.zig");
const eth = @import("rlpx_eth.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

/// Dial a local Geth fixture on the given port and supply one signed transaction.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3) return error.ExpectedPortAndTransaction;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (!std.mem.startsWith(u8, args[2], "0x") or args[2].len < 4 or args[2].len % 2 != 0) return error.InvalidTransaction;
    const raw = try a.alloc(u8, (args[2].len - 2) / 2);
    _ = try std.fmt.hexToBytes(raw, args[2][2..]);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(raw, &hash, .{});
    const local = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(.{11} ** 32));
    const remote = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(.{12} ** 32));
    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    const status = eth.Status{ .network_id = 1, .genesis = .{1} ** 32, .fork_hash = .{ 2, 3, 4, 5 }, .next_fork = 0, .earliest = 0, .latest = 0, .head = .{1} ** 32 };
    var connection = try peer.Peer.dial(a, init.io, local, remote.public_key, address, status);
    defer connection.deinit();
    const announcement = [_]eth.Announcement{.{ .tx_type = if (raw[0] >= 0xc0) 0 else raw[0], .size = @intCast(raw.len), .hash = hash }};
    const encoded = try eth.encodeAnnouncements(a, &announcement);
    try connection.send(eth.announce_code, encoded);
    for (0..4) |_| {
        const message = try connection.receive(5000);
        defer message.deinit(a);
        if (message.code == 2) {
            try connection.send(3, &.{0xc0});
            continue;
        }
        if (message.code != eth.get_code) return error.ExpectedTransactionRequest;
        const request = try eth.decodeRequest(a, message.body);
        if (request.count != 1 or !std.mem.eql(u8, &request.hashes[0], &hash)) return error.WrongTransactionRequest;
        var response: eth.Response = .{ .id = request.id, .count = 1 };
        response.transactions[0] = raw;
        const body = try eth.encodeResponse(a, response);
        try connection.send(eth.pooled_code, body);
        return;
    }
    return error.ExpectedTransactionRequest;
}

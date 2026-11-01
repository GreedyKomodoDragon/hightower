// This loopback discovery fixture advertises a signed Fulu ENR and answers
// authenticated discv5 requests from an independent implementation. Its
// fixed fork and custody fields define the test network; the UDP port is
// assigned at bind time and signed before the ENR is printed.
//
//   signed ENR -> WHOAREYOU -> PING/PONG -> FINDNODE/NODES
// The fixture has no TCP listener and serves only one local discovery test.
const std = @import("std");
const consensus = @import("consensus");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

/// Print a loopback ENR, then answer discv5 packets until the test stops us.
pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 1) return error.UnexpectedArgument;
    var seed: [32]u8 = undefined;
    init.io.random(&seed);
    const key = try Ecdsa.KeyPair.generateDeterministic(seed);
    const local = consensus.ENR.Local{
        .sequence = 1,
        .ip = .{ 127, 0, 0, 1 },
        .udp_port = 0,
        .tcp_port = 9001,
        .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 },
        .next_fork_digest = .{0} ** 4,
        .custody_group_count = 4,
    };
    var service = try consensus.Discv5Discovery.Service.init(allocator, init.io, key, local, 16);
    defer service.deinit();
    const uri = try service.localUri();
    try std.Io.File.stdout().writeStreamingAll(init.io, try std.fmt.allocPrint(allocator, "{s}\n", .{uri}));
    const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(200) } };
    while (true) service.step(timeout) catch |err| switch (err) {
        error.Timeout => {},
        else => return err,
    };
}

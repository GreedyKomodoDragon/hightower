// A fixture anchor is a validated block and post-state at slot zero. Its
// fork-choice store gives the HTTP API a stable head and finality checkpoints
// while integration tests make requests. This server only binds loopback.
const std = @import("std");
const api = @import("api");
const consensus = @import("consensus");
const fulu = @import("fulu");
const ssz = @import("ssz");

/// Serve the pinned anchor on loopback port 18080 in the requested test mode.
pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    const mode = if (args.len == 2) args[1] else return error.ExpectedTestMode;
    if (!std.mem.eql(u8, mode, "ready") and !std.mem.eql(u8, mode, "syncing") and !std.mem.eql(u8, mode, "unavailable"))
        return error.UnknownTestMode;
    const fixtures = consensus.fixtureRunner;
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    var store = try consensus.initForkChoiceStore(allocator, &state, &block);
    defer store.deinit();

    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 18080);
    var listener = try address.listen(init.io, .{ .reuse_address = true });
    defer listener.deinit(init.io);
    try api.serve(allocator, init.io, &listener, &store, .{
        .ready = !std.mem.eql(u8, mode, "unavailable"),
        .is_syncing = std.mem.eql(u8, mode, "syncing"),
        .genesis_fork_version = .{ 0, 0, 0, 0 },
    });
}

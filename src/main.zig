// The runtime exposes a read-only view of one trusted fork-choice anchor.
// Fork choice selects the beacon head and finalized checkpoint; this executable
// currently starts from the bundled anchor and has no peer import loop.
const std = @import("std");
const hightower = @import("hightower");
const ssz = @import("ssz");

comptime {
    _ = @sizeOf(hightower.fulu.BeaconState);
    _ = hightower.consensus.stateTransition;
}

const version = "0.0.0";
const Config = struct { listen_address: []const u8 };
const ParsedConfig = struct { address: std.Io.net.IpAddress };

/// Validate the required config before allocating runtime services or binding a socket.
fn parseConfig(allocator: std.mem.Allocator, bytes: []const u8) !ParsedConfig {
    const parsed = try std.json.parseFromSlice(Config, allocator, bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const separator = std.mem.lastIndexOfScalar(u8, parsed.value.listen_address, ':') orelse return error.InvalidListenAddress;
    if (separator == 0 or separator + 1 == parsed.value.listen_address.len) return error.InvalidListenAddress;
    const port = try std.fmt.parseInt(u16, parsed.value.listen_address[separator + 1 ..], 10);
    if (port == 0) return error.InvalidListenAddress;
    return .{ .address = try std.Io.net.IpAddress.parseIp4(parsed.value.listen_address[0..separator], port) };
}

/// Read and validate a bounded JSON config file.
fn loadConfig(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !ParsedConfig {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
    defer allocator.free(bytes);
    return parseConfig(allocator, bytes);
}

/// Start the configured read-only Beacon API and metrics listener.
pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
        try std.Io.File.stdout().writeStreamingAll(init.io, "Usage: hightower --config <path>\n");
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--version")) {
        try std.Io.File.stdout().writeStreamingAll(init.io, "hightower " ++ version ++ "\n");
        return;
    }
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--config")) return error.ExpectedConfigPath;
    const config = try loadConfig(init.io, allocator, args[2]);

    const fixtures = hightower.consensus.fixtureRunner;
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, hightower.fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, hightower.fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, hightower.fulu.BeaconBlock, block);
    var store = try hightower.consensus.initForkChoiceStore(allocator, &state, &block);
    defer store.deinit();

    var listener = try config.address.listen(init.io, .{ .reuse_address = true });
    defer listener.deinit(init.io);
    try hightower.api.serve(allocator, init.io, &listener, &store, .{ .genesis_fork_version = .{ 0, 0, 0, 0 } });
}

test "runtime config requires a valid IPv4 listen address and port" {
    const allocator = std.testing.allocator;
    const encoded = try std.json.Stringify.valueAlloc(allocator, Config{ .listen_address = "127.0.0.1:5052" }, .{});
    defer allocator.free(encoded);
    _ = try parseConfig(allocator, encoded);
    const invalid = try std.json.Stringify.valueAlloc(allocator, Config{ .listen_address = "localhost:0" }, .{});
    defer allocator.free(invalid);
    try std.testing.expectError(error.InvalidListenAddress, parseConfig(allocator, invalid));
}

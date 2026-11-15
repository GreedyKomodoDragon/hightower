// A trusted execution checkpoint supplies a header and its complete post-state.
// The operator fixes the header hash; the state root must match that header
// before the durable chain can use it as its first retained block. Earlier
// ancestry is trusted and later blocks still require execution validation.
//
//   trusted hash -> decoded header -> checked post-state -> durable anchor
// Checkpoint input is bounded to 512 MiB and is a local operator artifact.
const std = @import("std");
const execution = @import("execution.zig");

const max_header_bytes = 16 * 1024;
const max_state_bytes = 512 * 1024 * 1024;

/// Load a trusted Osaka header and its full state without changing world on failure.
pub fn load(allocator: std.mem.Allocator, io: std.Io, header_path: []const u8, state_path: []const u8, trusted_hash: execution.Hash, world: *execution.state.State) !execution.Header {
    const header_bytes = try std.Io.Dir.cwd().readFileAlloc(io, header_path, allocator, .limited(max_header_bytes));
    defer allocator.free(header_bytes);
    var decoded = try execution.parse(execution.Header, allocator, header_bytes);
    defer decoded.deinit();
    const hash = try execution.transition.headerHash(allocator, .osaka, decoded.value);
    if (!std.mem.eql(u8, &hash, &trusted_hash)) return error.UntrustedCheckpoint;
    const state_bytes = try std.Io.Dir.cwd().readFileAlloc(io, state_path, allocator, .limited(max_state_bytes));
    defer allocator.free(state_bytes);
    var restored = execution.state.State.init(allocator);
    errdefer restored.deinit();
    try restored.applyStateBytes(state_bytes);
    const root = try restored.stateRoot();
    if (!std.mem.eql(u8, &root, &decoded.value.state_root)) return error.InvalidCheckpointState;
    var header = decoded.value;
    header.extra_data = try allocator.dupe(u8, header.extra_data);
    world.deinit();
    world.* = restored;
    return header;
}


// Diagnostic traces expose authenticated protocol payloads, never key material.
// Noise authenticates encrypted frames before Yamux interprets their streams;
// discovery authenticates messages before consensus uses their peer records.
// Callers opt in before starting networking and close after all workers stop.
// Each JSONL event is serialized and synced before the protocol proceeds.
const std = @import("std");
var output: ?std.Io.File = null;
var trace_io: std.Io = undefined;
var mutex: std.Io.Mutex = .init;

/// Enable an exclusive, owner-only trace file; initialization must precede workers.
pub fn enable(io: std.Io, path: []const u8) !void {
    if (output != null) return error.TraceAlreadyEnabled;
    output = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    trace_io = io;
}

/// Close the unbuffered trace after workers stop; emit already synced every event.
pub fn close() void {
    if (output) |file| file.close(trace_io);
    output = null;
}

/// Record explicit public fields and bounded payload bytes; propagate disk errors.
pub fn emit(event: []const u8, details: anytype, payload: []const u8) !void {
    const file = output orelse return;
    try mutex.lock(trace_io);
    defer mutex.unlock(trace_io);
    const allocator = std.heap.page_allocator;
    const hex = try allocator.alloc(u8, payload.len * 2);
    defer allocator.free(hex);
    const alphabet = "0123456789abcdef";
    for (payload, 0..) |byte, i| {
        hex[i * 2] = alphabet[byte >> 4];
        hex[i * 2 + 1] = alphabet[byte & 15];
    }
    const line = try std.json.Stringify.valueAlloc(allocator, .{
        .timestamp_ns = std.Io.Clock.real.now(trace_io).nanoseconds,
        .event = event,
        .details = details,
        .payload_hex = hex,
    }, .{});
    defer allocator.free(line);
    try file.writeStreamingAll(trace_io, line);
    try file.writeStreamingAll(trace_io, "\n");
    try file.sync(trace_io);
}

test "opt-in trace serializes binary bytes and never overwrites artifacts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/trace.jsonl", .{dir_path});
    defer std.testing.allocator.free(path);
    try emit("disabled", .{}, "no output");
    try enable(io, path);
    defer close();
    try emit("authenticated", .{ .stream = 3 }, &.{ 0, 255, 10 });
    const bytes = try tmp.dir.readFileAlloc(io, "trace.jsonl", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("00ff0a", parsed.value.object.get("payload_hex").?.string);
    try std.testing.expectEqual(@as(i64, 3), parsed.value.object.get("details").?.object.get("stream").?.integer);
    close();
    try std.testing.expectError(error.PathAlreadyExists, enable(io, path));
}

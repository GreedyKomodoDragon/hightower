//! By convention, root.zig is the root source file when making a package.
const std = @import("std");
const Io = std.Io;

pub const fulu = @import("fulu");
pub const consensus = @import("consensus/root.zig");

/// This is a documentation comment to explain the `printAnotherMessage` function below.
///
/// Accepting an `Io.Writer` instance is a handy way to write reusable code.
pub fn printAnotherMessage(writer: *Io.Writer) Io.Writer.Error!void {
    try writer.print("Run `zig build test` to run the tests.\n", .{});
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}

test "Fulu shared types are exported" {
    _ = @sizeOf(fulu.SyncAggregate);
    const run: *const fn (std.mem.Allocator, *fulu.BeaconState, fulu.SignedBeaconBlock, consensus.ExecutionEngine) anyerror!void = consensus.stateTransition;
    _ = run;
}

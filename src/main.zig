const std = @import("std");
const hightower = @import("hightower");

// Force the executable to type-check the selected state schema and consensus API.
comptime {
    _ = @sizeOf(hightower.fulu.BeaconState);
    _ = hightower.consensus.stateTransition;
}

const version = "0.0.0";
const usage = "Usage: hightower [--help | --version]\nThe Hightower node runtime is not implemented yet.\n";

/// Runs the command-line entry point after the selected consensus preset compiles.
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const arg = if (args.len > 1) args[1] else "";
    const output = if (std.mem.eql(u8, arg, "--help"))
        usage
    else if (std.mem.eql(u8, arg, "--version"))
        "hightower " ++ version ++ "\n"
    else
        "The Hightower node runtime is not implemented yet.\n";

    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

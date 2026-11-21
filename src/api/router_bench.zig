const std = @import("std");
const routing = @import("router.zig");

const patterns = [_][]const u8{
    "/metrics",
    "/eth/v1/node/health",
    "/eth/v1/node/syncing",
    "/eth/v1/beacon/genesis",
    "/eth/v1/beacon/blocks/{id}/root",
    "/eth/v1/beacon/states/{id}/root",
    "/eth/v1/beacon/states/{id}/finality_checkpoints",
};
const labels = [_][]const u8{ "known", "parameterized", "unknown" };

/// Compare trie lookup with the previous endpoint-by-endpoint matcher.
pub fn main(init: std.process.Init) !void {
    var router = try routing.Router.init(std.heap.page_allocator);
    defer router.deinit();
    const args = try init.minimal.args.toSlice(std.heap.page_allocator);
    if (args.len != 7) return error.ExpectedSixPaths;
    const path_sets = [_][]const []const u8{ args[1..3], args[3..5], args[5..7] };
    const iterations = 2_000_000;
    const sample_count = 5;
    for (path_sets, 0..) |paths, index| {
        var trie_samples: [sample_count]f64 = undefined;
        var linear_samples: [sample_count]f64 = undefined;
        for (0..sample_count) |sample| {
            trie_samples[sample] = measure(init.io, iterations, .{ .router = &router, .paths = paths, .trie = true });
            linear_samples[sample] = measure(init.io, iterations, .{ .router = &router, .paths = paths, .trie = false });
        }
        const trie_ns = median(&trie_samples);
        const linear_ns = median(&linear_samples);
        const output = try std.fmt.allocPrint(std.heap.page_allocator, "{s}: trie {d:.2} ns/op ({d:.0} ops/s), linear {d:.2} ns/op ({d:.0} ops/s), allocs/op 0\n", .{
            labels[index],
            trie_ns,
            1_000_000_000.0 / trie_ns,
            linear_ns,
            1_000_000_000.0 / linear_ns,
        });
        defer std.heap.page_allocator.free(output);
        try std.Io.File.stdout().writeStreamingAll(init.io, output);
    }
}

const Context = struct { router: *const routing.Router, paths: []const []const u8, trie: bool };

/// Time repeated lookups and return average nanoseconds per operation.
fn measure(io: std.Io, iterations: usize, context: Context) f64 {
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var hits: usize = 0;
    var path_index: usize = 0;
    for (0..iterations) |_| {
        const index = path_index;
        path_index = (index + 1) % context.paths.len;
        const path = opaquePath(context.paths[index]);
        if (context.trie) {
            if (context.router.match("GET", path) != null) hits += 1;
        } else if (linearMatch("GET", path)) {
            hits += 1;
        }
    }
    std.mem.doNotOptimizeAway(hits);
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    return @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations));
}

/// Keep the compiler from reusing a lookup result for a constant benchmark path.
fn opaquePath(path: []const u8) []const u8 {
    var pointer = path.ptr;
    asm volatile (""
        : [pointer] "+r" (pointer),
    );
    return pointer[0..path.len];
}

/// Return the median sample without allocating.
fn median(samples: *[5]f64) f64 {
    for (1..samples.len) |index| {
        const value = samples[index];
        var position = index;
        while (position > 0 and samples[position - 1] > value) : (position -= 1) {
            samples[position] = samples[position - 1];
        }
        samples[position] = value;
    }
    return samples[samples.len / 2];
}

/// Model the former linear path checks over the same route patterns.
fn linearMatch(method: []const u8, path: []const u8) bool {
    if (!std.mem.eql(u8, method, "GET")) return false;
    for (patterns) |pattern| {
        const marker = std.mem.indexOf(u8, pattern, "{id}") orelse {
            if (std.mem.eql(u8, pattern, path)) return true;
            continue;
        };
        const suffix_start = marker + "{id}".len;
        if (std.mem.startsWith(u8, path, pattern[0..marker]) and
            std.mem.endsWith(u8, path, pattern[suffix_start..]) and
            path.len >= marker + pattern[suffix_start..].len)
            return true;
    }
    return false;
}

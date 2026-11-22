// Validated records remain addressable by hash while selected-path indexes
// serve canonical reads. Reorgs replace those indexes as one ordered update.
// genesis -> 4096 retained records; the benchmark includes all records in RAM.
const std = @import("std");
const execution = @import("execution");

const retained_blocks = 4096;
const iterations = 1_000_000;

/// Builds a retained chain and measures its indexed read operations.
pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    const cloned_bytes = try retainedMemoryBytes(false);
    const owned_bytes = try retainedMemoryBytes(true);
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    var genesis = std.mem.zeroes(execution.Header);
    genesis.gas_limit = 30_000_000;
    genesis.state_root = try world.stateRoot();
    var chain = try execution.chain.Chain.init(allocator, 1, .paris, genesis, &world);
    defer chain.deinit();
    var parent_hash = chain.latest().hash;
    var canonical: std.ArrayList(usize) = .empty;
    defer canonical.deinit(allocator);
    try canonical.append(allocator, 0);
    for (1..retained_blocks + 1) |number| {
        var header = genesis;
        header.number = number;
        header.parent_hash = parent_hash;
        header.timestamp = number;
        const raw = [_]u8{ @truncate(number), @truncate(number >> 8), 0xa5 };
        var result_arena = std.heap.ArenaAllocator.init(allocator);
        const result_allocator = result_arena.allocator();
        const result: execution.transition.BlockResult = .{
            .arena = result_arena,
            .receipts = try result_allocator.alloc(execution.Receipt, 0),
            .state_root = genesis.state_root,
            .transactions_root = genesis.transactions_root,
            .receipts_root = genesis.receipts_root,
            .withdrawals_root = genesis.withdrawals_root,
            .logs_bloom = genesis.logs_bloom,
            .gas_used = 0,
        };
        try chain.retain(header, &.{&raw}, &.{}, result, &world);
        parent_hash = chain.records.items[chain.records.items.len - 1].hash;
        try canonical.append(allocator, chain.records.items.len - 1);
    }
    const canonical_path = canonical;
    canonical = .empty;
    var previous = try chain.replaceCanonical(canonical_path);
    previous.deinit(allocator);
    const target = chain.records.items[retained_blocks / 2 + 1];
    // SAFETY: Keccak writes all 32 output bytes before the hash is read.
    var tx_hash: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(target.transactions[0], &tx_hash, .{});
    var hits: usize = 0;
    const start = std.Io.Clock.awake.now(init.io).nanoseconds;
    for (0..iterations) |i| {
        const number = 1 + i % retained_blocks;
        if (chain.byNumber(number)) |record| hits += @intFromBool(record.header.number == number);
        if (chain.byHash(target.hash) != null) hits += 1;
        if (chain.canonicalByHash(target.hash) != null) hits += 1;
        if (chain.transaction(tx_hash) != null) hits += 1;
        if (i % 100 == 0) {
            const ancestors = try chain.ancestorHashes(allocator, target.hash);
            if (ancestors.len != 255) return error.InvalidAncestorCount;
            allocator.free(ancestors);
        }
    }
    if (hits != iterations * 4) return error.LookupIndexMismatch;
    const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - start;
    std.mem.doNotOptimizeAway(hits);
    const output = try std.fmt.allocPrint(allocator, "{d} retained blocks, {d} mixed lookup iterations: {d:.2} us/iteration ({d} checks)\n{d} retained post-states: clone path {d} requested bytes, ownership transfer {d} requested bytes ({d} fewer, {d:.1}% reduction)\n", .{
        retained_blocks,
        iterations,
        @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations)) / std.time.ns_per_us,
        hits,
        memory_sample_blocks,
        cloned_bytes,
        owned_bytes,
        cloned_bytes - owned_bytes,
        @as(f64, @floatFromInt(cloned_bytes - owned_bytes)) * 100 / @as(f64, @floatFromInt(cloned_bytes)),
    });
    defer allocator.free(output);
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

const memory_sample_blocks = 256;
const MemoryAllocator = std.heap.DebugAllocator(.{ .enable_memory_limit = true });

/// Measures live allocator-requested bytes after retaining cloned or moved states.
fn retainedMemoryBytes(owned: bool) !usize {
    var debug_allocator: MemoryAllocator = .{};
    defer if (debug_allocator.deinit() != .ok) @panic("retention memory benchmark leaked allocations");
    const allocator = debug_allocator.allocator();
    var seed = execution.state.State.init(allocator);
    defer seed.deinit();
    try seed.setBalance(.{0x42} ** 20, 1);
    var genesis = std.mem.zeroes(execution.Header);
    genesis.gas_limit = 30_000_000;
    genesis.state_root = try seed.stateRoot();
    var chain = try execution.chain.Chain.init(allocator, 1, .paris, genesis, &seed);
    defer chain.deinit();
    const base_bytes = debug_allocator.total_requested_bytes;
    var retained_bytes: usize = 0;
    for (1..memory_sample_blocks + 1) |number| {
        var header = genesis;
        header.number = number;
        header.parent_hash = chain.records.items[chain.records.items.len - 1].hash;
        header.timestamp = number;
        var child = try seed.clone(allocator);
        var result_arena = std.heap.ArenaAllocator.init(allocator);
        const result: execution.transition.BlockResult = .{
            .arena = result_arena,
            .receipts = try result_arena.allocator().alloc(execution.Receipt, 0),
            .state_root = genesis.state_root,
            .transactions_root = genesis.transactions_root,
            .receipts_root = genesis.receipts_root,
            .withdrawals_root = null,
            .logs_bloom = genesis.logs_bloom,
            .gas_used = 0,
        };
        if (owned) {
            if (!try chain.retainOwned(header, &.{}, &.{}, result, &child)) return error.StateNotTransferred;
        } else {
            try chain.retain(header, &.{}, &.{}, result, &child);
        }
        retained_bytes = @max(retained_bytes, debug_allocator.total_requested_bytes - base_bytes);
        if (!owned) child.deinit();
    }
    return retained_bytes;
}

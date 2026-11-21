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
    var previous = try chain.replaceCanonical(canonical);
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
    const output = try std.fmt.allocPrint(allocator, "{d} retained blocks, {d} mixed lookup iterations: {d:.2} us/iteration ({d} checks)\n", .{
        retained_blocks,
        iterations,
        @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations)) / std.time.ns_per_us,
        hits,
    });
    defer allocator.free(output);
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

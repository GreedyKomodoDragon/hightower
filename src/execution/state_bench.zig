// A block state root commits every account and its storage root in Ethereum's
// Merkle-Patricia trie. Full rebuilds hash each trie node after block execution;
// incremental roots reuse unchanged nodes while blocks update a small account set.
// benchmark chain: 512 accounts, one account with 256 storage slots, 32 blocks
const std = @import("std");
const execution = @import("execution");

const account_count = 512;
const storage_slots = 256;
const iterations = 32;
const fork: execution.transition.Fork = .shanghai;
const BlockImport = struct { parent: execution.Header, header: execution.Header, withdrawal: execution.Withdrawal };
const ImportPlan = struct {
    imports: []BlockImport,
    baseline_states: []execution.state.State,

    /// Releases prepared block specifications and parent states.
    fn deinit(self: *ImportPlan, allocator: std.mem.Allocator) void {
        for (self.baseline_states) |*state| state.deinit();
        allocator.free(self.baseline_states);
        allocator.free(self.imports);
    }
};

/// Builds valid withdrawal blocks, then compares full-rebuild and incremental imports.
pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    var seed = execution.state.State.init(allocator);
    defer seed.deinit();
    for (0..account_count) |i| {
        var address: execution.state.Address = .{0} ** 20;
        address[18] = @truncate(i >> 8);
        address[19] = @truncate(i);
        try seed.setBalance(address, @intCast(i + 1));
    }
    const target: execution.state.Address = .{0x77} ** 20;
    for (0..storage_slots) |slot| try seed.setStorage(target, @intCast(slot), @intCast(slot + 1));
    _ = try seed.stateRoot();

    var plan = try buildImportPlan(allocator, &seed, target);
    defer plan.deinit(allocator);

    var baseline_work: usize = 0;
    const baseline_start = std.Io.Clock.awake.now(init.io).nanoseconds;
    for (plan.imports, 0..) |block, i| {
        var result = try execution.transition.applyBlock(allocator, &plan.baseline_states[i], .{ .fork = fork, .parent_fork = fork, .chain_id = 1 }, block.parent, block.header, &.{}, &.{block.withdrawal});
        result.deinit();
        baseline_work += plan.baseline_states[i].trieNodeBuilds();
    }
    const baseline_elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - baseline_start;

    var incremental = try seed.clone(allocator);
    defer incremental.deinit();
    var incremental_work: usize = 0;
    const incremental_start = std.Io.Clock.awake.now(init.io).nanoseconds;
    for (plan.imports) |block| {
        const before = incremental.trieNodeBuilds();
        var result = try execution.transition.applyBlock(allocator, &incremental, .{ .fork = fork, .parent_fork = fork, .chain_id = 1 }, block.parent, block.header, &.{}, &.{block.withdrawal});
        result.deinit();
        incremental_work += incremental.trieNodeBuilds() - before;
    }
    const incremental_elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - incremental_start;
    const output = try std.fmt.allocPrint(
        allocator,
        "{d} account block imports ({d} storage slots, {d} blocks)\nfull rebuild: {d:.2} ms/block, {d} trie nodes built\nincremental: {d:.2} ms/block, {d} trie nodes built\n",
        .{
            account_count,
            storage_slots,
            iterations,
            nsPerIteration(baseline_elapsed),
            baseline_work,
            nsPerIteration(incremental_elapsed),
            incremental_work,
        },
    );
    defer allocator.free(output);
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

/// Produces linked, valid Shanghai blocks and their expected post-withdrawal state roots.
fn buildImportPlan(allocator: std.mem.Allocator, seed: *const execution.state.State, target: execution.state.Address) !ImportPlan {
    const imports = try allocator.alloc(BlockImport, iterations);
    errdefer allocator.free(imports);
    const baseline_states = try allocator.alloc(execution.state.State, iterations);
    var initialized_states: usize = 0;
    errdefer {
        for (baseline_states[0..initialized_states]) |*state| state.deinit();
        allocator.free(baseline_states);
    }
    var planning = try seed.clone(allocator);
    defer planning.deinit();
    var parent = std.mem.zeroes(execution.Header);
    parent.gas_limit = 30_000_000;
    parent.base_fee_per_gas = 1;
    parent.state_root = try planning.stateRoot();
    parent.transactions_root = try execution.trie.orderedRoot(allocator, &.{});
    parent.receipts_root = try execution.receiptsRoot(allocator, &.{});
    parent.withdrawals_root = try execution.trie.orderedRoot(allocator, &.{});

    for (imports, 0..) |*block, i| {
        baseline_states[i] = try planning.clone(allocator);
        initialized_states += 1;
        const withdrawal = execution.Withdrawal{ .index = i, .validator_index = i, .address = target, .amount = 1 };
        var header = parent;
        header.parent_hash = try execution.transition.headerHash(allocator, fork, parent);
        header.number = parent.number + 1;
        header.timestamp = parent.timestamp + 1;
        header.base_fee_per_gas = try execution.transition.nextBaseFee(parent.gas_limit, parent.gas_used, parent.base_fee_per_gas);
        const encoded_withdrawal = try execution.encode(allocator, withdrawal);
        defer allocator.free(encoded_withdrawal);
        header.withdrawals_root = try execution.trie.orderedRoot(allocator, &.{encoded_withdrawal});
        const credited_balance = try std.math.add(u256, planning.getBalance(target), 1_000_000_000);
        try planning.setBalance(target, credited_balance);
        header.state_root = try planning.stateRoot();
        block.* = .{ .parent = parent, .header = header, .withdrawal = withdrawal };
        parent = header;
    }
    return .{ .imports = imports, .baseline_states = baseline_states };
}

/// Converts a total nanosecond duration to milliseconds per imported block.
fn nsPerIteration(elapsed: i96) f64 {
    return @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations)) / std.time.ns_per_ms;
}

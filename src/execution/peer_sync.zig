// An execution peer supplies untrusted RLP blocks. The requested hash binds a
// response to its header; the parent must already have a validated post-state.
// Blocks execute in ancestry order, and a durable marker precedes retention.
// Fork choice alone selects the canonical head. Responses are limited to 11 MiB.
//
// checkpoint -> verified parent -> execute block -> durable marker -> fork choice
const std = @import("std");
const execution = @import("execution.zig");
const chain_mod = @import("chain.zig");
const durable = @import("durable.zig");

const max_block_bytes = 11 * 1024 * 1024;

/// Verifies one requested peer block and retains it off the canonical path.
/// The caller serializes access to chain and store; unknown parents are retried
/// only after their ancestors are available.
pub fn importBlock(allocator: std.mem.Allocator, chain: *chain_mod.Chain, store: ?*durable.Store, requested: execution.Hash, raw: []const u8) !void {
    if (raw.len > max_block_bytes) return error.PeerBlockTooLarge;
    var decoded = try execution.parse(execution.Block, allocator, raw);
    defer decoded.deinit();
    const block = decoded.value;
    const hash = try execution.transition.headerHash(allocator, chain.fork, block.header);
    if (!std.mem.eql(u8, &hash, &requested)) return error.UnrequestedPeerBlock;
    if (chain.byHash(hash) != null) return;
    const parent = chain.byHash(block.header.parent_hash) orelse return error.UnknownParent;
    const next_number = std.math.add(u64, parent.header.number, 1) catch return error.InvalidPeerAncestry;
    if (block.header.number != next_number) return error.InvalidPeerAncestry;
    var parent_world = try chain.loadWorld(allocator, parent.hash);
    defer parent_world.deinit();
    var world = try parent_world.clone(allocator);
    var world_owned = true;
    defer if (world_owned) world.deinit();
    const ancestors = try chain.ancestorHashes(allocator, parent.hash);
    defer allocator.free(ancestors);
    const transactions = try allocator.alloc([]const u8, block.transactions.len);
    defer allocator.free(transactions);
    var transaction_count: usize = 0;
    defer for (transactions[0..transaction_count]) |transaction| allocator.free(transaction);
    var blob_hashes: std.ArrayList(execution.Hash) = .empty;
    defer blob_hashes.deinit(allocator);
    for (block.transactions, 0..) |transaction, index| {
        transactions[index] = try execution.encode(allocator, transaction);
        transaction_count += 1;
        if (transaction == .blob) try blob_hashes.appendSlice(allocator, transaction.blob.blob_versioned_hashes);
    }
    const max_blobs: u64 = switch (chain.fork) {
        .cancun => 6,
        .prague, .osaka => 9,
        .fulu => 21,
        else => 0,
    };
    var result = try execution.transition.applyBlock(allocator, &world, .{
        .fork = chain.fork,
        .parent_fork = chain.fork,
        .chain_id = chain.chain_id,
        .older_hashes = ancestors,
        .max_blobs_per_block = max_blobs,
        .expected_blob_hashes = blob_hashes.items,
        .verify_requests_hash = true,
        .kzg_settings = chain.kzg_settings,
    }, parent.header, block.header, transactions, block.withdrawals);
    errdefer result.deinit();
    if (store) |db| try db.stage(chain.fork, block.header, transactions, block.withdrawals, result.receipts, &parent_world, &world);
    world_owned = !(try chain.retainOwned(block.header, transactions, block.withdrawals, result, &world));
}

// Canonical execution history keeps one validated block per number. Each
// post-state snapshot backs historical RPC reads; receipt and transaction
// order follows block order. This in-memory index does not handle reorgs or
// persistence, which belong to node storage and the Engine API.
//
// genesis state -> block 1 post-state -> block 2 post-state -> latest
const std = @import("std");
const execution = @import("execution.zig");
const transition = @import("transition.zig");

pub const Record = struct {
    header: execution.Header,
    hash: execution.Hash,
    transactions: [][]u8,
    withdrawals: []execution.Withdrawal,
    result: ?transition.BlockResult,
    world: execution.state.State,

    /// Releases a block snapshot and all retained canonical execution data.
    pub fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        allocator.free(self.header.extra_data);
        for (self.transactions) |raw| allocator.free(raw);
        allocator.free(self.transactions);
        allocator.free(self.withdrawals);
        if (self.result) |*result| result.deinit();
        self.world.deinit();
    }

    /// Returns the ordered receipts, empty for a genesis anchor.
    pub fn receipts(self: *const Record) []const execution.Receipt {
        return if (self.result) |result| result.receipts else &.{};
    }
};

/// Owns canonical blocks and their post-states in memory.
pub const Chain = struct {
    allocator: std.mem.Allocator,
    chain_id: u256,
    fork: transition.Fork,
    records: std.ArrayList(Record) = .empty,

    /// Takes a snapshot of genesis state and its already validated header.
    pub fn init(allocator: std.mem.Allocator, chain_id: u256, fork: transition.Fork, genesis: execution.Header, world: *const execution.state.State) !Chain {
        var chain: Chain = .{ .allocator = allocator, .chain_id = chain_id, .fork = fork };
        errdefer chain.deinit();
        try chain.records.append(allocator, try chain.copyRecord(genesis, &.{}, &.{}, null, world));
        return chain;
    }

    /// Releases all canonical snapshots and receipt data.
    pub fn deinit(self: *Chain) void {
        for (self.records.items) |*record| record.deinit(self.allocator);
        self.records.deinit(self.allocator);
        self.* = undefined;
    }

    /// Validates and appends the next canonical block against ordered consensus blob hashes.
    pub fn append(self: *Chain, world: *execution.state.State, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, expected_blob_hashes: []const execution.Hash) !void {
        const parent = self.latest().header;
        const older_hashes = try self.olderHashes(self.allocator);
        defer self.allocator.free(older_hashes);
        const snap = try world.snapshot();
        var open = true;
        errdefer if (open) world.revert(snap) catch {};
        const max_blobs: u64 = switch (self.fork) {
            .cancun => 6,
            .prague, .osaka => 9,
            else => 21,
        };
        var result = try transition.applyBlock(self.allocator, world, .{ .fork = self.fork, .parent_fork = self.fork, .chain_id = self.chain_id, .older_hashes = older_hashes, .max_blobs_per_block = max_blobs, .expected_blob_hashes = expected_blob_hashes }, parent, header, transactions, withdrawals);
        var result_owned = true;
        errdefer if (result_owned) result.deinit();
        var record = try self.copyRecord(header, transactions, withdrawals, result, world);
        result_owned = false;
        errdefer record.deinit(self.allocator);
        try self.records.append(self.allocator, record);
        world.commit(snap) catch unreachable;
        open = false;
    }

    /// Returns the canonical head.
    pub fn latest(self: *const Chain) *const Record {
        return &self.records.items[self.records.items.len - 1];
    }

    /// Resolves a canonical number or block tag.
    pub fn byNumber(self: *const Chain, number: u64) ?*const Record {
        for (self.records.items) |*record| if (record.header.number == number) return record;
        return null;
    }

    /// Resolves a canonical block hash.
    pub fn byHash(self: *const Chain, hash: execution.Hash) ?*const Record {
        for (self.records.items) |*record| if (std.mem.eql(u8, &record.hash, &hash)) return record;
        return null;
    }

    /// Copies up to 255 canonical ancestors before the current head, newest first.
    pub fn olderHashes(self: *const Chain, allocator: std.mem.Allocator) ![]execution.Hash {
        const count = @min(self.records.items.len - 1, 255);
        const hashes = try allocator.alloc(execution.Hash, count);
        for (hashes, 0..) |*hash, i| hash.* = self.records.items[self.records.items.len - 2 - i].hash;
        return hashes;
    }

    /// Locates a transaction and its zero-based index in canonical history.
    pub fn transaction(self: *const Chain, hash: execution.Hash) ?struct { record: *const Record, index: usize } {
        for (self.records.items) |*record| for (record.transactions, 0..) |raw, index| {
            var candidate: execution.Hash = undefined;
            std.crypto.hash.sha3.Keccak256.hash(raw, &candidate, .{});
            if (std.mem.eql(u8, &candidate, &hash)) return .{ .record = record, .index = index };
        };
        return null;
    }

    /// Copies a block header, canonical transaction bytes, and post-state.
    fn copyRecord(self: *Chain, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, result: ?transition.BlockResult, world: *const execution.state.State) !Record {
        var owned_header = header;
        owned_header.extra_data = try self.allocator.dupe(u8, header.extra_data);
        errdefer self.allocator.free(owned_header.extra_data);
        const raws = try self.allocator.alloc([]u8, transactions.len);
        errdefer self.allocator.free(raws);
        var copied: usize = 0;
        errdefer for (raws[0..copied]) |raw| self.allocator.free(raw);
        for (transactions, 0..) |raw, i| {
            raws[i] = try self.allocator.dupe(u8, raw);
            copied += 1;
        }
        var snapshot = try world.clone(self.allocator);
        errdefer snapshot.deinit();
        const copied_withdrawals = try self.allocator.dupe(execution.Withdrawal, withdrawals);
        errdefer self.allocator.free(copied_withdrawals);
        return .{ .header = owned_header, .hash = try transition.headerHash(self.allocator, self.fork, header), .transactions = raws, .withdrawals = copied_withdrawals, .result = result, .world = snapshot };
    }
};

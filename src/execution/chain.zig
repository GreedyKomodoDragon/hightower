// Validated execution blocks retain their parent hash and post-state. Fork
// choice selects a separate canonical path; block-number and log reads follow
// that path, while block-hash lookup can find a validated side branch.
//
// genesis -> A1 -> A2  (validated ancestry)
//         \-> B1 -> B2  (canonical path selected by fork choice)
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

/// Owns validated blocks and a canonical path through them in memory.
pub const Chain = struct {
    allocator: std.mem.Allocator,
    chain_id: u256,
    fork: transition.Fork,
    records: std.ArrayList(Record) = .empty,
    canonical: std.ArrayList(usize) = .empty,
    safe_hash: execution.Hash = [_]u8{0} ** 32,
    finalized_hash: execution.Hash = [_]u8{0} ** 32,

    /// Takes a snapshot of genesis state and its already validated header.
    pub fn init(allocator: std.mem.Allocator, chain_id: u256, fork: transition.Fork, genesis: execution.Header, world: *const execution.state.State) !Chain {
        var chain: Chain = .{ .allocator = allocator, .chain_id = chain_id, .fork = fork };
        errdefer chain.deinit();
        try chain.records.append(allocator, try chain.copyRecord(genesis, &.{}, &.{}, null, world));
        try chain.canonical.append(allocator, 0);
        return chain;
    }

    /// Releases all canonical snapshots and receipt data.
    pub fn deinit(self: *Chain) void {
        for (self.records.items) |*record| record.deinit(self.allocator);
        self.records.deinit(self.allocator);
        self.canonical.deinit(self.allocator);
        self.* = undefined;
    }

    /// Validates and appends the next canonical block against ordered blob hashes and requests.
    pub fn append(self: *Chain, world: *execution.state.State, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, expected_blob_hashes: []const execution.Hash, expected_requests: ?[]const []const u8) !void {
        const parent = self.latest().header;
        const older_hashes = try self.olderHashes(self.allocator);
        defer self.allocator.free(older_hashes);
        const snap = try world.snapshot();
        var open = true;
        errdefer if (open) world.revert(snap) catch |err| std.log.err("best-effort operation failed: {s}", .{@errorName(err)});
        const max_blobs: u64 = switch (self.fork) {
            .cancun => 6,
            .prague, .osaka => 9,
            else => 21,
        };
        var result = try transition.applyBlock(self.allocator, world, .{ .fork = self.fork, .parent_fork = self.fork, .chain_id = self.chain_id, .older_hashes = older_hashes, .max_blobs_per_block = max_blobs, .expected_blob_hashes = expected_blob_hashes, .expected_requests = expected_requests }, parent, header, transactions, withdrawals);
        var result_owned = true;
        errdefer if (result_owned) result.deinit();
        var record = try self.copyRecord(header, transactions, withdrawals, result, world);
        result_owned = false;
        var record_owned = true;
        errdefer if (record_owned) record.deinit(self.allocator);
        try self.records.append(self.allocator, record);
        record_owned = false;
        errdefer {
            var removed = self.records.pop().?;
            removed.deinit(self.allocator);
        }
        try self.canonical.append(self.allocator, self.records.items.len - 1);
        errdefer _ = self.canonical.pop();
        try world.commit(snap);
        open = false;
    }

    /// Returns the canonical head.
    pub fn latest(self: *const Chain) *const Record {
        return &self.records.items[self.canonical.items[self.canonical.items.len - 1]];
    }

    /// Resolves a canonical number or block tag.
    pub fn byNumber(self: *const Chain, number: u64) ?*const Record {
        for (self.canonical.items) |index| {
            const record = &self.records.items[index];
            if (record.header.number == number) return record;
        }
        return null;
    }

    /// Resolves a canonical block hash.
    pub fn byHash(self: *const Chain, hash: execution.Hash) ?*const Record {
        for (self.records.items) |*record| if (std.mem.eql(u8, &record.hash, &hash)) return record;
        return null;
    }

    /// Builds the complete canonical path before publishing a fork-choice change.
    pub fn path(self: *const Chain, allocator: std.mem.Allocator, head: execution.Hash) !std.ArrayList(usize) {
        var reverse: std.ArrayList(usize) = .empty;
        errdefer reverse.deinit(allocator);
        var current = head;
        while (true) {
            var found: ?usize = null;
            for (self.records.items, 0..) |record, index| if (std.mem.eql(u8, &record.hash, &current)) {
                found = index;
                break;
            };
            const index = found orelse return error.UnknownBlock;
            try reverse.append(allocator, index);
            if (index == 0) break;
            current = self.records.items[index].header.parent_hash;
            if (reverse.items.len > self.records.items.len) return error.InvalidAncestry;
        }
        std.mem.reverse(usize, reverse.items);
        for (reverse.items, 0..) |index, number| if (self.records.items[index].header.number != self.records.items[0].header.number + number) return error.InvalidAncestry;
        return reverse;
    }

    /// Retains an executed block independently of the canonical path.
    pub fn retain(self: *Chain, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, result: transition.BlockResult, world: *const execution.state.State) !void {
        var record = try self.copyRecord(header, transactions, withdrawals, null, world);
        errdefer record.deinit(self.allocator);
        try self.records.append(self.allocator, record);
        self.records.items[self.records.items.len - 1].result = result;
    }

    /// Copies up to 255 canonical ancestors before the current head, newest first.
    pub fn olderHashes(self: *const Chain, allocator: std.mem.Allocator) ![]execution.Hash {
        return self.ancestorHashes(allocator, self.latest().hash);
    }

    /// Copies up to 255 ancestors of any validated block, newest first.
    pub fn ancestorHashes(self: *const Chain, allocator: std.mem.Allocator, head: execution.Hash) ![]execution.Hash {
        const record = self.byHash(head) orelse return error.UnknownBlock;
        const count = @min(record.header.number - self.records.items[0].header.number, 255);
        const hashes = try allocator.alloc(execution.Hash, count);
        var current = record;
        for (hashes) |*hash| {
            current = self.byHash(current.header.parent_hash) orelse return error.InvalidAncestry;
            hash.* = current.hash;
        }
        return hashes;
    }

    /// Locates a transaction and its zero-based index in canonical history.
    pub fn transaction(self: *const Chain, hash: execution.Hash) ?struct { record: *const Record, index: usize } {
        for (self.canonical.items) |record_index| for (self.records.items[record_index].transactions, 0..) |raw, index| {
            // SAFETY: This value is fully initialized before any read.
            var candidate: execution.Hash = undefined;
            std.crypto.hash.sha3.Keccak256.hash(raw, &candidate, .{});
            if (std.mem.eql(u8, &candidate, &hash)) return .{ .record = &self.records.items[record_index], .index = index };
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

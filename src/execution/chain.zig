// Validated execution blocks retain their parent hash and post-state. Fork
// choice selects a separate canonical path; public reads follow that path.
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
    world: ?execution.state.State,

    /// Releases a block snapshot and all retained canonical execution data.
    pub fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        allocator.free(self.header.extra_data);
        for (self.transactions) |raw| allocator.free(raw);
        allocator.free(self.transactions);
        allocator.free(self.withdrawals);
        if (self.result) |*result| result.deinit();
        if (self.world) |*world| world.deinit();
    }

    /// Returns the ordered receipts, empty for a genesis anchor.
    pub fn receipts(self: *const Record) []const execution.Receipt {
        return if (self.result) |result| result.receipts else &.{};
    }
};

const TransactionLocation = struct { record: usize, index: usize };

/// Owns validated blocks and a canonical path through them in memory.
pub const Chain = struct {
    allocator: std.mem.Allocator,
    chain_id: u256,
    fork: transition.Fork,
    kzg_settings: ?*const execution.kzg.Settings = null,
    records: std.ArrayList(Record) = .empty,
    canonical: std.ArrayList(usize) = .empty,
    record_by_hash: std.AutoHashMap(execution.Hash, usize),
    canonical_by_hash: std.AutoHashMap(execution.Hash, usize),
    canonical_by_number: std.AutoHashMap(u64, usize),
    canonical_transactions: std.AutoHashMap(execution.Hash, TransactionLocation),
    safe_hash: execution.Hash = [_]u8{0} ** 32,
    finalized_hash: execution.Hash = [_]u8{0} ** 32,
    history_floor: u64 = 0,
    durability_uncertain: bool = false,
    state_loader: ?struct {
        context: *anyopaque,
        load: *const fn (*anyopaque, *const Chain, std.mem.Allocator, execution.Hash) anyerror!execution.state.State,
    } = null,

    /// Takes a snapshot of genesis state and its already validated header.
    pub fn init(allocator: std.mem.Allocator, chain_id: u256, fork: transition.Fork, genesis: execution.Header, world: *const execution.state.State) !Chain {
        var chain: Chain = .{ .allocator = allocator, .chain_id = chain_id, .fork = fork, .record_by_hash = .init(allocator), .canonical_by_hash = .init(allocator), .canonical_by_number = .init(allocator), .canonical_transactions = .init(allocator) };
        errdefer chain.deinit();
        try chain.records.append(allocator, try chain.copyRecord(genesis, &.{}, &.{}, null, world));
        try chain.canonical.append(allocator, 0);
        try chain.rebuildIndexes();
        return chain;
    }

    /// Releases all canonical snapshots and receipt data.
    pub fn deinit(self: *Chain) void {
        for (self.records.items) |*record| record.deinit(self.allocator);
        self.records.deinit(self.allocator);
        self.canonical.deinit(self.allocator);
        self.record_by_hash.deinit();
        self.canonical_by_hash.deinit();
        self.canonical_by_number.deinit();
        self.canonical_transactions.deinit();
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
        var result = try transition.applyBlock(self.allocator, world, .{ .fork = self.fork, .parent_fork = self.fork, .chain_id = self.chain_id, .older_hashes = older_hashes, .max_blobs_per_block = max_blobs, .expected_blob_hashes = expected_blob_hashes, .expected_requests = expected_requests, .kzg_settings = self.kzg_settings }, parent, header, transactions, withdrawals);
        var result_owned = true;
        errdefer if (result_owned) result.deinit();
        var record = try self.copyRecord(header, transactions, withdrawals, result, world);
        result_owned = false;
        var record_owned = true;
        errdefer if (record_owned) record.deinit(self.allocator);
        try self.reserveIndexes(record);
        try self.records.ensureUnusedCapacity(self.allocator, 1);
        try self.canonical.ensureUnusedCapacity(self.allocator, 1);
        try self.records.append(self.allocator, record);
        record_owned = false;
        const index = self.records.items.len - 1;
        self.record_by_hash.putAssumeCapacity(self.records.items[index].hash, index);
        try self.canonical.append(self.allocator, index);
        errdefer {
            const added = &self.records.items[index];
            if (self.record_by_hash.get(added.hash) == index) _ = self.record_by_hash.remove(added.hash);
            if (self.canonical_by_hash.get(added.hash) == index) _ = self.canonical_by_hash.remove(added.hash);
            if (self.canonical_by_number.get(added.header.number) == index) _ = self.canonical_by_number.remove(added.header.number);
            for (added.transactions, 0..) |raw, tx_index| {
                // SAFETY: Keccak writes all 32 output bytes before the hash is read.
                var hash: execution.Hash = undefined;
                std.crypto.hash.sha3.Keccak256.hash(raw, &hash, .{});
                if (self.canonical_transactions.get(hash)) |location| {
                    if (location.record == index and location.index == tx_index) _ = self.canonical_transactions.remove(hash);
                }
            }
            _ = self.canonical.pop();
            var removed = self.records.pop().?;
            removed.deinit(self.allocator);
        }
        try self.indexCanonicalRecord(index);
        try world.commit(snap);
        open = false;
    }

    /// Returns the canonical head.
    pub fn latest(self: *const Chain) *const Record {
        return &self.records.items[self.canonical.items[self.canonical.items.len - 1]];
    }

    /// Resolves a canonical number or block tag.
    pub fn byNumber(self: *const Chain, number: u64) ?*const Record {
        if (number < self.history_floor and number != self.records.items[0].header.number) return null;
        const index = self.canonical_by_number.get(number) orelse return null;
        return &self.records.items[index];
    }

    /// Resolves a validated block hash for Engine ancestry and branch execution.
    pub fn byHash(self: *const Chain, hash: execution.Hash) ?*const Record {
        const index = self.record_by_hash.get(hash) orelse return null;
        return &self.records.items[index];
    }

    /// Resolves a block hash only when it belongs to the selected canonical path.
    pub fn canonicalByHash(self: *const Chain, hash: execution.Hash) ?*const Record {
        const index = self.canonical_by_hash.get(hash) orelse return null;
        return &self.records.items[index];
    }

    /// Returns an owned post-state from RAM or durable checkpoint and delta data.
    pub fn loadWorld(self: *const Chain, allocator: std.mem.Allocator, hash: execution.Hash) !execution.state.State {
        const record = self.byHash(hash) orelse return error.UnknownBlock;
        if (record.header.number < self.history_floor and record.header.number != self.records.items[0].header.number) return error.PrunedExecutionState;
        if (record.world) |*world| return world.clone(allocator);
        const loader = self.state_loader orelse return error.MissingExecutionState;
        return loader.load(loader.context, self, allocator, hash);
    }

    /// Builds the canonical path from genesis or the retained checkpoint anchor.
    pub fn path(self: *const Chain, allocator: std.mem.Allocator, head: execution.Hash) !std.ArrayList(usize) {
        var reverse: std.ArrayList(usize) = .empty;
        errdefer reverse.deinit(allocator);
        var current = head;
        while (true) {
            const index = self.record_by_hash.get(current) orelse return error.UnknownBlock;
            try reverse.append(allocator, index);
            if (index == 0 or self.records.items[index].header.number == self.history_floor) break;
            current = self.records.items[index].header.parent_hash;
            if (reverse.items.len > self.records.items.len) return error.InvalidAncestry;
        }
        std.mem.reverse(usize, reverse.items);
        const start = self.records.items[reverse.items[0]].header.number;
        if (start != self.records.items[0].header.number and start != self.history_floor) return error.InvalidAncestry;
        for (reverse.items, 0..) |index, number| if (self.records.items[index].header.number != start + number) return error.InvalidAncestry;
        if (start != self.records.items[0].header.number) try reverse.insert(allocator, 0, 0);
        return reverse;
    }

    /// Retains an executed block independently of the canonical path.
    pub fn retain(self: *Chain, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, result: transition.BlockResult, world: *const execution.state.State) !void {
        var record = try self.copyRecord(header, transactions, withdrawals, null, world);
        errdefer record.deinit(self.allocator);
        try self.reserveIndexes(record);
        try self.records.append(self.allocator, record);
        const index = self.records.items.len - 1;
        self.records.items[self.records.items.len - 1].result = result;
        self.record_by_hash.putAssumeCapacity(self.records.items[index].hash, index);
    }

    /// Retains an executed post-state by moving it into the record after all fallible preparation succeeds.
    pub fn retainOwned(self: *Chain, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, result: transition.BlockResult, world: *execution.state.State) !bool {
        var record = try self.copyRecord(header, transactions, withdrawals, null, null);
        errdefer record.deinit(self.allocator);
        try self.reserveIndexes(record);
        try self.records.ensureUnusedCapacity(self.allocator, 1);
        const consumed = self.state_loader == null;
        if (consumed) {
            record.world = world.*;
            // SAFETY: Ownership moved into the record; callers must not deinitialize the source.
            world.* = undefined;
        }
        self.records.appendAssumeCapacity(record);
        const index = self.records.items.len - 1;
        self.records.items[index].result = result;
        self.record_by_hash.putAssumeCapacity(self.records.items[index].hash, index);
        return consumed;
    }

    /// Frees excluded records and remaps the canonical indexes.
    pub fn retainOnly(self: *Chain, keep: []const bool) !void {
        if (keep.len != self.records.items.len) return error.InvalidPruneMask;
        if (!keep[0]) return error.InvalidPruneMask;
        const positions = try self.allocator.alloc(usize, keep.len);
        defer self.allocator.free(positions);
        var retained: std.ArrayList(Record) = .empty;
        errdefer retained.deinit(self.allocator);
        var canonical: std.ArrayList(usize) = .empty;
        errdefer canonical.deinit(self.allocator);
        try canonical.ensureTotalCapacity(self.allocator, self.canonical.items.len);
        var count: usize = 0;
        for (keep) |wanted| if (wanted) {
            count += 1;
        };
        try retained.ensureTotalCapacity(self.allocator, count);
        for (self.records.items, 0..) |*record, index| if (keep[index]) {
            positions[index] = retained.items.len;
            retained.appendAssumeCapacity(record.*);
        };
        for (self.canonical.items) |index| if (keep[index]) canonical.appendAssumeCapacity(positions[index]);
        var old_records = self.records;
        var old_canonical = self.canonical;
        self.records = retained;
        self.canonical = canonical;
        self.rebuildIndexes() catch |err| {
            self.records = old_records;
            self.canonical = old_canonical;
            retained.deinit(self.allocator);
            canonical.deinit(self.allocator);
            retained = .empty;
            canonical = .empty;
            return err;
        };
        for (old_records.items, 0..) |*record, index| if (!keep[index]) record.deinit(self.allocator);
        old_records.deinit(self.allocator);
        old_canonical.deinit(self.allocator);
    }

    /// Copies up to 255 canonical ancestors before the current head, newest first.
    pub fn olderHashes(self: *const Chain, allocator: std.mem.Allocator) ![]execution.Hash {
        return self.ancestorHashes(allocator, self.latest().hash);
    }

    /// Copies up to 255 ancestors of any validated block, newest first.
    pub fn ancestorHashes(self: *const Chain, allocator: std.mem.Allocator, head: execution.Hash) ![]execution.Hash {
        const record = self.byHash(head) orelse return error.UnknownBlock;
        const count = @min(record.header.number - @max(self.records.items[0].header.number, self.history_floor), 255);
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
        const found = self.canonical_transactions.get(hash) orelse return null;
        if (self.records.items[found.record].header.number < self.history_floor) return null;
        return .{ .record = &self.records.items[found.record], .index = found.index };
    }

    /// Reserves capacity before a record is published into the chain.
    fn reserveIndexes(self: *Chain, record: Record) !void {
        try self.record_by_hash.ensureUnusedCapacity(1);
        try self.canonical_by_hash.ensureUnusedCapacity(1);
        try self.canonical_by_number.ensureUnusedCapacity(1);
        try self.canonical_transactions.ensureUnusedCapacity(@intCast(record.transactions.len));
    }

    /// Adds one canonical record and its transactions to derived indexes.
    fn indexCanonicalRecord(self: *Chain, index: usize) !void {
        const record = &self.records.items[index];
        try self.canonical_by_hash.put(record.hash, index);
        try self.canonical_by_number.put(record.header.number, index);
        if (record.header.number < self.history_floor) return;
        for (record.transactions, 0..) |raw, tx_index| {
            // SAFETY: Keccak writes all 32 output bytes before the hash is read.
            var hash: execution.Hash = undefined;
            std.crypto.hash.sha3.Keccak256.hash(raw, &hash, .{});
            if (!self.canonical_transactions.contains(hash)) try self.canonical_transactions.put(hash, .{ .record = index, .index = tx_index });
        }
    }

    /// Rebuilds derived lookup maps from retained records and the selected path.
    pub fn rebuildIndexes(self: *Chain) !void {
        var records: std.AutoHashMap(execution.Hash, usize) = .init(self.allocator);
        errdefer records.deinit();
        var hashes: std.AutoHashMap(execution.Hash, usize) = .init(self.allocator);
        errdefer hashes.deinit();
        var numbers: std.AutoHashMap(u64, usize) = .init(self.allocator);
        errdefer numbers.deinit();
        var transactions: std.AutoHashMap(execution.Hash, TransactionLocation) = .init(self.allocator);
        errdefer transactions.deinit();
        for (self.records.items, 0..) |record, index| try records.put(record.hash, index);
        for (self.canonical.items) |index| {
            const record = &self.records.items[index];
            try hashes.put(record.hash, index);
            try numbers.put(record.header.number, index);
            if (record.header.number < self.history_floor) continue;
            for (record.transactions, 0..) |raw, tx_index| {
                // SAFETY: Keccak writes all 32 output bytes before the hash is read.
                var hash: execution.Hash = undefined;
                std.crypto.hash.sha3.Keccak256.hash(raw, &hash, .{});
                if (!transactions.contains(hash)) try transactions.put(hash, .{ .record = index, .index = tx_index });
            }
        }
        self.record_by_hash.deinit();
        self.canonical_by_hash.deinit();
        self.canonical_by_number.deinit();
        self.canonical_transactions.deinit();
        self.record_by_hash = records;
        self.canonical_by_hash = hashes;
        self.canonical_by_number = numbers;
        self.canonical_transactions = transactions;
    }

    /// Selects a validated path and rebuilds indexes before releasing the old path.
    pub fn replaceCanonical(self: *Chain, new_path: std.ArrayList(usize)) !std.ArrayList(usize) {
        const old = self.canonical;
        self.canonical = new_path;
        self.rebuildIndexes() catch |err| {
            self.canonical = old;
            return err;
        };
        return old;
    }

    /// Copies a block header, canonical transaction bytes, and post-state.
    fn copyRecord(self: *Chain, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, result: ?transition.BlockResult, world: ?*const execution.state.State) !Record {
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
        var snapshot: ?execution.state.State = if (self.state_loader == null and world != null) try world.?.clone(self.allocator) else null;
        errdefer if (snapshot) |*state| state.deinit();
        const copied_withdrawals = try self.allocator.dupe(execution.Withdrawal, withdrawals);
        errdefer self.allocator.free(copied_withdrawals);
        return .{ .header = owned_header, .hash = try transition.headerHash(self.allocator, self.fork, header), .transactions = raws, .withdrawals = copied_withdrawals, .result = result, .world = snapshot };
    }
};

// Validated execution data is written under its block hash before a small
// marker makes the block recoverable. Fork choice is one checksummed LSM value,
// so recovery sees either the old or new head, safe, and finalized hashes.
// State deltas replace changed accounts; every 128th block also stores a
// chunked full checkpoint. Recovery verifies ancestry and all committed roots.
//
// block/receipts/delta chunks -> validated marker -> choice(head,safe,final)
const std = @import("std");
const execution = @import("execution.zig");
const chain_mod = @import("chain.zig");
const storage = @import("storage");

const chunk_size = 4 * 1024 * 1024;
const checkpoint_interval = 128;
const retained_canonical_blocks = 4096;
const marker_size = 8 + 4 * (4 + 32);

const BlobInfo = struct { len: u32, hash: execution.Hash };
const Marker = struct {
    number: u64,
    block: BlobInfo,
    receipts: BlobInfo,
    delta: BlobInfo,
    checkpoint: BlobInfo,
};

/// Owns a checksummed LSM database for validated execution branches.
pub const Store = struct {
    allocator: std.mem.Allocator,
    db: storage.Database,

    /// Opens storage and restores the checked genesis state into world.
    pub fn open(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, fork: execution.transition.Fork, genesis: execution.Header, world: *execution.state.State) !Store {
        var db = try storage.Database.open(allocator, io, dir, path);
        errdefer db.close();
        const genesis_hash = try execution.transition.headerHash(allocator, fork, genesis);
        var store: Store = .{ .allocator = allocator, .db = db };
        const saved = try store.db.get(allocator, "genesis");
        defer if (saved) |bytes| allocator.free(bytes);
        if (saved) |bytes| {
            if (bytes.len != 32 + 4 + 32 or !std.mem.eql(u8, bytes[0..32], &genesis_hash)) return error.GenesisMismatch;
            const checkpoint = try store.readBlob("genesis", genesis_hash, .{ .len = std.mem.readInt(u32, bytes[32..36], .little), .hash = bytes[36..68].* });
            defer allocator.free(checkpoint);
            var restored = execution.state.State.init(allocator);
            errdefer restored.deinit();
            try restored.applyStateBytes(checkpoint);
            const recovered_root = try restored.stateRoot();
            if (!std.mem.eql(u8, &recovered_root, &genesis.state_root)) return error.CorruptExecutionState;
            world.deinit();
            world.* = restored;
            return store;
        }
        const root = try world.stateRoot();
        if (!std.mem.eql(u8, &root, &genesis.state_root)) return error.InvalidGenesis;
        const checkpoint = try world.checkpointBytes(allocator);
        defer allocator.free(checkpoint);
        const info = try store.writeBlob("genesis", genesis_hash, checkpoint);
        var marker: [68]u8 = undefined;
        @memcpy(marker[0..32], &genesis_hash);
        std.mem.writeInt(u32, marker[32..36], info.len, .little);
        @memcpy(marker[36..68], &info.hash);
        try store.db.put("genesis", &marker);
        return store;
    }

    /// Closes the database after all readers and Engine handlers stop.
    pub fn close(self: *Store) void {
        self.db.close();
    }

    /// Connects a chain to on-demand state reconstruction before staging blocks.
    pub fn attach(self: *Store, chain: *chain_mod.Chain) void {
        chain.state_loader = .{ .context = self, .load = loadState };
    }

    /// Persists one fully executed payload; the validated marker is written last.
    pub fn stage(self: *Store, fork: execution.transition.Fork, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, receipts: []const execution.Receipt, parent: *const execution.state.State, world: *const execution.state.State) !void {
        const hash = try execution.transition.headerHash(self.allocator, fork, header);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const decoded = try a.alloc(execution.Transaction, transactions.len);
        for (transactions, decoded) |raw, *tx| tx.* = (try execution.parse(execution.Transaction, a, raw)).value;
        const body = try execution.encode(a, execution.Block{ .header = header, .transactions = decoded, .withdrawals = withdrawals });
        var receipt_bytes: std.ArrayList(u8) = .empty;
        try appendInt(&receipt_bytes, a, u32, @intCast(receipts.len));
        for (receipts) |receipt| {
            const raw = try execution.encode(a, receipt);
            try appendInt(&receipt_bytes, a, u32, @intCast(raw.len));
            try receipt_bytes.appendSlice(a, raw);
        }
        const delta = try world.deltaBytes(a, parent);
        const checkpoint = if (header.number % checkpoint_interval == 0) try world.checkpointBytes(a) else &.{};
        _ = try self.writeBlob("header", hash, try execution.encode(a, header));
        const marker: Marker = .{
            .number = header.number,
            .block = try self.writeBlob("block", hash, body),
            .receipts = try self.writeBlob("receipt", hash, receipt_bytes.items),
            .delta = try self.writeBlob("delta", hash, delta),
            .checkpoint = try self.writeBlob("checkpoint", hash, checkpoint),
        };
        const key = try blockKey(a, header.number, hash);
        const bytes = encodeMarker(marker);
        try self.db.put(key, &bytes);
    }

    /// Atomically publishes the three fork-choice hashes after staged data is durable.
    pub fn commit(self: *Store, head: execution.Hash, safe: execution.Hash, finalized: execution.Hash) !void {
        var choice: [96]u8 = undefined;
        @memcpy(choice[0..32], &head);
        @memcpy(choice[32..64], &safe);
        @memcpy(choice[64..96], &finalized);
        try self.db.put("choice", &choice);
    }

    /// Removes finalized canonical bodies older than the retained checkpoint floor.
    pub fn prune(self: *Store, chain: *chain_mod.Chain) !void {
        try self.pruneSides(chain);
        try self.pruneRetained(chain, retained_canonical_blocks);
    }

    /// Removes branches that cannot descend from the finalized block.
    fn pruneSides(self: *Store, chain: *chain_mod.Chain) !void {
        if (std.mem.allEqual(u8, &chain.finalized_hash, 0)) return;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const keep = try a.alloc(bool, chain.records.items.len);
        @memset(keep, false);
        for (chain.canonical.items) |index| keep[index] = true;
        const Pending = struct { hash: execution.Hash, number: u64, marker: Marker };
        var doomed: std.ArrayList(Pending) = .empty;
        for (chain.records.items, 0..) |record, index| {
            if (keep[index] or isAncestor(chain, record.hash, chain.finalized_hash)) {
                keep[index] = true;
                continue;
            }
            const key = try blockKey(a, record.header.number, record.hash);
            const bytes = try self.db.get(a, key) orelse return error.MissingExecutionMarker;
            try doomed.append(a, .{ .hash = record.hash, .number = record.header.number, .marker = try decodeMarker(bytes) });
        }
        if (doomed.items.len == 0) return;
        try chain.retainOnly(keep);
        var index = doomed.items.len;
        while (index > 0) {
            index -= 1;
            const item = doomed.items[index];
            const journal = try pruneKey(a, item.hash);
            const marker = encodeMarker(item.marker);
            try self.db.put(journal, &marker);
            try self.finishPrune(item.hash, item.marker);
        }
    }

    /// Applies the fixed policy, with a smaller window available to tests.
    fn pruneRetained(self: *Store, chain: *chain_mod.Chain, retained: u64) !void {
        const finalized = chain.byHash(chain.finalized_hash) orelse return;
        const genesis_number = chain.records.items[0].header.number;
        if (finalized.header.number <= genesis_number + retained and chain.history_floor == 0) return;
        const target = ((finalized.header.number -| retained) / checkpoint_interval) * checkpoint_interval;
        const floor = @max(target, chain.history_floor);
        if (floor <= genesis_number) return;
        const completed = try self.db.get(self.allocator, "pruned");
        defer if (completed) |bytes| self.allocator.free(bytes);
        if (completed) |bytes| {
            if (bytes.len != 8) return error.CorruptExecutionFloor;
            if (std.mem.readInt(u64, bytes[0..8], .little) >= floor) return;
        }
        var floor_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &floor_bytes, floor, .little);
        if (floor > chain.history_floor) {
            try self.db.put("floor", &floor_bytes);
            chain.history_floor = floor;
        }
        const keep = try self.allocator.alloc(bool, chain.records.items.len);
        defer self.allocator.free(keep);
        @memset(keep, true);
        for (chain.canonical.items) |index| {
            const record = &chain.records.items[index];
            if (record.header.number == genesis_number or record.header.number >= floor) continue;
            keep[index] = false;
            const key = try blockKey(self.allocator, record.header.number, record.hash);
            defer self.allocator.free(key);
            const bytes = try self.db.get(self.allocator, key);
            defer if (bytes) |value| self.allocator.free(value);
            if (bytes) |value| {
                const marker = try decodeMarker(value);
                const journal = try pruneKey(self.allocator, record.hash);
                defer self.allocator.free(journal);
                const encoded = encodeMarker(marker);
                try self.db.put(journal, &encoded);
                try self.finishPrune(record.hash, marker);
            }
        }
        try chain.retainOnly(keep);
        try self.db.put("pruned", &floor_bytes);
    }

    /// Reconstructs validated blocks and verifies the selected canonical path.
    pub fn recover(self: *Store, chain: *chain_mod.Chain, world: *execution.state.State) !void {
        try self.finishPendingPrunes();
        self.attach(chain);
        const floor = try self.db.get(self.allocator, "floor");
        defer if (floor) |bytes| self.allocator.free(bytes);
        if (floor) |bytes| {
            if (bytes.len != 8) return error.CorruptExecutionFloor;
            chain.history_floor = std.mem.readInt(u64, bytes[0..8], .little);
            if (chain.history_floor % checkpoint_interval != 0) return error.CorruptExecutionFloor;
        }
        var after: ?[]u8 = null;
        defer if (after) |key| self.allocator.free(key);
        while (true) {
            const rows = try self.db.scan(self.allocator, "v/", "v0", after, 128, 1024 * 1024);
            defer storage.Database.freeRows(self.allocator, rows);
            if (rows.len == 0) break;
            for (rows) |row| try self.recoverBlock(chain, row);
            const next = try self.allocator.dupe(u8, rows[rows.len - 1].key);
            if (after) |key| self.allocator.free(key);
            after = next;
        }
        const choice = try self.db.get(self.allocator, "choice") orelse return;
        defer self.allocator.free(choice);
        if (choice.len != 96) return error.CorruptExecutionChoice;
        const head = choice[0..32].*;
        const safe = choice[32..64].*;
        const finalized = choice[64..96].*;
        if (chain.byHash(head) == null) return error.CorruptExecutionChoice;
        var path = try chain.path(self.allocator, head);
        errdefer path.deinit(self.allocator);
        if (!isAncestor(chain, head, safe) or !isAncestor(chain, safe, finalized)) return error.CorruptExecutionChoice;
        chain.canonical.deinit(self.allocator);
        chain.canonical = path;
        path = .empty;
        chain.safe_hash = safe;
        chain.finalized_hash = finalized;
        const current = try chain.loadWorld(world.allocator, chain.latest().hash);
        world.deinit();
        world.* = current;
    }

    /// Verifies and restores one block whose marker survived a complete write.
    fn recoverBlock(self: *Store, chain: *chain_mod.Chain, row: storage.Row) !void {
        if (row.key.len != 2 + 16 + 1 + 64 or row.key[18] != '/' or row.value.len != marker_size) return error.CorruptExecutionBlock;
        const number = std.fmt.parseInt(u64, row.key[2..18], 16) catch return error.CorruptExecutionBlock;
        // SAFETY: hexToBytes initializes all 32 bytes before the hash is read.
        var hash: execution.Hash = undefined;
        _ = std.fmt.hexToBytes(&hash, row.key[19..83]) catch return error.CorruptExecutionBlock;
        const marker = try decodeMarker(row.value);
        if (marker.number != number) return error.CorruptExecutionBlock;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        if (number < chain.history_floor) return;
        const body = try self.readBlob("block", hash, marker.block);
        defer self.allocator.free(body);
        const parsed = try execution.parse(execution.Block, a, body);
        const block = parsed.value;
        if (block.header.number != number or !std.mem.eql(u8, &(try execution.transition.headerHash(a, chain.fork, block.header)), &hash)) return error.CorruptExecutionBlock;
        const anchored = number == chain.history_floor and number != chain.records.items[0].header.number;
        const parent = chain.byHash(block.header.parent_hash);
        if (!anchored and (parent == null or number != parent.?.header.number + 1)) return error.CorruptExecutionAncestry;
        var restored = if (anchored) execution.state.State.init(self.allocator) else try chain.loadWorld(self.allocator, parent.?.hash);
        defer restored.deinit();
        if (anchored) {
            if (marker.checkpoint.len == 0) return error.MissingExecutionCheckpoint;
            const checkpoint = try self.readBlob("checkpoint", hash, marker.checkpoint);
            defer self.allocator.free(checkpoint);
            try restored.applyStateBytes(checkpoint);
        } else {
            const delta = try self.readBlob("delta", hash, marker.delta);
            defer self.allocator.free(delta);
            try restored.applyStateBytes(delta);
        }
        if (!std.mem.eql(u8, &(try restored.stateRoot()), &block.header.state_root)) return error.CorruptExecutionState;
        if (marker.checkpoint.len != 0) {
            const checkpoint = try self.readBlob("checkpoint", hash, marker.checkpoint);
            defer self.allocator.free(checkpoint);
            var checked = execution.state.State.init(self.allocator);
            defer checked.deinit();
            try checked.applyStateBytes(checkpoint);
            if (!std.mem.eql(u8, &(try checked.stateRoot()), &block.header.state_root)) return error.CorruptExecutionState;
        }
        const raw_txs = try a.alloc([]const u8, block.transactions.len);
        for (block.transactions, raw_txs) |tx, *raw| raw.* = try execution.encode(a, tx);
        if (!std.mem.eql(u8, &(try execution.trie.orderedRoot(a, raw_txs)), &block.header.transactions_root)) return error.CorruptExecutionBlock;
        if (@intFromEnum(chain.fork) >= @intFromEnum(execution.transition.Fork.shanghai)) {
            const encoded_withdrawals = try a.alloc([]const u8, block.withdrawals.len);
            for (block.withdrawals, encoded_withdrawals) |withdrawal, *raw| raw.* = try execution.encode(a, withdrawal);
            if (!std.mem.eql(u8, &(try execution.trie.orderedRoot(a, encoded_withdrawals)), &block.header.withdrawals_root)) return error.CorruptExecutionBlock;
        }
        const receipt_blob = try self.readBlob("receipt", hash, marker.receipts);
        defer self.allocator.free(receipt_blob);
        var offset: usize = 0;
        const count = try takeInt(u32, receipt_blob, &offset);
        if (count != raw_txs.len) return error.CorruptExecutionReceipt;
        var result_arena = std.heap.ArenaAllocator.init(self.allocator);
        var result_owned = true;
        errdefer if (result_owned) result_arena.deinit();
        const receipts = try result_arena.allocator().alloc(execution.Receipt, count);
        for (receipts) |*receipt| {
            const len = try takeInt(u32, receipt_blob, &offset);
            const raw = try takeBytes(receipt_blob, &offset, len);
            receipt.* = (try execution.parse(execution.Receipt, result_arena.allocator(), raw)).value;
        }
        if (offset != receipt_blob.len or !std.mem.eql(u8, &(try execution.receiptsRoot(a, receipts)), &block.header.receipts_root) or !std.mem.eql(u8, &execution.receiptsBloom(receipts), &block.header.logs_bloom)) return error.CorruptExecutionReceipt;
        const gas_used: u64 = if (receipts.len == 0) 0 else switch (receipts[receipts.len - 1]) {
            inline else => |r| r.cumulative_gas_used,
        };
        if (gas_used != block.header.gas_used) return error.CorruptExecutionReceipt;
        const result: execution.transition.BlockResult = .{ .arena = result_arena, .receipts = receipts, .state_root = block.header.state_root, .transactions_root = block.header.transactions_root, .receipts_root = block.header.receipts_root, .withdrawals_root = block.header.withdrawals_root, .logs_bloom = block.header.logs_bloom, .gas_used = gas_used };
        try chain.retain(block.header, raw_txs, block.withdrawals, result, &restored);
        result_owned = false;
    }

    /// Writes a content-hashed value in bounded LSM chunks.
    fn writeBlob(self: *Store, kind: []const u8, hash: execution.Hash, bytes: []const u8) !BlobInfo {
        if (bytes.len > std.math.maxInt(u32)) return error.ExecutionBlobTooLarge;
        const info: BlobInfo = .{ .len = @intCast(bytes.len), .hash = sha(bytes) };
        for (0..try std.math.divCeil(usize, bytes.len, chunk_size)) |index| {
            const key = try blobKey(self.allocator, kind, hash, index);
            defer self.allocator.free(key);
            try self.db.put(key, bytes[index * chunk_size .. @min(bytes.len, (index + 1) * chunk_size)]);
        }
        return info;
    }

    /// Reads all chunks and verifies their length and content hash.
    fn readBlob(self: *Store, kind: []const u8, hash: execution.Hash, info: BlobInfo) ![]u8 {
        const bytes = try self.allocator.alloc(u8, info.len);
        errdefer self.allocator.free(bytes);
        for (0..try std.math.divCeil(usize, info.len, chunk_size)) |index| {
            const key = try blobKey(self.allocator, kind, hash, index);
            defer self.allocator.free(key);
            const chunk = try self.db.get(self.allocator, key) orelse return error.MissingExecutionChunk;
            defer self.allocator.free(chunk);
            const offset = index * chunk_size;
            if (chunk.len != @min(bytes.len - offset, chunk_size)) return error.CorruptExecutionChunk;
            @memcpy(bytes[offset..][0..chunk.len], chunk);
        }
        if (!std.mem.eql(u8, &sha(bytes), &info.hash)) return error.CorruptExecutionChunk;
        return bytes;
    }

    /// Tombstones every chunk of a value after the floor marker is durable.
    fn deleteBlob(self: *Store, kind: []const u8, hash: execution.Hash, info: BlobInfo) !void {
        for (0..try std.math.divCeil(usize, info.len, chunk_size)) |index| {
            const key = try blobKey(self.allocator, kind, hash, index);
            defer self.allocator.free(key);
            try self.db.delete(key);
        }
    }

    /// Completes one journaled side-branch deletion in crash-safe order.
    fn finishPrune(self: *Store, hash: execution.Hash, marker: Marker) !void {
        const key = try blockKey(self.allocator, marker.number, hash);
        defer self.allocator.free(key);
        try self.db.delete(key);
        const header_key = try blobKey(self.allocator, "header", hash, 0);
        defer self.allocator.free(header_key);
        try self.db.delete(header_key);
        try self.deleteBlob("block", hash, marker.block);
        try self.deleteBlob("receipt", hash, marker.receipts);
        try self.deleteBlob("delta", hash, marker.delta);
        try self.deleteBlob("checkpoint", hash, marker.checkpoint);
        const journal = try pruneKey(self.allocator, hash);
        defer self.allocator.free(journal);
        try self.db.delete(journal);
    }

    /// Resumes a side-branch deletion interrupted after its journal was written.
    fn finishPendingPrunes(self: *Store) !void {
        const rows = try self.db.scan(self.allocator, "prune/", "prune0", null, 1024, 1024 * 1024);
        defer storage.Database.freeRows(self.allocator, rows);
        for (rows) |row| {
            if (row.key.len != 6 + 64) return error.CorruptExecutionPruneJournal;
            // SAFETY: hexToBytes initializes all 32 bytes before the hash is read.
            var hash: execution.Hash = undefined;
            _ = std.fmt.hexToBytes(&hash, row.key[6..]) catch return error.CorruptExecutionPruneJournal;
            try self.finishPrune(hash, try decodeMarker(row.value));
        }
    }

    /// Loads at most one checkpoint interval of deltas to recreate a post-state.
    fn loadState(context: *anyopaque, chain: *const chain_mod.Chain, allocator: std.mem.Allocator, hash: execution.Hash) anyerror!execution.state.State {
        const self: *Store = @ptrCast(@alignCast(context));
        var pending: std.ArrayList(execution.Hash) = .empty;
        defer pending.deinit(allocator);
        var current = chain.byHash(hash) orelse return error.UnknownBlock;
        // SAFETY: each loop exit assigns state before the first read.
        var state: execution.state.State = undefined;
        while (true) {
            if (current.world) |*cached| {
                state = try cached.clone(allocator);
                break;
            }
            if (current.header.number % checkpoint_interval == 0) {
                const key = try blockKey(allocator, current.header.number, current.hash);
                defer allocator.free(key);
                const bytes = try self.db.get(allocator, key) orelse return error.MissingExecutionMarker;
                defer allocator.free(bytes);
                const marker = try decodeMarker(bytes);
                if (marker.checkpoint.len == 0) return error.MissingExecutionCheckpoint;
                const checkpoint = try self.readBlob("checkpoint", current.hash, marker.checkpoint);
                defer self.allocator.free(checkpoint);
                state = execution.state.State.init(allocator);
                errdefer state.deinit();
                try state.applyStateBytes(checkpoint);
                break;
            }
            try pending.append(allocator, current.hash);
            current = chain.byHash(current.header.parent_hash) orelse return error.CorruptExecutionAncestry;
        }
        errdefer state.deinit();
        while (pending.pop()) |next_hash| {
            const record = chain.byHash(next_hash) orelse return error.CorruptExecutionAncestry;
            const key = try blockKey(allocator, record.header.number, next_hash);
            defer allocator.free(key);
            const bytes = try self.db.get(allocator, key) orelse return error.MissingExecutionMarker;
            defer allocator.free(bytes);
            const marker = try decodeMarker(bytes);
            const delta = try self.readBlob("delta", next_hash, marker.delta);
            defer self.allocator.free(delta);
            try state.applyStateBytes(delta);
            if (!std.mem.eql(u8, &(try state.stateRoot()), &record.header.state_root)) return error.CorruptExecutionState;
        }
        if (!std.mem.eql(u8, &(try state.stateRoot()), &chain.byHash(hash).?.header.state_root)) return error.CorruptExecutionState;
        return state;
    }
};

/// Encodes a marker without native padding or endianness.
fn encodeMarker(marker: Marker) [marker_size]u8 {
    var bytes: [marker_size]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..8], marker.number, .little);
    var offset: usize = 8;
    for ([_]BlobInfo{ marker.block, marker.receipts, marker.delta, marker.checkpoint }) |info| {
        std.mem.writeInt(u32, bytes[offset..][0..4], info.len, .little);
        @memcpy(bytes[offset + 4 ..][0..32], &info.hash);
        offset += 36;
    }
    return bytes;
}

/// Decodes one fixed-size validated marker.
fn decodeMarker(bytes: []const u8) !Marker {
    if (bytes.len != marker_size) return error.CorruptExecutionBlock;
    var offset: usize = 8;
    var infos: [4]BlobInfo = undefined;
    for (&infos) |*info| {
        info.* = .{ .len = std.mem.readInt(u32, bytes[offset..][0..4], .little), .hash = bytes[offset + 4 ..][0..32].* };
        offset += 36;
    }
    return .{ .number = std.mem.readInt(u64, bytes[0..8], .little), .block = infos[0], .receipts = infos[1], .delta = infos[2], .checkpoint = infos[3] };
}

/// Formats a validated marker key in block-number order.
fn blockKey(allocator: std.mem.Allocator, number: u64, hash: execution.Hash) ![]u8 {
    var number_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &number_bytes, number, .big);
    return std.fmt.allocPrint(allocator, "v/{s}/{s}", .{ std.fmt.bytesToHex(number_bytes, .lower), std.fmt.bytesToHex(hash, .lower) });
}

/// Formats one chunk key under the block hash.
fn blobKey(allocator: std.mem.Allocator, kind: []const u8, hash: execution.Hash, index: usize) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}/{d}", .{ kind, std.fmt.bytesToHex(hash, .lower), index });
}

/// Formats a resumable prune journal key for one branch.
fn pruneKey(allocator: std.mem.Allocator, hash: execution.Hash) ![]u8 {
    return std.fmt.allocPrint(allocator, "prune/{s}", .{std.fmt.bytesToHex(hash, .lower)});
}

/// Calculates a content checksum for an execution blob.
fn sha(bytes: []const u8) execution.Hash {
    // SAFETY: Sha256.hash writes the full output before it is returned.
    var hash: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return hash;
}

/// Appends a fixed-width integer to receipt data.
fn appendInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try out.appendSlice(allocator, &encoded);
}

/// Reads a bounded field from receipt data.
fn takeBytes(bytes: []const u8, offset: *usize, len: usize) ![]const u8 {
    if (offset.* > bytes.len or len > bytes.len - offset.*) return error.CorruptExecutionReceipt;
    const field = bytes[offset.*..][0..len];
    offset.* += len;
    return field;
}

/// Reads a fixed-width integer from receipt data.
fn takeInt(comptime T: type, bytes: []const u8, offset: *usize) !T {
    const field = try takeBytes(bytes, offset, @sizeOf(T));
    return std.mem.readInt(T, field[0..@sizeOf(T)], .little);
}

/// Checks retained ancestry including the selected block.
fn isAncestor(chain: *const chain_mod.Chain, head: execution.Hash, ancestor: execution.Hash) bool {
    if (std.mem.allEqual(u8, &ancestor, 0)) return true;
    var current = chain.byHash(head) orelse return false;
    while (true) {
        if (std.mem.eql(u8, &current.hash, &ancestor)) return true;
        if (current.header.number == chain.records.items[0].header.number) return false;
        current = chain.byHash(current.header.parent_hash) orelse return false;
    }
}

test "durable execution recovers selected head and a selectable side branch" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var genesis = std.mem.zeroes(execution.Header);
    var world = execution.state.State.init(a);
    defer world.deinit();
    genesis.state_root = try world.stateRoot();
    genesis.gas_limit = 30_000_000;
    genesis.base_fee_per_gas = 1;
    const genesis_hash = try execution.transition.headerHash(a, .paris, genesis);
    var store = try Store.open(a, io, tmp.dir, "execution", .paris, genesis, &world);
    var chain = try chain_mod.Chain.init(a, 1, .paris, genesis, &world);
    store.attach(&chain);
    const account: execution.Address = .{0x33} ** 20;
    var state_a = try world.clone(a);
    defer state_a.deinit();
    try state_a.setBalance(account, 1);
    var state_b = try world.clone(a);
    defer state_b.deinit();
    try state_b.setBalance(account, 2);
    var header_a = genesis;
    header_a.parent_hash = genesis_hash;
    header_a.number = 1;
    header_a.timestamp = 1;
    header_a.state_root = try state_a.stateRoot();
    header_a.transactions_root = try execution.trie.orderedRoot(a, &.{});
    header_a.receipts_root = try execution.receiptsRoot(a, &.{});
    const hash_a = try execution.transition.headerHash(a, .paris, header_a);
    var header_b = header_a;
    header_b.extra_data = &.{0x42};
    header_b.state_root = try state_b.stateRoot();
    const hash_b = try execution.transition.headerHash(a, .paris, header_b);
    try store.stage(.paris, header_a, &.{}, &.{}, &.{}, &world, &state_a);
    try store.stage(.paris, header_b, &.{}, &.{}, &.{}, &world, &state_b);
    try store.commit(hash_a, genesis_hash, genesis_hash);
    const prior_end = store.db.wal_end;
    try store.commit(hash_b, genesis_hash, genesis_hash);
    const wal_name = try std.fmt.allocPrint(a, "execution/wal_{d}.bin", .{store.db.wal_id});
    defer a.free(wal_name);
    chain.deinit();
    store.close();
    const wal = try tmp.dir.readFileAlloc(io, wal_name, a, .limited(1024 * 1024));
    defer a.free(wal);
    try tmp.dir.writeFile(io, .{ .sub_path = wal_name, .data = wal[0 .. prior_end + 43] });

    var reopened = try Store.open(a, io, tmp.dir, "execution", .paris, genesis, &world);
    var recovered = try chain_mod.Chain.init(a, 1, .paris, genesis, &world);
    try reopened.recover(&recovered, &world);
    try std.testing.expectEqualSlices(u8, &hash_a, &recovered.latest().hash);
    try std.testing.expectEqualSlices(u8, &header_a.state_root, &(try world.stateRoot()));
    try std.testing.expect(recovered.byHash(hash_b) != null);
    try reopened.commit(hash_b, genesis_hash, genesis_hash);
    recovered.deinit();
    reopened.close();

    {
        var selected = try Store.open(a, io, tmp.dir, "execution", .paris, genesis, &world);
        defer selected.close();
        var selected_chain = try chain_mod.Chain.init(a, 1, .paris, genesis, &world);
        defer selected_chain.deinit();
        try selected.recover(&selected_chain, &world);
        try std.testing.expectEqualSlices(u8, &hash_b, &selected_chain.latest().hash);
        try std.testing.expectEqual(@as(u256, 2), world.getBalance(account));
        selected_chain.finalized_hash = hash_b;
        try selected.commit(hash_b, hash_b, hash_b);
        const side_key = try blockKey(a, 1, hash_a);
        defer a.free(side_key);
        const side_marker = (try selected.db.get(a, side_key)).?;
        defer a.free(side_marker);
        try selected.prune(&selected_chain);
        try std.testing.expect(selected_chain.byHash(hash_a) == null);
        try std.testing.expect((try selected.db.get(a, side_key)) == null);
        const orphan_key = try blobKey(a, "delta", hash_a, 0);
        defer a.free(orphan_key);
        try selected.db.put(orphan_key, "orphan");
        const journal = try pruneKey(a, hash_a);
        defer a.free(journal);
        try selected.db.put(journal, side_marker);
    }
    var last_store = try Store.open(a, io, tmp.dir, "execution", .paris, genesis, &world);
    defer last_store.close();
    var last_chain = try chain_mod.Chain.init(a, 1, .paris, genesis, &world);
    defer last_chain.deinit();
    try last_store.recover(&last_chain, &world);
    try std.testing.expectEqualSlices(u8, &hash_b, &last_chain.latest().hash);
    try std.testing.expect(last_chain.byHash(hash_a) == null);
    const orphan_key = try blobKey(a, "delta", hash_a, 0);
    defer a.free(orphan_key);
    try std.testing.expect((try last_store.db.get(a, orphan_key)) == null);
}

test "periodic execution checkpoint reconstructs state without older deltas" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var world = execution.state.State.init(a);
    defer world.deinit();
    var genesis = std.mem.zeroes(execution.Header);
    genesis.state_root = try world.stateRoot();
    genesis.gas_limit = 30_000_000;
    genesis.base_fee_per_gas = 1;
    var store = try Store.open(a, io, tmp.dir, "execution", .paris, genesis, &world);
    var chain = try chain_mod.Chain.init(a, 1, .paris, genesis, &world);
    store.attach(&chain);
    var parent_hash = chain.latest().hash;
    var first_hash: execution.Hash = undefined;
    var checkpoint_hash: execution.Hash = undefined;
    for (1..checkpoint_interval + 3) |number| {
        var header = genesis;
        header.number = @intCast(number);
        header.timestamp = @intCast(number);
        header.parent_hash = parent_hash;
        header.transactions_root = try execution.trie.orderedRoot(a, &.{});
        header.receipts_root = try execution.receiptsRoot(a, &.{});
        try store.stage(.paris, header, &.{}, &.{}, &.{}, &world, &world);
        try chain.retain(header, &.{}, &.{}, .{
            .arena = std.heap.ArenaAllocator.init(a),
            .receipts = try a.alloc(execution.Receipt, 0),
            .state_root = header.state_root,
            .transactions_root = header.transactions_root,
            .receipts_root = header.receipts_root,
            .withdrawals_root = null,
            .logs_bloom = header.logs_bloom,
            .gas_used = 0,
        }, &world);
        parent_hash = chain.records.items[chain.records.items.len - 1].hash;
        if (number == 1) first_hash = parent_hash;
        if (number == checkpoint_interval) checkpoint_hash = parent_hash;
    }
    const key = try blockKey(a, checkpoint_interval, checkpoint_hash);
    defer a.free(key);
    const bytes = (try store.db.get(a, key)).?;
    defer a.free(bytes);
    try std.testing.expect((try decodeMarker(bytes)).checkpoint.len > 0);
    const old_delta = try blobKey(a, "delta", first_hash, 0);
    defer a.free(old_delta);
    const path = try chain.path(a, parent_hash);
    chain.canonical.deinit(a);
    chain.canonical = path;
    chain.finalized_hash = chain.records.items[0].hash;
    try store.prune(&chain);
    const unfinalized_delta = try store.db.get(a, old_delta);
    defer if (unfinalized_delta) |value| a.free(value);
    try std.testing.expect(unfinalized_delta != null);
    chain.finalized_hash = parent_hash;
    try store.commit(parent_hash, parent_hash, parent_hash);
    try store.pruneRetained(&chain, 1);
    try std.testing.expectEqual(@as(u64, checkpoint_interval), chain.history_floor);
    try std.testing.expectEqual(@as(usize, 4), chain.records.items.len);
    const ancestors = try chain.ancestorHashes(a, parent_hash);
    defer a.free(ancestors);
    try std.testing.expectEqual(@as(usize, 2), ancestors.len);
    try std.testing.expectEqualSlices(u8, &checkpoint_hash, &ancestors[1]);
    try std.testing.expect((try store.db.get(a, old_delta)) == null);
    var restored = try chain.loadWorld(a, parent_hash);
    defer restored.deinit();
    try std.testing.expectEqualSlices(u8, &genesis.state_root, &(try restored.stateRoot()));
    chain.deinit();
    store.close();
    var reopened = try Store.open(a, io, tmp.dir, "execution", .paris, genesis, &world);
    defer reopened.close();
    var recovered = try chain_mod.Chain.init(a, 1, .paris, genesis, &world);
    defer recovered.deinit();
    try reopened.recover(&recovered, &world);
    try std.testing.expectEqualSlices(u8, &parent_hash, &recovered.latest().hash);
    try std.testing.expectEqual(@as(u64, checkpoint_interval), recovered.history_floor);
    try std.testing.expect(recovered.byNumber(1) == null);
    try std.testing.expectEqual(@as(usize, 4), recovered.records.items.len);
}

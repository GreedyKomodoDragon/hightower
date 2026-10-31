// A log-structured key/value store commits whole batches to a checksummed WAL
// before exposing them to readers. Sorted immutable tables hold flushed keys;
// a manifest names the files that recovery may trust. New tables are synced
// before the manifest changes, so an interrupted flush leaves either the WAL
// or its replacement table reachable. Later tables and larger sequence numbers
// supersede earlier values. Deletes are tombstones until compaction can discard
// shadowed data.
//
// batch -> synced WAL -> memtable -> sorted table -> manifest -> compaction
// Keys are at most 4 KiB; values at most 10 MiB; batches at most 16 MiB.
// shortcut: the index holds every key and compaction is synchronous; add a
// sparse table index and a worker when the 4096-epoch store exceeds RAM or
// compaction pauses peer responses.
const std = @import("std");

const wal_magic = "HTWAL002";
const table_magic = "HTSST001";
const manifest_magic = "HTMAN001";
const max_key = 4096;
const max_value = 10 * 1024 * 1024;
const max_batch = 16 * 1024 * 1024;
const mem_limit = 64 * 1024 * 1024;
const record_header = 2 + 4 + 8 + 1 + 32;

pub const Operation = union(enum) {
    put: struct { key: []const u8, value: []const u8 },
    delete: []const u8,
};

pub const Row = struct { key: []u8, value: []u8 };
const Location = union(enum) { memory: []u8, table: struct { id: u64, offset: u64 } };
const Entry = struct { seq: u64, deleted: bool, location: Location };
const Table = struct { id: u64, level: u8 };
const Move = struct { key: []const u8, offset: u64 };

pub const Database = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    lock_file: std.Io.File,
    wal: std.Io.File,
    wal_id: u64,
    wal_end: u64,
    next_id: u64,
    seq: u64 = 0,
    mem_bytes: usize = 0,
    poisoned: bool = false,
    mutex: std.Io.RwLock = .init,
    index: std.StringHashMapUnmanaged(Entry) = .empty,
    tables: std.ArrayList(Table) = .empty,

    /// Open one database directory exclusively, recovering its manifest and WAL.
    pub fn open(allocator: std.mem.Allocator, io: std.Io, parent: std.Io.Dir, path: []const u8) !Database {
        try parent.createDirPath(io, path);
        const dir = try parent.openDir(io, path, .{ .iterate = true });
        errdefer dir.close(io);
        const lock_file = try dir.createFile(io, "LOCK", .{ .read = true, .truncate = false, .lock = .exclusive, .lock_nonblocking = true });
        errdefer lock_file.close(io);
        var db = Database{ .allocator = allocator, .io = io, .dir = dir, .lock_file = lock_file, .wal = undefined, .wal_id = 1, .wal_end = wal_magic.len, .next_id = 2 };
        errdefer db.freeIndex();
        errdefer db.tables.deinit(allocator);
        const manifest = dir.readFileAlloc(io, "MANIFEST", allocator, .limited(1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (manifest) |bytes| {
            defer allocator.free(bytes);
            try db.loadManifest(bytes);
            for (db.tables.items) |table| try db.loadTable(table);
        } else {
            const name = try fileName(allocator, "wal", db.wal_id);
            defer allocator.free(name);
            var first = try dir.createFile(io, name, .{ .read = true, .exclusive = true });
            defer first.close(io);
            try first.writeStreamingAll(io, wal_magic);
            try first.sync(io);
            try db.saveManifest(db.wal_id, db.next_id, db.tables.items);
        }
        const name = try fileName(allocator, "wal", db.wal_id);
        defer allocator.free(name);
        db.wal = try dir.openFile(io, name, .{ .mode = .read_write });
        errdefer db.wal.close(io);
        db.wal_end = try db.replayWal();
        try db.cleanupOrphans();
        return db;
    }

    /// Close files and free owned index keys and in-memory values.
    pub fn close(self: *Database) void {
        self.wal.close(self.io);
        self.lock_file.close(self.io);
        self.dir.close(self.io);
        self.freeIndex();
        self.tables.deinit(self.allocator);
    }

    /// Return an owned value, or null for an absent or deleted key.
    pub fn get(self: *Database, allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
        try self.mutex.lockShared(self.io);
        defer self.mutex.unlockShared(self.io);
        if (self.poisoned) return error.DatabaseNeedsReopen;
        return self.getLocked(allocator, key);
    }

    /// Durably replace one key.
    pub fn put(self: *Database, key: []const u8, value: []const u8) !void {
        try self.write(&.{.{ .put = .{ .key = key, .value = value } }});
    }

    /// Durably tombstone one key.
    pub fn delete(self: *Database, key: []const u8) !void {
        try self.write(&.{.{ .delete = key }});
    }

    /// Commit all operations as one visible, synced WAL record.
    pub fn write(self: *Database, operations: []const Operation) !void {
        if (operations.len == 0) return;
        if (operations.len > max_batch / 8 or operations.len > std.math.maxInt(u32)) return error.InvalidSize;
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (self.poisoned) return error.DatabaseNeedsReopen;
        if (self.seq > std.math.maxInt(u64) - operations.len) return error.SequenceExhausted;
        var record: std.ArrayList(u8) = .empty;
        defer record.deinit(self.allocator);
        try record.resize(self.allocator, 8 + 32);
        @memset(record.items, 0);
        try appendInt(&record, self.allocator, u32, @intCast(operations.len));
        try appendInt(&record, self.allocator, u64, self.seq + 1);
        for (operations) |operation| {
            const key, const value, const tag: u8 = switch (operation) {
                .put => |item| .{ item.key, item.value, 1 },
                .delete => |item| .{ item, &.{}, 0 },
            };
            if (key.len == 0 or key.len > max_key or value.len > max_value) return error.InvalidSize;
            const payload_len = record.items.len - 8 - 32;
            if (payload_len > max_batch - 7 - key.len - value.len) return error.InvalidSize;
            try record.append(self.allocator, tag);
            try appendInt(&record, self.allocator, u16, @intCast(key.len));
            try appendInt(&record, self.allocator, u32, @intCast(value.len));
            try record.appendSlice(self.allocator, key);
            try record.appendSlice(self.allocator, value);
        }
        const payload = record.items[8 + 32 ..];
        std.mem.writeInt(u32, record.items[0..4], @intCast(payload.len), .little);
        std.mem.writeInt(u32, record.items[4..8], ~@as(u32, @intCast(payload.len)), .little);
        std.crypto.hash.sha2.Sha256.hash(payload, record.items[8..40], .{});
        if (self.mem_bytes != 0 and (payload.len > mem_limit -| self.mem_bytes or record.items.len > mem_limit -| self.wal_end)) try self.flushLocked();
        self.wal.writePositionalAll(self.io, record.items, self.wal_end) catch |err| {
            self.poisoned = true;
            return err;
        };
        self.wal.sync(self.io) catch |err| {
            self.poisoned = true;
            return err;
        };
        self.wal_end += record.items.len;
        self.applyBatch(payload) catch |err| {
            self.poisoned = true;
            return err;
        };
    }

    /// Return sorted, owned rows in [lower, upper), after an optional exclusive key.
    pub fn scan(self: *Database, allocator: std.mem.Allocator, lower: []const u8, upper: []const u8, after: ?[]const u8, limit: usize, max_bytes: usize) ![]Row {
        if (limit == 0 or limit > 1024 or max_bytes == 0 or max_bytes > max_batch) return error.InvalidSize;
        try self.mutex.lockShared(self.io);
        defer self.mutex.unlockShared(self.io);
        if (self.poisoned) return error.DatabaseNeedsReopen;
        var keys: std.ArrayList([]const u8) = .empty;
        defer keys.deinit(allocator);
        var iter = self.index.iterator();
        while (iter.next()) |item| {
            const key = item.key_ptr.*;
            if (item.value_ptr.deleted or std.mem.order(u8, key, lower) == .lt or std.mem.order(u8, key, upper) != .lt) continue;
            if (after) |cursor| if (std.mem.order(u8, key, cursor) != .gt) continue;
            try keys.append(allocator, key);
        }
        std.mem.sort([]const u8, keys.items, {}, lessKey);
        var rows: std.ArrayList(Row) = .empty;
        errdefer {
            for (rows.items) |row| {
                allocator.free(row.key);
                allocator.free(row.value);
            }
            rows.deinit(allocator);
        }
        var used: usize = 0;
        for (keys.items[0..@min(keys.items.len, limit)]) |key| {
            const value = (try self.getLocked(allocator, key)).?;
            if (key.len + value.len > max_bytes - used) {
                allocator.free(value);
                if (rows.items.len == 0) return error.ScanLimitTooSmall;
                break;
            }
            const copy = allocator.dupe(u8, key) catch |err| {
                allocator.free(value);
                return err;
            };
            rows.append(allocator, .{ .key = copy, .value = value }) catch |err| {
                allocator.free(copy);
                allocator.free(value);
                return err;
            };
            used += key.len + value.len;
        }
        return rows.toOwnedSlice(allocator);
    }

    /// Snapshot live keys in [lower, upper) once for callers that batch mutations.
    pub fn snapshotKeys(self: *Database, allocator: std.mem.Allocator, lower: []const u8, upper: []const u8) ![][]u8 {
        try self.mutex.lockShared(self.io);
        defer self.mutex.unlockShared(self.io);
        if (self.poisoned) return error.DatabaseNeedsReopen;
        var result: std.ArrayList([]u8) = .empty;
        errdefer {
            for (result.items) |key| allocator.free(key);
            result.deinit(allocator);
        }
        var iter = self.index.iterator();
        while (iter.next()) |item| {
            const key = item.key_ptr.*;
            if (item.value_ptr.deleted or std.mem.order(u8, key, lower) == .lt or std.mem.order(u8, key, upper) != .lt) continue;
            const copy = try allocator.dupe(u8, key);
            result.append(allocator, copy) catch |err| {
                allocator.free(copy);
                return err;
            };
        }
        std.mem.sort([]u8, result.items, {}, struct {
            fn less(_: void, a: []u8, b: []u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);
        return result.toOwnedSlice(allocator);
    }

    /// Free a key snapshot returned by snapshotKeys.
    pub fn freeKeys(allocator: std.mem.Allocator, keys_snapshot: [][]u8) void {
        for (keys_snapshot) |key| allocator.free(key);
        allocator.free(keys_snapshot);
    }

    /// Free a page returned by scan.
    pub fn freeRows(allocator: std.mem.Allocator, rows: []Row) void {
        for (rows) |row| {
            allocator.free(row.key);
            allocator.free(row.value);
        }
        allocator.free(rows);
    }

    /// Force the mutable WAL into an immutable table.
    pub fn flush(self: *Database) !void {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (self.poisoned) return error.DatabaseNeedsReopen;
        try self.flushLocked();
    }

    /// Fully compact live keys and reclaim tombstones, including small batches.
    pub fn compact(self: *Database) !void {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (self.poisoned) return error.DatabaseNeedsReopen;
        try self.flushLocked();
        try self.reclaimLocked();
    }

    /// Reclaim accumulated tombstones by replacing every table with live keys.
    pub fn reclaimIfNeeded(self: *Database) !void {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (self.poisoned) return error.DatabaseNeedsReopen;
        var deleted: usize = 0;
        var live: usize = 0;
        var iter = self.index.iterator();
        while (iter.next()) |item| {
            if (item.value_ptr.deleted) deleted += 1 else live += 1;
        }
        if (deleted < 128 or deleted < live / 4) return;
        try self.flushLocked();
        try self.reclaimLocked();
    }

    /// Find a live value while the read lock is held.
    fn getLocked(self: *Database, allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
        const entry = self.index.get(key) orelse return null;
        if (entry.deleted) return null;
        return switch (entry.location) {
            .memory => |value| try allocator.dupe(u8, value),
            .table => |ref| blk: {
                const record = try self.readTableRecord(allocator, ref.id, ref.offset);
                defer allocator.free(record.key);
                if (!std.mem.eql(u8, record.key, key) or record.seq != entry.seq) {
                    allocator.free(record.value);
                    return error.CorruptTable;
                }
                break :blk record.value;
            },
        };
    }

    /// Replay complete WAL batches and remove a torn final record.
    fn replayWal(self: *Database) !u64 {
        const wal_name = try fileName(self.allocator, "wal", self.wal_id);
        defer self.allocator.free(wal_name);
        const bytes = try self.dir.readFileAlloc(self.io, wal_name, self.allocator, .limited(512 * 1024 * 1024));
        defer self.allocator.free(bytes);
        if (bytes.len < wal_magic.len or !std.mem.eql(u8, bytes[0..wal_magic.len], wal_magic)) return error.CorruptWal;
        var offset: usize = wal_magic.len;
        while (offset + 40 <= bytes.len) {
            const size = std.mem.readInt(u32, bytes[offset..][0..4], .little);
            const inverse = std.mem.readInt(u32, bytes[offset + 4 ..][0..4], .little);
            if (inverse != ~size) return error.CorruptWal;
            if (size > max_batch) return error.CorruptWal;
            if (size > bytes.len - offset - 40) break;
            var hash: [32]u8 = undefined;
            const payload = bytes[offset + 40 ..][0..size];
            std.crypto.hash.sha2.Sha256.hash(payload, &hash, .{});
            if (!std.mem.eql(u8, &hash, bytes[offset + 8 ..][0..32])) return error.CorruptWal;
            try self.applyBatch(payload);
            offset += 40 + size;
        }
        if (offset != bytes.len) {
            const name = try fileName(self.allocator, "wal", self.wal_id);
            defer self.allocator.free(name);
            var atomic = try self.dir.createFileAtomic(self.io, name, .{ .replace = true });
            defer atomic.deinit(self.io);
            try atomic.file.writeStreamingAll(self.io, bytes[0..offset]);
            try atomic.file.sync(self.io);
            try atomic.replace(self.io);
            try self.syncDir();
            self.wal.close(self.io);
            self.wal = try self.dir.openFile(self.io, name, .{ .mode = .read_write });
        }
        return offset;
    }

    /// Apply one validated batch in sequence order.
    fn applyBatch(self: *Database, bytes: []const u8) !void {
        if (bytes.len < 12) return error.CorruptWal;
        const count = std.mem.readInt(u32, bytes[0..4], .little);
        const start = std.mem.readInt(u64, bytes[4..12], .little);
        if (start != self.seq + 1 or count == 0 or count > max_batch / 8 or start > std.math.maxInt(u64) - @as(u64, count)) return error.CorruptWal;
        var offset: usize = 12;
        for (0..count) |i| {
            if (bytes.len - offset < 7) return error.CorruptWal;
            const tag = bytes[offset];
            const key_len = std.mem.readInt(u16, bytes[offset + 1 ..][0..2], .little);
            const value_len = std.mem.readInt(u32, bytes[offset + 3 ..][0..4], .little);
            offset += 7;
            if (tag > 1 or key_len == 0 or key_len > max_key or value_len > max_value or key_len + value_len > bytes.len - offset) return error.CorruptWal;
            if (tag == 0 and value_len != 0) return error.CorruptWal;
            const key = bytes[offset..][0..key_len];
            offset += key_len;
            const value = bytes[offset..][0..value_len];
            offset += value_len;
            const copy = try self.allocator.dupe(u8, value);
            self.setEntry(key, .{ .seq = start + i, .deleted = tag == 0, .location = .{ .memory = copy } }) catch |err| {
                self.allocator.free(copy);
                return err;
            };
        }
        if (offset != bytes.len) return error.CorruptWal;
        self.seq = @max(self.seq, start + count - 1);
    }

    /// Replace one index entry, retaining ownership of its key.
    fn setEntry(self: *Database, key: []const u8, entry: Entry) !void {
        if (self.index.getPtr(key)) |old| {
            if (old.location == .memory) {
                const bytes = old.location.memory;
                self.mem_bytes -= key.len + bytes.len;
                self.allocator.free(bytes);
            }
            old.* = entry;
        } else {
            const copy = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(copy);
            try self.index.put(self.allocator, copy, entry);
        }
        if (entry.location == .memory) self.mem_bytes += key.len + entry.location.memory.len;
    }

    /// Write the current memtable to an SST and rotate the WAL under the lock.
    fn flushLocked(self: *Database) !void {
        if (self.mem_bytes == 0) return;
        const table_id = self.next_id;
        const wal_id = table_id + 1;
        var moves = try self.writeTable(table_id, 0, null, false);
        defer moves.deinit(self.allocator);
        var installed = false;
        const wal_name = try fileName(self.allocator, "wal", wal_id);
        defer self.allocator.free(wal_name);
        const new_wal = try self.dir.createFile(self.io, wal_name, .{ .read = true, .exclusive = true });
        errdefer {
            if (!installed) {
                new_wal.close(self.io);
            }
        }
        try new_wal.writeStreamingAll(self.io, wal_magic);
        try new_wal.sync(self.io);
        try self.syncDir();
        try self.tables.append(self.allocator, .{ .id = table_id, .level = 0 });
        errdefer {
            if (!installed) self.tables.items.len -= 1;
        }
        self.saveManifest(wal_id, wal_id + 1, self.tables.items) catch |err| {
            self.poisoned = true;
            return err;
        };
        const old_wal = self.wal_id;
        self.wal.close(self.io);
        self.wal = new_wal;
        self.wal_id = wal_id;
        self.wal_end = wal_magic.len;
        self.next_id = wal_id + 1;
        installed = true;
        for (moves.items) |move| {
            const entry = self.index.getPtr(move.key).?;
            self.allocator.free(entry.location.memory);
            entry.location = .{ .table = .{ .id = table_id, .offset = move.offset } };
        }
        self.mem_bytes = 0;
        const old_name = try fileName(self.allocator, "wal", old_wal);
        defer self.allocator.free(old_name);
        self.dir.deleteFile(self.io, old_name) catch {};
        try self.compactLocked();
    }

    /// Merge one four-table run without altering live keys before manifest commit.
    fn compactLocked(self: *Database) !void {
        var level: u8 = 0;
        while (level < 16) {
            var selected: [4]u64 = undefined;
            var count: usize = 0;
            for (self.tables.items) |table| {
                if (table.level != level) continue;
                selected[count] = table.id;
                count += 1;
                if (count == 4) break;
            }
            if (count < 4) {
                level += 1;
                continue;
            }
            const new_id = self.next_id;
            var moves = try self.writeTable(new_id, level + 1, &selected, false);
            defer moves.deinit(self.allocator);
            var replacement: std.ArrayList(Table) = .empty;
            defer replacement.deinit(self.allocator);
            for (self.tables.items) |table| {
                var remove = false;
                for (selected) |id| if (table.id == id) {
                    remove = true;
                    break;
                };
                if (!remove) try replacement.append(self.allocator, table);
            }
            if (moves.items.len != 0) try replacement.append(self.allocator, .{ .id = new_id, .level = level + 1 });
            self.saveManifest(self.wal_id, new_id + 1, replacement.items) catch |err| {
                self.poisoned = true;
                return err;
            };
            self.tables.deinit(self.allocator);
            self.tables = replacement;
            replacement = .empty;
            self.next_id = new_id + 1;
            for (moves.items) |move| self.index.getPtr(move.key).?.location = .{ .table = .{ .id = new_id, .offset = move.offset } };
            for (selected) |id| {
                const name = try fileName(self.allocator, "sst", id);
                defer self.allocator.free(name);
                self.dir.deleteFile(self.io, name) catch {};
            }
            if (moves.items.len == 0) {
                const name = try fileName(self.allocator, "sst", new_id);
                defer self.allocator.free(name);
                self.dir.deleteFile(self.io, name) catch {};
            }
            level = 0;
        }
    }

    /// Install one table of live keys before deleting old tables and tombstones.
    fn reclaimLocked(self: *Database) !void {
        const new_id = self.next_id;
        var moves = try self.writeTable(new_id, 0, null, true);
        defer moves.deinit(self.allocator);
        var dead: std.ArrayList([]const u8) = .empty;
        defer dead.deinit(self.allocator);
        var manifest_attempted = false;
        errdefer if (!manifest_attempted) {
            const name = fileName(self.allocator, "sst", new_id) catch null;
            if (name) |path| {
                defer self.allocator.free(path);
                self.dir.deleteFile(self.io, path) catch {};
            }
        };
        var iter = self.index.iterator();
        while (iter.next()) |item| if (item.value_ptr.deleted) {
            try dead.append(self.allocator, item.key_ptr.*);
        };
        try self.tables.ensureTotalCapacity(self.allocator, 1);
        const replacement = [_]Table{.{ .id = new_id, .level = 0 }};
        manifest_attempted = true;
        self.saveManifest(self.wal_id, new_id + 1, &replacement) catch |err| {
            self.poisoned = true;
            return err;
        };
        for (moves.items) |move| self.index.getPtr(move.key).?.location = .{ .table = .{ .id = new_id, .offset = move.offset } };
        for (dead.items) |key| {
            const removed = self.index.fetchRemove(key).?;
            self.allocator.free(removed.key);
        }
        for (self.tables.items) |table| {
            const name = fileName(self.allocator, "sst", table.id) catch continue;
            defer self.allocator.free(name);
            self.dir.deleteFile(self.io, name) catch {};
        }
        self.tables.clearRetainingCapacity();
        self.tables.appendAssumeCapacity(replacement[0]);
        self.next_id = new_id + 1;
    }

    /// Serialize selected current entries in key order into one immutable SST.
    fn writeTable(self: *Database, id: u64, level: u8, sources: ?*const [4]u64, live_only: bool) !std.ArrayList(Move) {
        _ = level;
        var keys: std.ArrayList([]const u8) = .empty;
        defer keys.deinit(self.allocator);
        var iter = self.index.iterator();
        while (iter.next()) |item| {
            const location = item.value_ptr.location;
            const selected = if (live_only) !item.value_ptr.deleted else if (sources) |ids| blk: {
                if (location != .table) break :blk false;
                for (ids) |candidate| if (candidate == location.table.id) break :blk true;
                break :blk false;
            } else location == .memory;
            if (selected) try keys.append(self.allocator, item.key_ptr.*);
        }
        std.mem.sort([]const u8, keys.items, {}, lessKey);
        const name = try fileName(self.allocator, "sst", id);
        defer self.allocator.free(name);
        var file = try self.dir.createFile(self.io, name, .{ .read = true, .exclusive = true });
        errdefer self.dir.deleteFile(self.io, name) catch {};
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, table_magic);
        var offset: u64 = table_magic.len;
        var moves: std.ArrayList(Move) = .empty;
        errdefer moves.deinit(self.allocator);
        for (keys.items) |key| {
            const entry = self.index.get(key).?;
            const value = switch (entry.location) {
                .memory => |bytes| try self.allocator.dupe(u8, bytes),
                .table => |ref| blk: {
                    const record = try self.readTableRecord(self.allocator, ref.id, ref.offset);
                    defer self.allocator.free(record.key);
                    break :blk record.value;
                },
            };
            defer self.allocator.free(value);
            var header: [record_header]u8 = undefined;
            std.mem.writeInt(u16, header[0..2], @intCast(key.len), .little);
            std.mem.writeInt(u32, header[2..6], @intCast(value.len), .little);
            std.mem.writeInt(u64, header[6..14], entry.seq, .little);
            header[14] = @intFromBool(!entry.deleted);
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(header[0..15]);
            hash.update(key);
            hash.update(value);
            hash.final(header[15..47]);
            try file.writeStreamingAll(self.io, &header);
            try file.writeStreamingAll(self.io, key);
            try file.writeStreamingAll(self.io, value);
            try moves.append(self.allocator, .{ .key = key, .offset = offset });
            offset += record_header + key.len + value.len;
        }
        try file.sync(self.io);
        try self.syncDir();
        return moves;
    }

    /// Rebuild the newest-key index from one checksummed table.
    fn loadTable(self: *Database, table: Table) !void {
        const name = try fileName(self.allocator, "sst", table.id);
        defer self.allocator.free(name);
        var file = try self.dir.openFile(self.io, name, .{});
        defer file.close(self.io);
        const size = (try file.stat(self.io)).size;
        var magic: [8]u8 = undefined;
        if (try file.readPositionalAll(self.io, &magic, 0) != 8 or !std.mem.eql(u8, &magic, table_magic)) return error.CorruptTable;
        var offset: u64 = 8;
        while (offset < size) {
            const record = try readRecord(self.allocator, self.io, file, offset, size);
            defer self.allocator.free(record.key);
            defer self.allocator.free(record.value);
            if (record.seq > self.seq) self.seq = record.seq;
            if (self.index.get(record.key)) |old| if (old.seq >= record.seq) {
                offset = record.next;
                continue;
            };
            try self.setEntry(record.key, .{ .seq = record.seq, .deleted = record.deleted, .location = .{ .table = .{ .id = table.id, .offset = offset } } });
            offset = record.next;
        }
    }

    /// Read and verify one SST record by file ID and offset.
    fn readTableRecord(self: *Database, allocator: std.mem.Allocator, id: u64, offset: u64) !Record {
        const name = try fileName(allocator, "sst", id);
        defer allocator.free(name);
        var file = try self.dir.openFile(self.io, name, .{});
        defer file.close(self.io);
        return readRecord(allocator, self.io, file, offset, (try file.stat(self.io)).size);
    }

    /// Parse the versioned manifest without trusting lengths or checksums.
    fn loadManifest(self: *Database, bytes: []const u8) !void {
        if (bytes.len < 8 + 8 + 8 + 4 + 32 or !std.mem.eql(u8, bytes[0..8], manifest_magic)) return error.CorruptManifest;
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes[0 .. bytes.len - 32], &hash, .{});
        if (!std.mem.eql(u8, &hash, bytes[bytes.len - 32 ..])) return error.CorruptManifest;
        self.wal_id = std.mem.readInt(u64, bytes[8..16], .little);
        self.next_id = std.mem.readInt(u64, bytes[16..24], .little);
        const count = std.mem.readInt(u32, bytes[24..28], .little);
        if (self.wal_id == 0 or self.next_id <= self.wal_id or count > 10000 or bytes.len != 28 + 9 * count + 32) return error.CorruptManifest;
        for (0..count) |i| {
            const offset = 28 + 9 * i;
            const id = std.mem.readInt(u64, bytes[offset..][0..8], .little);
            if (id == 0 or id == self.wal_id or id >= self.next_id or bytes[offset + 8] > 16) return error.CorruptManifest;
            for (self.tables.items) |existing| if (existing.id == id) return error.CorruptManifest;
            try self.tables.append(self.allocator, .{ .id = id, .level = bytes[offset + 8] });
        }
    }

    /// Atomically install a checksummed manifest after syncing referenced files.
    fn saveManifest(self: *Database, wal_id: u64, next_id: u64, tables: []const Table) !void {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(self.allocator);
        try bytes.appendSlice(self.allocator, manifest_magic);
        try appendInt(&bytes, self.allocator, u64, wal_id);
        try appendInt(&bytes, self.allocator, u64, next_id);
        try appendInt(&bytes, self.allocator, u32, @intCast(tables.len));
        for (tables) |table| {
            try appendInt(&bytes, self.allocator, u64, table.id);
            try bytes.append(self.allocator, table.level);
        }
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes.items, &hash, .{});
        try bytes.appendSlice(self.allocator, &hash);
        var atomic = try self.dir.createFileAtomic(self.io, "MANIFEST", .{ .replace = true });
        defer atomic.deinit(self.io);
        try atomic.file.writeStreamingAll(self.io, bytes.items);
        try atomic.file.sync(self.io);
        try atomic.replace(self.io);
        try self.syncDir();
    }

    /// Persist directory entries after a new table, WAL, or manifest rename.
    fn syncDir(self: *Database) !void {
        const file = std.Io.File{ .handle = self.dir.handle, .flags = .{ .nonblocking = false } };
        try file.sync(self.io);
    }

    /// Remove files left by a crash before or after a manifest replacement.
    fn cleanupOrphans(self: *Database) !void {
        var iter = self.dir.iterate();
        while (try iter.next(self.io)) |item| {
            if (!std.mem.endsWith(u8, item.name, ".bin")) continue;
            const is_wal = std.mem.startsWith(u8, item.name, "wal_");
            const is_sst = std.mem.startsWith(u8, item.name, "sst_");
            if (!is_wal and !is_sst) continue;
            const id = std.fmt.parseInt(u64, item.name[4 .. item.name.len - 4], 10) catch continue;
            var live = is_wal and id == self.wal_id;
            if (is_sst) for (self.tables.items) |table| {
                if (table.id == id) {
                    live = true;
                    break;
                }
            };
            if (!live) try self.dir.deleteFile(self.io, item.name);
        }
    }

    /// Release keys and mutable values in the index.
    fn freeIndex(self: *Database) void {
        var iter = self.index.iterator();
        while (iter.next()) |item| {
            if (item.value_ptr.location == .memory) self.allocator.free(item.value_ptr.location.memory);
            self.allocator.free(item.key_ptr.*);
        }
        self.index.deinit(self.allocator);
    }
};

const Record = struct { key: []u8, value: []u8, seq: u64, deleted: bool, next: u64 };

/// Read and checksum one bounded table record.
fn readRecord(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File, offset: u64, file_size: u64) !Record {
    if (offset > file_size or file_size - offset < record_header) return error.CorruptTable;
    var header: [record_header]u8 = undefined;
    if (try file.readPositionalAll(io, &header, offset) != record_header) return error.CorruptTable;
    const key_len = std.mem.readInt(u16, header[0..2], .little);
    const value_len = std.mem.readInt(u32, header[2..6], .little);
    const seq = std.mem.readInt(u64, header[6..14], .little);
    if (key_len == 0 or key_len > max_key or value_len > max_value or seq == 0 or header[14] > 1 or (header[14] == 0 and value_len != 0) or key_len + value_len > file_size - offset - record_header) return error.CorruptTable;
    const key = try allocator.alloc(u8, key_len);
    errdefer allocator.free(key);
    const value = try allocator.alloc(u8, value_len);
    errdefer allocator.free(value);
    if (try file.readPositionalAll(io, key, offset + record_header) != key_len or try file.readPositionalAll(io, value, offset + record_header + key_len) != value_len) return error.CorruptTable;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(header[0..15]);
    hash.update(key);
    hash.update(value);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    if (!std.mem.eql(u8, &digest, header[15..47])) return error.CorruptTable;
    return .{ .key = key, .value = value, .seq = seq, .deleted = header[14] == 0, .next = offset + record_header + key_len + value_len };
}

/// Format one ID-named immutable file.
fn fileName(allocator: std.mem.Allocator, prefix: []const u8, id: u64) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}_{d}.bin", .{ prefix, id });
}

/// Append a little-endian integer to a record buffer.
fn appendInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try out.appendSlice(allocator, &bytes);
}

/// Sort binary keys in byte order.
fn lessKey(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

test "durable batches, ordered scan and reopen" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    try db.write(&.{ .{ .put = .{ .key = "b", .value = "two" } }, .{ .put = .{ .key = "a", .value = "one" } } });
    const rows = try db.scan(allocator, "a", "z", null, 10, 1024);
    defer Database.freeRows(allocator, rows);
    try std.testing.expectEqualStrings("a", rows[0].key);
    try std.testing.expectEqualStrings("b", rows[1].key);
    db.close();
    var restored = try Database.open(allocator, io, tmp.dir, "kv");
    defer restored.close();
    const value = (try restored.get(allocator, "a")).?;
    defer allocator.free(value);
    try std.testing.expectEqualStrings("one", value);
    try restored.delete("a");
    try std.testing.expect((try restored.get(allocator, "a")) == null);
    try restored.flush();
    try std.testing.expect((try restored.get(allocator, "a")) == null);
}

test "four flushed tables compact without losing later writes or tombstones" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    for (0..4) |i| {
        const value = try std.fmt.allocPrint(allocator, "value-{d}", .{i});
        defer allocator.free(value);
        try db.put("key", value);
        try db.put("other", "stable");
        try db.flush();
    }
    try std.testing.expectEqual(@as(usize, 1), db.tables.items.len);
    const latest = (try db.get(allocator, "key")).?;
    defer allocator.free(latest);
    try std.testing.expectEqualStrings("value-3", latest);
    try db.delete("key");
    try db.flush();
    db.close();
    var restored = try Database.open(allocator, io, tmp.dir, "kv");
    defer restored.close();
    try std.testing.expect((try restored.get(allocator, "key")) == null);
    const other = (try restored.get(allocator, "other")).?;
    defer allocator.free(other);
    try std.testing.expectEqualStrings("stable", other);
}

test "multiple compaction levels retain the latest value" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    for (0..20) |i| {
        const value = try std.fmt.allocPrint(allocator, "revision-{d}", .{i});
        defer allocator.free(value);
        try db.put("hot", value);
        if (i % 3 == 0) try db.delete("cold");
        try db.flush();
    }
    db.close();
    var restored = try Database.open(allocator, io, tmp.dir, "kv");
    defer restored.close();
    const hot = (try restored.get(allocator, "hot")).?;
    defer allocator.free(hot);
    try std.testing.expectEqualStrings("revision-19", hot);
    try std.testing.expect((try restored.get(allocator, "cold")) == null);
}

test "reclamation removes tombstones without reviving older table values" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    for (0..4) |round| {
        for (0..130) |i| {
            const key = try std.fmt.allocPrint(allocator, "expired-{d}", .{i});
            defer allocator.free(key);
            const value = try std.fmt.allocPrint(allocator, "round-{d}", .{round});
            defer allocator.free(value);
            try db.put(key, value);
        }
        try db.flush();
    }
    try db.put("keep", "live");
    for (0..130) |i| {
        const key = try std.fmt.allocPrint(allocator, "expired-{d}", .{i});
        defer allocator.free(key);
        try db.delete(key);
    }
    try db.reclaimIfNeeded();
    try std.testing.expectEqual(@as(usize, 1), db.index.count());
    try std.testing.expectEqual(@as(usize, 1), db.tables.items.len);
    db.close();
    var restored = try Database.open(allocator, io, tmp.dir, "kv");
    defer restored.close();
    try std.testing.expectEqual(@as(usize, 1), restored.index.count());
    try std.testing.expect((try restored.get(allocator, "expired-0")) == null);
    const keep = (try restored.get(allocator, "keep")).?;
    defer allocator.free(keep);
    try std.testing.expectEqualStrings("live", keep);
    try restored.put("expired-0", "new");
    try restored.flush();
    const revived = (try restored.get(allocator, "expired-0")).?;
    defer allocator.free(revived);
    try std.testing.expectEqualStrings("new", revived);
    try restored.put("gone", "old");
    try restored.flush();
    try restored.delete("gone");
    try restored.compact();
    try std.testing.expectEqual(@as(usize, 2), restored.index.count());
    try std.testing.expect((try restored.get(allocator, "gone")) == null);
}

test "recovery discards an incomplete WAL tail and rejects complete corruption" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    try db.put("safe", "durable");
    const id = db.wal_id;
    db.close();
    const name = try std.fmt.allocPrint(allocator, "kv/wal_{d}.bin", .{id});
    defer allocator.free(name);
    var file = try tmp.dir.openFile(io, name, .{ .mode = .read_write });
    const old_len = (try file.stat(io)).size;
    try file.writePositionalAll(io, &.{ 7, 0, 0, 0, 0xff }, old_len);
    try file.sync(io);
    file.close(io);
    var restored = try Database.open(allocator, io, tmp.dir, "kv");
    const value = (try restored.get(allocator, "safe")).?;
    defer allocator.free(value);
    try std.testing.expectEqualStrings("durable", value);
    restored.close();
    file = try tmp.dir.openFile(io, name, .{ .mode = .read_write });
    var bad: [1]u8 = .{0};
    try file.writePositionalAll(io, &bad, wal_magic.len + 4);
    try file.sync(io);
    file.close(io);
    try std.testing.expectError(error.CorruptWal, Database.open(allocator, io, tmp.dir, "kv"));
}

test "recovery rejects corrupt table and manifest bytes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    try db.put("a", "durable");
    try db.flush();
    const table_id = db.tables.items[0].id;
    db.close();
    const table_name = try std.fmt.allocPrint(allocator, "kv/sst_{d}.bin", .{table_id});
    defer allocator.free(table_name);
    var file = try tmp.dir.openFile(io, table_name, .{ .mode = .read_write });
    var byte: [1]u8 = undefined;
    const offset = table_magic.len + record_header + 1;
    _ = try file.readPositionalAll(io, &byte, offset);
    byte[0] ^= 1;
    try file.writePositionalAll(io, &byte, offset);
    try file.sync(io);
    file.close(io);
    try std.testing.expectError(error.CorruptTable, Database.open(allocator, io, tmp.dir, "kv"));

    const manifest_name = "kv/MANIFEST";
    file = try tmp.dir.openFile(io, manifest_name, .{ .mode = .read_write });
    _ = try file.readPositionalAll(io, &byte, 8);
    byte[0] ^= 1;
    try file.writePositionalAll(io, &byte, 8);
    try file.sync(io);
    file.close(io);
    try std.testing.expectError(error.CorruptManifest, Database.open(allocator, io, tmp.dir, "kv"));
}

test "recovery ignores a table absent from the manifest" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    try db.put("a", "safe");
    db.close();
    try tmp.dir.writeFile(io, .{ .sub_path = "kv/sst_999.bin", .data = "orphan" });
    var restored = try Database.open(allocator, io, tmp.dir, "kv");
    defer restored.close();
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "kv/sst_999.bin", .{}));
    const value = (try restored.get(allocator, "a")).?;
    defer allocator.free(value);
    try std.testing.expectEqualStrings("safe", value);
}

test "torn batch is invisible and a second writer is rejected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    if (Database.open(allocator, io, tmp.dir, "kv")) |second| {
        var unexpected = second;
        unexpected.close();
        return error.LockNotEnforced;
    } else |_| {}
    try db.put("safe", "one");
    const safe_end = db.wal_end;
    try db.write(&.{ .{ .put = .{ .key = "left", .value = "two" } }, .{ .put = .{ .key = "right", .value = "three" } } });
    const name = try std.fmt.allocPrint(allocator, "kv/wal_{d}.bin", .{db.wal_id});
    defer allocator.free(name);
    db.close();
    const original = try tmp.dir.readFileAlloc(io, name, allocator, .limited(1024));
    defer allocator.free(original);
    try tmp.dir.writeFile(io, .{ .sub_path = name, .data = original[0 .. safe_end + 43] });
    var restored = try Database.open(allocator, io, tmp.dir, "kv");
    defer restored.close();
    try std.testing.expect((try restored.get(allocator, "left")) == null);
    try std.testing.expect((try restored.get(allocator, "right")) == null);
    const safe = (try restored.get(allocator, "safe")).?;
    defer allocator.free(safe);
    try std.testing.expectEqualStrings("one", safe);
}

test "concurrent readers observe complete synced values" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try Database.open(allocator, io, tmp.dir, "kv");
    defer db.close();
    try db.put("key", "first");
    try db.put("stable", "on disk");
    try db.flush();
    var failed: u8 = 0;
    const Worker = struct {
        fn read(database: *Database, flag: *u8) void {
            for (0..40) |_| {
                const value = database.get(std.heap.page_allocator, "key") catch {
                    @atomicStore(u8, flag, 1, .seq_cst);
                    return;
                } orelse {
                    @atomicStore(u8, flag, 1, .seq_cst);
                    return;
                };
                const valid = std.mem.eql(u8, value, "first") or std.mem.eql(u8, value, "second");
                std.heap.page_allocator.free(value);
                if (!valid) {
                    @atomicStore(u8, flag, 1, .seq_cst);
                    return;
                }
                const stable = database.get(std.heap.page_allocator, "stable") catch {
                    @atomicStore(u8, flag, 1, .seq_cst);
                    return;
                } orelse {
                    @atomicStore(u8, flag, 1, .seq_cst);
                    return;
                };
                const disk_valid = std.mem.eql(u8, stable, "on disk");
                std.heap.page_allocator.free(stable);
                if (!disk_valid) {
                    @atomicStore(u8, flag, 1, .seq_cst);
                    return;
                }
            }
        }
    };
    const a = try std.Thread.spawn(.{}, Worker.read, .{ &db, &failed });
    const b = try std.Thread.spawn(.{}, Worker.read, .{ &db, &failed });
    for (0..20) |_| try db.put("key", "second");
    a.join();
    b.join();
    try std.testing.expectEqual(@as(u8, 0), @atomicLoad(u8, &failed, .seq_cst));
}

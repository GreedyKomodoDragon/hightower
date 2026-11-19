// Durable operation records are keyed by operation type and SSZ root. A synced
// batch becomes visible before callers publish it to the in-memory pool; deletes
// and attestation replacement use the same atomic batch boundary.
//
// operation/v1/type/root -> version/type/root/length/SSZ bytes
// The database checksums batches and discards incomplete trailing WAL records.
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const lsm = @import("storage");
const preset = @import("consensus_preset").Config;
const pool_api = @import("operation_pool.zig");

const prefix = "operations/v1/";
const header_len = 38;
const scan_rows = 128;
const max_records = 2 * (preset.MAX_ATTESTATIONS_ELECTRA + preset.MAX_PROPOSER_SLASHINGS + preset.MAX_ATTESTER_SLASHINGS_ELECTRA + preset.MAX_VOLUNTARY_EXITS + preset.MAX_BLS_TO_EXECUTION_CHANGES);
const max_record = header_len + @max(
    maxSszSize(fulu.Attestation),
    @max(maxSszSize(fulu.ProposerSlashing), @max(maxSszSize(fulu.AttesterSlashing), @max(maxSszSize(fulu.SignedVoluntaryExit), maxSszSize(fulu.SignedBLSToExecutionChange)))),
);
const max_recovery_bytes = (prefix.len + 33 + header_len + maxSszSize(fulu.Attestation)) * countLimit(.attestation) +
    (prefix.len + 33 + header_len + maxSszSize(fulu.ProposerSlashing)) * countLimit(.proposer_slashing) +
    (prefix.len + 33 + header_len + maxSszSize(fulu.AttesterSlashing)) * countLimit(.attester_slashing) +
    (prefix.len + 33 + header_len + maxSszSize(fulu.SignedVoluntaryExit)) * countLimit(.voluntary_exit) +
    (prefix.len + 33 + header_len + maxSszSize(fulu.SignedBLSToExecutionChange)) * countLimit(.bls_change);

comptime {
    if (max_record > 10 * 1024 * 1024) @compileError("operation record exceeds the LSM value limit");
}

pub const Kind = enum(u8) { attestation = 1, proposer_slashing, attester_slashing, voluntary_exit, bls_change };
pub const Value = union(Kind) {
    attestation: fulu.Attestation,
    proposer_slashing: fulu.ProposerSlashing,
    attester_slashing: fulu.AttesterSlashing,
    voluntary_exit: fulu.SignedVoluntaryExit,
    bls_change: fulu.SignedBLSToExecutionChange,
};

pub const Record = struct { key: [prefix.len + 33]u8, value: Value };

/// Own the operation namespace in a separate LSM database directory.
pub const Store = struct {
    allocator: std.mem.Allocator,
    database: lsm.Database,
    mutex: std.Io.Mutex = .init,
    poisoned: bool = false,

    /// Open and exclusively own the operation database below `dir/path`.
    pub fn open(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !Store {
        return .{ .allocator = allocator, .database = try lsm.Database.open(allocator, io, dir, path) };
    }

    /// Close the database and release its exclusive ownership lock.
    pub fn deinit(self: *Store) void {
        self.database.close();
    }

    /// Commit a typed SSZ operation before its caller publishes it in memory.
    pub fn put(self: *Store, value: Value) !void {
        const bytes = try encode(self.allocator, value);
        defer self.allocator.free(bytes);
        const key = recordKey(kind(value), bytes[2..34]);
        try self.mutex.lock(self.database.io);
        defer self.mutex.unlock(self.database.io);
        try self.requireWritable();
        const old = try self.database.get(self.allocator, &key);
        if (old) |existing| {
            defer self.allocator.free(existing);
            if (std.mem.eql(u8, existing, bytes)) return;
            return error.RootCollision;
        }
        try self.checkCapacity(kind(value), key.len + bytes.len, null);
        self.database.put(&key, bytes) catch |err| {
            self.poisoned = true;
            return err;
        };
    }

    /// Atomically replace one attestation key with a merged attestation key.
    pub fn mergeAttestations(self: *Store, old_root: fulu.Root, merged: fulu.Attestation) !void {
        const bytes = try encode(self.allocator, .{ .attestation = merged });
        defer self.allocator.free(bytes);
        const new_key = recordKey(.attestation, bytes[2..34]);
        const old_key = recordKey(.attestation, &old_root);
        if (std.mem.eql(u8, &old_key, &new_key)) return error.DuplicateOperation;
        try self.mutex.lock(self.database.io);
        defer self.mutex.unlock(self.database.io);
        try self.requireWritable();
        const old = try self.database.get(self.allocator, &new_key);
        if (old) |existing| {
            defer self.allocator.free(existing);
            if (!std.mem.eql(u8, existing, bytes)) return error.RootCollision;
            return error.DuplicateOperation;
        }
        const old_bytes = (try self.database.get(self.allocator, &old_key)) orelse return error.MissingOperation;
        defer self.allocator.free(old_bytes);
        try self.checkCapacity(.attestation, new_key.len + bytes.len, .{ .key = old_key, .bytes = old_bytes.len });
        self.database.write(&.{ .{ .delete = &old_key }, .{ .put = .{ .key = &new_key, .value = bytes } } }) catch |err| {
            self.poisoned = true;
            return err;
        };
    }

    /// Delete operation keys in synced atomic batches of at most 128.
    pub fn delete(self: *Store, keys: []const [prefix.len + 33]u8) !void {
        for (keys) |key| {
            if (!std.mem.startsWith(u8, &key, prefix) or std.meta.intToEnum(Kind, key[prefix.len]) catch null == null) return error.InvalidKey;
        }
        try self.mutex.lock(self.database.io);
        defer self.mutex.unlock(self.database.io);
        try self.requireWritable();
        var offset: usize = 0;
        while (offset < keys.len) {
            const count = @min(128, keys.len - offset);
            var ops: [128]lsm.Operation = undefined;
            for (keys[offset .. offset + count], 0..) |key, i| ops[i] = .{ .delete = &key };
            self.database.write(ops[0..count]) catch |err| {
                self.poisoned = true;
                return err;
            };
            offset += count;
        }
    }

    /// Load all records through bounded pages, rejecting corruption without returning partial data.
    pub fn recover(self: *Store, allocator: std.mem.Allocator) ![]Record {
        const lower = prefix ++ [_]u8{0};
        const upper = prefix ++ [_]u8{255};
        var result: std.ArrayList(Record) = .empty;
        errdefer {
            for (result.items) |record| freeValue(allocator, record.value);
            result.deinit(allocator);
        }
        var cursor: ?[]u8 = null;
        defer if (cursor) |key| allocator.free(key);
        var total: usize = 0;
        var counts = [_]usize{0} ** 5;
        while (true) {
            const rows = try self.database.scan(allocator, &lower, &upper, cursor, scan_rows, 16 * 1024 * 1024);
            defer lsm.Database.freeRows(allocator, rows);
            if (rows.len == 0) break;
            for (rows) |row| {
                if (row.key.len != prefix.len + 33 or row.value.len > max_record) return error.InvalidRecord;
                total = std.math.add(usize, total, row.key.len + row.value.len) catch return error.PoolByteLimit;
                if (total > max_recovery_bytes) return error.PoolByteLimit;
                const record = try decode(allocator, row.key, row.value);
                const index = @intFromEnum(kind(record.value)) - 1;
                counts[index] += 1;
                if (counts[index] > countLimit(kind(record.value)) or result.items.len == max_records) {
                    freeValue(allocator, record.value);
                    return error.PoolFull;
                }
                result.append(allocator, record) catch |err| {
                    freeValue(allocator, record.value);
                    return err;
                };
            }
            if (cursor) |old| allocator.free(old);
            cursor = try allocator.dupe(u8, rows[rows.len - 1].key);
            if (rows.len < scan_rows) break;
        }
        return result.toOwnedSlice(allocator);
    }

    /// Revalidate records against the current state, remove invalid entries, and rebuild deterministic pool ordering.
    pub fn recoverPool(self: *Store, allocator: std.mem.Allocator, state: *const fulu.BeaconState) !pool_api.Pool {
        const records = try self.recover(allocator);
        defer Store.freeRecords(allocator, records);
        var pool = pool_api.Pool.init(allocator);
        errdefer pool.deinit();
        var invalid: std.ArrayList([prefix.len + 33]u8) = .empty;
        defer invalid.deinit(allocator);
        for (records) |record| {
            const admitted = switch (record.value) {
                .attestation => |value| pool.addAttestation(state, value),
                .proposer_slashing => |value| pool.addProposerSlashing(state, value),
                .attester_slashing => |value| pool.addAttesterSlashing(state, value),
                .voluntary_exit => |value| pool.addVoluntaryExit(state, value),
                .bls_change => |value| pool.addBlsChange(state, value),
            };
            admitted catch |err| {
                if (err == error.OutOfMemory) return err;
                try invalid.append(allocator, record.key);
            };
        }
        try self.delete(invalid.items);
        return pool;
    }

    /// Free decoded values from a successful recovery scan.
    pub fn freeRecords(allocator: std.mem.Allocator, records: []Record) void {
        for (records) |record| freeValue(allocator, record.value);
        allocator.free(records);
    }

    /// Compact the database and reclaim obsolete operation tombstones.
    pub fn reclaim(self: *Store) !void {
        try self.mutex.lock(self.database.io);
        defer self.mutex.unlock(self.database.io);
        try self.requireWritable();
        self.database.reclaimIfNeeded() catch |err| {
            self.poisoned = true;
            return err;
        };
    }

    /// Reject writes after an ambiguous failure until this store is reopened.
    fn requireWritable(self: *Store) !void {
        if (self.poisoned) return error.DatabaseNeedsReopen;
    }

    /// Check live byte and per-type limits before a synced write is attempted.
    fn checkCapacity(self: *Store, added_kind: Kind, added_bytes: usize, removed: ?struct { key: [prefix.len + 33]u8, bytes: usize }) !void {
        const lower = prefix ++ [_]u8{0};
        const upper = prefix ++ [_]u8{255};
        var total: usize = added_bytes;
        var records: usize = 1;
        var counts = [_]usize{0} ** 5;
        var cursor: ?[]u8 = null;
        defer if (cursor) |key| self.allocator.free(key);
        while (true) {
            const rows = try self.database.scan(self.allocator, &lower, &upper, cursor, scan_rows, 16 * 1024 * 1024);
            defer lsm.Database.freeRows(self.allocator, rows);
            if (rows.len == 0) break;
            for (rows) |row| {
                if (row.key.len != prefix.len + 33) return error.InvalidRecord;
                if (removed) |item| if (std.mem.eql(u8, row.key, &item.key)) {
                    total -= @min(total, item.key.len + item.bytes);
                    records -= 1;
                    counts[@intFromEnum(added_kind) - 1] -|= 1;
                    continue;
                };
                const tag = std.meta.intToEnum(Kind, row.key[prefix.len]) catch return error.UnknownOperationType;
                total = std.math.add(usize, total, row.key.len + row.value.len) catch return error.PoolByteLimit;
                records += 1;
                counts[@intFromEnum(tag) - 1] += 1;
            }
            if (cursor) |old| self.allocator.free(old);
            cursor = try self.allocator.dupe(u8, rows[rows.len - 1].key);
            if (rows.len < scan_rows) break;
        }
        counts[@intFromEnum(added_kind) - 1] += 1;
        if (total > max_recovery_bytes or records > max_records or counts[@intFromEnum(added_kind) - 1] > countLimit(added_kind)) return error.PoolFull;
    }
};

/// Map the record union tag to its stable on-disk discriminator.
fn kind(value: Value) Kind {
    return std.meta.activeTag(value);
}

/// Return the existing operation pool cap for a discriminator.
fn countLimit(tag: Kind) usize {
    return switch (tag) {
        .attestation => 2 * preset.MAX_ATTESTATIONS_ELECTRA,
        .proposer_slashing => 2 * preset.MAX_PROPOSER_SLASHINGS,
        .attester_slashing => 2 * preset.MAX_ATTESTER_SLASHINGS_ELECTRA,
        .voluntary_exit => 2 * preset.MAX_VOLUNTARY_EXITS,
        .bls_change => 2 * preset.MAX_BLS_TO_EXECUTION_CHANGES,
    };
}

/// Compute the maximum SSZ byte length of a type from its declared bounds.
fn maxSszSize(comptime T: type) usize {
    const descriptor = ssz.SszType(T);
    return switch (descriptor.kind) {
        .Bool, .Uint8, .Uint16, .Uint32, .Uint64, .Uint128, .Uint256, .BitVector, .ByteVector => descriptor.fixed_size.?,
        .BitList => (descriptor.max_bits.? + 8) / 8,
        .ByteList => descriptor.max_bytes.?,
        .List => blk: {
            const element_size = maxSszSize(descriptor.element.?);
            const element_descriptor = ssz.SszType(descriptor.element.?);
            const stride = element_size + if (element_descriptor.is_variable) @as(usize, 4) else 0;
            break :blk descriptor.max_length.? * stride;
        },
        .Array => blk: {
            const array_info = @typeInfo(T).array;
            const element_descriptor = ssz.SszType(array_info.child);
            if (!element_descriptor.is_variable) break :blk descriptor.fixed_size.?;
            break :blk array_info.len * (4 + maxSszSize(array_info.child));
        },
        .Container, .ProgressiveContainer => blk: {
            var total: usize = 0;
            inline for (@typeInfo(T).@"struct".fields) |field| {
                const field_descriptor = ssz.SszType(field.type);
                if (field_descriptor.is_variable) {
                    total += 4 + maxSszSize(field.type);
                } else total += field_descriptor.fixed_size.?;
            }
            break :blk total;
        },
    };
}

/// Return the maximum SSZ payload size for a durable operation discriminator.
fn maxSszSizeForKind(tag: Kind) usize {
    return switch (tag) {
        .attestation => maxSszSize(fulu.Attestation),
        .proposer_slashing => maxSszSize(fulu.ProposerSlashing),
        .attester_slashing => maxSszSize(fulu.AttesterSlashing),
        .voluntary_exit => maxSszSize(fulu.SignedVoluntaryExit),
        .bls_change => maxSszSize(fulu.SignedBLSToExecutionChange),
    };
}

/// Encode a schema, discriminator, SSZ root, length, and signed SSZ bytes.
fn encode(allocator: std.mem.Allocator, value: Value) ![]u8 {
    const payload = try switch (value) {
        .attestation => |item| ssz.serializeAlloc(allocator, item),
        .proposer_slashing => |item| ssz.serializeAlloc(allocator, item),
        .attester_slashing => |item| ssz.serializeAlloc(allocator, item),
        .voluntary_exit => |item| ssz.serializeAlloc(allocator, item),
        .bls_change => |item| ssz.serializeAlloc(allocator, item),
    };
    defer allocator.free(payload);
    if (payload.len > maxSszSizeForKind(kind(value))) return error.InvalidRecord;
    const root = try switch (value) {
        .attestation => |item| merkle.HashTreeRoot(allocator, item),
        .proposer_slashing => |item| merkle.HashTreeRoot(allocator, item),
        .attester_slashing => |item| merkle.HashTreeRoot(allocator, item),
        .voluntary_exit => |item| merkle.HashTreeRoot(allocator, item),
        .bls_change => |item| merkle.HashTreeRoot(allocator, item),
    };
    const bytes = try allocator.alloc(u8, header_len + payload.len);
    bytes[0] = 1;
    bytes[1] = @intFromEnum(kind(value));
    @memcpy(bytes[2..34], &root);
    std.mem.writeInt(u32, bytes[34..38], @intCast(payload.len), .little);
    @memcpy(bytes[header_len..], payload);
    return bytes;
}

/// Decode and validate the key, schema, encoded length, SSZ value, and root.
fn decode(allocator: std.mem.Allocator, key: []const u8, bytes: []const u8) !Record {
    if (key.len != prefix.len + 33 or !std.mem.startsWith(u8, key, prefix) or bytes.len < header_len or bytes[0] != 1) return error.InvalidRecord;
    const tag = std.meta.intToEnum(Kind, bytes[1]) catch return error.UnknownOperationType;
    if (key[prefix.len] != @intFromEnum(tag) or std.mem.readInt(u32, bytes[34..38], .little) != bytes.len - header_len or !std.mem.eql(u8, key[prefix.len + 1 ..], bytes[2..34])) return error.InvalidRecord;
    if (bytes.len - header_len > maxSszSizeForKind(tag)) return error.InvalidRecord;
    var reader: std.Io.Reader = .fixed(bytes[header_len..]);
    const value: Value = switch (tag) {
        .attestation => .{ .attestation = try ssz.deserialize(allocator, fulu.Attestation, &reader) },
        .proposer_slashing => .{ .proposer_slashing = try ssz.deserialize(allocator, fulu.ProposerSlashing, &reader) },
        .attester_slashing => .{ .attester_slashing = try ssz.deserialize(allocator, fulu.AttesterSlashing, &reader) },
        .voluntary_exit => .{ .voluntary_exit = try ssz.deserialize(allocator, fulu.SignedVoluntaryExit, &reader) },
        .bls_change => .{ .bls_change = try ssz.deserialize(allocator, fulu.SignedBLSToExecutionChange, &reader) },
    };
    errdefer freeValue(allocator, value);
    if (reader.seek != bytes.len - header_len) return error.InvalidRecord;
    const root = try switch (value) {
        .attestation => |item| merkle.HashTreeRoot(allocator, item),
        .proposer_slashing => |item| merkle.HashTreeRoot(allocator, item),
        .attester_slashing => |item| merkle.HashTreeRoot(allocator, item),
        .voluntary_exit => |item| merkle.HashTreeRoot(allocator, item),
        .bls_change => |item| merkle.HashTreeRoot(allocator, item),
    };
    if (!std.mem.eql(u8, &root, bytes[2..34])) return error.InvalidRecord;
    var result: Record = .{ .key = undefined, .value = value };
    @memcpy(&result.key, key);
    return result;
}

/// Construct a stable namespace key from its type and root.
fn recordKey(tag: Kind, root: []const u8) [prefix.len + 33]u8 {
    var key: [prefix.len + 33]u8 = undefined;
    @memcpy(key[0..prefix.len], prefix);
    key[prefix.len] = @intFromEnum(tag);
    @memcpy(key[prefix.len + 1 ..], root);
    return key;
}

/// Release the nested allocations owned by a decoded operation.
fn freeValue(allocator: std.mem.Allocator, value: Value) void {
    switch (value) {
        .attestation => |item| ssz.freeDecoded(allocator, fulu.Attestation, item),
        .proposer_slashing => |item| ssz.freeDecoded(allocator, fulu.ProposerSlashing, item),
        .attester_slashing => |item| ssz.freeDecoded(allocator, fulu.AttesterSlashing, item),
        .voluntary_exit => |item| ssz.freeDecoded(allocator, fulu.SignedVoluntaryExit, item),
        .bls_change => |item| ssz.freeDecoded(allocator, fulu.SignedBLSToExecutionChange, item),
    }
}

test "operation record codec rejects wrong key and malformed lengths" {
    const allocator = std.testing.allocator;
    const bytes = try encode(allocator, .{ .voluntary_exit = .{ .message = .{ .epoch = 2, .validator_index = 3 }, .signature = [_]u8{0} ** 96 } });
    defer allocator.free(bytes);
    const key = recordKey(.voluntary_exit, bytes[2..34]);
    const record = try decode(allocator, &key, bytes);
    freeValue(allocator, record.value);
    var malformed = try allocator.dupe(u8, bytes);
    defer allocator.free(malformed);
    malformed[34] +%= 1;
    try std.testing.expectError(error.InvalidRecord, decode(allocator, &key, malformed));
}

test "operation store syncs, recovers, and deletes typed records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    const value: Value = .{ .voluntary_exit = .{ .message = .{ .epoch = 2, .validator_index = 3 }, .signature = [_]u8{0} ** 96 } };
    try store.put(value);
    try store.put(value);
    store.poisoned = true;
    try std.testing.expectError(error.DatabaseNeedsReopen, store.put(value));
    store.deinit();
    store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    var records = try store.recover(allocator);
    try std.testing.expectEqual(@as(usize, 1), records.len);
    const key = records[0].key;
    Store.freeRecords(allocator, records);
    try store.delete(&.{key});
    records = try store.recover(allocator);
    defer Store.freeRecords(allocator, records);
    try std.testing.expectEqual(@as(usize, 0), records.len);
    store.deinit();
}

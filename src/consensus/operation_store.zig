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
const helpers = @import("helpers.zig");
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
            if (!std.mem.startsWith(u8, &key, prefix) or std.enums.fromInt(Kind, key[prefix.len]) == null) return error.InvalidKey;
        }
        try self.mutex.lock(self.database.io);
        defer self.mutex.unlock(self.database.io);
        try self.requireWritable();
        var offset: usize = 0;
        while (offset < keys.len) {
            const count = @min(128, keys.len - offset);
            var ops: [128]lsm.Operation = undefined;
            for (keys[offset .. offset + count], 0..) |*key, i| ops[i] = .{ .delete = key };
            self.database.write(ops[0..count]) catch |err| {
                self.poisoned = true;
                return err;
            };
            offset += count;
        }
    }

    /// Remove block-included operations durably before dropping their pool entries.
    pub fn accepted(self: *Store, pool: *pool_api.Pool, body: fulu.BeaconBlockBody) !void {
        var keys: std.ArrayList([prefix.len + 33]u8) = .empty;
        defer keys.deinit(self.allocator);
        inline for (.{ "proposer_slashings", "attester_slashings", "attestations", "voluntary_exits", "bls_to_execution_changes" }) |field| {
            for (@field(body, field).data) |value| {
                const value_kind: Kind = if (comptime std.mem.eql(u8, field, "proposer_slashings")) .proposer_slashing else if (comptime std.mem.eql(u8, field, "attester_slashings")) .attester_slashing else if (comptime std.mem.eql(u8, field, "attestations")) .attestation else if (comptime std.mem.eql(u8, field, "voluntary_exits")) .voluntary_exit else .bls_change;
                const root = try merkle.HashTreeRoot(self.allocator, value);
                try keys.append(self.allocator, recordKey(value_kind, &root));
            }
        }
        try self.delete(keys.items);
        try pool.accepted(body);
    }

    /// Persist a detached-branch operation before validating and publishing it again.
    pub fn readmit(self: *Store, pool: *pool_api.Pool, state: *const fulu.BeaconState, value: Value) !void {
        if (value == .attestation) {
            pool.addAttestationDurable(state, value.attestation, self, commitAttestation) catch |err| {
                if (err == error.OutOfMemory or err == error.DurableWriteFailed) return err;
            };
            return;
        }
        self.put(value) catch |err| {
            if (err == error.PoolFull) return;
            return err;
        };
        const admitted = switch (value) {
            .attestation => |item| pool.addAttestation(state, item),
            .proposer_slashing => |item| pool.addProposerSlashing(state, item),
            .attester_slashing => |item| pool.addAttesterSlashing(state, item),
            .voluntary_exit => |item| pool.addVoluntaryExit(state, item),
            .bls_change => |item| pool.addBlsChange(state, item),
        };
        admitted catch |err| {
            if (err == error.DuplicateOperation) return;
            const bytes = try encode(self.allocator, value);
            defer self.allocator.free(bytes);
            try self.delete(&.{recordKey(kind(value), bytes[2..34])});
            if (err == error.OutOfMemory) return err;
        };
    }

    /// Commit an operation before pool publication, rolling back rejected admissions.
    pub fn admit(self: *Store, pool: *pool_api.Pool, state: *const fulu.BeaconState, value: Value) !void {
        if (value == .attestation) {
            pool.addAttestationDurable(state, value.attestation, self, commitAttestation) catch |err| {
                if (err == error.DuplicateOperation) return;
                return err;
            };
            return;
        }
        self.put(value) catch |err| {
            if (err == error.PoolFull) return err;
            return error.DurableWriteFailed;
        };
        const admitted = switch (value) {
            .attestation => |item| pool.addAttestation(state, item),
            .proposer_slashing => |item| pool.addProposerSlashing(state, item),
            .attester_slashing => |item| pool.addAttesterSlashing(state, item),
            .voluntary_exit => |item| pool.addVoluntaryExit(state, item),
            .bls_change => |item| pool.addBlsChange(state, item),
        };
        admitted catch |err| {
            if (err == error.DuplicateOperation) return;
            const bytes = try encode(self.allocator, value);
            defer self.allocator.free(bytes);
            self.delete(&.{recordKey(kind(value), bytes[2..34])}) catch return error.DurableWriteFailed;
            return err;
        };
    }

    /// Write a new attestation or atomically replace its merged predecessor.
    fn commitAttestation(context: *Store, old_root: ?fulu.Root, value: fulu.Attestation) !void {
        if (old_root) |root| {
            context.mergeAttestations(root, value) catch |err| {
                if (err == error.PoolFull) return err;
                return error.DurableWriteFailed;
            };
            return;
        }
        context.put(.{ .attestation = value }) catch |err| {
            if (err == error.PoolFull) return err;
            return error.DurableWriteFailed;
        };
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
            const rows = try self.database.scan(allocator, lower, upper, cursor, scan_rows, 16 * 1024 * 1024);
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
            if (record.value == .attestation) {
                const slot = record.value.attestation.data.slot;
                if (slot > state.slot or state.slot - slot > helpers.SLOTS_PER_EPOCH) {
                    try invalid.append(allocator, record.key);
                    continue;
                }
            }
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
        for (pool.attestations.items) |entry| {
            const key = recordKey(.attestation, &entry.root);
            var stored = false;
            for (records) |record| {
                if (std.mem.eql(u8, &record.key, &key)) {
                    stored = true;
                    break;
                }
            }
            if (!stored) {
                const bytes = try encode(allocator, .{ .attestation = entry.value });
                defer allocator.free(bytes);
                var ops: [max_records + 1]lsm.Operation = undefined;
                var count: usize = 0;
                for (records) |*record| {
                    if (record.value != .attestation or !std.meta.eql(record.value.attestation.data, entry.value.data)) continue;
                    var retained = false;
                    for (pool.attestations.items) |candidate| {
                        if (std.mem.eql(u8, record.key[prefix.len + 1 ..], &candidate.root)) {
                            retained = true;
                            break;
                        }
                    }
                    if (!retained) {
                        ops[count] = .{ .delete = &record.key };
                        count += 1;
                    }
                }
                ops[count] = .{ .put = .{ .key = &key, .value = bytes } };
                try self.mutex.lock(self.database.io);
                defer self.mutex.unlock(self.database.io);
                try self.requireWritable();
                self.database.write(ops[0 .. count + 1]) catch |err| {
                    self.poisoned = true;
                    return err;
                };
            }
        }
        for (records) |record| {
            if (kind(record.value) != .attestation) continue;
            var retained = false;
            for (pool.attestations.items) |entry| {
                if (std.mem.eql(u8, record.key[prefix.len + 1 ..], &entry.root)) {
                    retained = true;
                    break;
                }
            }
            if (!retained) try invalid.append(allocator, record.key);
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
            const rows = try self.database.scan(self.allocator, lower, upper, cursor, scan_rows, 16 * 1024 * 1024);
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
                const tag = std.enums.fromInt(Kind, row.key[prefix.len]) orelse return error.UnknownOperationType;
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
    const tag = std.enums.fromInt(Kind, bytes[1]) orelse return error.UnknownOperationType;
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
    return .{ .key = key[0 .. prefix.len + 33].*, .value = value };
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
    malformed[0] = 2;
    try std.testing.expectError(error.InvalidRecord, decode(allocator, &key, malformed));
}

test "operation store syncs, recovers, and deletes typed records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    const value: Value = .{ .voluntary_exit = .{ .message = .{ .epoch = 2, .validator_index = 3 }, .signature = [_]u8{0} ** 96 } };
    const other: Value = .{ .voluntary_exit = .{ .message = .{ .epoch = 2, .validator_index = 4 }, .signature = [_]u8{0} ** 96 } };
    try store.put(value);
    try store.put(other);
    try store.put(value);
    store.poisoned = true;
    try std.testing.expectError(error.DatabaseNeedsReopen, store.put(value));
    store.deinit();
    store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    var records = try store.recover(allocator);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    const keys = [_][prefix.len + 33]u8{ records[0].key, records[1].key };
    Store.freeRecords(allocator, records);
    try store.delete(&keys);
    records = try store.recover(allocator);
    defer Store.freeRecords(allocator, records);
    try std.testing.expectEqual(@as(usize, 0), records.len);
    store.deinit();
}

test "corrupt durable records abort recovery without exposing a partial pool" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    defer store.deinit();
    try store.put(.{ .voluntary_exit = .{ .message = .{ .epoch = 2, .validator_index = 3 }, .signature = [_]u8{0} ** 96 } });
    var corrupt_key = [_]u8{0} ** (prefix.len + 33);
    @memcpy(corrupt_key[0..prefix.len], prefix);
    corrupt_key[prefix.len] = @intFromEnum(Kind.voluntary_exit);
    try store.database.put(&corrupt_key, &.{1});
    try std.testing.expectError(error.InvalidRecord, store.recoverPool(allocator, &state));
}

test "accepted block operations are deleted from durable storage" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/voluntary_exit_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const input = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/voluntary_exit_valid/voluntary_exit.ssz_snappy"));
    defer allocator.free(input);
    var reader: std.Io.Reader = .fixed(input);
    const exit = try ssz.deserialize(allocator, fulu.SignedVoluntaryExit, &reader);
    defer ssz.freeDecoded(allocator, fulu.SignedVoluntaryExit, exit);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    defer store.deinit();
    var pool = pool_api.Pool.init(allocator);
    defer pool.deinit();
    try store.admit(&pool, &state, .{ .voluntary_exit = exit });
    try std.testing.expectEqual(@as(usize, 1), pool.voluntary_exits.items.len);
    var body = std.mem.zeroes(fulu.BeaconBlockBody);
    body.voluntary_exits.data = &.{exit};
    store.poisoned = true;
    try std.testing.expectError(error.DatabaseNeedsReopen, store.accepted(&pool, body));
    try std.testing.expectEqual(@as(usize, 1), pool.voluntary_exits.items.len);
    store.poisoned = false;
    try store.accepted(&pool, body);
    try std.testing.expectEqual(@as(usize, 0), pool.voluntary_exits.items.len);
    const records = try store.recover(allocator);
    defer Store.freeRecords(allocator, records);
    try std.testing.expectEqual(@as(usize, 0), records.len);
}

test "uncertain durable admission does not publish into the operation pool" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    defer store.deinit();
    store.poisoned = true;
    var pool = pool_api.Pool.init(allocator);
    defer pool.deinit();
    try std.testing.expectError(error.DurableWriteFailed, store.admit(&pool, &state, .{ .voluntary_exit = .{ .message = .{ .epoch = 0, .validator_index = 0 }, .signature = [_]u8{0} ** 96 } }));
    try std.testing.expectEqual(@as(usize, 0), pool.voluntary_exits.items.len);
}

test "reorg readmission drops operations invalid on the new state" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    defer store.deinit();
    var pool = pool_api.Pool.init(allocator);
    defer pool.deinit();
    try store.readmit(&pool, &state, .{ .voluntary_exit = .{ .message = .{ .epoch = 0, .validator_index = 0 }, .signature = [_]u8{0} ** 96 } });
    const records = try store.recover(allocator);
    defer Store.freeRecords(allocator, records);
    try std.testing.expectEqual(@as(usize, 0), records.len);
    try std.testing.expectEqual(@as(usize, 0), pool.voluntary_exits.items.len);
}

test "reorg readmission persists a valid operation through normal admission" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/voluntary_exit_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const input = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/voluntary_exit_valid/voluntary_exit.ssz_snappy"));
    defer allocator.free(input);
    var reader: std.Io.Reader = .fixed(input);
    const value = try ssz.deserialize(allocator, fulu.SignedVoluntaryExit, &reader);
    defer ssz.freeDecoded(allocator, fulu.SignedVoluntaryExit, value);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    defer store.deinit();
    var pool = pool_api.Pool.init(allocator);
    defer pool.deinit();
    try store.readmit(&pool, &state, .{ .voluntary_exit = value });
    try std.testing.expectEqual(@as(usize, 1), pool.voluntary_exits.items.len);
    const records = try store.recover(allocator);
    defer Store.freeRecords(allocator, records);
    try std.testing.expectEqual(@as(usize, 1), records.len);
}

test "recovery persists merged attestation under its final root" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const blst = @import("blst");
    const bls = @import("bls.zig");
    const domains = @import("domains.zig");
    const operations = @import("block_operations.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const fixture = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer allocator.free(fixture);
    var reader: std.Io.Reader = .fixed(fixture);
    const template = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, template);
    if (template.aggregation_bits.data.len < 2) return error.FixtureTooSmall;
    var votes = [2]fulu.Attestation{ template, template };
    var signing_keys = [2]blst.SecretKey{ .{}, .{} };
    defer for (&signing_keys) |*signing_key| signing_key.deinit();
    const root = try merkle.HashTreeRoot(allocator, template.data);
    const domain = domains.getDomain(state, helpers.DOMAIN_BEACON_ATTESTER, template.data.target.epoch);
    for (&votes, &signing_keys, 0..) |*vote, *signing_key, i| {
        const bits = try allocator.dupe(bool, template.aggregation_bits.data);
        @memset(bits, false);
        bits[i] = true;
        vote.aggregation_bits.data = bits;
        const indices = try operations.getAttestingIndices(allocator, &state, vote.*);
        defer allocator.free(indices);
        if (indices.len != 1) return error.InvalidFixtureCommittee;
        const seed = [_]u8{@as(u8, @intCast(0x50 + i))} ** 32;
        signing_key.keygen(&seed, null);
        @constCast(state.validators.data)[indices[0]].pubkey = try bls.publicKey(signing_key);
        vote.signature = bls.sign(signing_key, domains.computeSigningRoot(root, domain));
    }
    defer for (votes) |vote| allocator.free(vote.aggregation_bits.data);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var live_store = try Store.open(allocator, std.testing.io, tmp.dir, "live-operations");
    defer live_store.deinit();
    var live_pool = pool_api.Pool.init(allocator);
    defer live_pool.deinit();
    try live_store.admit(&live_pool, &state, .{ .attestation = votes[0] });
    try live_store.admit(&live_pool, &state, .{ .attestation = votes[1] });
    try std.testing.expectEqual(@as(usize, 1), live_pool.attestations.items.len);
    var live_records = try live_store.recover(allocator);
    defer Store.freeRecords(allocator, live_records);
    try std.testing.expectEqual(@as(usize, 1), live_records.len);
    try std.testing.expectEqual(live_pool.attestations.items[0].root, live_records[0].key[prefix.len + 1 ..][0..32].*);
    var stale_store = try Store.open(allocator, std.testing.io, tmp.dir, "stale-operations");
    defer stale_store.deinit();
    try stale_store.put(.{ .attestation = votes[0] });
    var stale_state = try pool_api.copyValue(allocator, fulu.BeaconState, state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, stale_state);
    stale_state.slot = votes[0].data.slot + helpers.SLOTS_PER_EPOCH + 1;
    var stale_pool = try stale_store.recoverPool(allocator, &stale_state);
    defer stale_pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), stale_pool.attestations.items.len);
    const stale_records = try stale_store.recover(allocator);
    defer Store.freeRecords(allocator, stale_records);
    try std.testing.expectEqual(@as(usize, 0), stale_records.len);
    var store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    try store.put(.{ .attestation = votes[0] });
    try store.put(.{ .attestation = votes[1] });
    var pool = try store.recoverPool(allocator, &state);
    try std.testing.expectEqual(@as(usize, 1), pool.attestations.items.len);
    const merged_key = recordKey(.attestation, &pool.attestations.items[0].root);
    pool.deinit();
    store.deinit();
    store = try Store.open(allocator, std.testing.io, tmp.dir, "operations");
    defer store.deinit();
    const records = try store.recover(allocator);
    defer Store.freeRecords(allocator, records);
    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqualSlices(u8, &merged_key, &records[0].key);
    try store.delete(&.{merged_key});
    var recovered = try store.recoverPool(allocator, &state);
    defer recovered.deinit();
    try std.testing.expectEqual(@as(usize, 0), recovered.attestations.items.len);
}

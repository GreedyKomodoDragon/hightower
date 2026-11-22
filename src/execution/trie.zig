// The Merkle-Patricia trie stores byte keys as nibbles in leaf, extension, and
// branch nodes. Keys are optionally Keccak-hashed for state/storage tries;
// transaction and receipt tries use RLP-encoded indexes without key hashing.
// Updates replace a key's value and deletions remove it, so operation order
// matters when keys repeat. Encoded subtrees remain cached in memory; nodes are
// not persisted and historical roots are not retained.
//
// entries -> nibble paths -> compact RLP nodes -> Keccak root
//                            └── proof path: root → selected leaf
const std = @import("std");
const rlp = @import("rlp");
const encoding = rlp.encoding;
const decode = rlp.decode;

pub const Hash = [32]u8;
pub const Error = error{ KeyNotFound, KeyCollision };

const Entry = struct { key: []u8, nibbles: []u8, value: []u8 };
const Prepared = struct { nibbles: []u8, value: []const u8, index: usize };
const Item = union(enum) { string: []const u8, raw: []const u8, hash: Hash };
const Built = struct { bytes: []u8, hash: Hash, includes_key: bool };
const CachedNode = struct { prefix: []u8, bytes: []u8, hash: Hash };
const CompactPath = struct { nibbles: []u8, leaf: bool };

/// An owned proof containing the encoded trie nodes on one included-key path.
pub const Proof = struct {
    allocator: std.mem.Allocator,
    nodes: [][]u8,

    /// Frees all encoded nodes and the proof slice with its creating allocator.
    pub fn deinit(self: *Proof) void {
        for (self.nodes) |node| self.allocator.free(node);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }
};

/// An in-memory trie; `secure` hashes keys before nibble encoding.
pub const Trie = struct {
    allocator: std.mem.Allocator,
    secure: bool,
    entries: std.ArrayList(Entry) = .empty,
    entry_index: std.StringHashMapUnmanaged(usize) = .empty,
    sorted_indices: ?[]usize = null,
    nodes: std.StringHashMapUnmanaged(CachedNode) = .empty,
    cached_root: ?Hash = null,
    root_node_builds: usize = 0,
    root_cache_lock: std.atomic.Mutex = .unlocked,

    /// Creates an empty trie; the caller chooses secure or raw-key semantics.
    pub fn init(allocator: std.mem.Allocator, secure: bool) Trie {
        return .{ .allocator = allocator, .secure = secure };
    }

    /// Releases keys and values copied into the trie.
    pub fn deinit(self: *Trie) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.nibbles);
            self.allocator.free(entry.value);
        }
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        if (self.sorted_indices) |indices| self.allocator.free(indices);
        var node_iterator = self.nodes.iterator();
        while (node_iterator.next()) |node| {
            self.allocator.free(node.value_ptr.prefix);
            self.allocator.free(node.value_ptr.bytes);
        }
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    /// Inserts or replaces a byte key; an empty value follows Ethereum trie semantics and deletes it.
    pub fn put(self: *Trie, key: []const u8, value: []const u8) !void {
        if (value.len == 0) {
            self.delete(key);
            return;
        }
        if (self.entry_index.get(key)) |index| {
            const entry = &self.entries.items[index];
            if (std.mem.eql(u8, entry.value, value)) return;
            const new_value = try self.allocator.dupe(u8, value);
            self.allocator.free(entry.value);
            entry.value = new_value;
            self.invalidate(entry.nibbles);
            return;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        try self.entry_index.ensureUnusedCapacity(self.allocator, 1);
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        const owned_nibbles = try keyNibbles(self.allocator, key, self.secure);
        errdefer self.allocator.free(owned_nibbles);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(.{ .key = owned_key, .nibbles = owned_nibbles, .value = owned_value });
        self.entry_index.putAssumeCapacity(owned_key, index);
        self.invalidateSortedIndices();
        self.invalidate(owned_nibbles);
    }

    /// Deletes a key if present; deleting an absent key is a no-op.
    pub fn delete(self: *Trie, key: []const u8) void {
        const index = self.entry_index.fetchRemove(key) orelse return;
        const removed = self.entries.swapRemove(index.value);
        if (index.value < self.entries.items.len) self.entry_index.getPtr(self.entries.items[index.value].key).?.* = index.value;
        self.invalidateSortedIndices();
        self.allocator.free(removed.key);
        self.invalidate(removed.nibbles);
        self.allocator.free(removed.nibbles);
        self.allocator.free(removed.value);
    }

    /// Computes the root; root and proof reads are serialized, while mutations require exclusive access.
    pub fn root(self: *Trie) !Hash {
        while (!self.root_cache_lock.tryLock()) std.atomic.spinLoopHint();
        defer self.root_cache_lock.unlock();
        if (self.cached_root) |root_hash| return root_hash;
        if (self.entries.items.len == 0) {
            const root_hash = keccak(&.{0x80});
            self.cached_root = root_hash;
            return root_hash;
        }
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const prepared = try self.prepare(arena.allocator());
        const built = try buildNode(arena.allocator(), prepared, 0, null, null, self);
        const root_hash = built.hash;
        self.cached_root = root_hash;
        return root_hash;
    }

    /// Builds and owns the encoded node path for an included key.
    pub fn prove(self: *Trie, key: []const u8) !Proof {
        while (!self.root_cache_lock.tryLock()) std.atomic.spinLoopHint();
        defer self.root_cache_lock.unlock();
        if (self.entries.items.len == 0) return error.KeyNotFound;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const prepared = try self.prepare(allocator);
        const path = try keyNibbles(allocator, key, self.secure);
        var reverse_nodes: std.ArrayList([]u8) = .empty;
        defer reverse_nodes.deinit(allocator);
        const built = try buildNode(allocator, prepared, 0, path, &reverse_nodes, null);
        if (!built.includes_key) return error.KeyNotFound;

        const nodes = try self.allocator.alloc([]u8, reverse_nodes.items.len);
        var initialized: usize = 0;
        errdefer {
            for (nodes[0..initialized]) |node| self.allocator.free(node);
            self.allocator.free(nodes);
        }
        for (reverse_nodes.items, 0..) |node, i| {
            nodes[i] = try self.allocator.dupe(u8, node);
            initialized += 1;
        }
        std.mem.reverse([]u8, nodes);
        return .{ .allocator = self.allocator, .nodes = nodes };
    }

    /// Converts owned entries into compact nibble paths, hashing keys when secure mode is enabled.
    fn prepare(self: *Trie, allocator: std.mem.Allocator) ![]Prepared {
        const prepared = try allocator.alloc(Prepared, self.entries.items.len);
        if (self.sorted_indices) |indices| {
            for (indices, 0..) |index, i| {
                const entry = self.entries.items[index];
                prepared[i] = .{ .nibbles = entry.nibbles, .value = entry.value, .index = index };
            }
        } else {
            for (self.entries.items, 0..) |entry, i| {
                prepared[i] = .{ .nibbles = entry.nibbles, .value = entry.value, .index = i };
            }
            std.mem.sort(Prepared, prepared, {}, lessPrepared);
            const indices = try self.allocator.alloc(usize, prepared.len);
            for (prepared, 0..) |entry, i| indices[i] = entry.index;
            self.sorted_indices = indices;
        }
        for (1..prepared.len) |i| {
            if (std.mem.eql(u8, prepared[i - 1].nibbles, prepared[i].nibbles)) return error.KeyCollision;
        }
        return prepared;
    }

    /// Drops key ordering after an insertion or deletion changes trie membership.
    fn invalidateSortedIndices(self: *Trie) void {
        if (self.sorted_indices) |indices| self.allocator.free(indices);
        self.sorted_indices = null;
    }

    /// Removes cached subtrees from the root through one changed nibble path.
    fn invalidate(self: *Trie, nibbles: []const u8) void {
        self.cached_root = null;
        for (0..nibbles.len + 1) |depth| {
            if (self.nodes.fetchRemove(nibbles[0..depth])) |removed| {
                self.allocator.free(removed.value.prefix);
                self.allocator.free(removed.value.bytes);
            }
        }
    }
};

/// Builds a non-secure trie for indexed transaction or receipt values.
pub fn orderedRoot(allocator: std.mem.Allocator, values: []const []const u8) !Hash {
    var trie = Trie.init(allocator, false);
    defer trie.deinit();
    for (values, 0..) |value, index| {
        var key_writer = std.Io.Writer.Allocating.init(allocator);
        defer key_writer.deinit();
        try rlp.rlp(&key_writer.writer, index);
        const key = try key_writer.toOwnedSlice();
        defer allocator.free(key);
        try trie.put(key, value);
    }
    return trie.root();
}

/// Verifies an inclusion proof for a raw key/value pair; malformed or mismatching proofs return false.
pub fn verifyProof(allocator: std.mem.Allocator, root_hash: Hash, key: []const u8, value: []const u8, proof: []const []const u8, secure: bool) bool {
    if (proof.len == 0 or !std.mem.eql(u8, &keccak(proof[0]), &root_hash)) return false;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const path = keyNibbles(arena.allocator(), key, secure) catch return false;
    var offset: usize = 0;

    for (proof, 0..) |encoded, proof_index| {
        var node = decode.decodeAll(arena.allocator(), encoded) catch return false;
        defer node.deinit(arena.allocator());
        if (node != .list) return false;
        const fields = node.list;
        var child: ?decode.Value = null;

        if (fields.len == 2) {
            if (fields[0] != .string) return false;
            const compact = decodeCompact(arena.allocator(), fields[0].string) catch return false;
            if (path.len -| offset < compact.nibbles.len or !std.mem.eql(u8, path[offset..][0..compact.nibbles.len], compact.nibbles)) return false;
            offset += compact.nibbles.len;
            if (compact.leaf) {
                return proof_index + 1 == proof.len and offset == path.len and fields[1] == .string and std.mem.eql(u8, fields[1].string, value);
            }
            if (offset == path.len) return false;
            child = fields[1];
        } else if (fields.len == 17) {
            if (offset == path.len) {
                return proof_index + 1 == proof.len and fields[16] == .string and fields[16].string.len != 0 and std.mem.eql(u8, fields[16].string, value);
            }
            child = fields[path[offset]];
            offset += 1;
        } else return false;

        if (proof_index + 1 >= proof.len or child == null) return false;
        const next = proof[proof_index + 1];
        switch (child.?) {
            .list => |inline_node| {
                const inline_bytes = encodeDecoded(arena.allocator(), .{ .list = inline_node }) catch return false;
                if (!std.mem.eql(u8, inline_bytes, next)) return false;
            },
            .string => |reference| {
                if (reference.len != 32 or !std.mem.eql(u8, reference, &keccak(next))) return false;
            },
        }
    }
    return false;
}

/// Recursively creates a leaf, extension, or branch node and records a matching proof path in reverse.
fn buildNode(allocator: std.mem.Allocator, entries: []const Prepared, depth: usize, target: ?[]const u8, proof_nodes: ?*std.ArrayList([]u8), cache: ?*Trie) anyerror!Built {
    const prefix = entries[0].nibbles[0..depth];
    if (cache) |trie| if (trie.nodes.get(prefix)) |node| return .{ .bytes = node.bytes, .hash = node.hash, .includes_key = false };
    const built = try buildNodeUncached(allocator, entries, depth, target, proof_nodes, cache);
    if (cache) |trie| {
        try trie.nodes.ensureUnusedCapacity(trie.allocator, 1);
        const owned_prefix = try trie.allocator.dupe(u8, prefix);
        errdefer trie.allocator.free(owned_prefix);
        const owned_bytes = try trie.allocator.dupe(u8, built.bytes);
        errdefer trie.allocator.free(owned_bytes);
        trie.nodes.putAssumeCapacity(owned_prefix, .{ .prefix = owned_prefix, .bytes = owned_bytes, .hash = built.hash });
        trie.root_node_builds += 1;
    }
    return built;
}

/// Creates a trie node after its unchanged descendants have been reused.
fn buildNodeUncached(allocator: std.mem.Allocator, entries: []const Prepared, depth: usize, target: ?[]const u8, proof_nodes: ?*std.ArrayList([]u8), cache: ?*Trie) anyerror!Built {
    if (entries.len == 1) {
        const entry = entries[0];
        const compact = try compactEncode(allocator, entry.nibbles[depth..], true);
        const node = try encodeList(allocator, &.{ .{ .string = compact }, .{ .string = entry.value } });
        const includes = if (target) |path| std.mem.eql(u8, path, entry.nibbles) else false;
        if (includes) try recordProofNode(allocator, proof_nodes, node);
        return .{ .bytes = node, .hash = keccak(node), .includes_key = includes };
    }

    var common = depth;
    const shortest = minKeyLength(entries);
    while (common < shortest and allNibble(entries, common, entries[0].nibbles[common])) : (common += 1) {}
    if (common > depth) {
        const child = try buildNode(allocator, entries, common, target, proof_nodes, cache);
        const compact = try compactEncode(allocator, entries[0].nibbles[depth..common], false);
        const reference = childReference(child);
        const node = try encodeList(allocator, &.{ .{ .string = compact }, reference });
        if (child.includes_key) try recordProofNode(allocator, proof_nodes, node);
        return .{ .bytes = node, .hash = keccak(node), .includes_key = child.includes_key };
    }

    var items: [17]Item = [_]Item{.{ .string = "" }} ** 17;
    var includes = false;
    var cursor: usize = 0;
    while (cursor < entries.len) {
        const entry = entries[cursor];
        if (entry.nibbles.len == depth) {
            items[16] = .{ .string = entry.value };
            if (target) |path| includes = includes or std.mem.eql(u8, path, entry.nibbles);
            cursor += 1;
            continue;
        }
        const nibble = entry.nibbles[depth];
        const start = cursor;
        cursor += 1;
        while (cursor < entries.len and entries[cursor].nibbles.len > depth and entries[cursor].nibbles[depth] == nibble) : (cursor += 1) {}
        const child = try buildNode(allocator, entries[start..cursor], depth + 1, target, proof_nodes, cache);
        items[nibble] = childReference(child);
        includes = includes or child.includes_key;
    }
    const node = try encodeList(allocator, &items);
    if (includes) try recordProofNode(allocator, proof_nodes, node);
    return .{ .bytes = node, .hash = keccak(node), .includes_key = includes };
}

/// Encodes list items, preserving child nodes inline when their reference is raw RLP.
fn encodeList(allocator: std.mem.Allocator, items: []const Item) ![]u8 {
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    for (items) |item| switch (item) {
        .string => |bytes| try encoding.encodeString(&payload.writer, bytes),
        .raw => |bytes| try payload.writer.writeAll(bytes),
        .hash => |hash| try encoding.encodeString(&payload.writer, &hash),
    };
    const contents = try payload.toOwnedSlice();
    defer allocator.free(contents);
    var encoded = std.Io.Writer.Allocating.init(allocator);
    errdefer encoded.deinit();
    try encoding.encodeListHeader(&encoded.writer, contents.len);
    try encoded.writer.writeAll(contents);
    return encoded.toOwnedSlice();
}

/// Chooses the canonical inline-node or hashed-node reference.
fn childReference(child: Built) Item {
    if (child.bytes.len < 32) return .{ .raw = child.bytes };
    return .{ .hash = child.hash };
}

/// Encodes the hex-prefix compact path and leaf/extension flags.
fn compactEncode(allocator: std.mem.Allocator, path: []const u8, leaf: bool) ![]u8 {
    const odd = path.len % 2 == 1;
    const prefix: u8 = (if (leaf) @as(u8, 2) else 0) | @as(u8, @intFromBool(odd));
    const out = try allocator.alloc(u8, (path.len + 2) / 2);
    if (odd) {
        out[0] = (prefix << 4) | path[0];
        for (1..path.len) |i| out[(i + 1) / 2] = if (i % 2 == 1) path[i] << 4 else out[(i + 1) / 2] | path[i];
    } else {
        out[0] = prefix << 4;
        for (path, 0..) |nibble, i| out[(i + 2) / 2] = if (i % 2 == 0) (nibble << 4) else out[(i + 2) / 2] | nibble;
    }
    return out;
}

/// Decodes compact-path flags and nibble pairs, rejecting invalid even padding.
fn decodeCompact(allocator: std.mem.Allocator, bytes: []const u8) !CompactPath {
    if (bytes.len == 0) return error.InvalidPath;
    const flag = bytes[0] >> 4;
    if (flag > 3 or (flag & 1 == 0 and bytes[0] & 0x0f != 0)) return error.InvalidPath;
    const odd = flag & 1 != 0;
    const count = bytes.len * 2 - (if (odd) @as(usize, 1) else @as(usize, 2));
    const nibbles = try allocator.alloc(u8, count);
    var out: usize = 0;
    if (odd) {
        nibbles[out] = bytes[0] & 0x0f;
        out += 1;
    }
    for (bytes[1..]) |byte| {
        nibbles[out] = byte >> 4;
        nibbles[out + 1] = byte & 0x0f;
        out += 2;
    }
    return .{ .nibbles = nibbles, .leaf = flag >= 2 };
}

/// Converts a byte key into high/low nibbles, optionally hashing it first.
fn keyNibbles(allocator: std.mem.Allocator, key: []const u8, secure: bool) ![]u8 {
    // SAFETY: This value is fully initialized before any read.
    var digest: Hash = undefined;
    const bytes = if (secure) blk: {
        digest = keccak(key);
        break :blk &digest;
    } else key;
    const length = try std.math.mul(usize, bytes.len, 2);
    const nibbles = try allocator.alloc(u8, length);
    for (bytes, 0..) |byte, i| {
        nibbles[i * 2] = byte >> 4;
        nibbles[i * 2 + 1] = byte & 0x0f;
    }
    return nibbles;
}

/// Encodes a decoded RLP value canonically for comparing inline proof nodes.
fn encodeDecoded(allocator: std.mem.Allocator, value: decode.Value) ![]u8 {
    switch (value) {
        .string => |bytes| {
            var writer = std.Io.Writer.Allocating.init(allocator);
            defer writer.deinit();
            try encoding.encodeString(&writer.writer, bytes);
            return writer.toOwnedSlice();
        },
        .list => |items| {
            var encoded_items: std.ArrayList(Item) = .empty;
            defer encoded_items.deinit(allocator);
            for (items) |item| try encoded_items.append(allocator, .{ .raw = try encodeDecoded(allocator, item) });
            return encodeList(allocator, encoded_items.items);
        },
    }
}

/// Adds a copied node to the reverse-order proof builder when proof generation is enabled.
fn recordProofNode(allocator: std.mem.Allocator, proof_nodes: ?*std.ArrayList([]u8), node: []const u8) !void {
    if (proof_nodes) |nodes| try nodes.append(allocator, try allocator.dupe(u8, node));
}

/// Returns the shortest prepared path length for branch construction.
fn minKeyLength(entries: []const Prepared) usize {
    var result = entries[0].nibbles.len;
    for (entries[1..]) |entry| result = @min(result, entry.nibbles.len);
    return result;
}

/// Checks whether every path has the same nibble at the requested offset.
fn allNibble(entries: []const Prepared, index: usize, nibble: u8) bool {
    for (entries[1..]) |entry| if (entry.nibbles[index] != nibble) return false;
    return true;
}

/// Orders prepared keys lexicographically by nibble path.
fn lessPrepared(_: void, lhs: Prepared, rhs: Prepared) bool {
    return std.mem.lessThan(u8, lhs.nibbles, rhs.nibbles);
}

/// Computes Keccak-256, Ethereum's legacy Keccak padding rather than SHA3 padding.
fn keccak(bytes: []const u8) Hash {
    // SAFETY: This value is fully initialized before any read.
    var digest: Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(bytes, &digest, .{});
    return digest;
}

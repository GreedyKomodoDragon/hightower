// The Merkle-Patricia trie stores byte keys as nibbles in leaf, extension, and
// branch nodes. Keys are optionally Keccak-hashed for state/storage tries;
// transaction and receipt tries use RLP-encoded indexes without key hashing.
// Updates replace a key's value and deletions remove it, so operation order
// matters when keys repeat. This implementation rebuilds nodes in memory and
// does not persist nodes or retain historical roots.
//
// entries -> nibble paths -> compact RLP nodes -> Keccak root
//                            └── proof path: root → selected leaf
const std = @import("std");
const rlp = @import("rlp");
const encoding = rlp.encoding;
const decode = rlp.decode;

pub const Hash = [32]u8;
pub const Error = error{ KeyNotFound, KeyCollision };

const Entry = struct { key: []u8, value: []u8 };
const Prepared = struct { nibbles: []u8, value: []const u8 };
const Item = union(enum) { string: []const u8, raw: []const u8 };
const Built = struct { bytes: []u8, includes_key: bool };
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

    /// Creates an empty trie; the caller chooses secure or raw-key semantics.
    pub fn init(allocator: std.mem.Allocator, secure: bool) Trie {
        return .{ .allocator = allocator, .secure = secure };
    }

    /// Releases keys and values copied into the trie.
    pub fn deinit(self: *Trie) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Inserts or replaces a byte key; an empty value follows Ethereum trie semantics and deletes it.
    pub fn put(self: *Trie, key: []const u8, value: []const u8) !void {
        if (value.len == 0) {
            self.delete(key);
            return;
        }
        for (self.entries.items) |*entry| {
            if (!std.mem.eql(u8, entry.key, key)) continue;
            const new_value = try self.allocator.dupe(u8, value);
            self.allocator.free(entry.value);
            entry.value = new_value;
            return;
        }
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);
        try self.entries.append(self.allocator, .{ .key = owned_key, .value = owned_value });
    }

    /// Deletes a key if present; deleting an absent key is a no-op.
    pub fn delete(self: *Trie, key: []const u8) void {
        for (self.entries.items, 0..) |entry, i| {
            if (!std.mem.eql(u8, entry.key, key)) continue;
            const removed = self.entries.orderedRemove(i);
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return;
        }
    }

    /// Computes the Keccak-256 root; the empty trie root hashes the RLP empty string.
    pub fn root(self: *const Trie) !Hash {
        if (self.entries.items.len == 0) return keccak(&.{0x80});
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const prepared = try self.prepare(arena.allocator());
        const built = try buildNode(arena.allocator(), prepared, 0, null, null);
        return keccak(built.bytes);
    }

    /// Builds and owns the encoded node path for an included key.
    pub fn prove(self: *const Trie, key: []const u8) !Proof {
        if (self.entries.items.len == 0) return error.KeyNotFound;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const prepared = try self.prepare(allocator);
        const path = try keyNibbles(allocator, key, self.secure);
        var reverse_nodes: std.ArrayList([]u8) = .empty;
        defer reverse_nodes.deinit(allocator);
        const built = try buildNode(allocator, prepared, 0, path, &reverse_nodes);
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
    fn prepare(self: *const Trie, allocator: std.mem.Allocator) ![]Prepared {
        const prepared = try allocator.alloc(Prepared, self.entries.items.len);
        for (self.entries.items, 0..) |entry, i| {
            prepared[i] = .{ .nibbles = try keyNibbles(allocator, entry.key, self.secure), .value = entry.value };
        }
        std.mem.sort(Prepared, prepared, {}, lessPrepared);
        for (1..prepared.len) |i| {
            if (std.mem.eql(u8, prepared[i - 1].nibbles, prepared[i].nibbles)) return error.KeyCollision;
        }
        return prepared;
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
fn buildNode(allocator: std.mem.Allocator, entries: []const Prepared, depth: usize, target: ?[]const u8, proof_nodes: ?*std.ArrayList([]u8)) !Built {
    if (entries.len == 1) {
        const entry = entries[0];
        const compact = try compactEncode(allocator, entry.nibbles[depth..], true);
        const node = try encodeList(allocator, &.{ .{ .string = compact }, .{ .string = entry.value } });
        const includes = if (target) |path| std.mem.eql(u8, path, entry.nibbles) else false;
        if (includes) try recordProofNode(allocator, proof_nodes, node);
        return .{ .bytes = node, .includes_key = includes };
    }

    var common = depth;
    const shortest = minKeyLength(entries);
    while (common < shortest and allNibble(entries, common, entries[0].nibbles[common])) : (common += 1) {}
    if (common > depth) {
        const child = try buildNode(allocator, entries, common, target, proof_nodes);
        const compact = try compactEncode(allocator, entries[0].nibbles[depth..common], false);
        const reference = childReference(allocator, child.bytes) catch return error.OutOfMemory;
        const node = try encodeList(allocator, &.{ .{ .string = compact }, reference });
        if (child.includes_key) try recordProofNode(allocator, proof_nodes, node);
        return .{ .bytes = node, .includes_key = child.includes_key };
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
        const child = try buildNode(allocator, entries[start..cursor], depth + 1, target, proof_nodes);
        items[nibble] = try childReference(allocator, child.bytes);
        includes = includes or child.includes_key;
    }
    const node = try encodeList(allocator, &items);
    if (includes) try recordProofNode(allocator, proof_nodes, node);
    return .{ .bytes = node, .includes_key = includes };
}

/// Encodes list items, preserving child nodes inline when their reference is raw RLP.
fn encodeList(allocator: std.mem.Allocator, items: []const Item) ![]u8 {
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    for (items) |item| switch (item) {
        .string => |bytes| try encoding.encodeString(&payload.writer, bytes),
        .raw => |bytes| try payload.writer.writeAll(bytes),
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
fn childReference(allocator: std.mem.Allocator, child: []const u8) !Item {
    if (child.len < 32) return .{ .raw = child };
    return .{ .string = try allocator.dupe(u8, &keccak(child)) };
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
    var digest: Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(bytes, &digest, .{});
    return digest;
}

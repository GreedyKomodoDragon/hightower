//  SSZ (Simple Serialize) gives Ethereum consensus objects two related
//  Merkleized by first computing the SSZ hash-tree root of each field:
//
//      root(slot)
//      root(active)
//      root(root)
//
//  Those 32-byte field roots become the leaves of the container's Merkle tree.
//  If necessary, the leaves are padded with zero nodes to form the required
//  binary tree, then adjacent nodes are SHA-256 hashed together until one
//  32-byte root remains.
//
//  Conceptually:
//
//      slot_root   active_root   root_root   ZERO
//          \           /             \        /
//           left_parent              right_parent
//                   \                 /
//                    container_root
//
//  Nested values are handled recursively: a nested container, vector, or list
//  first computes its own hash-tree root, and that root becomes a leaf in its
//  parent's tree.
//
//  Different SSZ types have different Merkleization rules:
//
//    - bool / uint:
//        encoded into a 32-byte chunk, zero-padded as required
//
//    - Vector of basic values:
//        values are packed into 32-byte chunks and Merkleized
//
//    - Container:
//        each field contributes one 32-byte hash-tree root
//
//    - List:
//        contents are Merkleized according to the list's maximum capacity,
//        then the current length is mixed into the resulting root
//
//  Therefore SSZ Merkleization depends on both the VALUE and its TYPE.
//  Serialization and Merkleization share the same SSZ schema, but they are
//  separate operations with different purposes:
//
//      serialize(value)    -> canonical bytes
//      hashTreeRoot(value) -> canonical 32-byte commitment
//
//  This file implements the latter by recursively inspecting the SSZ value's
//  type and reducing it to a single 32-byte Merkle root.

const std = @import("std");
const bitList = @import("bitlist");

pub fn GetChunks(allocator: std.mem.Allocator, value: anytype) ![][32]u8 {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .int => |info| {
            if (info.signedness == std.builtin.Signedness.signed) {
                @compileError("not implemented merkleize signed int type: " ++ @typeName(T));
            }

            var currentChunk = [_]u8{0} ** 32;
            const result = try allocator.alloc([32]u8, 1);

            writeIntToChunk(
                T,
                &currentChunk,
                0,
                value,
            );

            result[0] = currentChunk;
            return result;
        },
        .bool => {
            // fill the array with zeros
            var chunk: [32]u8 = [_]u8{0} ** 32;
            chunk[0] = if (value) 1 else 0;

            const result = try allocator.alloc([32]u8, 1);
            result[0] = chunk;

            return result;
        },
        .array => |info| {
            const Item = info.child;

            switch (@typeInfo(Item)) {
                .int, .bool => {
                    return packBasicArray(
                        Item,
                        allocator,
                        value,
                    );
                },
                .@"struct" => {
                    const result = try allocator.alloc([32]u8, info.len);
                    errdefer allocator.free(result);

                    for (value, 0..) |item, i| {
                        result[i] = try HashTreeRoot(
                            allocator,
                            item,
                        );
                    }

                    return result;
                },
                else => {
                    @compileError(
                        "unsupported SSZ array item type: " ++ @typeName(Item),
                    );
                },
            }
        },
        .@"struct" => |info| {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .bitlist => {
                        return bitList.writeBitListToChunk(
                            allocator,
                            value,
                        );
                    },
                    .bitvector => {
                        return bitList.writeBitVectorToChunk(
                            T,
                            allocator,
                            value,
                        );
                    },
                    .bytelist => {
                        return bitList.writeByteListToChunk(
                            allocator,
                            value,
                        );
                    },
                    .bytevector => {
                        return bitList.writeByteListToChunk(
                            allocator,
                            value,
                        );
                    },
                    .list => {
                        return writeListToChunks(
                            T,
                            allocator,
                            value.data,
                        );
                    },
                    else => {
                        return error.SszNotImplemented;
                    },
                }
            }

            if (@hasDecl(T, "ssz_active_fields")) {
                return progressiveContainerLeaves(
                    allocator,
                    value,
                );
            }

            const result = try allocator.alloc([32]u8, info.fields.len);
            errdefer allocator.free(result);

            inline for (info.fields, 0..) |field, i| {
                const field_value = @field(value, field.name);

                result[i] = try HashTreeRoot(
                    allocator,
                    field_value,
                );
            }

            return result;
        },
        else => {
            @compileError("unsupported RLP type: " ++ @typeName(T));
        },
    }

    @compileError("unsupported RLP type");
}

fn writeIntToChunk(
    comptime T: type,
    chunk: *[32]u8,
    offset: usize,
    value: T,
) void {
    var int_bytes: [@sizeOf(T)]u8 = undefined;

    std.mem.writeInt(
        T,
        &int_bytes,
        value,
        .little,
    );

    @memcpy(
        chunk[offset .. offset + @sizeOf(T)],
        &int_bytes,
    );
}

// HashTreeRoot will be used in the following:
//
// beacon code
//     uses HashTreeRoot(...)

// SSZ code
//     HashTreeRoot(...)
//         calls GetChunks(...)
//         calls Merkleize(...)
pub fn HashTreeRoot(
    allocator: std.mem.Allocator,
    value: anytype,
) ![32]u8 {
    const T = @TypeOf(value);

    // Progressive containers merkleize one leaf per layout position
    // over a spine, then mix the layout word in (EIP-7495).
    if (@typeInfo(T) == .@"struct" and @hasDecl(T, "ssz_active_fields")) {
        const chunks = try progressiveContainerLeaves(allocator, value);
        defer allocator.free(chunks);

        const spine = try merkleizeProgressive(allocator, chunks, 1);

        var input: [64]u8 = undefined;
        @memcpy(input[0..32], &spine);
        @memcpy(input[32..64], &activeFieldsWord(T));

        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&input, &out, .{});

        return out;
    }

    if (@typeInfo(T) == .@"struct" and @hasDecl(T, "ssz_kind")) {
        switch (T.ssz_kind) {
            .bitlist => {
                const chunks = try GetChunks(
                    allocator,
                    value,
                );
                defer allocator.free(chunks);

                const content_root = try Merkleize(
                    allocator,
                    chunks,
                    limitChunks(T),
                );

                return bitList.mixInLength(
                    content_root,
                    value.data.len,
                );
            },
            .bytelist => {
                const chunks = try GetChunks(
                    allocator,
                    value,
                );
                defer allocator.free(chunks);

                const content_root = try Merkleize(
                    allocator,
                    chunks,
                    limitChunks(T),
                );

                return bitList.mixInLength(
                    content_root,
                    value.data.len,
                );
            },
            .list => {
                const chunks = try GetChunks(
                    allocator,
                    value,
                );
                defer allocator.free(chunks);

                const content_root = try Merkleize(
                    allocator,
                    chunks,
                    limitChunks(T),
                );

                return bitList.mixInLength(
                    content_root,
                    value.data.len,
                );
            },

            else => {},
        }
    }

    // get all the chunks for a specifc value
    const chunks = try GetChunks(allocator, value);
    defer allocator.free(chunks);

    // then do the pairwise SHA-256 reduction
    return Merkleize(allocator, chunks, null);
}

// Merkleize will do something like this:
//
//      ROOT
//     /    \
//   H0      H1
//  / \      / \
// A   B    C   D
pub fn Merkleize(
    allocator: std.mem.Allocator,
    chunks: []const [32]u8,
    limit: ?usize,
) ![32]u8 {
    const count = chunks.len;

    // A capacity sets the tree width instead, rounded up to a power of two.
    const width = if (limit) |l| blk: {
        if (l < count) return error.MerkleizeLimit;
        break :blk nextPow2(l);
    } else nextPow2(count);

    // No data under a capacity roots to that width's zero tree.
    if (count == 0) {
        if (limit != null) return zeroTreeRoot(width);
        return [_]u8{0} ** 32;
    }

    if (width == 1) {
        return chunks[0];
    }

    var level = try allocator.alloc([32]u8, width);
    defer allocator.free(level);

    @memset(level, [_]u8{0} ** 32);

    for (chunks, 0..) |chunk, i| {
        level[i] = chunk;
    }

    var current_len = width;

    while (current_len > 1) {
        var i: usize = 0;
        var parent: usize = 0;

        while (i < current_len) : ({
            i += 2;
            parent += 1;
        }) {
            var input: [64]u8 = undefined;

            @memcpy(input[0..32], &level[i]);
            @memcpy(input[32..64], &level[i + 1]);

            // block is taking two 32-byte child nodes and hashing them into one 32-byte parent node
            // done compress many leaves into one cryptographic commitment
            std.crypto.hash.sha2.Sha256.hash(
                &input,
                &level[parent],
                .{},
            );
        }

        current_len /= 2;
    }

    return level[0];
}

/// Smallest power of two greater than or equal to x. Returns 1 for 0.
fn nextPow2(x: usize) usize {
    if (x <= 1) return 1;
    return std.math.ceilPowerOfTwo(usize, x) catch unreachable;
}

/// Root of the all-zero perfect binary tree spanning `width` leaves.
/// `width` must be a power of two.
fn zeroTreeRoot(width: usize) [32]u8 {
    var node = [_]u8{0} ** 32;
    var n = width;
    while (n > 1) : (n /= 2) {
        var input: [64]u8 = undefined;
        @memcpy(input[0..32], &node);
        @memcpy(input[32..64], &node);
        std.crypto.hash.sha2.Sha256.hash(&input, &node, .{});
    }
    return node;
}

/// Chunk capacity of a variable-size SSZ type from its declared limit,
/// or null when the type packs exactly what it holds.
fn limitChunks(comptime T: type) ?usize {
    if (@hasDecl(T, "max_bytes")) return (T.max_bytes + 31) / 32;
    if (@hasDecl(T, "max_bits")) return (T.max_bits + 255) / 256;
    if (@hasDecl(T, "bit_length")) return (T.bit_length + 255) / 256;
    if (@hasDecl(T, "max_length")) return maxChunks(T.Element, T.max_length);
    return null;
}

/// Worst-case chunk count for `count` items of element type E.
/// Basic items pack densely; composite items cost one chunk each.
fn maxChunks(comptime E: type, count: usize) usize {
    switch (@typeInfo(E)) {
        .int => return (count * @sizeOf(E) + 31) / 32,
        .bool => return (count + 31) / 32,
        .array => |info| {
            switch (@typeInfo(info.child)) {
                .int, .bool => return (count * flatByteSize(E) + 31) / 32,
                else => return count * maxChunks(info.child, info.len),
            }
        },
        else => return count,
    }
}

/// Serialized byte size of a fixed-size basic/array element.
fn flatByteSize(comptime E: type) usize {
    switch (@typeInfo(E)) {
        .int => return @sizeOf(E),
        .bool => return 1,
        .array => |info| return info.len * flatByteSize(info.child),
        else => @compileError("not a fixed-size basic SSZ type: " ++ @typeName(E)),
    }
}

/// Chunk view of a List payload: basic elements pack densely,
/// composite elements contribute one hash-tree root each.
fn writeListToChunks(
    comptime T: type,
    allocator: std.mem.Allocator,
    data: []const T.Element,
) ![][32]u8 {
    const E = T.Element;

    switch (@typeInfo(E)) {
        .int, .bool => {
            return packBasicArray(E, allocator, data);
        },
        .array => |info| {
            switch (@typeInfo(info.child)) {
                .int, .bool => return packFixedArrays(E, allocator, data),
                else => {},
            }
        },
        else => {},
    }

    const result = try allocator.alloc([32]u8, data.len);
    errdefer allocator.free(result);

    for (data, 0..) |item, i| {
        result[i] = try HashTreeRoot(allocator, item);
    }

    return result;
}

/// Pack a slice of fixed-size array elements (e.g. [32]u8) into chunks.
fn packFixedArrays(
    comptime E: type,
    allocator: std.mem.Allocator,
    data: []const E,
) ![][32]u8 {
    const elem_size = flatByteSize(E);
    const total = data.len * elem_size;
    const chunk_count = (total + 31) / 32;

    const flat = try allocator.alloc(u8, total);
    defer allocator.free(flat);

    var off: usize = 0;
    for (data) |item| {
        writeFlat(E, flat[off..], item);
        off += elem_size;
    }

    const result = try allocator.alloc([32]u8, chunk_count);
    errdefer allocator.free(result);
    @memset(result, [_]u8{0} ** 32);

    for (flat, 0..) |byte, i| {
        result[i / 32][i % 32] = byte;
    }

    return result;
}

fn writeFlat(comptime E: type, out: []u8, item: E) void {
    switch (@typeInfo(E)) {
        .int => {
            std.mem.writeInt(E, out[0..@sizeOf(E)], item, .little);
        },
        .bool => {
            out[0] = if (item) 1 else 0;
        },
        .array => |info| {
            const stride = flatByteSize(info.child);
            for (item, 0..) |sub, i| {
                writeFlat(info.child, out[i * stride ..], sub);
            }
        },
        else => @compileError("not a fixed-size basic SSZ type: " ++ @typeName(E)),
    }
}

/// One leaf per layout position of a progressive container (EIP-7495).
/// Active positions hold the field root, gaps hold zero chunks.
/// The n-th field maps to the n-th set bit of `ssz_active_fields`.
fn progressiveContainerLeaves(
    allocator: std.mem.Allocator,
    value: anytype,
) ![][32]u8 {
    const T = @TypeOf(value);
    const info = @typeInfo(T).@"struct";
    const active = T.ssz_active_fields;

    if (comptime active.len > 256) {
        @compileError(
            "progressive layout exceeds 256 positions: " ++ @typeName(T),
        );
    }

    comptime var field_count: usize = 0;
    inline for (active) |occupied| {
        if (occupied) field_count += 1;
    }

    if (comptime field_count != info.fields.len) {
        @compileError(
            "progressive layout/field count mismatch: " ++ @typeName(T),
        );
    }

    const result = try allocator.alloc([32]u8, active.len);
    errdefer allocator.free(result);

    comptime var field_index: usize = 0;
    inline for (active, 0..) |occupied, position| {
        if (occupied) {
            result[position] = try HashTreeRoot(
                allocator,
                @field(value, info.fields[field_index].name),
            );
            field_index += 1;
        } else {
            result[position] = [_]u8{0} ** 32;
        }
    }

    return result;
}

/// The layout word a progressive container mixes in: bit i set when
/// position i is occupied, little-endian, one 32-byte word.
fn activeFieldsWord(comptime T: type) [32]u8 {
    const active = T.ssz_active_fields;

    var word = [_]u8{0} ** 32;

    inline for (active, 0..) |occupied, position| {
        if (occupied) {
            word[position / 8] |= @as(u8, 1) << @intCast(position % 8);
        }
    }

    return word;
}

/// Progressive spine root over chunks (EIP-7916): level n holds
/// 4**(n-1) chunks as one binary subtree, closed by a zero node.
fn merkleizeProgressive(
    allocator: std.mem.Allocator,
    chunks: []const [32]u8,
    width: usize,
) ![32]u8 {
    if (chunks.len == 0) {
        return [_]u8{0} ** 32;
    }

    const take = @min(chunks.len, width);
    const left = try Merkleize(allocator, chunks[0..take], width);
    const right = try merkleizeProgressive(allocator, chunks[take..], width * 4);

    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);

    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &out, .{});

    return out;
}

fn packBasicArray(
    comptime Item: type,
    allocator: std.mem.Allocator,
    value: anytype,
) ![][32]u8 {
    const item_size: usize = switch (@typeInfo(Item)) {
        .int => @sizeOf(Item),
        .bool => 1,
        else => @compileError("not a basic SSZ type"),
    };

    const total_bytes = value.len * item_size;
    const chunk_count = (total_bytes + 31) / 32;

    const result = try allocator.alloc([32]u8, chunk_count);
    errdefer allocator.free(result);

    var current_chunk = [_]u8{0} ** 32;
    var offset: usize = 0;
    var chunk_num: usize = 0;

    for (value) |item| {
        switch (@typeInfo(Item)) {
            .int => {
                writeIntToChunk(
                    Item,
                    &current_chunk,
                    offset,
                    item,
                );
            },
            .bool => {
                current_chunk[offset] = if (item) 1 else 0;
            },

            else => unreachable,
        }

        offset += item_size;

        if (offset == 32) {
            result[chunk_num] = current_chunk;
            chunk_num += 1;

            current_chunk = [_]u8{0} ** 32;
            offset = 0;
        }
    }

    if (offset > 0) {
        result[chunk_num] = current_chunk;
    }

    return result;
}

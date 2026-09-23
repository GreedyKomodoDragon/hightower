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

pub fn Chunk(allocator: std.mem.Allocator, value: anytype) ![][32]u8 {
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

            // chunk count
            const total_bytes: usize = info.len * @sizeOf(Item);
            const chunk_count: usize = (total_bytes + 31) / 32;

            var offset: u64 = 0;
            var chunkNum: u64 = 0;

            var currentChunk = [_]u8{0} ** 32;
            const result = try allocator.alloc([32]u8, chunk_count);
            errdefer allocator.free(result);

            switch (@typeInfo(Item)) {
                .int => {
                    for (value) |item| {
                        writeIntToChunk(
                            Item,
                            &currentChunk,
                            offset,
                            item,
                        );

                        offset += @sizeOf(Item);
                        if (offset >= 32) {
                            result[chunkNum] = currentChunk;
                            chunkNum += 1;

                            currentChunk = [_]u8{0} ** 32;
                            offset = 0;
                        }
                    }

                    // any unwritten chunks
                    if (offset > 0) {
                        result[chunkNum] = currentChunk;
                    }

                    return result;
                },

                else => {},
            }
        },

        else => {
            @compileError("unsupported RLP type: " ++ @typeName(T));
        },
    }

    return;
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

//! Per-kind chunking strategies: how each SSZ type class maps its
//! value onto 32-byte chunks. `get_chunks.GetChunks` dispatches here.
//!
//! - basic ints / bools: one value stream packed densely
//! - fixed byte arrays (e.g. `[32]u8`): concatenated then chunked
//! - composite values (containers, lists, ...): one hash-tree root each

const std = @import("std");
const desc_mod = @import("type_descriptor");
const htr_mod = @import("hash_tree_root.zig");

/// Chunk capacity of a variable-size SSZ type from its declared limit,
/// or null when the type packs exactly what it holds.
pub fn limitChunks(comptime T: type) ?usize {
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .ByteList => return (desc.max_bytes.? + 31) / 32,
        .BitList => return (desc.max_bits.? + 255) / 256,
        .BitVector => return (desc.bit_length.? + 255) / 256,
        .List => return maxChunks(desc.element.?, desc.max_length.?),
        else => return null,
    }
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

/// True for types that pack densely into chunks: ints, bools, and
/// fixed arrays thereof (recursively).
pub fn isDensePackable(comptime E: type) bool {
    switch (@typeInfo(E)) {
        .int, .bool => return true,
        .array => |info| return isDensePackable(info.child),
        else => return false,
    }
}

/// One chunk holding a single int value, zero-padded.
pub fn intToChunk(
    comptime T: type,
    allocator: std.mem.Allocator,
    value: T,
) ![][32]u8 {
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
}

/// One chunk holding a single bool, zero-padded.
pub fn boolToChunk(
    allocator: std.mem.Allocator,
    value: bool,
) ![][32]u8 {
    // fill the array with zeros
    var chunk: [32]u8 = [_]u8{0} ** 32;
    chunk[0] = if (value) 1 else 0;

    const result = try allocator.alloc([32]u8, 1);
    result[0] = chunk;

    return result;
}

/// One hash-tree root per container field, in field order.
pub fn containerLeaves(
    allocator: std.mem.Allocator,
    value: anytype,
) ![][32]u8 {
    const T = @TypeOf(value);
    const info = @typeInfo(T).@"struct";

    const result = try allocator.alloc([32]u8, info.fields.len);
    errdefer allocator.free(result);

    inline for (info.fields, 0..) |field, i| {
        result[i] = try htr_mod.HashTreeRoot(
            allocator,
            @field(value, field.name),
        );
    }

    return result;
}

/// Chunk view of a List payload: basic elements pack densely,
/// composite elements contribute one hash-tree root each.
pub fn writeListToChunks(
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
        result[i] = try htr_mod.HashTreeRoot(allocator, item);
    }

    return result;
}

/// Pack a slice of fixed-size array elements (e.g. [32]u8) into chunks.
pub fn packFixedArrays(
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

pub fn packBasicArray(
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

/// Serialized byte size of a fixed-size basic/array element.
fn flatByteSize(comptime E: type) usize {
    switch (@typeInfo(E)) {
        .int => return @sizeOf(E),
        .bool => return 1,
        .array => |info| return info.len * flatByteSize(info.child),
        else => @compileError("not a fixed-size basic SSZ type: " ++ @typeName(E)),
    }
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

//! List(Element, limit) plus its fixed-alphabet siblings
//! ByteList and BitList, which share the ownership pattern
//! (decoded form borrows nothing, owns a heap slice).

const std = @import("std");
const desc_mod = @import("type_descriptor");
const serialize_mod = @import("serialize.zig");
const deserialize_mod = @import("deserialize.zig");
const size_mod = @import("size.zig");
const offset_mod = @import("offset.zig");
const free_mod = @import("free.zig");

pub fn serializeList(
    comptime T: type,
    writer: *std.Io.Writer,
    value: T,
) !void {
    const desc = comptime desc_mod.SszType(T);

    if (value.data.len > desc.max_length.?) {
        return error.ListTooLong;
    }

    const elem = comptime desc_mod.SszType(desc.element.?);
    if (comptime !elem.is_variable) {
        for (value.data) |item| {
            try serialize_mod.serialize(writer, item);
        }
        return;
    }

    // Variable-size elements: offset table then payloads.
    var variable_offset: usize = value.data.len * 4;

    for (value.data) |item| {
        try offset_mod.writeOffset(writer, variable_offset);
        variable_offset += size_mod.serializedSize(item);
    }

    for (value.data) |item| {
        try serialize_mod.serialize(writer, item);
    }
}

pub fn deserializeList(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const desc = comptime desc_mod.SszType(T);
    const E = desc.element.?;

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    const elem = comptime desc_mod.SszType(E);
    if (comptime !elem.is_variable) {
        const elem_size = elem.fixed_size.?;

        if (elem_size == 0) {
            if (bytes.len != 0) return error.InvalidLength;
            return T{ .data = try allocator.alloc(E, 0) };
        }

        if (bytes.len % elem_size != 0) return error.InvalidLength;

        const count = bytes.len / elem_size;
        if (count > desc.max_length.?) return error.ListTooLong;

        return T{ .data = try decodeFixedItems(allocator, E, bytes, count) };
    }

    // Variable-size elements: leading offset table, then payloads.
    if (bytes.len == 0) {
        return T{ .data = try allocator.alloc(E, 0) };
    }
    if (bytes.len < 4) return error.InvalidOffset;

    const first = offset_mod.readOffset(bytes, 0);
    if (first % 4 != 0 or first > bytes.len) return error.InvalidOffset;

    const count: usize = @intCast(first / 4);
    if (count == 0 or count > desc.max_length.?) return error.InvalidOffset;

    const offsets = try offset_mod.splitVariable(allocator, bytes, count);
    defer allocator.free(offsets);

    return T{ .data = try decodeVariableItems(allocator, E, bytes, offsets) };
}

/// Decode `count` fixed-size items laid out back-to-back.
pub fn decodeFixedItems(
    allocator: std.mem.Allocator,
    comptime E: type,
    bytes: []const u8,
    count: usize,
) ![]E {
    const data = try allocator.alloc(E, count);
    var done: usize = 0;
    errdefer {
        for (data[0..done]) |*item| {
            free_mod.freeDecoded(allocator, E, item.*);
        }
        allocator.free(data);
    }

    var sub: std.Io.Reader = .fixed(bytes);
    for (data) |*item| {
        item.* = try deserialize_mod.deserializeAlloc(allocator, E, &sub);
        done += 1;
    }

    return data;
}

/// Decode items addressed by a validated `offsets` table
/// (`offsets.len == count + 1`, last entry = end of payload).
pub fn decodeVariableItems(
    allocator: std.mem.Allocator,
    comptime E: type,
    bytes: []const u8,
    offsets: []const usize,
) ![]E {
    const count = offsets.len - 1;
    const data = try allocator.alloc(E, count);
    var done: usize = 0;
    errdefer {
        for (data[0..done]) |*item| {
            free_mod.freeDecoded(allocator, E, item.*);
        }
        allocator.free(data);
    }

    for (data, 0..) |*item, i| {
        var elem_reader: std.Io.Reader = .fixed(bytes[offsets[i]..offsets[i + 1]]);
        item.* = try deserialize_mod.deserializeAlloc(allocator, E, &elem_reader);
        // Trailing bytes inside an element are malformed.
        if (elem_reader.bufferedLen() != 0) return error.TrailingBytes;
        done += 1;
    }

    return data;
}

pub fn deserializeByteList(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const desc = comptime desc_mod.SszType(T);

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    errdefer allocator.free(bytes);

    if (bytes.len > desc.max_bytes.?) return error.ByteListTooLong;

    return T{ .data = bytes };
}

pub fn deserializeBitList(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const desc = comptime desc_mod.SszType(T);

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    if (bytes.len == 0) return error.EndOfStream;
    // Minimal encoding: the delimiter bit lives in the last byte.
    const top = bytes[bytes.len - 1];
    if (top == 0) return error.NoDelimiterBit;

    // Index of the delimiter bit = data length.
    var hi: usize = 8;
    while (hi > 0 and (top >> @as(u3, @intCast(hi - 1)) & 1) == 0) {
        hi -= 1;
    }
    const data_len = (bytes.len - 1) * 8 + hi - 1;
    if (data_len > desc.max_bits.?) return error.BitListTooLong;

    const data = try allocator.alloc(bool, data_len);
    errdefer allocator.free(data);

    for (data, 0..) |*bit, i| {
        bit.* = (bytes[i / 8] >> @as(u3, @intCast(i % 8)) & 1) != 0;
    }

    return T{ .data = data };
}

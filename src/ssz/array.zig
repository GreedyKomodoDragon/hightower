//! Fixed-length vectors `[N]E`. Fixed-element vectors pack
//! inline; variable-element vectors use an offset table like Lists.

const std = @import("std");
const desc_mod = @import("type_descriptor");
const serialize_mod = @import("serialize.zig");
const deserialize_mod = @import("deserialize.zig");
const size_mod = @import("size.zig");
const offset_mod = @import("offset.zig");
const free_mod = @import("free.zig");

pub fn serializeArray(
    comptime T: type,
    writer: *std.Io.Writer,
    value: T,
) !void {
    const desc = comptime desc_mod.SszType(T);
    const elem = comptime desc_mod.SszType(desc.element.?);

    if (comptime !elem.is_variable) {
        for (value) |item| {
            try serialize_mod.serialize(writer, item);
        }
        return;
    }

    // Variable-size elements: offset table then payloads.
    var variable_offset: usize = value.len * 4;

    for (value) |item| {
        try offset_mod.writeOffset(writer, variable_offset);
        variable_offset += size_mod.serializedSize(item);
    }

    for (value) |item| {
        try serialize_mod.serialize(writer, item);
    }
}

pub fn deserializeArrayVar(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const info = @typeInfo(T).array;

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    const offsets = try offset_mod.splitVariable(allocator, bytes, info.len);
    defer allocator.free(offsets);

    var result: T = undefined;
    var done: usize = 0;
    errdefer {
        for (result[0..done]) |*item| {
            free_mod.freeDecoded(allocator, info.child, item.*);
        }
    }

    for (&result, 0..) |*item, i| {
        var sub: std.Io.Reader = .fixed(bytes[offsets[i]..offsets[i + 1]]);
        item.* = try deserialize_mod.deserialize(allocator, info.child, &sub);
        if (sub.bufferedLen() != 0) return error.TrailingBytes;
        done += 1;
    }

    return result;
}

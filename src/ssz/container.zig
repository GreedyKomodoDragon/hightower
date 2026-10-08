//! Plain and progressive containers. Both lay out bytes identically
//! (fixed fields inline, 4-byte offsets for variable fields); only
//! Merkleization treats progressive containers specially.

const std = @import("std");
const desc_mod = @import("type_descriptor");
const serialize_mod = @import("serialize.zig");
const deserialize_mod = @import("deserialize.zig");
const size_mod = @import("size.zig");
const offset_mod = @import("offset.zig");
const free_mod = @import("free.zig");

pub fn serializeContainer(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);
    const info = @typeInfo(T).@"struct";

    const fixed_section_size = size_mod.containerFixedSectionSize(T);

    // This points to where the next variable payload will start.
    var variable_offset: usize = fixed_section_size;

    // Pass 1: write the fixed section.
    inline for (info.fields) |field| {
        const field_desc = comptime desc_mod.SszType(field.type);
        const field_value = @field(value, field.name);

        if (comptime !field_desc.is_variable) {
            // Fixed fields live directly in the fixed section.
            try serialize_mod.serialize(writer, field_value);
        } else {
            // Variable fields get a 4-byte offset.
            try offset_mod.writeOffset(writer, variable_offset);
            // Advance to where the NEXT variable payload starts.
            variable_offset += size_mod.serializedSize(field_value);
        }
    }

    // Pass 2: write variable payloads.
    inline for (info.fields) |field| {
        const field_desc = comptime desc_mod.SszType(field.type);
        if (comptime field_desc.is_variable) {
            try serialize_mod.serialize(writer, @field(value, field.name));
        }
    }
}

/// Decode a variable-size container: fixed fields inline, variable
/// fields addressed by offsets into the trailing payload area.
/// Offsets must start exactly at the fixed section, increase
/// monotonically, and stay within bounds.
pub fn deserializeContainer(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const info = @typeInfo(T).@"struct";

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    const fixed_section = size_mod.containerFixedSectionSize(T);
    if (bytes.len < fixed_section) return error.EndOfStream;

    comptime var var_count: usize = 0;
    inline for (info.fields) |field| {
        const field_desc = comptime desc_mod.SszType(field.type);
        if (comptime field_desc.is_variable) var_count += 1;
    }

    if (var_count == 0) {
        if (bytes.len != fixed_section) return error.TrailingBytes;

        var sub: std.Io.Reader = .fixed(bytes);
        var result: T = undefined;
        inline for (info.fields) |field| {
            @field(result, field.name) = try deserialize_mod.deserializeAlloc(allocator, field.type, &sub);
        }
        return result;
    }

    // Collect offsets in field order from their fixed-section slots.
    var offsets: [var_count + 1]usize = undefined;
    {
        var slot: usize = 0;
        var pos: usize = 0;
        inline for (info.fields) |field| {
            const field_desc = comptime desc_mod.SszType(field.type);
            if (comptime !field_desc.is_variable) {
                pos += field_desc.fixed_size.?;
            } else {
                offsets[slot] = offset_mod.readOffset(bytes, pos);
                slot += 1;
                pos += 4;
            }
        }
    }
    offsets[var_count] = bytes.len;

    if (offsets[0] != fixed_section) return error.InvalidOffset;
    for (offsets[0..var_count], offsets[1..]) |start, end| {
        if (end < start or end > bytes.len) return error.InvalidOffset;
    }

    var result: T = undefined;
    var done: usize = 0;
    errdefer {
        inline for (info.fields, 0..) |field, i| {
            if (i < done) {
                free_mod.freeDecoded(allocator, field.type, @field(result, field.name));
            }
        }
    }

    var fixed_pos: usize = 0;
    var var_index: usize = 0;
    inline for (info.fields) |field| {
        const field_desc = comptime desc_mod.SszType(field.type);
        if (comptime !field_desc.is_variable) {
            const size = field_desc.fixed_size.?;
            var sub: std.Io.Reader = .fixed(bytes[fixed_pos..][0..size]);
            @field(result, field.name) = try deserialize_mod.deserializeAlloc(allocator, field.type, &sub);
            if (sub.bufferedLen() != 0) return error.TrailingBytes;
            fixed_pos += size;
        } else {
            var sub: std.Io.Reader = .fixed(bytes[offsets[var_index]..offsets[var_index + 1]]);
            @field(result, field.name) = try deserialize_mod.deserializeAlloc(allocator, field.type, &sub);
            if (sub.bufferedLen() != 0) return error.TrailingBytes;
            fixed_pos += 4;
            var_index += 1;
        }
        done += 1;
    }

    return result;
}

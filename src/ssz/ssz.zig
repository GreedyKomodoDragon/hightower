// serialization format used in the ethereum blockchain
// types are:
//
// bool
// uint8
// uint16
// uint32
// uint64
// uint128
// uint256

const std = @import("std");
const types = @import("types");
const bitList = @import("bitlist.zig");
const bitvector = @import("bitvector.zig");
const bytelist = @import("bytelist.zig");
const fixed = @import("fixed.zig");

pub fn serialize(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .int => |info| {
            if (info.signedness == std.builtin.Signedness.signed) {
                @compileError("not implemented RLP signed int type: " ++ @typeName(T));
            }

            switch (info.bits) {
                8, 16, 32, 64, 128, 256 => {
                    var buf: [info.bits / 8]u8 = undefined;
                    std.mem.writeInt(T, &buf, value, .little);

                    try writer.writeAll(&buf);
                },
                else => {
                    @compileError("not implemented RLP signed int type: " ++ @typeName(T));
                },
            }
        },
        .array => |array_info| {
            if (comptime fixed.isFixedSize(array_info.child)) {
                for (value) |item| {
                    // calling the serialize to recursively
                    try serialize(writer, item);
                }
                return;
            }

            // Variable-size elements: offset table then payloads.
            var variable_offset: usize = value.len * 4;

            for (value) |item| {
                var offset_bytes: [4]u8 = undefined;
                std.mem.writeInt(
                    u32,
                    &offset_bytes,
                    @intCast(variable_offset),
                    .little,
                );
                try writer.writeAll(&offset_bytes);
                variable_offset += serializedSize(item);
            }

            for (value) |item| {
                try serialize(writer, item);
            }
        },
        .bool => {
            try writer.writeByte(if (value) 0x01 else 0x00);
        },
        .@"struct" => {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .bitlist => {
                        return bitList.serializeBitList(
                            T,
                            writer,
                            value,
                        );
                    },
                    .bitvector => {
                        return bitvector.serializeBitVector(
                            T,
                            writer,
                            value,
                        );
                    },
                    .bytelist => {
                        return bytelist.serializeByteList(
                            T,
                            writer,
                            value,
                        );
                    },
                    .bytevector => {
                        try writer.writeAll(value.data[0..]);
                        return;
                    },
                    .list => {
                        if (value.data.len > T.max_length) {
                            return error.ListTooLong;
                        }

                        if (comptime fixed.isFixedSize(T.Element)) {
                            for (value.data) |item| {
                                try serialize(writer, item);
                            }
                            return;
                        }

                        // Variable-size elements: offset table then payloads.
                        var variable_offset: usize = value.data.len * 4;

                        for (value.data) |item| {
                            var offset_bytes: [4]u8 = undefined;
                            std.mem.writeInt(
                                u32,
                                &offset_bytes,
                                @intCast(variable_offset),
                                .little,
                            );
                            try writer.writeAll(&offset_bytes);
                            variable_offset += serializedSize(item);
                        }

                        for (value.data) |item| {
                            try serialize(writer, item);
                        }
                        return;
                    },

                    else => {
                        return error.SszNotImplemented;
                    },
                }
            }

            return serializeContainer(
                writer,
                value,
            );
        },
        else => {
            @compileError("unsupported RLP type: " ++ @typeName(T));
        },
    }

    return;
}

fn serializeContainer(
    writer: *std.Io.Writer,
    value: anytype,
) !void {
    const T = @TypeOf(value);
    const info = @typeInfo(T).@"struct";

    const fixed_section_size =
        containerFixedSectionSize(T);

    // This points to where the next variable payload
    // will start.
    var variable_offset: usize = fixed_section_size;

    // ---------------------------------
    // Pass 1: write the fixed section
    // ---------------------------------

    inline for (info.fields) |field| {
        const field_value = @field(value, field.name);

        if (comptime fixed.isFixedSize(field.type)) {
            // Fixed fields live directly in the fixed section.
            try serialize(
                writer,
                field_value,
            );
        } else {
            // Variable fields get a 4-byte offset.
            var offset_bytes: [4]u8 = undefined;

            std.mem.writeInt(
                u32,
                &offset_bytes,
                @intCast(variable_offset),
                .little,
            );

            try writer.writeAll(&offset_bytes);

            // Advance to where the NEXT variable payload starts.
            variable_offset += serializedSize(field_value);
        }
    }

    // ---------------------------------
    // Pass 2: write variable payloads
    // ---------------------------------

    inline for (info.fields) |field| {
        if (comptime !fixed.isFixedSize(field.type)) {
            const field_value = @field(value, field.name);

            try serialize(
                writer,
                field_value,
            );
        }
    }
}

fn serializedSize(value: anytype) usize {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .int => |info| {
            return info.bits / 8;
        },

        .bool => {
            return 1;
        },

        .array => {
            if (comptime fixed.isFixedSize(T)) {
                return fixed.fixedSize(T);
            }

            // Vector containing variable-size elements:
            //
            // [offset][offset][offset]...[payloads]
            var size: usize = value.len * 4;

            for (value) |item| {
                size += serializedSize(item);
            }

            return size;
        },

        .@"struct" => |info| {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .bitlist => {
                        // +1 bit for BitList delimiter.
                        return (value.data.len + 1 + 7) / 8;
                    },

                    .bitvector => {
                        return (T.bit_length + 7) / 8;
                    },

                    .bytelist => {
                        return value.data.len;
                    },

                    .bytevector => {
                        return T.byte_length;
                    },

                    .list => {
                        if (comptime fixed.isFixedSize(T.Element)) {
                            return value.data.len * fixed.fixedSize(T.Element);
                        }

                        var size: usize = value.data.len * 4;

                        for (value.data) |item| {
                            size += serializedSize(item);
                        }

                        return size;
                    },

                    else => {
                        @compileError(
                            "serializedSize not implemented for: " ++
                                @typeName(T),
                        );
                    },
                }
            }

            if (comptime fixed.isFixedSize(T)) {
                return fixed.fixedSize(T);
            }

            // Variable-size container.
            var size = containerFixedSectionSize(T);

            inline for (info.fields) |field| {
                if (comptime !fixed.isFixedSize(field.type)) {
                    const field_value = @field(value, field.name);
                    size += serializedSize(field_value);
                }
            }

            return size;
        },

        else => {
            @compileError(
                "serializedSize unsupported for: " ++ @typeName(T),
            );
        },
    }
}

fn containerFixedSectionSize(comptime T: type) usize {
    const info = @typeInfo(T).@"struct";

    var size: usize = 0;

    inline for (info.fields) |field| {
        if (comptime fixed.isFixedSize(field.type)) {
            size += fixed.fixedSize(field.type);
        } else {
            // Variable-size fields occupy a 4-byte offset
            // in the fixed section.
            size += 4;
        }
    }

    return size;
}

pub fn deserialize(
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    return switch (@typeInfo(T)) {
        .bool => blk: {
            const byte = try reader.takeByte();

            break :blk switch (byte) {
                0x00 => false,
                0x01 => true,
                else => error.InvalidBoolean,
            };
        },
        .array => |info| {
            if (comptime !fixed.isFixedSize(info.child)) {
                return error.NeedsAllocator;
            }

            var result: T = undefined;

            for (&result) |*item| {
                item.* = try deserialize(info.child, reader);
            }

            return result;
        },
        .int => |info| {
            if (info.signedness == std.builtin.Signedness.signed) {
                @compileError("unsupported SSZ type: " ++ @typeName(T));
            }

            switch (info.bits) {
                8, 16, 32, 64, 128, 256 => {
                    return try reader.takeInt(T, std.builtin.Endian.little);
                },
                else => {
                    @compileError("not implemented RLP signed int type: " ++ @typeName(T));
                },
            }
        },
        .@"struct" => |info| {
            // Custom SSZ kinds (bitlist, etc.) are not plain structs.
            // Fail at runtime so one unimplemented type does not stop
            // the whole test binary from compiling.
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .bytevector => {
                        var result: T = undefined;
                        const n = try reader.readSliceShort(result.data[0..]);
                        if (n != T.byte_length) return error.EndOfStream;
                        return result;
                    },
                    .list => return error.ListNeedsAllocator,
                    .bitlist, .bytelist => return error.NeedsAllocator,
                    else => return error.SszNotImplemented,
                }
            }

            if (comptime !fixed.isFixedSize(T)) {
                return error.NeedsAllocator;
            }

            var result: T = undefined;

            inline for (info.fields) |field| {
                @field(result, field.name) = try deserialize(field.type, reader);
            }

            return result;
        },
        else => return error.SszNotImplemented,
    };
}

/// Allocator-aware deserialize for variable-size SSZ types whose
/// decoded form owns memory (containers with variable fields, List,
/// ByteList, BitList, fixed arrays of variable-size elements).
/// Fixed-size types forward to `deserialize` and allocate nothing.
pub fn deserializeAlloc(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    switch (@typeInfo(T)) {
        .@"struct" => {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .list => return deserializeList(allocator, T, reader),
                    .bytelist => return deserializeByteList(allocator, T, reader),
                    .bitlist => return deserializeBitList(allocator, T, reader),
                    else => return deserialize(T, reader),
                }
            }

            return deserializeContainer(allocator, T, reader);
        },
        .array => |info| {
            if (comptime fixed.isFixedSize(info.child)) {
                return deserialize(T, reader);
            }

            const bytes = try reader.allocRemaining(allocator, .unlimited);
            defer allocator.free(bytes);

            const offsets = try splitVariable(allocator, bytes, info.len);
            defer allocator.free(offsets);

            var result: T = undefined;
            var done: usize = 0;
            errdefer {
                for (result[0..done]) |*item| {
                    freeDecoded(allocator, info.child, item.*);
                }
            }

            for (&result, 0..) |*item, i| {
                var sub: std.Io.Reader = .fixed(bytes[offsets[i]..offsets[i + 1]]);
                item.* = try deserializeAlloc(allocator, info.child, &sub);
                if (sub.bufferedLen() != 0) return error.TrailingBytes;
                done += 1;
            }

            return result;
        },
        else => return deserialize(T, reader),
    }
}

/// Decode a variable-size container: fixed fields inline, variable
/// fields addressed by offsets into the trailing payload area.
/// Offsets must start exactly at the fixed section, increase
/// monotonically, and stay within bounds.
fn deserializeContainer(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const info = @typeInfo(T).@"struct";

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    const fixed_section = containerFixedSectionSize(T);
    if (bytes.len < fixed_section) return error.EndOfStream;

    comptime var var_count: usize = 0;
    inline for (info.fields) |field| {
        if (comptime !fixed.isFixedSize(field.type)) var_count += 1;
    }

    if (var_count == 0) {
        if (bytes.len != fixed_section) return error.TrailingBytes;

        var sub: std.Io.Reader = .fixed(bytes);
        var result: T = undefined;
        inline for (info.fields) |field| {
            @field(result, field.name) = try deserializeAlloc(allocator, field.type, &sub);
        }
        return result;
    }

    // Collect offsets in field order from their fixed-section slots.
    var offsets: [var_count + 1]usize = undefined;
    {
        var slot: usize = 0;
        var pos: usize = 0;
        inline for (info.fields) |field| {
            if (comptime fixed.isFixedSize(field.type)) {
                pos += fixed.fixedSize(field.type);
            } else {
                offsets[slot] = std.mem.readInt(u32, bytes[pos..][0..4], .little);
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
                freeDecoded(allocator, field.type, @field(result, field.name));
            }
        }
    }

    var fixed_pos: usize = 0;
    var var_index: usize = 0;
    inline for (info.fields) |field| {
        if (comptime fixed.isFixedSize(field.type)) {
            const size = fixed.fixedSize(field.type);
            var sub: std.Io.Reader = .fixed(bytes[fixed_pos..][0..size]);
            @field(result, field.name) = try deserializeAlloc(allocator, field.type, &sub);
            if (sub.bufferedLen() != 0) return error.TrailingBytes;
            fixed_pos += size;
        } else {
            var sub: std.Io.Reader = .fixed(bytes[offsets[var_index]..offsets[var_index + 1]]);
            @field(result, field.name) = try deserializeAlloc(allocator, field.type, &sub);
            if (sub.bufferedLen() != 0) return error.TrailingBytes;
            fixed_pos += 4;
            var_index += 1;
        }
        done += 1;
    }

    return result;
}

/// Split a variable-size payload into `count` element ranges using its
/// leading offset table. The table must span exactly `count * 4` bytes,
/// offsets must increase monotonically and stay within bounds.
fn splitVariable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    count: usize,
) ![]usize {
    if (count == 0) {
        if (bytes.len != 0) return error.InvalidLength;
        const offsets = try allocator.alloc(usize, 1);
        offsets[0] = 0;
        return offsets;
    }
    if (bytes.len < count * 4) return error.InvalidOffset;

    var sub: std.Io.Reader = .fixed(bytes);
    const offsets = try allocator.alloc(usize, count + 1);
    errdefer allocator.free(offsets);

    for (offsets[0..count]) |*slot| {
        slot.* = try sub.takeInt(u32, std.builtin.Endian.little);
    }
    offsets[count] = bytes.len;

    if (offsets[0] != count * 4) return error.InvalidOffset;
    for (offsets[0..count], offsets[1..]) |start, end| {
        if (end < start or end > bytes.len) return error.InvalidOffset;
    }

    return offsets;
}

/// Release memory owned by a value produced with `deserializeAlloc`.
/// Safe to call on any value; fixed-size types compile to a no-op.
pub fn freeDecoded(
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) void {
    switch (@typeInfo(T)) {
        .@"struct" => |struct_info| {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .list => {
                        if (needsFree(T.Element)) {
                            for (value.data) |item| {
                                freeDecoded(allocator, T.Element, item);
                            }
                        }
                        allocator.free(value.data);
                        return;
                    },
                    .bitlist, .bytelist => {
                        allocator.free(value.data);
                        return;
                    },
                    else => return,
                }
            }

            inline for (struct_info.fields) |field| {
                freeDecoded(allocator, field.type, @field(value, field.name));
            }
        },
        .array => |array_info| {
            if (comptime needsFree(array_info.child)) {
                for (value) |item| {
                    freeDecoded(allocator, array_info.child, item);
                }
            }
        },
        else => {},
    }
}

fn needsFree(comptime T: type) bool {
    switch (@typeInfo(T)) {
        .@"struct" => {
            if (@hasDecl(T, "ssz_kind")) {
                return switch (T.ssz_kind) {
                    .list, .bitlist, .bytelist => true,
                    else => false,
                };
            }
            inline for (@typeInfo(T).@"struct".fields) |field| {
                if (comptime needsFree(field.type)) return true;
            }
            return false;
        },
        .array => |info| return needsFree(info.child),
        else => return false,
    }
}

fn deserializeList(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const E = T.Element;

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    if (comptime fixed.isFixedSize(E)) {
        const elem_size = fixed.fixedSize(E);

        if (elem_size == 0) {
            if (bytes.len != 0) return error.InvalidLength;
            return T{ .data = try allocator.alloc(E, 0) };
        }

        if (bytes.len % elem_size != 0) return error.InvalidLength;

        const count = bytes.len / elem_size;
        if (count > T.max_length) return error.ListTooLong;

        const data = try allocator.alloc(E, count);
        var done: usize = 0;
        errdefer {
            for (data[0..done]) |*item| {
                freeDecoded(allocator, E, item.*);
            }
            allocator.free(data);
        }

        var sub: std.Io.Reader = .fixed(bytes);
        for (data) |*item| {
            item.* = try deserializeAlloc(allocator, E, &sub);
            done += 1;
        }

        return T{ .data = data };
    }

    // Variable-size elements: leading offset table, then payloads.
    if (bytes.len == 0) {
        return T{ .data = try allocator.alloc(E, 0) };
    }
    if (bytes.len < 4) return error.InvalidOffset;

    const first = std.mem.readInt(u32, bytes[0..][0..4], .little);
    if (first % 4 != 0 or first > bytes.len) return error.InvalidOffset;

    const count: usize = @intCast(first / 4);
    if (count == 0 or count > T.max_length) return error.InvalidOffset;

    const offsets = try splitVariable(allocator, bytes, count);
    defer allocator.free(offsets);

    const data = try allocator.alloc(E, count);
    var done: usize = 0;
    errdefer {
        for (data[0..done]) |*item| {
            freeDecoded(allocator, E, item.*);
        }
        allocator.free(data);
    }

    for (data, 0..) |*item, i| {
        var elem_reader: std.Io.Reader = .fixed(bytes[offsets[i]..offsets[i + 1]]);
        item.* = try deserializeAlloc(allocator, E, &elem_reader);
        // Trailing bytes inside an element are malformed.
        if (elem_reader.bufferedLen() != 0) return error.TrailingBytes;
        done += 1;
    }

    return T{ .data = data };
}

fn deserializeByteList(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const bytes = try reader.allocRemaining(allocator, .unlimited);
    errdefer allocator.free(bytes);

    if (bytes.len > T.max_bytes) return error.ByteListTooLong;

    return T{ .data = bytes };
}

fn deserializeBitList(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
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
    if (data_len > T.max_bits) return error.BitListTooLong;

    const data = try allocator.alloc(bool, data_len);
    errdefer allocator.free(data);

    for (data, 0..) |*bit, i| {
        bit.* = (bytes[i / 8] >> @as(u3, @intCast(i % 8)) & 1) != 0;
    }

    return T{ .data = data };
}

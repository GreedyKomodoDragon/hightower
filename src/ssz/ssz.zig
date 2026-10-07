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
        .array => {
            for (value) |item| {
                // calling the serialize to recursively
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

                        if (fixed.isFixedSize(T.Element)) {
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

        if (fixed.isFixedSize(field.type)) {
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
        if (!fixed.isFixedSize(field.type)) {
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
            if (fixed.isFixedSize(T)) {
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
                        if (fixed.isFixedSize(T.Element)) {
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

            if (fixed.isFixedSize(T)) {
                return fixed.fixedSize(T);
            }

            // Variable-size container.
            var size = containerFixedSectionSize(T);

            inline for (info.fields) |field| {
                if (!fixed.isFixedSize(field.type)) {
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
        if (fixed.isFixedSize(field.type)) {
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
                    else => return error.SszNotImplemented,
                }
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
/// decoded form owns memory (List today; ByteList/BitList later).
/// Fixed-size types forward to `deserialize` and allocate nothing.
pub fn deserializeAlloc(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    if (@typeInfo(T) == .@"struct" and @hasDecl(T, "ssz_kind")) {
        switch (T.ssz_kind) {
            .list => return deserializeList(allocator, T, reader),
            else => return deserialize(T, reader),
        }
    }

    if (@typeInfo(T) == .@"struct" and !fixed.isFixedSize(T)) {
        return error.VariableContainerNotImplemented;
    }

    return deserialize(T, reader);
}

fn deserializeList(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const E = T.Element;

    const bytes = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    if (fixed.isFixedSize(E)) {
        const elem_size = fixed.fixedSize(E);

        if (elem_size == 0) {
            if (bytes.len != 0) return error.InvalidLength;
            return T{ .data = try allocator.alloc(E, 0) };
        }

        if (bytes.len % elem_size != 0) return error.InvalidLength;

        const count = bytes.len / elem_size;
        if (count > T.max_length) return error.ListTooLong;

        const data = try allocator.alloc(E, count);
        errdefer allocator.free(data);

        var sub: std.Io.Reader = .fixed(bytes);
        for (data) |*item| {
            item.* = try deserializeAlloc(allocator, E, &sub);
        }

        return T{ .data = data };
    }

    // Variable-size elements: leading offset table, then payloads.
    if (bytes.len == 0) {
        return T{ .data = try allocator.alloc(E, 0) };
    }
    if (bytes.len < 4) return error.InvalidOffset;

    var sub: std.Io.Reader = .fixed(bytes);
    const first = try sub.takeInt(u32, std.builtin.Endian.little);
    if (first % 4 != 0 or first > bytes.len) return error.InvalidOffset;

    const count: usize = @intCast(first / 4);
    if (count == 0 or count > T.max_length) return error.InvalidOffset;
    if (bytes.len < first) return error.InvalidOffset;

    const offsets = try allocator.alloc(usize, count + 1);
    defer allocator.free(offsets);
    offsets[0] = first;
    for (offsets[1..count]) |*slot| {
        const off = try sub.takeInt(u32, std.builtin.Endian.little);
        slot.* = off;
    }
    offsets[count] = bytes.len;

    for (offsets[0..count], offsets[1..]) |start, end| {
        if (end < start or end > bytes.len) return error.InvalidOffset;
    }

    const data = try allocator.alloc(E, count);
    errdefer allocator.free(data);

    for (data, 0..) |*item, i| {
        var elem_reader: std.Io.Reader = .fixed(bytes[offsets[i]..offsets[i + 1]]);
        item.* = try deserializeAlloc(allocator, E, &elem_reader);
        // Trailing bytes inside an element are malformed.
        if (elem_reader.bufferedLen() != 0) return error.TrailingBytes;
    }

    return T{ .data = data };
}

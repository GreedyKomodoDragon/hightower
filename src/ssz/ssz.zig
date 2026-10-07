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
                return error.SszNotImplemented;
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

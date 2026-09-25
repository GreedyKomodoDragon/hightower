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
        .@"struct" => |info| {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .bitlist => {
                        return bitList.serializeBitList(
                            T,
                            writer,
                            value,
                        );
                    },
                    else => {
                        @compileError("unsupported RLP type: " ++ @typeName(T));
                    },
                }
            }

            inline for (info.fields) |field| {
                const field_value = @field(value, field.name);

                try serialize(writer, field_value);
            }
        },
        else => {
            @compileError("unsupported RLP type: " ++ @typeName(T));
        },
    }

    return;
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

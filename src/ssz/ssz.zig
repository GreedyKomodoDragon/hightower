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

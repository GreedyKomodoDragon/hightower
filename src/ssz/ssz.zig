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
        .int => {
            @compileError("not implemented RLP int type: " ++ @typeName(T));
        },
        .array => {
            @compileError("not implemented RLP type: " ++ @typeName(T));
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

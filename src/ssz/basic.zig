//! Scalar SSZ codecs: bool and unsigned ints.
//! Everything here is fixed-size, little-endian, no allocation.

const std = @import("std");

pub fn serializeBasic(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .bool => {
            try writer.writeByte(if (value) 0x01 else 0x00);
        },
        .int => |info| {
            if (info.signedness != .unsigned) {
                @compileError("SSZ does not support signed int: " ++ @typeName(T));
            }
            switch (info.bits) {
                8, 16, 32, 64, 128, 256 => {
                    var buf: [info.bits / 8]u8 = undefined;
                    std.mem.writeInt(T, &buf, value, .little);
                    try writer.writeAll(&buf);
                },
                else => {
                    @compileError("SSZ does not support uint size: " ++ @typeName(T));
                },
            }
        },
        else => {
            @compileError("not a basic SSZ type: " ++ @typeName(T));
        },
    }
}

pub fn deserializeBasic(comptime T: type, reader: *std.Io.Reader) !T {
    return switch (@typeInfo(T)) {
        .bool => blk: {
            const byte = try reader.takeByte();
            break :blk switch (byte) {
                0x00 => false,
                0x01 => true,
                else => error.InvalidBoolean,
            };
        },
        .int => |info| {
            if (info.signedness != .unsigned) {
                @compileError("SSZ does not support signed int: " ++ @typeName(T));
            }
            switch (info.bits) {
                8, 16, 32, 64, 128, 256 => {
                    return try reader.takeInt(T, std.builtin.Endian.little);
                },
                else => {
                    @compileError("SSZ does not support uint size: " ++ @typeName(T));
                },
            }
        },
        else => {
            @compileError("not a basic SSZ type: " ++ @typeName(T));
        },
    };
}

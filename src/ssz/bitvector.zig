const std = @import("std");

pub fn serializeBitVector(
    comptime T: type,
    writer: *std.Io.Writer,
    value: T,
) !void {
    const byte_count = (T.bit_length + 7) / 8;
    var buf: [byte_count]u8 = [_]u8{0} ** byte_count;

    // pack data bits
    for (value.data, 0..) |bit, i| {
        // only need to update if it is a 1
        if (bit) {
            const byte_index = i / 8;
            const bit_index: u3 = @intCast(i % 8);

            buf[byte_index] |= (@as(u8, 1) << bit_index);
        }
    }

    try writer.writeAll(&buf);
}

pub fn deserializeBitVector(
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    const byte_count = (T.bit_length + 7) / 8;

    var raw: [byte_count]u8 = undefined;
    const n = try reader.readSliceShort(&raw);
    if (n != byte_count) return error.EndOfStream;

    // Bits past bit_length in the last byte are padding and must be zero.
    const excess = byte_count * 8 - T.bit_length;
    if (excess > 0) {
        const mask: u8 = @as(u8, 0xff) << @intCast(8 - excess);
        if (raw[byte_count - 1] & mask != 0) return error.NonZeroPaddingBits;
    }

    var result: T = undefined;
    for (&result.data, 0..) |*bit, i| {
        bit.* = (raw[i / 8] >> @as(u3, @intCast(i % 8)) & 1) != 0;
    }
    return result;
}

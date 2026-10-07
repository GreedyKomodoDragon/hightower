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

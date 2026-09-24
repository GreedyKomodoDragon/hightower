const std = @import("std");

pub fn serializeBitList(
    comptime T: type,
    writer: *std.Io.Writer,
    value: T,
) !void {
    if (value.data.len > T.max_bits) {
        return error.BitListTooLong;
    }

    const max_bytes = (T.max_bits + 1 + 7) / 8;
    var buf: [max_bytes]u8 = [_]u8{0} ** max_bytes;

    // pack data bits
    for (value.data, 0..) |bit, i| {
        // only need to update if it is a 1
        if (bit) {
            const byte_index = i / 8;
            const bit_index: u3 = @intCast(i % 8);

            buf[byte_index] |= (@as(u8, 1) << bit_index);
        }
    }

    // SSZ BitList delimiter bit comes immediately after the last data bit
    const delimiter_index = value.data.len;
    const delimiter_byte = delimiter_index / 8;
    const delimiter_bit: u3 = @intCast(delimiter_index % 8);

    buf[delimiter_byte] |= (@as(u8, 1) << delimiter_bit);

    const used_bytes = (value.data.len + 1 + 7) / 8;

    try writer.writeAll(buf[0..used_bytes]);
}

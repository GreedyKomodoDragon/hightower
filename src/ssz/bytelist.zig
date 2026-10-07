const std = @import("std");

pub fn serializeByteList(
    comptime T: type,
    writer: *std.Io.Writer,
    value: T,
) !void {
    if (value.data.len > T.max_bytes) {
        return error.ByteListTooLong;
    }

    try writer.writeAll(value.data);
}

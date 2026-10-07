//! ByteVector[N]: fixed N raw bytes. No length prefix,
//! no length mix-in. (Plain `[N]u8` arrays encode identically.)

const std = @import("std");

pub fn serializeByteVector(
    comptime T: type,
    writer: *std.Io.Writer,
    value: T,
) !void {
    try writer.writeAll(value.data[0..]);
}

pub fn deserializeByteVector(
    comptime T: type,
    reader: *std.Io.Reader,
) !T {
    var result: T = undefined;
    const n = try reader.readSliceShort(result.data[0..]);
    if (n != T.byte_length) return error.EndOfStream;
    return result;
}

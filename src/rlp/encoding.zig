// 0x00 - 0x7f   single byte, encoded as itself

// 0x80 - 0xb7   short string
//               prefix = 0x80 + string_length

// 0xb8 - 0xbf   long string
//               prefix = 0xb7 + length_of_length

// 0xc0 - 0xf7   short list
//               prefix = 0xc0 + payload_length

// 0xf8 - 0xff   long list
//               prefix = 0xf7 + length_of_length

const std = @import("std");

pub fn encodeString(writer: *std.Io.Writer, bytes: []const u8) !void {
    if (bytes.len == 0) {
        try writer.writeByte(0x80);
        return;
    }

    if (bytes.len == 1 and bytes[0] < 0x80) {
        try writer.writeByte(bytes[0]);
        return;
    }

    if (bytes.len <= 55) {
        try writer.writeByte(0x80 + @as(u8, @intCast(bytes.len)));
        try writer.writeAll(bytes);
        return;
    }

    // long-string case
    var len_buf: [@sizeOf(usize)]u8 = undefined;
    const len_bytes = encodeLengthBigEndian(&len_buf, bytes.len);

    try writer.writeByte(
        0xB7 + @as(u8, @intCast(len_bytes.len)), // this tells the decode this is a long string
    );
    try writer.writeAll(len_bytes);
    try writer.writeAll(bytes);
}

pub fn encodeBytes(writer: *std.Io.Writer, bytes: []const u8) !void {
    if (bytes.len == 1 and bytes[0] < 0x80) {
        try writer.writeByte(bytes[0]);
        return;
    }

    if (bytes.len <= 55) {
        try writer.writeByte(0xC0 + @as(u8, @intCast(bytes.len)));
        try writer.writeAll(bytes);
        return;
    }

    var len_buf: [@sizeOf(usize)]u8 = undefined;
    const len_bytes = encodeLengthBigEndian(&len_buf, bytes.len);

    try writer.writeByte(
        0xF7 + @as(u8, @intCast(len_bytes.len)),
    );
    try writer.writeAll(len_bytes);
    try writer.writeAll(bytes);
}

fn encodeLengthBigEndian(buf: []u8, value: usize) []const u8 {
    var v = value;
    var i = buf.len;

    while (v != 0) {
        i -= 1;
        buf[i] = @intCast(v & 0xff);
        v >>= 8;
    }

    return buf[i..];
}

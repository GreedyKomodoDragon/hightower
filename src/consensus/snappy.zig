const std = @import("std");

const MAX_BLOCK_SIZE = 64 * 1024 * 1024;

pub const Error = error{
    MalformedBlock,
    OutputTooLarge,
};

pub fn decompress(allocator: std.mem.Allocator, input: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    var cursor: usize = 0;
    const output_len = try readVarint(input, &cursor);
    if (output_len > MAX_BLOCK_SIZE) return error.OutputTooLarge;
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    var written: usize = 0;
    while (cursor < input.len and written < output.len) {
        const tag = input[cursor];
        cursor += 1;
        switch (tag & 0x03) {
            0 => {
                var literal_len: usize = tag >> 2;
                if (literal_len < 60) {
                    literal_len += 1;
                } else {
                    const extra_bytes = literal_len - 59;
                    if (extra_bytes > 4 or cursor + extra_bytes > input.len) return error.MalformedBlock;
                    literal_len = 0;
                    for (0..extra_bytes) |i| literal_len |= @as(usize, input[cursor + i]) << @as(u6, @intCast(i * 8));
                    cursor += extra_bytes;
                    literal_len += 1;
                }
                if (literal_len > output.len - written or literal_len > input.len - cursor) return error.MalformedBlock;
                @memcpy(output[written .. written + literal_len], input[cursor .. cursor + literal_len]);
                written += literal_len;
                cursor += literal_len;
            },
            1 => {
                if (cursor >= input.len) return error.MalformedBlock;
                const length = 4 + ((tag >> 2) & 0x07);
                const offset = (@as(usize, tag & 0xe0) << 3) | input[cursor];
                cursor += 1;
                try copyMatch(output, &written, offset, length);
            },
            2 => {
                if (cursor + 2 > input.len) return error.MalformedBlock;
                const length: usize = 1 + (tag >> 2);
                const offset = @as(u16, input[cursor]) | (@as(u16, input[cursor + 1]) << 8);
                cursor += 2;
                try copyMatch(output, &written, offset, length);
            },
            3 => {
                if (cursor + 4 > input.len) return error.MalformedBlock;
                const length: usize = 1 + (tag >> 2);
                const offset = @as(u32, input[cursor]) |
                    (@as(u32, input[cursor + 1]) << 8) |
                    (@as(u32, input[cursor + 2]) << 16) |
                    (@as(u32, input[cursor + 3]) << 24);
                cursor += 4;
                try copyMatch(output, &written, offset, length);
            },
            else => unreachable,
        }
    }
    if (written != output.len or cursor != input.len) return error.MalformedBlock;
    return output;
}

fn readVarint(input: []const u8, cursor: *usize) Error!usize {
    var value: usize = 0;
    for (0..5) |byte_index| {
        if (cursor.* >= input.len) return error.MalformedBlock;
        const byte = input[cursor.*];
        cursor.* += 1;
        const part = @as(usize, byte & 0x7f) << @as(u6, @intCast(byte_index * 7));
        value = std.math.add(usize, value, part) catch return error.MalformedBlock;
        if (byte & 0x80 == 0) return value;
    }
    return error.MalformedBlock;
}

fn copyMatch(output: []u8, written: *usize, offset_value: anytype, length: usize) Error!void {
    const offset: usize = offset_value;
    if (offset == 0 or offset > written.* or length > output.len - written.*) return error.MalformedBlock;
    for (0..length) |_| {
        output[written.*] = output[written.* - offset];
        written.* += 1;
    }
}

test "Snappy block decoder expands literals and overlapping copies" {
    const allocator = std.testing.allocator;
    const literal = [_]u8{ 3, 8, 'a', 'b', 'c' };
    const actual = try decompress(allocator, &literal);
    defer allocator.free(actual);
    try std.testing.expectEqualStrings("abc", actual);

    const repeated = [_]u8{ 5, 0, 'a', 1, 1 };
    const repeated_actual = try decompress(allocator, &repeated);
    defer allocator.free(repeated_actual);
    try std.testing.expectEqualStrings("aaaaa", repeated_actual);
}

test "Snappy block decoder rejects bad offsets and truncated input" {
    try std.testing.expectError(error.MalformedBlock, decompress(std.testing.allocator, &[_]u8{ 2, 1, 1, 0 }));
    try std.testing.expectError(error.MalformedBlock, decompress(std.testing.allocator, &[_]u8{ 3, 8, 'a' }));
    try std.testing.expectError(error.OutputTooLarge, decompress(std.testing.allocator, &[_]u8{ 0x80, 0x80, 0x80, 0x21 }));
}

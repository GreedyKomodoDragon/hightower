// Snappy is the wire compression used by consensus fixture and block data. Its
// length prefix is untrusted, so decompression checks the selected preset's
// byte cap before allocating; malformed blocks never produce partial output.
const std = @import("std");
const preset = @import("consensus_preset").Config;

pub const Error = error{
    MalformedBlock,
    OutputTooLarge,
};

/// Decompresses one Snappy block, rejecting malformed data or preset-oversized output before allocation.
pub fn decompress(allocator: std.mem.Allocator, input: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    return decompressLimited(allocator, input, preset.MAX_SNAPPY_DECOMPRESSED_BLOCK_BYTES);
}

/// Decode a block under a caller-supplied wire size cap.
pub fn decompressLimited(allocator: std.mem.Allocator, input: []const u8, max_output: usize) (Error || std.mem.Allocator.Error)![]u8 {
    var cursor: usize = 0;
    const output_len = try readVarint(input, &cursor);
    if (output_len > max_output) return error.OutputTooLarge;
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

/// Encode a valid Snappy block with greedy four-byte matches; callers enforce
/// encoded peer limits. Matches use two-byte offsets so the encoder stays
/// bounded even for large state snapshots.
pub fn compress(allocator: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var length = input.len;
    while (length >= 128) : (length >>= 7) try output.append(allocator, @as(u8, @truncate(length)) | 0x80);
    try output.append(allocator, @intCast(length));
    if (input.len < 4) {
        try emitLiteral(&output, allocator, input);
        return output.toOwnedSlice(allocator);
    }
    const table = try allocator.alloc(u32, 1 << 15);
    defer allocator.free(table);
    @memset(table, std.math.maxInt(u32));
    var literal_start: usize = 0;
    var i: usize = 0;
    while (i + 4 <= input.len) {
        const slot = matchHash(input[i..][0..4]);
        const candidate = table[slot];
        table[slot] = @intCast(i);
        if (candidate == std.math.maxInt(u32) or i - candidate > std.math.maxInt(u16) or
            !std.mem.eql(u8, input[candidate..][0..4], input[i..][0..4]))
        {
            i += 1;
            continue;
        }
        try emitLiteral(&output, allocator, input[literal_start..i]);
        var match_len: usize = 4;
        while (i + match_len < input.len and input[candidate + match_len] == input[i + match_len]) match_len += 1;
        try emitCopy(&output, allocator, i - candidate, match_len);
        var next = i + 1;
        while (next < i + match_len and next + 4 <= input.len) : (next += 1) {
            table[matchHash(input[next..][0..4])] = @intCast(next);
        }
        i += match_len;
        literal_start = i;
    }
    try emitLiteral(&output, allocator, input[literal_start..]);
    return output.toOwnedSlice(allocator);
}

/// Hash four input bytes into the fixed match table.
fn matchHash(bytes: *const [4]u8) usize {
    const value = std.mem.readInt(u32, bytes, .little);
    return (value *% 2_654_435_761) >> 17;
}

/// Emit literal runs using Snappy's inline or extended length forms.
fn emitLiteral(output: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const chunk_len: usize = @min(bytes.len - offset, 65536);
        const encoded_len = chunk_len - 1;
        if (encoded_len < 60) {
            try output.append(allocator, @intCast(encoded_len << 2));
        } else {
            const extra: usize = if (encoded_len <= 0xff) 1 else 2;
            try output.append(allocator, @intCast((59 + extra) << 2));
            try output.append(allocator, @truncate(encoded_len));
            if (extra == 2) try output.append(allocator, @truncate(encoded_len >> 8));
        }
        try output.appendSlice(allocator, bytes[offset..][0..chunk_len]);
        offset += chunk_len;
    }
}

/// Emit a back-reference split into Snappy's maximum copy length.
fn emitCopy(output: *std.ArrayList(u8), allocator: std.mem.Allocator, offset: usize, length: usize) std.mem.Allocator.Error!void {
    var remaining = length;
    while (remaining > 0) {
        const chunk: usize = @min(remaining, 64);
        if (offset < 2048 and chunk >= 4 and chunk <= 11) {
            try output.append(allocator, @intCast(((chunk - 4) << 2) | ((offset >> 8) << 5) | 1));
            try output.append(allocator, @truncate(offset));
        } else {
            try output.append(allocator, @intCast(((chunk - 1) << 2) | 2));
            try output.append(allocator, @truncate(offset));
            try output.append(allocator, @truncate(offset >> 8));
        }
        remaining -= chunk;
    }
}

/// Reads the Snappy length prefix and advances the cursor, rejecting truncated or overlong values.
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

/// Copies a back-reference into the output, allowing overlap while enforcing prior-output bounds.
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

test "Snappy encoder round trips across the 64 KiB boundary" {
    const allocator = std.testing.allocator;
    const input = try allocator.alloc(u8, 65537);
    defer allocator.free(input);
    @memset(input, 0x42);
    const encoded = try compress(allocator, input);
    defer allocator.free(encoded);
    const decoded = try decompressLimited(allocator, encoded, input.len);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, input, decoded);
    try std.testing.expect(encoded.len < input.len / 2);
    try std.testing.expectError(error.OutputTooLarge, decompressLimited(allocator, encoded, input.len - 1));
}

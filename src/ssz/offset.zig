//! Shared offset-table helpers for variable-size SSZ encoding.
//!
//! Variable-size sequences (Lists, Arrays and Containers with
//! variable fields) address their payloads with little-endian u32
//! offsets measured from the start of the enclosing value.

const std = @import("std");

/// Write one offset slot.
pub fn writeOffset(writer: *std.Io.Writer, offset: usize) !void {
    var offset_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &offset_bytes, @intCast(offset), .little);
    try writer.writeAll(&offset_bytes);
}

/// Read one offset slot.
pub fn readOffset(bytes: []const u8, pos: usize) usize {
    return std.mem.readInt(u32, bytes[pos..][0..4], .little);
}

/// Split a variable-size payload into `count` element ranges using its
/// leading offset table. The table must span exactly `count * 4` bytes,
/// offsets must increase monotonically and stay within bounds.
pub fn splitVariable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    count: usize,
) ![]usize {
    if (count == 0) {
        if (bytes.len != 0) return error.InvalidLength;
        const offsets = try allocator.alloc(usize, 1);
        offsets[0] = 0;
        return offsets;
    }
    if (bytes.len < count * 4) return error.InvalidOffset;

    var sub: std.Io.Reader = .fixed(bytes);
    const offsets = try allocator.alloc(usize, count + 1);
    errdefer allocator.free(offsets);

    for (offsets[0..count]) |*slot| {
        slot.* = try sub.takeInt(u32, std.builtin.Endian.little);
    }
    offsets[count] = bytes.len;

    if (offsets[0] != count * 4) return error.InvalidOffset;
    for (offsets[0..count], offsets[1..]) |start, end| {
        if (end < start or end > bytes.len) return error.InvalidOffset;
    }

    return offsets;
}

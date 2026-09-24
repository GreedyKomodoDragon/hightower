const std = @import("std");

pub fn writeBitListToChunk(
    allocator: std.mem.Allocator,
    value: anytype,
) ![][32]u8 {
    const bit_count = value.data.len;

    // Number of bytes needed to hold the actual data bits.
    const packed_bytes = (bit_count + 7) / 8;

    // Number of 32-byte Merkle chunks needed.
    const chunk_count = (packed_bytes + 31) / 32;

    const result = try allocator.alloc([32]u8, chunk_count);
    errdefer allocator.free(result);

    @memset(result, [_]u8{0} ** 32);

    for (value.data, 0..) |bit, i| {
        if (!bit) continue;

        // Which packed byte contains this bit?
        const byte_index = i / 8;

        // Which bit within that byte?
        const bit_index: u3 = @intCast(i % 8);

        // Which 32-byte Merkle chunk?
        const chunk_index = byte_index / 32;

        // Which byte inside that chunk?
        const byte_offset = byte_index % 32;

        result[chunk_index][byte_offset] |=
            (@as(u8, 1) << bit_index);
    }

    return result;
}

pub fn mixInLength(
    root: [32]u8,
    length: usize,
) ![32]u8 {
    var length_chunk = [_]u8{0} ** 32;

    var length_bytes: [8]u8 = undefined;
    std.mem.writeInt(
        u64,
        &length_bytes,
        @intCast(length),
        .little,
    );

    @memcpy(length_chunk[0..8], &length_bytes);

    var input: [64]u8 = undefined;

    @memcpy(input[0..32], &root);
    @memcpy(input[32..64], &length_chunk);

    var result: [32]u8 = undefined;

    std.crypto.hash.sha2.Sha256.hash(
        &input,
        &result,
        .{},
    );

    return result;
}

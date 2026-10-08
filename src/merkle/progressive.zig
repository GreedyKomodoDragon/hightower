//! Progressive containers and lists (EIP-7495 / EIP-7916).
//! Kept isolated: core SSZ never touches this module, only the
//! `ProgressiveContainer` dispatch arms call in.

const std = @import("std");
const htr_mod = @import("hash_tree_root.zig");
const merkleize_mod = @import("merkleize.zig");

/// Progressive container root: spine over layout positions, then the
/// active-fields word mixed in (EIP-7495).
pub fn progressiveHashTreeRoot(
    allocator: std.mem.Allocator,
    value: anytype,
) ![32]u8 {
    const T = @TypeOf(value);

    const chunks = try progressiveContainerLeaves(allocator, value);
    defer allocator.free(chunks);

    const spine = try merkleizeProgressive(allocator, chunks, 1);

    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &spine);
    @memcpy(input[32..64], &activeFieldsWord(T));

    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &out, .{});

    return out;
}

/// One leaf per layout position of a progressive container (EIP-7495).
/// Active positions hold the field root, gaps hold zero chunks.
/// The n-th field maps to the n-th set bit of `ssz_active_fields`.
pub fn progressiveContainerLeaves(
    allocator: std.mem.Allocator,
    value: anytype,
) ![][32]u8 {
    const T = @TypeOf(value);
    const info = @typeInfo(T).@"struct";
    const active = T.ssz_active_fields;

    if (comptime active.len > 256) {
        @compileError(
            "progressive layout exceeds 256 positions: " ++ @typeName(T),
        );
    }

    comptime var field_count: usize = 0;
    inline for (active) |occupied| {
        if (occupied) field_count += 1;
    }

    if (comptime field_count != info.fields.len) {
        @compileError(
            "progressive layout/field count mismatch: " ++ @typeName(T),
        );
    }

    const result = try allocator.alloc([32]u8, active.len);
    errdefer allocator.free(result);

    comptime var field_index: usize = 0;
    inline for (active, 0..) |occupied, position| {
        if (occupied) {
            result[position] = try htr_mod.HashTreeRoot(
                allocator,
                @field(value, info.fields[field_index].name),
            );
            field_index += 1;
        } else {
            result[position] = [_]u8{0} ** 32;
        }
    }

    return result;
}

/// The layout word a progressive container mixes in: bit i set when
/// position i is occupied, little-endian, one 32-byte word.
fn activeFieldsWord(comptime T: type) [32]u8 {
    const active = T.ssz_active_fields;

    var word = [_]u8{0} ** 32;

    inline for (active, 0..) |occupied, position| {
        if (occupied) {
            word[position / 8] |= @as(u8, 1) << @intCast(position % 8);
        }
    }

    return word;
}

/// Progressive spine root over chunks (EIP-7916): level n holds
/// 4**(n-1) chunks as one binary subtree, closed by a zero node.
fn merkleizeProgressive(
    allocator: std.mem.Allocator,
    chunks: []const [32]u8,
    width: usize,
) ![32]u8 {
    if (chunks.len == 0) {
        return [_]u8{0} ** 32;
    }

    const take = @min(chunks.len, width);
    const left = try merkleize_mod.Merkleize(allocator, chunks[0..take], width);
    const right = try merkleizeProgressive(allocator, chunks[take..], width * 4);

    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);

    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &out, .{});

    return out;
}

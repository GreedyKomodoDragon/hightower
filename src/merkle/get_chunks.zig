//! Chunk extraction: map an SSZ value onto its 32-byte chunks.
//! Thin kind-dispatch; packing rules live in `strategy`, layout
//! positions in `progressive`.

const std = @import("std");
const desc_mod = @import("type_descriptor");
const errors = @import("ssz_errors");

const strategy_mod = @import("strategy.zig");
const progressive_mod = @import("progressive.zig");
const htr_mod = @import("hash_tree_root.zig");

pub const SszError = errors.SszError;

pub fn GetChunks(allocator: std.mem.Allocator, value: anytype) (std.mem.Allocator.Error || SszError)![][32]u8 {
    const T = @TypeOf(value);
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .Bool => {
            return strategy_mod.boolToChunk(allocator, value);
        },
        .Uint8,
        .Uint16,
        .Uint32,
        .Uint64,
        .Uint128,
        .Uint256,
        => {
            if (@typeInfo(T).int.signedness != .unsigned) {
                @compileError("not implemented merkleize signed int type: " ++ @typeName(T));
            }
            return strategy_mod.intToChunk(T, allocator, value);
        },
        .Array => {
            const E = desc.element.?;
            if (comptime strategy_mod.isDensePackable(E)) {
                if (comptime @typeInfo(E) == .array) {
                    return strategy_mod.packFixedArrays(E, allocator, value);
                }
                return strategy_mod.packBasicArray(E, allocator, value);
            }
            const info = @typeInfo(T).array;
            const result = try allocator.alloc([32]u8, info.len);
            errdefer allocator.free(result);

            for (value, 0..) |item, i| {
                result[i] = try htr_mod.HashTreeRoot(
                    allocator,
                    item,
                );
            }

            return result;
        },
        .BitList => {
            return strategy_mod.writeBitListToChunk(
                allocator,
                value,
            );
        },
        .BitVector => {
            return strategy_mod.writeBitVectorToChunk(
                T,
                allocator,
                value,
            );
        },
        .ByteList, .ByteVector => {
            return strategy_mod.writeByteListToChunk(
                allocator,
                value,
            );
        },
        .List => {
            return strategy_mod.writeListToChunks(
                T,
                allocator,
                value.data,
            );
        },
        .ProgressiveContainer => {
            return progressive_mod.progressiveContainerLeaves(
                allocator,
                value,
            );
        },
        .Container => {
            return strategy_mod.containerLeaves(allocator, value);
        },
    }
}

//! SSZ deserialization entry points.
//!
//! `deserialize` handles fixed-size types with no allocation.
//! `deserializeAlloc` handles everything, allocating owned slices
//! for variable-size types (released with `free.freeDecoded`).

const std = @import("std");
const desc_mod = @import("type_descriptor");
const errors = @import("ssz_errors");
const basic_mod = @import("basic.zig");
const byte_vector_mod = @import("bytevector.zig");
const list_mod = @import("list.zig");
const array_mod = @import("array.zig");
const container_mod = @import("container.zig");

pub const SszError = errors.SszError;

pub fn deserialize(
    comptime T: type,
    reader: *std.Io.Reader,
) (std.Io.Reader.Error || SszError)!T {
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .Bool,
        .Uint8,
        .Uint16,
        .Uint32,
        .Uint64,
        .Uint128,
        .Uint256,
        => {
            return basic_mod.deserializeBasic(T, reader);
        },
        .ByteVector => {
            return byte_vector_mod.deserializeByteVector(T, reader);
        },
        // BitVector decode is not implemented yet.
        .BitVector => {
            return error.SszNotImplemented;
        },
        .Array => {
            if (comptime desc.is_variable) {
                return error.NeedsAllocator;
            }
            var result: T = undefined;
            const info = @typeInfo(T).array;
            for (&result) |*item| {
                item.* = try deserialize(info.child, reader);
            }
            return result;
        },
        .Container, .ProgressiveContainer => {
            if (comptime desc.is_variable) {
                return error.NeedsAllocator;
            }
            var result: T = undefined;
            inline for (@typeInfo(T).@"struct".fields) |field| {
                @field(result, field.name) = try deserialize(field.type, reader);
            }
            return result;
        },
        .List => {
            return error.ListNeedsAllocator;
        },
        .BitList, .ByteList => {
            return error.NeedsAllocator;
        },
    }
}

pub fn deserializeAlloc(
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) (std.Io.Reader.Error || std.mem.Allocator.Error || SszError)!T {
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .List => {
            return list_mod.deserializeList(allocator, T, reader);
        },
        .ByteList => {
            return list_mod.deserializeByteList(allocator, T, reader);
        },
        .BitList => {
            return list_mod.deserializeBitList(allocator, T, reader);
        },
        .Array => {
            if (comptime !desc.is_variable) {
                return deserialize(T, reader);
            }
            return array_mod.deserializeArrayVar(allocator, T, reader);
        },
        .Container, .ProgressiveContainer => {
            return container_mod.deserializeContainer(allocator, T, reader);
        },
        else => {
            return deserialize(T, reader);
        },
    }
}

//! SSZ deserialization: single entry point for all types.
//!
//! `deserialize(allocator, T, reader)` decodes any SSZ type.
//! Fixed-size types never touch the allocator; variable-size types
//! return owned slices, released with `free.freeDecoded`.

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
    allocator: std.mem.Allocator,
    comptime T: type,
    reader: *std.Io.Reader,
) (std.Io.Reader.Error || std.mem.Allocator.Error || SszError)!T {
    const desc = comptime desc_mod.SszType(T);

    // Fixed-size values stream straight off the reader and never
    // touch the allocator (proven by test: failing_allocator).
    if (comptime !desc.is_variable) {
        const result = try deserializeFixed(T, reader);
        // Exact for fixed-buffer readers; best-effort for live
        // streams (only already-buffered bytes are visible).
        if (reader.bufferedLen() != 0) return error.TrailingBytes;
        return result;
    }

    switch (desc.kind) {
        .Array => {
            return array_mod.deserializeArrayVar(allocator, T, reader);
        },
        .Container, .ProgressiveContainer => {
            return container_mod.deserializeContainer(allocator, T, reader);
        },
        .List => {
            return list_mod.deserializeList(allocator, T, reader);
        },
        .ByteList => {
            return list_mod.deserializeByteList(allocator, T, reader);
        },
        .BitList => {
            return list_mod.deserializeBitList(allocator, T, reader);
        },
        else => unreachable,
    }
}

/// Streaming decode for fixed-size types. Reads sequentially, allocates
/// nothing: safe to call with a failing allocator.
fn deserializeFixed(
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
        .Array => {
            var result: T = undefined;
            const info = @typeInfo(T).array;
            for (&result) |*item| {
                item.* = try deserializeFixed(info.child, reader);
            }
            return result;
        },
        .Container, .ProgressiveContainer => {
            var result: T = undefined;
            inline for (@typeInfo(T).@"struct".fields) |field| {
                @field(result, field.name) = try deserializeFixed(field.type, reader);
            }
            return result;
        },
        // BitVector decode is not implemented yet.
        else => {
            return error.SszNotImplemented;
        },
    }
}

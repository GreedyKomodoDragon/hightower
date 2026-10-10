//! Zero-copy views: validate input bytes and borrow them, no
//! allocation. This file takes no allocator by construction.
//!
//! Supported today: ByteList (borrows the slice directly) and List
//! with fixed-size elements (lazy per-element decode). Anything else
//! is a compile-time error — extend `ViewOf` to add more.

const std = @import("std");
const desc_mod = @import("type_descriptor");
const errors = @import("ssz_errors");
const deserialize_mod = @import("deserialize.zig");

pub const SszError = errors.SszError;

/// The borrowed form of `T`: `T` itself for ByteList,
/// `ListView` for Lists.
pub fn ViewOf(comptime T: type) type {
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .ByteList => return T,
        .List => {
            const elem = comptime desc_mod.SszType(desc.element.?);
            if (comptime elem.is_variable) {
                @compileError("views of variable-element Lists are not supported: " ++ @typeName(T));
            }
            return ListView(desc.element.?);
        },
        else => @compileError("views are not supported for: " ++ @typeName(T)),
    }
}

/// Validate `bytes` as `T` and borrow them (no copy, no allocation).
pub fn view(comptime T: type, bytes: []const u8) SszError!ViewOf(T) {
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .ByteList => return viewByteList(T, bytes),
        .List => return viewList(T, bytes),
        else => unreachable,
    }
}

/// Borrow `bytes` as a ByteList after limit validation.
/// The returned slice aliases `bytes`: it must outlive the view.
pub fn viewByteList(comptime T: type, bytes: []const u8) SszError!T {
    const desc = comptime desc_mod.SszType(T);

    if (bytes.len > desc.max_bytes.?) return error.ByteListTooLong;

    return T{ .data = bytes };
}

/// Lazy borrowed List: validates layout once, decodes elements on
/// demand. Backing bytes must outlive the view.
pub fn ListView(comptime E: type) type {
    return struct {
        const Self = @This();

        bytes: []const u8,
        count: usize,

        pub fn len(self: Self) usize {
            return self.count;
        }

        pub fn get(self: Self, index: usize) SszError!E {
            if (index >= self.count) return error.IndexOutOfBounds;

            // Lengths were validated at construction, so I/O errors
            // are impossible; map them to keep the set I/O-free.
            const elem_size = comptime desc_mod.SszType(E).fixed_size.?;
            var sub: std.Io.Reader = .fixed(self.bytes[index * elem_size ..][0..elem_size]);
            const value = deserialize_mod.deserializeFixed(E, &sub) catch |err| return switch (err) {
                error.ReadFailed, error.EndOfStream => error.InvalidLength,
                else => |e| e,
            };
            if (sub.bufferedLen() != 0) return error.TrailingBytes;
            return value;
        }
    };
}

/// Validate `bytes` as `T` and borrow them as a `ListView`.
/// The bytes must outlive the view.
pub fn viewList(comptime T: type, bytes: []const u8) SszError!ListView(desc_mod.SszType(T).element.?) {
    const desc = comptime desc_mod.SszType(T);
    const E = desc.element.?;

    const elem = comptime desc_mod.SszType(E);
    if (comptime elem.is_variable) return error.SszNotImplemented;

    const elem_size = elem.fixed_size.?;
    if (elem_size == 0) {
        if (bytes.len != 0) return error.InvalidLength;
        return .{ .bytes = bytes, .count = 0 };
    }

    if (bytes.len % elem_size != 0) return error.InvalidLength;

    const count = bytes.len / elem_size;
    if (count > desc.max_length.?) return error.ListTooLong;

    return .{ .bytes = bytes, .count = count };
}

//! Release memory owned by a value produced with `deserializeAlloc`.
//! Safe to call on any value; fixed-size types compile to a no-op.

const std = @import("std");
const desc_mod = @import("type_descriptor");

pub fn freeDecoded(
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) void {
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .List => {
            if (comptime needsFree(desc.element.?)) {
                for (value.data) |item| {
                    freeDecoded(allocator, desc.element.?, item);
                }
            }
            allocator.free(value.data);
        },
        .BitList, .ByteList => {
            allocator.free(value.data);
        },
        .Container, .ProgressiveContainer => {
            inline for (@typeInfo(T).@"struct".fields) |field| {
                freeDecoded(allocator, field.type, @field(value, field.name));
            }
        },
        .Array => {
            if (comptime needsFree(desc.element.?)) {
                for (value) |item| {
                    freeDecoded(allocator, desc.element.?, item);
                }
            }
        },
        else => {},
    }
}

fn needsFree(comptime T: type) bool {
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .List, .BitList, .ByteList => return true,
        .Container, .ProgressiveContainer => {
            inline for (@typeInfo(T).@"struct".fields) |field| {
                if (comptime needsFree(field.type)) return true;
            }
            return false;
        },
        .Array => return needsFree(desc.element.?),
        else => return false,
    }
}

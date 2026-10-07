//! SSZ serialization entry point. Thin kind-dispatch over the
//! per-type codecs; all layout logic lives in those modules.

const std = @import("std");
const desc_mod = @import("type_descriptor");
const errors = @import("ssz_errors");
const basic_mod = @import("basic.zig");
const bit_list_mod = @import("bitlist.zig");
const bit_vector_mod = @import("bitvector.zig");
const byte_list_mod = @import("bytelist.zig");
const byte_vector_mod = @import("bytevector.zig");
const list_mod = @import("list.zig");
const array_mod = @import("array.zig");
const container_mod = @import("container.zig");

pub const SszError = errors.SszError;

pub fn serialize(writer: *std.Io.Writer, value: anytype) (std.Io.Writer.Error || SszError)!void {
    const T = @TypeOf(value);
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
            return basic_mod.serializeBasic(writer, value);
        },
        .BitList => {
            return bit_list_mod.serializeBitList(T, writer, value);
        },
        .BitVector => {
            return bit_vector_mod.serializeBitVector(T, writer, value);
        },
        .ByteList => {
            return byte_list_mod.serializeByteList(T, writer, value);
        },
        .ByteVector => {
            return byte_vector_mod.serializeByteVector(T, writer, value);
        },
        .List => {
            return list_mod.serializeList(T, writer, value);
        },
        .Array => {
            return array_mod.serializeArray(T, writer, value);
        },
        .Container, .ProgressiveContainer => {
            return container_mod.serializeContainer(writer, value);
        },
    }
}

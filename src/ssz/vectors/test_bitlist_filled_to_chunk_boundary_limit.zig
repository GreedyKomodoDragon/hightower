// tests/fillers/ssz/test_merkleization_boundaries.py::test_bitlist_filled_to_chunk_boundary_limit[ssz_test]
// typeName: BoundaryBitList256
// value: {"data": [true × 256]}
// serialized: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01
// root: 0xbc16fae79b58a2e3dac0429d25b79cada399106276e08c5d3cfc3726db02b8ba

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitlist_filled_to_chunk_boundary_limit" {
    const allocator = testing.allocator;

    const BoundaryBitList256 = types.BitList(256);

    const bits = [_]bool{true} ** 256;

    const value = BoundaryBitList256{
        .data = &bits,
    };

    // ----------------------------
    // serialization
    // ----------------------------

    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(
        &writer,
        value,
    );

    const expected_serialized = [_]u8{0xff} ** 32 ++ [_]u8{0x01};

    try testing.expectEqualSlices(
        u8,
        &expected_serialized,
        writer.buffered(),
    );

    // ----------------------------
    // hash_tree_root
    // ----------------------------

    const root = try merkle.HashTreeRoot(
        allocator,
        value,
    );

    const expected_root = [_]u8{
        0xbc, 0x16, 0xfa, 0xe7,
        0x9b, 0x58, 0xa2, 0xe3,
        0xda, 0xc0, 0x42, 0x9d,
        0x25, 0xb7, 0x9c, 0xad,
        0xa3, 0x99, 0x10, 0x62,
        0x76, 0xe0, 0x8c, 0x5d,
        0x3c, 0xfc, 0x37, 0x26,
        0xdb, 0x02, 0xb8, 0xba,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

// tests/fillers/ssz/test_merkleization_boundaries.py::test_bitvector_length_one_all_set[ssz_test]
// typeName: BoundaryBitVector1
// value: {"data": [true]}
// serialized: 0x01
// root: 0x0100000000000000000000000000000000000000000000000000000000000000

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitvector_length_one_all_set" {
    const allocator = testing.allocator;

    const T = types.BitVector(1);

    const bits = [_]bool{true};

    const value = T{
        .data = bits,
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

    try testing.expectEqualSlices(
        u8,
        &.{0x01},
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
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

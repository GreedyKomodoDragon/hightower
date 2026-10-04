// tests/fillers/ssz/test_merkleization_boundaries.py::test_bitvector_length_255_all_set[ssz_test]
// typeName: BoundaryBitVector255
// value: {"data": [true x 255]}
// serialized: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
// root: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitvector_length_255_all_set" {
    const allocator = testing.allocator;

    const T = types.BitVector(255);

    const bits = [_]bool{true} ** 255;

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
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
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
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x7f,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

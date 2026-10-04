// tests/fillers/ssz/test_merkleization_boundaries.py::test_bitvector_length_256_all_set[ssz_test]
// typeName: BoundaryBitVector256
// value: {"data": [true x 256]}
// serialized: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
// root: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitvector_length_256_all_set" {
    const allocator = testing.allocator;

    const T = types.BitVector(256);

    const bits = [_]bool{true} ** 256;

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
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
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
        0xff, 0xff, 0xff, 0xff,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

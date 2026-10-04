// tests/fillers/ssz/test_merkleization_boundaries.py::test_bitvector_length_seven_all_set[ssz_test]
// typeName: BoundaryBitVector7
// value: {"data": [true, true, true, true, true, true, true]}
// serialized: 0x7f
// root: 0x7f00000000000000000000000000000000000000000000000000000000000000

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitvector_length_seven_all_set" {
    const allocator = testing.allocator;

    const T = types.BitVector(7);

    const bits = [_]bool{ true, true, true, true, true, true, true };

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
        &.{0x7f},
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
        0x7f, 0x00, 0x00, 0x00,
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

// tests/fillers/ssz/test_merkleization_boundaries.py::test_bitvector_length_257_all_set[ssz_test]
// typeName: BoundaryBitVector257
// value: {"data": [true x 257]}
// serialized: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01
// root: 0xe9bada28b960beb323e7992400b45875830bfce5a64f230c696cdddfafa551b8

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitvector_length_257_all_set" {
    const allocator = testing.allocator;

    const T = types.BitVector(257);

    const bits = [_]bool{true} ** 257;

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
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 },
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
        0xe9, 0xba, 0xda, 0x28,
        0xb9, 0x60, 0xbe, 0xb3,
        0x23, 0xe7, 0x99, 0x24,
        0x00, 0xb4, 0x58, 0x75,
        0x83, 0x0b, 0xfc, 0xe5,
        0xa6, 0x4f, 0x23, 0x0c,
        0x69, 0x6c, 0xdd, 0xdf,
        0xaf, 0xa5, 0x51, 0xb8,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

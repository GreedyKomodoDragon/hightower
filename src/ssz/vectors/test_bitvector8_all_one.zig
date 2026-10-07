// tests/fillers/ssz/test_basic_types.py::test_bitvector8_all_one[ssz_test]
// typeName: SampleBitVector8
// value: {"data": [true, true, true, true, true, true, true, true]}
// serialized: 0xff
// root: 0xff00000000000000000000000000000000000000000000000000000000000000

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitvector8_all_one" {
    const allocator = testing.allocator;

    const T = types.BitVector(8);

    const bits = [_]bool{ true, true, true, true, true, true, true, true };

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
        &.{0xff},
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
        0xff, 0x00, 0x00, 0x00,
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

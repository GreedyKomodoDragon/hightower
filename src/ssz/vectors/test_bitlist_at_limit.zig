// tests/fillers/ssz/test_basic_types.py::test_bitlist_at_limit[ssz_test]
// typeName: SampleBitList16
// value: {"data": [true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true]}
// serialized: 0xffff01
// root: 0xdc8212e2404720c98554dfddc81733f88cbbe307a1d4ca5eae4b88e55e382392

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitlist_at_limit" {
    const allocator = testing.allocator;

    const SampleBitList16 = types.BitList(16);

    const bits = [_]bool{true} ** 16;

    const value = SampleBitList16{
        .data = &bits,
    };

    // ----------------------------
    // serialization
    // ----------------------------

    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(
        &writer,
        value,
    );

    try testing.expectEqualSlices(
        u8,
        &.{
            0xff,
            0xff,
            0x01,
        },
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
        0xdc, 0x82, 0x12, 0xe2,
        0x40, 0x47, 0x20, 0xc9,
        0x85, 0x54, 0xdf, 0xdd,
        0xc8, 0x17, 0x33, 0xf8,
        0x8c, 0xbb, 0xe3, 0x07,
        0xa1, 0xd4, 0xca, 0x5e,
        0xae, 0x4b, 0x88, 0xe5,
        0x5e, 0x38, 0x23, 0x92,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

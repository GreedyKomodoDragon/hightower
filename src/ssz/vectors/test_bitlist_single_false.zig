// tests/fillers/ssz/test_basic_types.py::test_bitlist_single_false[ssz_test]
// typeName: SampleBitList16
// value: {"data": [false]}
// serialized: 0x02
// root: 0xcb592844121d926f1ca3ad4e1d6fb9d8e260ed6e3216361f7732e975a0e8bbf6

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitlist_single_false" {
    const allocator = testing.allocator;

    const SampleBitList16 = types.BitList(16);

    const bits = [_]bool{false};

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
        &.{0x02},
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
        0xcb, 0x59, 0x28, 0x44,
        0x12, 0x1d, 0x92, 0x6f,
        0x1c, 0xa3, 0xad, 0x4e,
        0x1d, 0x6f, 0xb9, 0xd8,
        0xe2, 0x60, 0xed, 0x6e,
        0x32, 0x16, 0x36, 0x1f,
        0x77, 0x32, 0xe9, 0x75,
        0xa0, 0xe8, 0xbb, 0xf6,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

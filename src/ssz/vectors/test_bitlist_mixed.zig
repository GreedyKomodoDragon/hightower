// tests/fillers/ssz/test_basic_types.py::test_bitlist_mixed[ssz_test]
// typeName: SampleBitList16
// value: {"data": [true, false, true, true, false]}
// serialized: 0x2d
// root: 0x88f1b289bdd0b2c8cc9ee45ebb26d1330024a595ead0a755eaf8cd164d90ab81

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitlist_mixed" {
    const allocator = testing.allocator;

    const SampleBitList16 = types.BitList(16);

    const bits = [_]bool{ true, false, true, true, false };

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
        &.{0x2d},
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
        0x88, 0xf1, 0xb2, 0x89,
        0xbd, 0xd0, 0xb2, 0xc8,
        0xcc, 0x9e, 0xe4, 0x5e,
        0xbb, 0x26, 0xd1, 0x33,
        0x00, 0x24, 0xa5, 0x95,
        0xea, 0xd0, 0xa7, 0x55,
        0xea, 0xf8, 0xcd, 0x16,
        0x4d, 0x90, 0xab, 0x81,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

// tests/fillers/ssz/test_basic_types.py::test_bitlist_empty[ssz_test]
// typeName: SampleBitList16
// value: {"data": []}
// serialized: 0x01
// root: 0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitlist_empty" {
    const allocator = testing.allocator;

    const SampleBitList16 = types.BitList(16);

    const bits = [_]bool{};

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
        0xf5, 0xa5, 0xfd, 0x42,
        0xd1, 0x6a, 0x20, 0x30,
        0x27, 0x98, 0xef, 0x6e,
        0xd3, 0x09, 0x97, 0x9b,
        0x43, 0x00, 0x3d, 0x23,
        0x20, 0xd9, 0xf0, 0xe8,
        0xea, 0x98, 0x31, 0xa9,
        0x27, 0x59, 0xfb, 0x4b,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

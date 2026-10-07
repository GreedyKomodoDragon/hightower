// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_square[ssz_test]
// typeName: SampleSquare
// value: {"side": 4660, "color": 86}
// serialized: 0x341256
// root: 0x5ebd038215d6c6868befbe172ffb9442b2f5ade276bd96eb304c1da38deff823

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_progressive_container_square" {
    const allocator = testing.allocator;

    const SampleSquare = struct {
        pub const ssz_active_fields = [_]bool{ true, false, true };

        side: u16,
        color: u8,
    };

    const value = SampleSquare{
        .side = 4660,
        .color = 86,
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
        &.{ 0x34, 0x12, 0x56 },
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
        0x5e, 0xbd, 0x03, 0x82,
        0x15, 0xd6, 0xc6, 0x86,
        0x8b, 0xef, 0xbe, 0x17,
        0x2f, 0xfb, 0x94, 0x42,
        0xb2, 0xf5, 0xad, 0xe2,
        0x76, 0xbd, 0x96, 0xeb,
        0x30, 0x4c, 0x1d, 0xa3,
        0x8d, 0xef, 0xf8, 0x23,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

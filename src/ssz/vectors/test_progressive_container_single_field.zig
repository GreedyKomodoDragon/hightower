// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_single_field[ssz_test]
// typeName: SampleOneField
// value: {"a": 48879}
// serialized: 0xefbe
// root: 0xa88f083e786a9c55bf466e4954c4e25b3112cad5a5a2f85248d3a88d42b9fc58

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_progressive_container_single_field" {
    const allocator = testing.allocator;

    const SampleOneField = struct {
        pub const ssz_active_fields = [_]bool{true};

        a: u16,
    };

    const value = SampleOneField{
        .a = 48879,
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
        &.{ 0xef, 0xbe },
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
        0xa8, 0x8f, 0x08, 0x3e,
        0x78, 0x6a, 0x9c, 0x55,
        0xbf, 0x46, 0x6e, 0x49,
        0x54, 0xc4, 0xe2, 0x5b,
        0x31, 0x12, 0xca, 0xd5,
        0xa5, 0xa2, 0xf8, 0x52,
        0x48, 0xd3, 0xa8, 0x8d,
        0x42, 0xb9, 0xfc, 0x58,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

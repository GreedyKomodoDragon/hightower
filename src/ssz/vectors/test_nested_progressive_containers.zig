// tests/fillers/ssz/test_progressive_containers.py::test_nested_progressive_containers[ssz_test]
// typeName: SampleOuterShape
// value: {"head": 1, "inner": {"x": 515, "y": 4}}
// serialized: 0x01030204
// root: 0xccf454ac88b0e70221c4458d2df7f53ff547eacfd8d15b00a3077bd611b7f6a1

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_nested_progressive_containers" {
    const allocator = testing.allocator;

    const SampleInnerShape = struct {
        pub const ssz_active_fields = [_]bool{ true, false, true };

        x: u16,
        y: u8,
    };

    const SampleOuterShape = struct {
        pub const ssz_active_fields = [_]bool{ true, false, true };

        head: u8,
        inner: SampleInnerShape,
    };

    const value = SampleOuterShape{
        .head = 1,
        .inner = .{
            .x = 515,
            .y = 4,
        },
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
        &.{ 0x01, 0x03, 0x02, 0x04 },
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
        0xcc, 0xf4, 0x54, 0xac,
        0x88, 0xb0, 0xe7, 0x02,
        0x21, 0xc4, 0x45, 0x8d,
        0x2d, 0xf7, 0xf5, 0x3f,
        0xf5, 0x47, 0xea, 0xcf,
        0xd8, 0xd1, 0x5b, 0x00,
        0xa3, 0x07, 0x7b, 0xd6,
        0x11, 0xb7, 0xf6, 0xa1,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

// tests/fillers/ssz/test_progressive_containers.py::test_container_holding_a_progressive_container[ssz_test]
// typeName: SampleShapeContainer
// value: {"tag": 255, "shape": {"side": 4660, "color": 86}}
// serialized: 0xff341256
// root: 0x82a3af75922fff248c6e24745fc37f8946ce3e5af7b8bf4778f297ec48ea533c

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_container_holding_a_progressive_container" {
    const allocator = testing.allocator;

    const SampleShape = struct {
        pub const ssz_active_fields = [_]bool{ true, false, true };

        side: u16,
        color: u8,
    };

    const SampleShapeContainer = struct {
        tag: u8,
        shape: SampleShape,
    };

    const value = SampleShapeContainer{
        .tag = 255,
        .shape = .{
            .side = 4660,
            .color = 86,
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
        &.{ 0xff, 0x34, 0x12, 0x56 },
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
        0x82, 0xa3, 0xaf, 0x75,
        0x92, 0x2f, 0xff, 0x24,
        0x8c, 0x6e, 0x24, 0x74,
        0x5f, 0xc3, 0x7f, 0x89,
        0x46, 0xce, 0x3e, 0x5a,
        0xf7, 0xb8, 0xbf, 0x47,
        0x78, 0xf2, 0x97, 0xec,
        0x48, 0xea, 0x53, 0x3c,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_circle[ssz_test]
// typeName: SampleCircle
// value: {"radius": 4660, "color": 86}
// serialized: 0x341256
// root: 0x44dd01593fff4f0bea317b62a9e70d20f063e7413f331598d681d9e645fa8eae

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_progressive_container_circle" {
    const allocator = testing.allocator;

    const SampleCircle = struct {
        pub const ssz_active_fields = [_]bool{ false, true, true };

        radius: u16,
        color: u8,
    };

    const value = SampleCircle{
        .radius = 4660,
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
        0x44, 0xdd, 0x01, 0x59,
        0x3f, 0xff, 0x4f, 0x0b,
        0xea, 0x31, 0x7b, 0x62,
        0xa9, 0xe7, 0x0d, 0x20,
        0xf0, 0x63, 0xe7, 0x41,
        0x3f, 0x33, 0x15, 0x98,
        0xd6, 0x81, 0xd9, 0xe6,
        0x45, 0xfa, 0x8e, 0xae,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_widest_layout[ssz_test]
// typeName: SampleWidestLayout
// value: {"tail": 171}
// serialized: 0xab
// root: 0x1bf935e375b4ebf1516fe0dae3e6d959168fd74f470b694b064e2d504491fba0

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_progressive_container_widest_layout" {
    const allocator = testing.allocator;

    const SampleWidestLayout = struct {
        pub const ssz_active_fields = [_]bool{false} ** 255 ++ [_]bool{true};

        tail: u8,
    };

    const value = SampleWidestLayout{
        .tail = 171,
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
        &.{0xab},
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
        0x1b, 0xf9, 0x35, 0xe3,
        0x75, 0xb4, 0xeb, 0xf1,
        0x51, 0x6f, 0xe0, 0xda,
        0xe3, 0xe6, 0xd9, 0x59,
        0x16, 0x8f, 0xd7, 0x4f,
        0x47, 0x0b, 0x69, 0x4b,
        0x06, 0x4e, 0x2d, 0x50,
        0x44, 0x91, 0xfb, 0xa0,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

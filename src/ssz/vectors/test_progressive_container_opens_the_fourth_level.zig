// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_opens_the_fourth_level[ssz_test]
// typeName: SampleLevelBoundary
// value: {"first": 4660, "last": 86}
// serialized: 0x341256
// root: 0x4ced50eb70f7547000227b026e875c87dfe4d4daa3be3f308f570268c5a55dc7

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_progressive_container_opens_the_fourth_level" {
    const allocator = testing.allocator;

    const SampleLevelBoundary = struct {
        pub const ssz_active_fields = [_]bool{true} ++ [_]bool{false} ** 20 ++ [_]bool{true};

        first: u16,
        last: u8,
    };

    const value = SampleLevelBoundary{
        .first = 4660,
        .last = 86,
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
        0x4c, 0xed, 0x50, 0xeb,
        0x70, 0xf7, 0x54, 0x70,
        0x00, 0x22, 0x7b, 0x02,
        0x6e, 0x87, 0x5c, 0x87,
        0xdf, 0xe4, 0xd4, 0xda,
        0xa3, 0xbe, 0x3f, 0x30,
        0x8f, 0x57, 0x02, 0x68,
        0xc5, 0xa5, 0x5d, 0xc7,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

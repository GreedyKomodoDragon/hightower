// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_multiple_gaps[ssz_test]
// typeName: SampleMultipleGaps
// value: {"a": 1, "b": 515, "c": 67438087}
// serialized: 0x01030207060504
// root: 0x4c581934216751d2ec29ea5bbaf238a78ae8c240c594afa8662b449eb51cd455

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_progressive_container_multiple_gaps" {
    const allocator = testing.allocator;

    const SampleMultipleGaps = struct {
        pub const ssz_active_fields = [_]bool{ true, false, false, true, false, true };

        a: u8,
        b: u16,
        c: u32,
    };

    const value = SampleMultipleGaps{
        .a = 1,
        .b = 515,
        .c = 67438087,
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
        &.{ 0x01, 0x03, 0x02, 0x07, 0x06, 0x05, 0x04 },
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
        0x4c, 0x58, 0x19, 0x34,
        0x21, 0x67, 0x51, 0xd2,
        0xec, 0x29, 0xea, 0x5b,
        0xba, 0xf2, 0x38, 0xa7,
        0x8a, 0xe8, 0xc2, 0x40,
        0xc5, 0x94, 0xaf, 0xa8,
        0x66, 0x2b, 0x44, 0x9e,
        0xb5, 0x1c, 0xd4, 0x55,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

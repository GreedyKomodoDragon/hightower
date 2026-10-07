// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_leading_gaps[ssz_test]
// typeName: SampleLeadingGaps
// value: {"c": 287454020}
// serialized: 0x44332211
// root: 0xee417c8b5e7a3051945e454ee09fc3e3b32a26352332a2d669a8912bcf4383d2

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

test "vectors.test_progressive_container_leading_gaps" {
    const allocator = testing.allocator;

    const SampleLeadingGaps = struct {
        pub const ssz_active_fields = [_]bool{ false, false, true };

        c: u32,
    };

    const value = SampleLeadingGaps{
        .c = 287454020,
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
        &.{ 0x44, 0x33, 0x22, 0x11 },
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
        0xee, 0x41, 0x7c, 0x8b,
        0x5e, 0x7a, 0x30, 0x51,
        0x94, 0x5e, 0x45, 0x4e,
        0xe0, 0x9f, 0xc3, 0xe3,
        0xb3, 0x2a, 0x26, 0x35,
        0x23, 0x32, 0xa2, 0xd6,
        0x69, 0xa8, 0x91, 0x2b,
        0xcf, 0x43, 0x83, 0xd2,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

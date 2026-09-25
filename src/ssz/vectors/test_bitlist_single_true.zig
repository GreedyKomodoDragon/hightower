// tests/fillers/ssz/test_basic_types.py::test_bitlist_single_true[ssz_test]
// typeName: SampleBitList16
// value: {"data": [true]}
// serialized: 0x03
// root: 0x56d8a66fbae0300efba7ec2c531973aaae22e7a2ed6ded081b5b32d07a32780a

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitlist_single_true" {
    const allocator = testing.allocator;

    const SampleBitList16 = types.BitList(16);

    const bits = [_]bool{true};

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
        &.{0x03},
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
        0x56, 0xd8, 0xa6, 0x6f,
        0xba, 0xe0, 0x30, 0x0e,
        0xfb, 0xa7, 0xec, 0x2c,
        0x53, 0x19, 0x73, 0xaa,
        0xae, 0x22, 0xe7, 0xa2,
        0xed, 0x6d, 0xed, 0x08,
        0x1b, 0x5b, 0x32, 0xd0,
        0x7a, 0x32, 0x78, 0x0a,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

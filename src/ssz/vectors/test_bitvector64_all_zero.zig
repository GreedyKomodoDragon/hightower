// tests/fillers/ssz/test_basic_types.py::test_bitvector64_all_zero[ssz_test]
// typeName: SampleBitVector64
// value: {"data": [true x 64]}
// serialized: 0x0000000000000000
// root: 0x0000000000000000000000000000000000000000000000000000000000000000

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bitvector64_all_zero" {
    const allocator = testing.allocator;

    const T = types.BitVector(64);

    const bits = [_]bool{ false, false } ** 32;

    const value = T{
        .data = bits,
    };

    // ----------------------------
    // serialization
    // ----------------------------

    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(
        &writer,
        value,
    );

    try testing.expectEqualSlices(
        u8,
        &.{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
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
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

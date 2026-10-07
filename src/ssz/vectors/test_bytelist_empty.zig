// tests/fillers/ssz/test_basic_types.py::test_bytelist_empty[ssz_test]
// typeName: ByteList512KiB
// value: 0x (0 bytes)
// serialized: 0x
// root: 0xe05ac02c0a8f889909fdb5ff44a8267e088b0e7eb6c11bbea096023884da27b8

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bytelist_empty" {
    const allocator = testing.allocator;

    const T = types.ByteList(524288);

    const bytes = [_]u8{};

    const value = T{
        .data = &bytes,
    };

    // ----------------------------
    // serialization
    // ----------------------------

    var buf: [1]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(
        &writer,
        value,
    );

    try testing.expectEqual(
        @as(usize, 0),
        writer.buffered().len,
    );

    // ----------------------------
    // hash_tree_root
    // ----------------------------

    const root = try merkle.HashTreeRoot(
        allocator,
        value,
    );

    const expected_root = [_]u8{
        0xe0, 0x5a, 0xc0, 0x2c,
        0x0a, 0x8f, 0x88, 0x99,
        0x09, 0xfd, 0xb5, 0xff,
        0x44, 0xa8, 0x26, 0x7e,
        0x08, 0x8b, 0x0e, 0x7e,
        0xb6, 0xc1, 0x1b, 0xbe,
        0xa0, 0x96, 0x02, 0x38,
        0x84, 0xda, 0x27, 0xb8,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

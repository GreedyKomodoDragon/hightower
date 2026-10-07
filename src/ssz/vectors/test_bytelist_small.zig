// tests/fillers/ssz/test_basic_types.py::test_bytelist_small[ssz_test]
// typeName: ByteList512KiB
// value: 0x01020304 (4 bytes)
// serialized: 0x01020304
// root: 0x7cb0faeb0401dcff1dba8a3d2e8836af0e41ac22213c9902a52f07b48833c792

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bytelist_small" {
    const allocator = testing.allocator;

    const T = types.ByteList(524288);

    const bytes = [_]u8{
        0x01, 0x02, 0x03, 0x04,
    };

    const value = T{
        .data = &bytes,
    };

    // ----------------------------
    // serialization
    // ----------------------------

    var buf: [4]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(
        &writer,
        value,
    );

    const expected_serialized = [_]u8{
        0x01, 0x02, 0x03, 0x04,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_serialized,
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
        0x7c, 0xb0, 0xfa, 0xeb,
        0x04, 0x01, 0xdc, 0xff,
        0x1d, 0xba, 0x8a, 0x3d,
        0x2e, 0x88, 0x36, 0xaf,
        0x0e, 0x41, 0xac, 0x22,
        0x21, 0x3c, 0x99, 0x02,
        0xa5, 0x2f, 0x07, 0xb4,
        0x88, 0x33, 0xc7, 0x92,
    };

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &root,
    );
}

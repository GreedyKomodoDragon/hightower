const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

// tests/fillers/ssz/test_basic_types.py::test_uint32_mid[ssz_test]
// typeName: Uint32

test "vectors.test_uint32_mid" {
    const allocator = testing.allocator;
    const value: u32 = @as(u32, 2147483648);

    const expected_serialized_hex = "00000080";
    var expected_serialized: [expected_serialized_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);

    const expected_root_hex = "0000008000000000000000000000000000000000000000000000000000000000";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);

    var out: [expected_serialized.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    try ssz.serialize(&writer, value);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(&expected_serialized);
    const decoded = try ssz.deserialize(u32, &reader);
    try testing.expectEqual(value, decoded);
}

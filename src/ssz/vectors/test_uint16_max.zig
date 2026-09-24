const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

// tests/fillers/ssz/test_basic_types.py::test_uint16_max[ssz_test]
// typeName: Uint16

test "vectors.test_uint16_max" {
    const allocator = testing.allocator;
    const value: u16 = @as(u16, 65535);

    const expected_serialized_hex = "ffff";
    var expected_serialized: [expected_serialized_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);

    const expected_root_hex = "ffff000000000000000000000000000000000000000000000000000000000000";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);

    var out: [expected_serialized.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    try ssz.serialize(&writer, value);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(&expected_serialized);
    const decoded = try ssz.deserialize(u16, &reader);
    try testing.expectEqual(value, decoded);
}

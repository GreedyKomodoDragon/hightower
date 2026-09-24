const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

// tests/fillers/ssz/test_basic_types.py::test_bytes32_incremental[ssz_test]
// typeName: Bytes32

test "vectors.test_bytes32_incremental" {
    const allocator = testing.allocator;
    var value: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&value, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const expected_serialized_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    var expected_serialized: [expected_serialized_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);

    const expected_root_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);

    var out: [expected_serialized.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    try ssz.serialize(&writer, value);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(&expected_serialized);
    const decoded = try ssz.deserialize([32]u8, &reader);
    try testing.expectEqual(value, decoded);
}

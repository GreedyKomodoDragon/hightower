const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

// tests/fillers/ssz/test_basic_types.py::test_bytes64_zero[ssz_test]
// typeName: Bytes64

test "vectors.test_bytes64_zero" {
    const allocator = testing.allocator;
    var value: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&value, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    const expected_serialized_hex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    var expected_serialized: [expected_serialized_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);

    const expected_root_hex = "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);

    var out: [expected_serialized.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    try ssz.serialize(&writer, value);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(&expected_serialized);
    const decoded = try ssz.deserialize([64]u8, &reader);
    try testing.expectEqual(value, decoded);
}

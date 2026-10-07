// tests/fillers/ssz/test_basic_types.py::test_bytes32_list_multiple[ssz_test]
// typeName: SampleBytes32List8
// value: {"data": ["0x0101010101010101010101010101010101010101010101010101010101010101", "0x0202020202020202020202020202020202020202020202020202020202020202", "0x0000000000000000000000000000000000000000000000000000000000000000"]}
// serialized: 0x010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000000000000000000000000000000000000000000000000000000
// root: 0x7248549abd0a6b2898dc656f323165dd1fd973bb3234727d384b0575fbeaa517

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bytes32_list_multiple" {
    const allocator = testing.allocator;

    const T = types.List([32]u8, 8);
    const items = [_][32]u8{
        [_]u8{0x01} ** 32,
        [_]u8{0x02} ** 32,
        [_]u8{0x00} ** 32,
    };
    const value = T{ .data = &items };

    var buf: [96]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, value);
    const expected_serialized_hex = "010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000000000000000000000000000000000000000000000000000000";
    var expected_serialized: [96]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    const expected_root_hex = "7248549abd0a6b2898dc656f323165dd1fd973bb3234727d384b0575fbeaa517";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer allocator.free(decoded.data);
    try testing.expectEqualSlices([32]u8, &items, decoded.data);
}

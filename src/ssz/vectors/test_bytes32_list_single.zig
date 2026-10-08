// tests/fillers/ssz/test_basic_types.py::test_bytes32_list_single[ssz_test]
// typeName: SampleBytes32List8
// value: {"data": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}
// serialized: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
// root: 0x23f61250eb803aed609f6b7b760298c3abfc31c6ef3019271b3fdf4fdb59011f

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bytes32_list_single" {
    const allocator = testing.allocator;

    const T = types.List([32]u8, 8);
    const items = [_][32]u8{[_]u8{0xaa} ** 32};
    const value = T{ .data = &items };

    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, value);
    try testing.expectEqualSlices(u8, &items[0], writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    const expected_root_hex = "23f61250eb803aed609f6b7b760298c3abfc31c6ef3019271b3fdf4fdb59011f";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserialize(allocator, T, &reader);
    defer allocator.free(decoded.data);
    try testing.expectEqualSlices([32]u8, &items, decoded.data);
}

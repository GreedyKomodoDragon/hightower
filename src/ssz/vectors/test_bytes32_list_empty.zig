// tests/fillers/ssz/test_basic_types.py::test_bytes32_list_empty[ssz_test]
// typeName: SampleBytes32List8
// value: {"data": []}
// serialized: 0x
// root: 0xe8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_bytes32_list_empty" {
    const allocator = testing.allocator;

    const T = types.List([32]u8, 8);
    const items = [_][32]u8{};
    const value = T{ .data = &items };

    var buf: [1]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, value);
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);

    const root = try merkle.HashTreeRoot(allocator, value);
    const expected_root_hex = "e8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer allocator.free(decoded.data);
    try testing.expectEqual(@as(usize, 0), decoded.data.len);
}

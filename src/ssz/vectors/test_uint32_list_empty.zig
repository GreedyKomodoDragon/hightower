// tests/fillers/ssz/test_basic_types.py::test_uint32_list_empty[ssz_test]
// typeName: SampleUint32List16
// value: {"data": []}
// serialized: 0x
// root: 0x7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_uint32_list_empty" {
    const allocator = testing.allocator;

    const T = types.List(u32, 16);
    const items = [_]u32{};
    const value = T{ .data = &items };

    var buf: [1]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, value);
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);

    const root = try merkle.HashTreeRoot(allocator, value);
    const expected_root_hex = "7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserialize(allocator, T, &reader);
    defer allocator.free(decoded.data);
    try testing.expectEqual(@as(usize, 0), decoded.data.len);
}

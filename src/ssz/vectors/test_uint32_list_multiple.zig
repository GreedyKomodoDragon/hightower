// tests/fillers/ssz/test_basic_types.py::test_uint32_list_multiple[ssz_test]
// typeName: SampleUint32List16
// value: {"data": [0, 100, 4294967295]}
// serialized: 0x0000000064000000ffffffff
// root: 0x417350028526a110c970acdfbdcc7c95a3735964d9c350109a26ff3b24837efb

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_uint32_list_multiple" {
    const allocator = testing.allocator;

    const T = types.List(u32, 16);
    const items = [_]u32{ 0, 100, 4294967295 };
    const value = T{ .data = &items };

    var buf: [12]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, value);
    const expected_serialized_hex = "0000000064000000ffffffff";
    var expected_serialized: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    const expected_root_hex = "417350028526a110c970acdfbdcc7c95a3735964d9c350109a26ff3b24837efb";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserialize(allocator, T, &reader);
    defer allocator.free(decoded.data);
    try testing.expectEqualSlices(u32, &items, decoded.data);
}

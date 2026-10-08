// tests/fillers/ssz/test_merkleization_boundaries.py::test_uint64_list_with_misaligned_chunk_count[ssz_test]
// typeName: BoundaryUint64List32
// value: {"data": [1, 2, 3]}
// serialized: 0x010000000000000002000000000000000300000000000000
// root: 0xeac541ed75add596f34e7d491f512397ad78e73126db30505ac611ea7eeca09c

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_uint64_list_with_misaligned_chunk_count" {
    const allocator = testing.allocator;

    const T = types.List(u64, 32);
    const items = [_]u64{ 1, 2, 3 };
    const value = T{ .data = &items };

    var buf: [24]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, value);
    const expected_serialized_hex = "010000000000000002000000000000000300000000000000";
    var expected_serialized: [24]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    const expected_root_hex = "eac541ed75add596f34e7d491f512397ad78e73126db30505ac611ea7eeca09c";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserialize(allocator, T, &reader);
    defer allocator.free(decoded.data);
    try testing.expectEqualSlices(u64, &items, decoded.data);
}

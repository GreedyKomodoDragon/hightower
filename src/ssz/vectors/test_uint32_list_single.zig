// tests/fillers/ssz/test_basic_types.py::test_uint32_list_single[ssz_test]
// typeName: SampleUint32List16
// value: {"data": [42]}
// serialized: 0x2a000000
// root: 0xce8fe301de280c5a7364836cf298c285ea47eef6ec3b48f22c43fe29bba02ac3

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");
const merkle = @import("merkle");

test "vectors.test_uint32_list_single" {
    const allocator = testing.allocator;

    const T = types.List(u32, 16);
    const items = [_]u32{42};
    const value = T{ .data = &items };

    var buf: [4]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, value);
    try testing.expectEqualSlices(u8, &.{ 0x2a, 0x00, 0x00, 0x00 }, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    const expected_root_hex = "ce8fe301de280c5a7364836cf298c285ea47eef6ec3b48f22c43fe29bba02ac3";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer allocator.free(decoded.data);
    try testing.expectEqualSlices(u32, &items, decoded.data);
}

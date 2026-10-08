// tests/fillers/ssz/test_progressive_containers.py::test_progressive_container_decode_failure_trailing_byte[ssz_test]
// typeName: SampleSquare
// value: {"side": 4660, "color": 86}
// serialized: 0x34125600
// root:
// rejectionReason: SCOPE

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");

test "vectors.test_progressive_container_decode_failure_trailing_byte" {
    const allocator = testing.allocator;

    const SampleSquare = struct {
        side: u16,
        color: u8,
    };

    // The fixture appends a spare 0x00 byte to the valid encoding
    // 0x341256. Strict decoding must reject the trailing byte.
    const input = [_]u8{ 0x34, 0x12, 0x56, 0x00 };

    var reader: std.Io.Reader = .fixed(&input);

    try testing.expectError(
        error.TrailingBytes,
        ssz.deserialize(allocator, SampleSquare, &reader),
    );
}

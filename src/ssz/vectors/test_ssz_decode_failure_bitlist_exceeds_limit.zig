// tests/fillers/ssz/test_decode_failure_smoke.py::test_ssz_decode_failure_bitlist_exceeds_limit[ssz_test]
// typeName: SmokeBitList8
// value: {"data": [false]}
// serialized: 0x0010
// root:

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const types = @import("types");

test "vectors.test_ssz_decode_failure_bitlist_exceeds_limit" {
    const SmokeBitList8 = types.BitList(8);

    // The fixture input decodes to more bits than the limit allows,
    // so deserialization must fail.
    const input = [_]u8{ 0x00, 0x10 };

    var reader: std.Io.Reader = .fixed(&input);

    try testing.expectError(
        error.BitListTooLong,
        ssz.deserialize(SmokeBitList8, &reader),
    );
}

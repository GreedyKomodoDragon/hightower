const std = @import("std");
const testing = std.testing;

const decode = @import("decode.zig");
const encoding = @import("encoding.zig");
const rlp = @import("rlp.zig");

// Canonical vectors from ethereum/tests RLPTests/rlptest.json.
const vectors = [_][]const u8{
    "80", // empty string
    "7f", // single byte below 0x80
    "83646f67", // "dog"
    "c161", // ["a"]
    "c88363617483646f67", // ["cat", "dog"]
    "c0", // empty list
    "820400", // integer 1024
    "c7c0c1c0c3c0c1c0", // [[], [[]], [[], [[]]]]
};

fn encodeValue(writer: *std.Io.Writer, value: decode.Value) !void {
    switch (value) {
        .string => |bytes| try encoding.encodeString(writer, bytes),
        .list => |items| {
            var scratch: [64]u8 = undefined;
            var counter: std.Io.Writer.Discarding = .init(&scratch);
            for (items) |item| try encodeValue(&counter.writer, item);
            try encoding.encodeListHeader(writer, @intCast(counter.fullCount()));
            for (items) |item| try encodeValue(writer, item);
        },
    }
}

test "decoder accepts canonical vectors and re-encodes them" {
    const gpa = testing.allocator;

    for (vectors) |vector| {
        var bytes_buf: [16]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&bytes_buf, vector);

        var value = try decode.decodeAll(gpa, bytes);
        defer value.deinit(gpa);

        var out_buf: [16]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&out_buf);
        try encodeValue(&writer, value);

        try testing.expectEqualSlices(u8, bytes, writer.buffered());
    }
}

test "decoder round-trips encoder output" {
    const gpa = testing.allocator;

    var input_buf: [9000]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&input_buf);

    const big = [_]u8{'q'} ** 5000;
    const list = [_][]const u8{ "cat", &big, "" };
    try rlp.rlp(&writer, list);

    var value = try decode.decodeAll(gpa, writer.buffered());
    defer value.deinit(gpa);

    const items = switch (value) {
        .list => |items| items,
        else => return error.TestUnexpectedResult,
    };

    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expectEqualStrings("cat", items[0].string);
    try testing.expectEqualSlices(u8, &big, items[1].string);
    try testing.expectEqualStrings("", items[2].string);
}

test "decoder round-trips canonical integers" {
    const cases = [_]u64{ 0, 1, 127, 128, 255, 256, 1024, 0x0102030405060708 };

    for (cases) |expected| {
        var buf: [32]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        try rlp.rlp(&writer, expected);

        var reader: std.Io.Reader = .fixed(writer.buffered());
        try testing.expectEqual(expected, try decode.decodeUnsigned(u64, &reader));
    }
}

test "decoder rejects non-canonical lengths" {
    const gpa = testing.allocator;

    const cases = [_][]const u8{
        &.{ 0xb8, 0x01, 0x61 }, // long string form for one byte
        &.{ 0xb9, 0x00, 0x38 }, // string length-of-length leading zero
        &.{ 0xf8, 0x01, 0x61 }, // long list form for one byte
        &.{ 0xf9, 0x00, 0x38 }, // list length-of-length leading zero
    };

    for (cases) |bytes| {
        try testing.expectError(
            error.NonCanonicalLength,
            decode.decodeAll(gpa, bytes),
        );
    }
}

test "decoder rejects non-canonical integers" {
    const cases = [_][]const u8{
        &.{0x00}, // zero must be 0x80
        &.{ 0x81, 0x00 }, // zero with a string prefix
        &.{ 0x82, 0x00, 0x01 }, // leading zero
    };

    for (cases) |bytes| {
        var reader: std.Io.Reader = .fixed(bytes);
        try testing.expectError(
            error.NonCanonicalInteger,
            decode.decodeUnsigned(u16, &reader),
        );
    }
}

test "decoder rejects integers wider than the target" {
    var reader: std.Io.Reader = .fixed(&.{ 0x82, 0x01, 0x00 });
    try testing.expectError(
        error.IntegerOverflow,
        decode.decodeUnsigned(u8, &reader),
    );
}

test "decoder distinguishes truncation from trailing bytes" {
    const gpa = testing.allocator;

    try testing.expectError(
        error.Truncated,
        decode.decodeAll(gpa, &.{ 0x83, 'd', 'o' }),
    );
    try testing.expectError(
        error.Truncated,
        decode.decodeAll(gpa, &.{0xb8}),
    );
    try testing.expectError(
        error.Truncated,
        decode.decodeAll(gpa, &.{ 0xc3, 0x80 }),
    );
    try testing.expectError(
        error.TrailingBytes,
        decode.decodeAll(gpa, &.{ 0x80, 0x00 }),
    );
}

test "decoder rejects nesting beyond the depth limit" {
    const gpa = testing.allocator;

    // Wrap an empty list `max_depth` times so the innermost list is entered at
    // depth `max_depth`. Each wrap prepends a canonical list header.
    var bytes: [256]u8 = undefined;
    bytes[0] = 0xc0;
    var len: usize = 1;

    for (0..decode.max_depth) |_| {
        var header_buf: [16]u8 = undefined;
        var header_writer: std.Io.Writer = .fixed(&header_buf);
        try encoding.encodeListHeader(&header_writer, len);
        const header = header_writer.buffered();

        std.mem.copyBackwards(u8, bytes[header.len .. header.len + len], bytes[0..len]);
        @memcpy(bytes[0..header.len], header);
        len += header.len;
    }

    try testing.expectError(
        error.DepthLimitExceeded,
        decode.decodeAll(gpa, bytes[0..len]),
    );
}

test "decoder streams and skips large string payloads" {
    var input_buf: [6000]u8 = undefined;
    var input_writer: std.Io.Writer = .fixed(&input_buf);

    const big = [_]u8{'s'} ** 5000;
    try rlp.rlp(&input_writer, &big);
    const encoded = input_writer.buffered();

    var reader: std.Io.Reader = .fixed(encoded);
    const header = try decode.readHeader(&reader);
    try testing.expectEqual(@as(usize, 5000), header.payload_len);

    var out_buf: [5000]u8 = undefined;
    var out_writer: std.Io.Writer = .fixed(&out_buf);
    try decode.streamPayload(&reader, &out_writer, header);
    try testing.expectEqualSlices(u8, &big, out_writer.buffered());

    var skip_reader: std.Io.Reader = .fixed(encoded);
    const skip_header = try decode.readHeader(&skip_reader);
    try decode.skipPayload(&skip_reader, skip_header);
    try testing.expectError(error.EndOfStream, skip_reader.peekByte());
}

test "decoder fuzz: canonical inputs round-trip and nothing panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;

    var input_buf: [4096]u8 = undefined;
    const len: usize = smith.value(u12);
    const input = input_buf[0..len];
    smith.bytes(input);

    var value = decode.decodeAll(gpa, input) catch return;
    defer value.deinit(gpa);

    var out_buf: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out_buf);
    try encodeValue(&writer, value);

    try testing.expectEqualSlices(u8, input, writer.buffered());
}

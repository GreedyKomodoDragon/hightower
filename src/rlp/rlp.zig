// Recursive Length Prefix (RLP) serialization is used extensively in Ethereum's execution clients
//
// RLP encoding is defined as follows:
// - For a positive integer, it is converted to the shortest byte array whose big-endian interpretation is the integer,
//   and then encoded as a string according to the rules below.
// - For a single byte whose value is in the [0x00, 0x7f] (decimal [0, 127]) range, that byte is its own RLP encoding.
// - Otherwise, if a string is 0-55 bytes long, the RLP encoding consists of a single byte with value 0x80 (dec. 128)
//   plus the length of the string followed by the string. The range of the first byte is thus [0x80, 0xb7] (dec. [128, 183]).
// - If a string is more than 55 bytes long, the RLP encoding consists of a single byte with value 0xb7 (dec. 183) plus the
//   length in bytes of the length of the string in binary form, followed by the length of the string, followed by the string.
//   For example, a 1024 byte long string would be encoded as \xb9\x04\x00 (dec. 185, 4, 0) followed by the string.
//   Here, 0xb9 (183 + 2 = 185) as the first byte, followed by the 2 bytes 0x0400 (dec. 1024) that denote the length of
//   the actual string. The range of the first byte is thus [0xb8, 0xbf] (dec. [184, 191]).
// - If a string is 2^64 bytes long, or longer, it may not be encoded.
// - If the total payload of a list (i.e., the combined length of all its items being RLP encoded) is 0-55 bytes long, the RLP
//   encoding consists of a single byte with value 0xc0 plus the length of the payload followed by the concatenation of the RLP
//   encodings of the items. The range of the first byte is thus [0xc0, 0xf7] (dec. [192, 247]).
// - If the total payload of a list is more than 55 bytes long, the RLP encoding consists of a single byte with value 0xf7 plus
//   the length in bytes of the length of the payload in binary form, followed by the length of the payload, followed by the
//   concatenation of the RLP encodings of the items. The range of the first byte is thus [0xf8, 0xff] (dec. [248, 255]).

// resources: https://thogiti.github.io/2024/04/30/RLP.html & https://ethereum.org/developers/docs/data-structures-and-encoding/rlp

const std = @import("std");
const encoding = @import("encoding.zig");

pub fn rlp(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);

    // std.debug.print("type={s} value={any}\n", .{
    //     @typeName(@TypeOf(value)),
    //     value,
    // });

    switch (@typeInfo(T)) {
        .int => |info| {
            // TODO: Wire up the bytes encoder

            // if it is unsigned then it is always positive
            if (info.signedness == std.builtin.Signedness.unsigned) {
                // TODO: big-endian is required, not sure if this is
                return std.mem.toBytes(value);
            }

            std.debug.print("integer: {}\n", .{value});
            // encode integer
        },

        .array => |arr| {
            if (arr.child == u8) {
                try encoding.encodeString(writer, value[0..]);
            } else {
                try encodeList(writer, value[0..]);
            }
        },

        .pointer => |ptr| {
            // string check conditions
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    encoding.encodeString(writer, value) catch |err| {
                        std.debug.print("encode failed: {}\n", .{err});
                        return;
                    };
                    return;
                }
            }

            // .one means the pointer points to exactly one value of its child type.
            if (ptr.size == .one) {
                switch (@typeInfo(ptr.child)) {
                    .array => |arr| {
                        if (arr.child == u8) {
                            encoding.encodeString(writer, value) catch |err| {
                                std.debug.print("encode failed: {}\n", .{err});
                                return;
                            };
                            return;
                        }

                        // encode list
                        encodeList(writer, value);

                        @compileError("unsupported RLP type in ptr.size == .one & array");
                    },
                    else => {},
                }
            }
        },

        else => {
            @compileError("unsupported RLP type: " ++ @typeName(T));
        },
    }

    return;
}

pub fn encodeList(writer: *std.Io.Writer, values: anytype) !void {
    var tmp_buf: [4096]u8 = undefined;
    var tmp_writer: std.Io.Writer = .fixed(&tmp_buf);

    for (values) |item| {
        try rlp(&tmp_writer, item);
    }

    const payload = tmp_writer.buffered();
    try encoding.encodeBytes(writer, payload);
}

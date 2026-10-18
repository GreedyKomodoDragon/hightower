// RLP decoding reverses the encoding rules in rlp.zig: a single byte is its
// own string, short strings and lists carry their length in the prefix, and
// long forms carry a big-endian length-of-length. Decoding is defined only for
// canonical encodings, so a long form used for a short payload, a length with a
// leading zero, or a non-minimal integer is rejected rather than normalized.
//
// Items are decoded from a streaming `std.Io.Reader`; list payloads are bounded
// with a limited sub-reader so an item can never read past its own list. This
// keeps memory proportional to the decoded value and lets callers stream or
// discard large string payloads instead of buffering them.

const std = @import("std");

/// Maximum list nesting accepted by the decoder. Ethereum RLP is shallow, and
/// the cap keeps adversarially nested input from exhausting the stack.
pub const max_depth: usize = 64;

pub const Error = error{
    /// Input ended in the middle of an item or list.
    Truncated,
    /// `decodeAll` left unconsumed bytes after the first item.
    TrailingBytes,
    /// A long form was used for a payload of 55 bytes or fewer, or a length
    /// field had a leading zero.
    NonCanonicalLength,
    /// A length field does not fit in `usize`.
    LengthOverflow,
    /// An integer was encoded with a leading zero, including `0x00` for zero.
    NonCanonicalInteger,
    /// An integer does not fit in the requested type.
    IntegerOverflow,
    /// A string-only operation was called on a list.
    ExpectedString,
    /// Nesting exceeded `max_depth`.
    DepthLimitExceeded,
    ReadFailed,
    WriteFailed,
    OutOfMemory,
};

pub const Kind = enum { string, list };

/// The decoded prefix of one item. `payload_len` is the number of payload
/// bytes that follow the prefix. A single-byte string has `header_len == 0`
/// because the byte itself is both prefix and payload.
pub const Header = struct {
    kind: Kind,
    payload_len: usize,
    header_len: usize,
};

/// An owned decoded item. Strings and list storage are allocated with the
/// allocator passed to `decode`; release them with `deinit`.
pub const Value = union(enum) {
    string: []u8,
    list: []Value,

    pub fn deinit(self: *Value, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .string => |bytes| gpa.free(bytes),
            .list => |items| {
                for (items) |*item| item.deinit(gpa);
                gpa.free(items);
            },
        }
    }
};

/// Parse and consume one item prefix, leaving the payload unread.
pub fn readHeader(r: *std.Io.Reader) Error!Header {
    const first = r.peekByte() catch |e| return mapRead(e);

    if (first <= 0x7f) {
        return .{ .kind = .string, .payload_len = 1, .header_len = 0 };
    }

    _ = r.takeByte() catch |e| return mapRead(e);

    if (first <= 0xb7) {
        return .{ .kind = .string, .payload_len = first - 0x80, .header_len = 1 };
    }
    if (first <= 0xbf) {
        const len_len = first - 0xb7;
        const payload_len = try readLength(r, len_len);
        if (payload_len <= 55) return error.NonCanonicalLength;
        return .{ .kind = .string, .payload_len = payload_len, .header_len = 1 + len_len };
    }
    if (first <= 0xf7) {
        return .{ .kind = .list, .payload_len = first - 0xc0, .header_len = 1 };
    }

    const len_len = first - 0xf7;
    const payload_len = try readLength(r, len_len);
    if (payload_len <= 55) return error.NonCanonicalLength;
    return .{ .kind = .list, .payload_len = payload_len, .header_len = 1 + len_len };
}

/// Decode exactly one item into an owned `Value`.
pub fn decode(gpa: std.mem.Allocator, r: *std.Io.Reader) Error!Value {
    return decodeDepth(gpa, r, 0);
}

/// Decode one item and reject any bytes left over.
pub fn decodeAll(gpa: std.mem.Allocator, bytes: []const u8) Error!Value {
    var r: std.Io.Reader = .fixed(bytes);
    var value = try decode(gpa, &r);
    errdefer value.deinit(gpa);

    if (r.peekByte()) |_| {
        return error.TrailingBytes;
    } else |e| switch (e) {
        error.EndOfStream => {},
        error.ReadFailed => return error.ReadFailed,
    }

    return value;
}

/// Decode a canonical RLP unsigned integer into `T`.
pub fn decodeUnsigned(comptime T: type, r: *std.Io.Reader) Error!T {
    const h = try readHeader(r);
    if (h.kind != .string) return error.ExpectedString;
    if (h.payload_len > @sizeOf(T)) return error.IntegerOverflow;

    // Right-align the big-endian payload so `readInt` sees zero padding on the
    // left; this avoids shifting a narrow `T` by a full byte.
    var buf = [_]u8{0} ** @sizeOf(T);
    const payload = buf[@sizeOf(T) - h.payload_len ..];
    r.readSliceAll(payload) catch |e| return mapRead(e);

    if (payload.len == 0) return 0;
    if (payload[0] == 0) return error.NonCanonicalInteger;

    if (payload.len == 1) {
        return std.math.cast(T, payload[0]) orelse error.IntegerOverflow;
    }

    return std.mem.readInt(T, &buf, .big);
}

/// Consume a string payload without allocating or retaining it.
pub fn skipPayload(r: *std.Io.Reader, h: Header) Error!void {
    if (h.kind != .string) return error.ExpectedString;
    r.discardAll(h.payload_len) catch |e| return mapRead(e);
}

/// Stream a string payload to `w` without buffering it in memory.
pub fn streamPayload(r: *std.Io.Reader, w: *std.Io.Writer, h: Header) Error!void {
    if (h.kind != .string) return error.ExpectedString;
    r.streamExact(w, h.payload_len) catch |e| switch (e) {
        error.EndOfStream => return error.Truncated,
        error.ReadFailed => return error.ReadFailed,
        error.WriteFailed => return error.WriteFailed,
    };
}

fn decodeDepth(gpa: std.mem.Allocator, r: *std.Io.Reader, depth: usize) Error!Value {
    const h = try readHeader(r);
    switch (h.kind) {
        .string => {
            const bytes = r.readAlloc(gpa, h.payload_len) catch |e| return mapReadAlloc(e);
            return .{ .string = bytes };
        },
        .list => return decodeList(gpa, r, h.payload_len, depth),
    }
}

fn decodeList(gpa: std.mem.Allocator, r: *std.Io.Reader, payload_len: usize, depth: usize) Error!Value {
    if (depth >= max_depth) return error.DepthLimitExceeded;

    var buffer: [64]u8 = undefined;
    var limited = r.limited(.limited(payload_len), &buffer);

    var items: std.ArrayList(Value) = .empty;
    errdefer {
        for (items.items) |*item| item.deinit(gpa);
        items.deinit(gpa);
    }

    // `Limited.remaining` tracks bytes pulled from the parent, which may run
    // ahead of what the caller consumes because of buffering. Peek instead to
    // detect the true end of the list, then require the whole payload to have
    // been available so a short underlying stream is reported as truncation.
    while (true) {
        _ = limited.interface.peekByte() catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return error.ReadFailed,
        };

        const item = try decodeDepth(gpa, &limited.interface, depth + 1);
        items.append(gpa, item) catch |e| {
            var owned = item;
            owned.deinit(gpa);
            return e;
        };
    }

    if (limited.remaining.nonzero()) return error.Truncated;

    return .{ .list = try items.toOwnedSlice(gpa) };
}

fn readLength(r: *std.Io.Reader, len_len: u8) Error!usize {
    const n: usize = len_len;
    if (n > @sizeOf(usize)) return error.LengthOverflow;

    var buf: [@sizeOf(usize)]u8 = undefined;
    const bytes = buf[0..n];
    r.readSliceAll(bytes) catch |e| return mapRead(e);

    if (bytes[0] == 0) return error.NonCanonicalLength;

    var value: usize = 0;
    for (bytes) |b| value = (value << 8) | b;
    return value;
}

fn mapRead(e: std.Io.Reader.Error) Error {
    return switch (e) {
        error.EndOfStream => error.Truncated,
        error.ReadFailed => error.ReadFailed,
    };
}

fn mapReadAlloc(e: std.Io.Reader.ReadAllocError) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.EndOfStream => error.Truncated,
        error.ReadFailed => error.ReadFailed,
    };
}

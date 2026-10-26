// Engine API peers authenticate every HTTP request with a short-lived HS256
// JWT. The shared 32-byte secret signs the header and issued-at claim; a
// signature check precedes timestamp parsing so forged claims are discarded.
const std = @import("std");

const encoder = std.base64.url_safe_no_pad.Encoder;
const decoder = std.base64.url_safe_no_pad.Decoder;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

/// Creates an Engine API bearer token for the supplied Unix second.
pub fn sign(a: std.mem.Allocator, secret: [32]u8, issued_at: i64) ![]u8 {
    const payload = try std.fmt.allocPrint(a, "{{\"iat\":{d}}}", .{issued_at});
    defer a.free(payload);
    const encoded_payload = try a.alloc(u8, encoder.calcSize(payload.len));
    defer a.free(encoded_payload);
    _ = encoder.encode(encoded_payload, payload);
    const message = try std.fmt.allocPrint(a, "{s}.{s}", .{ header, encoded_payload });
    defer a.free(message);
    var mac: [32]u8 = undefined;
    Hmac.create(&mac, message, &secret);
    var encoded_mac: [43]u8 = undefined;
    _ = encoder.encode(&encoded_mac, &mac);
    return std.fmt.allocPrint(a, "Bearer {s}.{s}", .{ message, encoded_mac });
}

/// Checks a bearer token's format, MAC, algorithm, and 60-second clock window.
pub fn verify(a: std.mem.Allocator, secret: [32]u8, bearer: []const u8, now: i64) !void {
    if (!std.mem.startsWith(u8, bearer, "Bearer ")) return error.Unauthorized;
    const token = bearer[7..];
    const first = std.mem.indexOfScalar(u8, token, '.') orelse return error.Unauthorized;
    const second = std.mem.indexOfScalarPos(u8, token, first + 1, '.') orelse return error.Unauthorized;
    if (!std.mem.eql(u8, token[0..first], header) or token.len - second - 1 != 43) return error.Unauthorized;
    var supplied: [32]u8 = undefined;
    decoder.decode(&supplied, token[second + 1 ..]) catch return error.Unauthorized;
    var expected: [32]u8 = undefined;
    Hmac.create(&expected, token[0..second], &secret);
    if (!std.crypto.timing_safe.eql([32]u8, supplied, expected)) return error.Unauthorized;
    const encoded_claim = token[first + 1 .. second];
    const len = decoder.calcSizeForSlice(encoded_claim) catch return error.Unauthorized;
    if (len > 128) return error.Unauthorized;
    const claim = try a.alloc(u8, len);
    defer a.free(claim);
    decoder.decode(claim, encoded_claim) catch return error.Unauthorized;
    const parsed = std.json.parseFromSlice(std.json.Value, a, claim, .{}) catch return error.Unauthorized;
    defer parsed.deinit();
    if (parsed.value != .object) return error.Unauthorized;
    const iat = parsed.value.object.get("iat") orelse return error.Unauthorized;
    if (iat != .integer or iat.integer < now - 60 or iat.integer > now + 60) return error.Unauthorized;
}

test "JWT rejects tampering and stale timestamps" {
    const a = std.testing.allocator;
    const secret = [_]u8{0x42} ** 32;
    const bearer = try sign(a, secret, 1_000);
    defer a.free(bearer);
    try verify(a, secret, bearer, 1_000);
    try std.testing.expectError(error.Unauthorized, verify(a, secret, bearer, 1_061));
    const altered = try a.dupe(u8, bearer);
    defer a.free(altered);
    altered[altered.len - 1] = if (altered[altered.len - 1] == 'A') 'B' else 'A';
    try std.testing.expectError(error.Unauthorized, verify(a, secret, altered, 1_000));
}

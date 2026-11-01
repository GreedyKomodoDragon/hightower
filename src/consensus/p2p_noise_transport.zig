// Noise XX yields two directional cipher keys after both ENR identities are
// authenticated. Each later TCP record encrypts its two-byte payload length
// and then its payload with consecutive nonces; a bad tag closes the record
// stream before any Yamux bytes reach a consensus handler.
//
//   encrypted length -> bounded plaintext length -> encrypted Yamux frame
// One plaintext record is limited to 16 KiB plus the 12-byte Yamux header.
const std = @import("std");
const xx = @import("p2p_noise_xx.zig");

const Cipher = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const tag_size = Cipher.tag_length;
pub const max_plaintext: usize = 16 * 1024 + 12;
pub const encrypted_length_size: usize = 2 + tag_size;

pub const Transport = struct {
    keys: xx.TransportKeys,
    send_nonce: u64 = 0,
    receive_nonce: u64 = 0,

    /// Use keys only after the peer's Noise XX identity proof has passed.
    pub fn init(keys: xx.TransportKeys) Transport {
        return .{ .keys = keys };
    }

    /// Encrypt one bounded Yamux frame; the caller owns the returned record.
    pub fn encode(self: *Transport, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
        if (plaintext.len > max_plaintext) return error.PayloadTooLarge;
        if (self.send_nonce > std.math.maxInt(u64) - 2) return error.NonceExhausted;
        const result = try allocator.alloc(u8, encrypted_length_size + plaintext.len + tag_size);
        errdefer allocator.free(result);
        var length: [2]u8 = undefined;
        std.mem.writeInt(u16, &length, @intCast(plaintext.len + tag_size), .big);
        Cipher.encrypt(result[0..2], result[2..encrypted_length_size], &length, "", nonce(self.send_nonce), self.keys.send);
        self.send_nonce += 1;
        Cipher.encrypt(result[encrypted_length_size..][0..plaintext.len], result[result.len - tag_size ..][0..tag_size], plaintext, "", nonce(self.send_nonce), self.keys.send);
        self.send_nonce += 1;
        return result;
    }

    /// Authenticate the record length before allocating or reading its body.
    pub fn decodeLength(self: *Transport, encrypted: *const [encrypted_length_size]u8) !usize {
        if (self.receive_nonce == std.math.maxInt(u64)) return error.NonceExhausted;
        var length: [2]u8 = undefined;
        Cipher.decrypt(&length, encrypted[0..2], encrypted[2..].*, "", nonce(self.receive_nonce), self.keys.receive) catch return error.InvalidNoiseRecord;
        self.receive_nonce += 1;
        const size = std.mem.readInt(u16, &length, .big);
        if (size < tag_size or size - tag_size > max_plaintext) return error.PayloadTooLarge;
        return size;
    }

    /// Authenticate exactly the advertised ciphertext bytes and return owned plaintext.
    pub fn decodeBody(self: *Transport, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        if (ciphertext.len < tag_size or ciphertext.len - tag_size > max_plaintext) return error.PayloadTooLarge;
        if (self.receive_nonce == std.math.maxInt(u64)) return error.NonceExhausted;
        const result = try allocator.alloc(u8, ciphertext.len - tag_size);
        errdefer allocator.free(result);
        Cipher.decrypt(result, ciphertext[0..result.len], ciphertext[result.len..][0..tag_size].*, "", nonce(self.receive_nonce), self.keys.receive) catch return error.InvalidNoiseRecord;
        self.receive_nonce += 1;
        return result;
    }
};

/// Place a Noise counter after four zero prefix bytes, in little-endian order.
fn nonce(counter: u64) [Cipher.nonce_length]u8 {
    var result: [Cipher.nonce_length]u8 = .{0} ** Cipher.nonce_length;
    std.mem.writeInt(u64, result[4..12], counter, .little);
    return result;
}

test "Noise transport authenticates bounded records and rejects altered bytes" {
    const allocator = std.testing.allocator;
    const a_keys = xx.TransportKeys{ .send = [_]u8{1} ** 32, .receive = [_]u8{2} ** 32, .handshake_hash = [_]u8{3} ** 32 };
    const b_keys = xx.TransportKeys{ .send = a_keys.receive, .receive = a_keys.send, .handshake_hash = a_keys.handshake_hash };
    var a = Transport.init(a_keys);
    var b = Transport.init(b_keys);
    const encoded = try a.encode(allocator, "yamux frame");
    defer allocator.free(encoded);
    const size = try b.decodeLength(encoded[0..encrypted_length_size]);
    try std.testing.expectEqual(encoded.len - encrypted_length_size, size);
    const decoded = try b.decodeBody(allocator, encoded[encrypted_length_size..]);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("yamux frame", decoded);
    try std.testing.expectError(error.PayloadTooLarge, a.encode(allocator, &([_]u8{0} ** (max_plaintext + 1))));
    var tampered = try allocator.dupe(u8, encoded);
    defer allocator.free(tampered);
    tampered[5] ^= 1;
    var fresh = Transport.init(b_keys);
    try std.testing.expectError(error.InvalidNoiseRecord, fresh.decodeLength(tampered[0..encrypted_length_size]));
}

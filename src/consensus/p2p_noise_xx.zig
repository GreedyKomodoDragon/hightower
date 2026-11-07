// Noise XX authenticates two peers before they exchange consensus streams.
// An ephemeral X25519 exchange encrypts each static key and its libp2p
// identity proof. The proof must match the peer's verified ENR before the
// split transport keys are exposed. Transcript order matters: every public
// key and ciphertext changes the handshake hash used as AEAD associated data.
//
//   initiator e -> responder e, ee, s, es -> initiator s, se
// Handshake frames use two-byte big-endian lengths. Outbound messages fit 256
// bytes without extensions; inbound messages are bounded to 2048 bytes.
const std = @import("std");
const enr = @import("enr.zig");
const identity = @import("p2p_noise_identity.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const X25519 = std.crypto.dh.X25519;
const Cipher = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
const key_size = 32;
const tag_size = Cipher.tag_length;
const nonce_prefix_size = Cipher.nonce_length - @sizeOf(u64);
const frame_prefix_size = 2;
const max_outbound_size = 256;
const max_inbound_size = 2048;

pub const Frame = struct {
    bytes: [max_outbound_size]u8 = .{0} ** max_outbound_size,
    len: usize,

    /// Borrow this complete framed handshake message for one transport write.
    pub fn slice(self: *const Frame) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const TransportKeys = struct {
    send: [key_size]u8,
    receive: [key_size]u8,
    handshake_hash: [key_size]u8,
};

const Symmetric = struct {
    chaining_key: [key_size]u8,
    hash: [key_size]u8,
    key: ?[key_size]u8 = null,
    nonce: u64 = 0,

    /// Start the exact libp2p XX cipher suite with the chosen prologue.
    fn init(prologue: []const u8) Symmetric {
        var initial: [key_size]u8 = .{0} ** key_size;
        @memcpy(initial[0..protocol_name.len], protocol_name);
        var state: Symmetric = .{ .chaining_key = initial, .hash = initial };
        state.mixHash(prologue);
        return state;
    }

    /// Include public keys and ciphertext in the running handshake hash.
    fn mixHash(self: *Symmetric, bytes: []const u8) void {
        var hasher = Sha256.init(.{});
        hasher.update(&self.hash);
        hasher.update(bytes);
        hasher.final(&self.hash);
    }

    /// Derive a new handshake cipher key from one X25519 shared secret.
    fn mixKey(self: *Symmetric, shared: [key_size]u8) void {
        const prk = Hkdf.extract(&self.chaining_key, &shared);
        var output: [2 * key_size]u8 = undefined;
        Hkdf.expand(&output, "", prk);
        self.chaining_key = output[0..key_size].*;
        self.key = output[key_size..].*;
        self.nonce = 0;
    }

    /// Encrypt and hash one handshake field; output includes its AEAD tag.
    fn encrypt(self: *Symmetric, output: []u8, plaintext: []const u8) !usize {
        if (output.len < plaintext.len + @as(usize, if (self.key == null) 0 else tag_size)) return error.MessageTooLarge;
        if (self.key) |key| {
            if (self.nonce == std.math.maxInt(u64)) return error.NonceExhausted;
            const nonce = nonceBytes(self.nonce);
            Cipher.encrypt(output[0..plaintext.len], output[plaintext.len..][0..tag_size], plaintext, &self.hash, nonce, key);
            self.nonce += 1;
            self.mixHash(output[0 .. plaintext.len + tag_size]);
            return plaintext.len + tag_size;
        }
        @memcpy(output[0..plaintext.len], plaintext);
        self.mixHash(plaintext);
        return plaintext.len;
    }

    /// Authenticate and hash ciphertext before exposing its plaintext.
    fn decrypt(self: *Symmetric, output: []u8, ciphertext: []const u8) !usize {
        if (self.key) |key| {
            if (ciphertext.len < tag_size or ciphertext.len - tag_size > output.len) return error.InvalidNoiseMessage;
            if (self.nonce == std.math.maxInt(u64)) return error.NonceExhausted;
            const length = ciphertext.len - tag_size;
            try Cipher.decrypt(output[0..length], ciphertext[0..length], ciphertext[length..][0..tag_size].*, &self.hash, nonceBytes(self.nonce), key);
            self.nonce += 1;
            self.mixHash(ciphertext);
            return length;
        }
        if (ciphertext.len > output.len) return error.InvalidNoiseMessage;
        @memcpy(output[0..ciphertext.len], ciphertext);
        self.mixHash(ciphertext);
        return ciphertext.len;
    }

    /// Split the final chaining key into direction-specific transport keys.
    fn split(self: *const Symmetric, initiator: bool) TransportKeys {
        const prk = Hkdf.extract(&self.chaining_key, "");
        var output: [2 * key_size]u8 = undefined;
        Hkdf.expand(&output, "", prk);
        return .{
            .send = if (initiator) output[0..key_size].* else output[key_size..].*,
            .receive = if (initiator) output[key_size..].* else output[0..key_size].*,
            .handshake_hash = self.hash,
        };
    }
};

pub const Initiator = struct {
    symmetric: Symmetric,
    identity_key: Ecdsa.KeyPair,
    static_key: X25519.KeyPair,
    ephemeral_key: X25519.KeyPair,
    remote: enr.Record,
    remote_ephemeral: [key_size]u8 = .{0} ** key_size,
    phase: enum { first, second, third, complete, failed } = .first,

    /// Borrow a verified remote ENR and fresh, distinct Noise keypairs.
    pub fn init(identity_key: Ecdsa.KeyPair, static_key: X25519.KeyPair, ephemeral_key: X25519.KeyPair, remote: enr.Record) !Initiator {
        if (std.mem.eql(u8, &static_key.public_key, &ephemeral_key.public_key)) return error.ReusedNoiseKey;
        return .{ .symmetric = Symmetric.init(""), .identity_key = identity_key, .static_key = static_key, .ephemeral_key = ephemeral_key, .remote = remote };
    }

    /// Write message 1: the ephemeral public key and empty plaintext payload.
    pub fn writeFirst(self: *Initiator) !Frame {
        if (self.phase != .first) return error.InvalidHandshakeOrder;
        errdefer self.phase = .failed;
        var frame: Frame = .{ .len = frame_prefix_size + key_size };
        @memcpy(frame.bytes[frame_prefix_size..frame.len], &self.ephemeral_key.public_key);
        self.symmetric.mixHash(&self.ephemeral_key.public_key);
        _ = try self.symmetric.encrypt(frame.bytes[frame.len..], "");
        writeLength(&frame);
        self.phase = .second;
        return frame;
    }

    /// Read message 2 and authenticate its decrypted identity against the ENR.
    pub fn readSecond(self: *Initiator, frame: []const u8) !void {
        if (self.phase != .second) return error.InvalidHandshakeOrder;
        errdefer self.phase = .failed;
        const message = try readFrame(frame);
        if (message.len < key_size + key_size + tag_size + tag_size) return error.InvalidNoiseMessage;
        self.remote_ephemeral = message[0..key_size].*;
        self.symmetric.mixHash(&self.remote_ephemeral);
        self.symmetric.mixKey(try X25519.scalarmult(self.ephemeral_key.secret_key, self.remote_ephemeral));
        var remote_static: [key_size]u8 = undefined;
        if (try self.symmetric.decrypt(&remote_static, message[key_size .. key_size + key_size + tag_size]) != key_size) return error.InvalidNoiseMessage;
        self.symmetric.mixKey(try X25519.scalarmult(self.ephemeral_key.secret_key, remote_static));
        var payload: [max_inbound_size]u8 = undefined;
        const length = try self.symmetric.decrypt(&payload, message[key_size + key_size + tag_size ..]);
        try identity.verify(payload[0..length], remote_static, self.remote);
        self.phase = .third;
    }

    /// Write message 3 and expose transport keys only after both proofs pass.
    pub fn writeThird(self: *Initiator) !struct { frame: Frame, keys: TransportKeys } {
        if (self.phase != .third) return error.InvalidHandshakeOrder;
        errdefer self.phase = .failed;
        var frame: Frame = .{ .len = frame_prefix_size };
        frame.len += try self.symmetric.encrypt(frame.bytes[frame.len..], &self.static_key.public_key);
        self.symmetric.mixKey(try X25519.scalarmult(self.static_key.secret_key, self.remote_ephemeral));
        const payload = try identity.encode(self.identity_key, self.static_key.public_key);
        frame.len += try self.symmetric.encrypt(frame.bytes[frame.len..], payload.slice());
        writeLength(&frame);
        self.phase = .complete;
        return .{ .frame = frame, .keys = self.symmetric.split(true) };
    }
};

pub const Responder = struct {
    symmetric: Symmetric,
    identity_key: Ecdsa.KeyPair,
    static_key: X25519.KeyPair,
    ephemeral_key: X25519.KeyPair,
    remote: enr.Record,
    remote_ephemeral: [key_size]u8 = .{0} ** key_size,
    phase: enum { first, second, third, complete, failed } = .first,

    /// Borrow a verified remote ENR and fresh, distinct Noise keypairs.
    pub fn init(identity_key: Ecdsa.KeyPair, static_key: X25519.KeyPair, ephemeral_key: X25519.KeyPair, remote: enr.Record) !Responder {
        if (std.mem.eql(u8, &static_key.public_key, &ephemeral_key.public_key)) return error.ReusedNoiseKey;
        return .{ .symmetric = Symmetric.init(""), .identity_key = identity_key, .static_key = static_key, .ephemeral_key = ephemeral_key, .remote = remote };
    }

    /// Read message 1 before sending any encrypted identity bytes.
    pub fn readFirst(self: *Responder, frame: []const u8) !void {
        if (self.phase != .first) return error.InvalidHandshakeOrder;
        errdefer self.phase = .failed;
        const message = try readFrame(frame);
        if (message.len != key_size) return error.InvalidNoiseMessage;
        self.remote_ephemeral = message[0..key_size].*;
        self.symmetric.mixHash(&self.remote_ephemeral);
        var empty: [0]u8 = .{};
        _ = try self.symmetric.decrypt(&empty, "");
        self.phase = .second;
    }

    /// Write message 2 with the responder's encrypted static key and proof.
    pub fn writeSecond(self: *Responder) !Frame {
        if (self.phase != .second) return error.InvalidHandshakeOrder;
        errdefer self.phase = .failed;
        var frame: Frame = .{ .len = frame_prefix_size + key_size };
        @memcpy(frame.bytes[frame_prefix_size..frame.len], &self.ephemeral_key.public_key);
        self.symmetric.mixHash(&self.ephemeral_key.public_key);
        self.symmetric.mixKey(try X25519.scalarmult(self.ephemeral_key.secret_key, self.remote_ephemeral));
        frame.len += try self.symmetric.encrypt(frame.bytes[frame.len..], &self.static_key.public_key);
        self.symmetric.mixKey(try X25519.scalarmult(self.static_key.secret_key, self.remote_ephemeral));
        const payload = try identity.encode(self.identity_key, self.static_key.public_key);
        frame.len += try self.symmetric.encrypt(frame.bytes[frame.len..], payload.slice());
        writeLength(&frame);
        self.phase = .third;
        return frame;
    }

    /// Read message 3, verify the initiator, and split transport keys.
    pub fn readThird(self: *Responder, frame: []const u8) !TransportKeys {
        if (self.phase != .third) return error.InvalidHandshakeOrder;
        errdefer self.phase = .failed;
        const message = try readFrame(frame);
        if (message.len < key_size + tag_size + tag_size) return error.InvalidNoiseMessage;
        var remote_static: [key_size]u8 = undefined;
        if (try self.symmetric.decrypt(&remote_static, message[0 .. key_size + tag_size]) != key_size) return error.InvalidNoiseMessage;
        self.symmetric.mixKey(try X25519.scalarmult(self.ephemeral_key.secret_key, remote_static));
        var payload: [max_inbound_size]u8 = undefined;
        const length = try self.symmetric.decrypt(&payload, message[key_size + tag_size ..]);
        try identity.verify(payload[0..length], remote_static, self.remote);
        self.phase = .complete;
        return self.symmetric.split(false);
    }
};

/// Form a Noise ChaChaPoly nonce with a zero prefix and little-endian counter.
fn nonceBytes(counter: u64) [Cipher.nonce_length]u8 {
    var result: [Cipher.nonce_length]u8 = .{0} ** Cipher.nonce_length;
    std.mem.writeInt(u64, result[nonce_prefix_size..], counter, .little);
    return result;
}

/// Prefix the message bytes with their two-byte big-endian length.
fn writeLength(frame: *Frame) void {
    std.mem.writeInt(u16, frame.bytes[0..frame_prefix_size], @intCast(frame.len - frame_prefix_size), .big);
}

/// Reject incomplete, trailing, or oversized framed handshake messages.
fn readFrame(frame: []const u8) ![]const u8 {
    if (frame.len < frame_prefix_size or frame.len > frame_prefix_size + max_inbound_size) return error.InvalidNoiseMessage;
    const length = std.mem.readInt(u16, frame[0..frame_prefix_size], .big);
    if (length != frame.len - frame_prefix_size) return error.InvalidNoiseMessage;
    return frame[frame_prefix_size..];
}

/// Produce a signature-verified test ENR for one secp256k1 identity.
fn testRecord(allocator: std.mem.Allocator, key: Ecdsa.KeyPair) !enr.Record {
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 9000, .tcp_port = 9001, .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = @import("data_columns.zig").custody_requirement };
    const encoded = try enr.encode(allocator, key, local);
    defer allocator.free(encoded);
    return enr.decode(allocator, encoded);
}

/// Decode a compile-time hex fixture into its exact byte array.
fn hex(comptime input: []const u8) [input.len / 2]u8 {
    var result: [input.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, input) catch @panic("invalid compile-time Noise vector hex");
    return result;
}

test "Noise XX matches noise-c ChaChaPoly SHA256 handshake vectors" {
    // noise-c tests/vector/cacophony.txt, Noise_XX_25519_ChaChaPoly_SHA256.
    const a_static = try X25519.KeyPair.generateDeterministic(hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
    const a_ephemeral = try X25519.KeyPair.generateDeterministic(hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"));
    const b_static = try X25519.KeyPair.generateDeterministic(hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
    const b_ephemeral = try X25519.KeyPair.generateDeterministic(hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"));
    var state = Symmetric.init("John Galt");
    var message: [256]u8 = undefined;
    @memcpy(message[0..key_size], &a_ephemeral.public_key);
    state.mixHash(&a_ephemeral.public_key);
    var length: usize = key_size;
    length += try state.encrypt(message[length..], &hex("4c756477696720766f6e204d69736573"));
    try std.testing.expectEqualSlices(u8, &hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"), message[0..length]);

    @memcpy(message[0..key_size], &b_ephemeral.public_key);
    state.mixHash(&b_ephemeral.public_key);
    state.mixKey(try X25519.scalarmult(b_ephemeral.secret_key, a_ephemeral.public_key));
    length = key_size;
    length += try state.encrypt(message[length..], &b_static.public_key);
    state.mixKey(try X25519.scalarmult(b_static.secret_key, a_ephemeral.public_key));
    length += try state.encrypt(message[length..], &hex("4d757272617920526f746862617264"));
    try std.testing.expectEqualSlices(u8, &hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad"), message[0..length]);

    length = 0;
    length += try state.encrypt(message[length..], &a_static.public_key);
    state.mixKey(try X25519.scalarmult(a_static.secret_key, b_ephemeral.public_key));
    length += try state.encrypt(message[length..], &hex("462e20412e20486179656b"));
    try std.testing.expectEqualSlices(u8, &hex("c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030"), message[0..length]);
}

test "Noise XX peers authenticate ENRs and derive opposite transport keys" {
    const allocator = std.testing.allocator;
    const a_identity = try Ecdsa.KeyPair.generateDeterministic([_]u8{61} ** 32);
    const b_identity = try Ecdsa.KeyPair.generateDeterministic([_]u8{62} ** 32);
    const a_record = try testRecord(allocator, a_identity);
    const b_record = try testRecord(allocator, b_identity);
    const a_static = try X25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const a_ephemeral = try X25519.KeyPair.generateDeterministic([_]u8{12} ** 32);
    const b_static = try X25519.KeyPair.generateDeterministic([_]u8{21} ** 32);
    const b_ephemeral = try X25519.KeyPair.generateDeterministic([_]u8{22} ** 32);
    try std.testing.expectError(error.ReusedNoiseKey, Initiator.init(a_identity, a_static, a_static, b_record));
    var a = try Initiator.init(a_identity, a_static, a_ephemeral, b_record);
    var b = try Responder.init(b_identity, b_static, b_ephemeral, a_record);
    try std.testing.expectError(error.InvalidHandshakeOrder, a.writeThird());
    const first = try a.writeFirst();
    try std.testing.expectEqual(@as(usize, frame_prefix_size + key_size), first.len);
    try std.testing.expectError(error.InvalidHandshakeOrder, a.writeFirst());
    try b.readFirst(first.slice());
    const second = try b.writeSecond();
    try a.readSecond(second.slice());
    const third = try a.writeThird();
    const b_keys = try b.readThird(third.frame.slice());
    try std.testing.expectEqualSlices(u8, &third.keys.send, &b_keys.receive);
    try std.testing.expectEqualSlices(u8, &third.keys.receive, &b_keys.send);
    try std.testing.expectEqualSlices(u8, &third.keys.handshake_hash, &b_keys.handshake_hash);
    try std.testing.expect(!std.mem.eql(u8, &third.keys.send, &third.keys.receive));
    try std.testing.expectError(error.InvalidHandshakeOrder, b.readThird(third.frame.slice()));
}

test "Noise XX rejects altered ciphertext, wrong ENR, and malformed frames" {
    const allocator = std.testing.allocator;
    const a_identity = try Ecdsa.KeyPair.generateDeterministic([_]u8{63} ** 32);
    const b_identity = try Ecdsa.KeyPair.generateDeterministic([_]u8{64} ** 32);
    const a_record = try testRecord(allocator, a_identity);
    const b_record = try testRecord(allocator, b_identity);
    const a_static = try X25519.KeyPair.generateDeterministic([_]u8{13} ** 32);
    const a_ephemeral = try X25519.KeyPair.generateDeterministic([_]u8{14} ** 32);
    const b_static = try X25519.KeyPair.generateDeterministic([_]u8{23} ** 32);
    const b_ephemeral = try X25519.KeyPair.generateDeterministic([_]u8{24} ** 32);
    var a = try Initiator.init(a_identity, a_static, a_ephemeral, b_record);
    var b = try Responder.init(b_identity, b_static, b_ephemeral, a_record);
    const first = try a.writeFirst();
    var malformed_b = try Responder.init(b_identity, b_static, b_ephemeral, a_record);
    try std.testing.expectError(error.InvalidNoiseMessage, malformed_b.readFirst(first.slice()[0 .. first.len - 1]));
    try std.testing.expectError(error.InvalidHandshakeOrder, malformed_b.readFirst(first.slice()));
    var wrong_length = first;
    wrong_length.bytes[1] += 1;
    var wrong_length_b = try Responder.init(b_identity, b_static, b_ephemeral, a_record);
    try std.testing.expectError(error.InvalidNoiseMessage, wrong_length_b.readFirst(wrong_length.slice()));
    try b.readFirst(first.slice());
    const second = try b.writeSecond();
    var altered_second = second;
    altered_second.bytes[altered_second.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, a.readSecond(altered_second.slice()));
    var wrong_peer = try Initiator.init(a_identity, a_static, a_ephemeral, a_record);
    _ = try wrong_peer.writeFirst();
    try std.testing.expectError(error.InvalidIdentity, wrong_peer.readSecond(second.slice()));
    var fresh_a = try Initiator.init(a_identity, a_static, a_ephemeral, b_record);
    _ = try fresh_a.writeFirst();
    try fresh_a.readSecond(second.slice());
    const third = try fresh_a.writeThird();
    var altered_third = third.frame;
    altered_third.bytes[altered_third.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, b.readThird(altered_third.slice()));
}

// RLPx encrypts each devp2p message with a continuous AES-CTR stream and
// authenticates its header and body with directional Keccak states. The
// handshake fixes both directions' keys; frames must be processed in order.
// A frame carries at most 10 MiB of compressed transaction data here.
//
// handshake secrets -> encrypted header -> encrypted body -> next frame
const std = @import("std");

const Keccak = std.crypto.hash.sha3.Keccak256;
const Aes = std.crypto.core.aes.Aes256;
pub const max_frame_size = 10 * 1024 * 1024;

/// Session keys and initial MAC states derived from an authenticated handshake.
pub const Secrets = struct {
    aes_key: [32]u8,
    mac_key: [32]u8,
    outgoing: Keccak,
    incoming: Keccak,

    /// Derive both directional states from the ephemeral agreement and exact wire handshakes.
    pub fn derive(ephemeral_agreement: [32]u8, initiator_nonce: [32]u8, recipient_nonce: [32]u8, auth: []const u8, ack: []const u8, initiator: bool) Secrets {
        const nonce_digest = digest(&.{ &recipient_nonce, &initiator_nonce });
        const shared = digest(&.{ &ephemeral_agreement, &nonce_digest });
        const aes_key = digest(&.{ &ephemeral_agreement, &shared });
        const mac_key = digest(&.{ &ephemeral_agreement, &aes_key });
        const sent_nonce = if (initiator) recipient_nonce else initiator_nonce;
        const received_nonce = if (initiator) initiator_nonce else recipient_nonce;
        return .{
            .aes_key = aes_key,
            .mac_key = mac_key,
            .outgoing = initialMac(mac_key, sent_nonce, if (initiator) auth else ack),
            .incoming = initialMac(mac_key, received_nonce, if (initiator) ack else auth),
        };
    }
};

/// Stateful frame cipher; one instance belongs to exactly one TCP session.
pub const Framer = struct {
    outgoing_cipher: Ctr,
    incoming_cipher: Ctr,
    mac_key: [32]u8,
    outgoing_mac: Keccak,
    incoming_mac: Keccak,

    /// Initialize continuous frame state after both handshake packets are known.
    pub fn init(secrets: Secrets) Framer {
        return .{
            .outgoing_cipher = Ctr.init(secrets.aes_key),
            .incoming_cipher = Ctr.init(secrets.aes_key),
            .mac_key = secrets.mac_key,
            .outgoing_mac = secrets.outgoing,
            .incoming_mac = secrets.incoming,
        };
    }

    /// Serialize, encrypt, and authenticate one bounded capability frame.
    pub fn encode(self: *Framer, allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
        if (payload.len > max_frame_size) return error.FrameTooLarge;
        const padded = std.mem.alignForward(usize, payload.len, 16);
        const output = try allocator.alloc(u8, 32 + padded + 16);
        errdefer allocator.free(output);
        @memset(output, 0);
        std.mem.writeInt(u24, output[0..3], @intCast(payload.len), .big);
        output[3] = 0xc2;
        output[4] = 0x80;
        output[5] = 0x80;
        self.outgoing_cipher.apply(output[0..16]);
        const header_tag = macStep(&self.outgoing_mac, self.mac_key, output[0..16].*);
        @memcpy(output[16..32], &header_tag);
        @memcpy(output[32 .. 32 + payload.len], payload);
        self.outgoing_cipher.apply(output[32 .. 32 + padded]);
        self.outgoing_mac.update(output[32 .. 32 + padded]);
        const body_tag = macStep(&self.outgoing_mac, self.mac_key, peek(self.outgoing_mac)[0..16].*);
        @memcpy(output[32 + padded ..], &body_tag);
        return output;
    }

    /// Authenticate a 32-byte header before exposing the bounded body length.
    pub fn decodeHeader(self: *Framer, header: [32]u8) !usize {
        const expected = macStep(&self.incoming_mac, self.mac_key, header[0..16].*);
        if (!std.crypto.timing_safe.eql([16]u8, expected, header[16..32].*)) return error.BadHeaderMac;
        var plain = header[0..16].*;
        self.incoming_cipher.apply(&plain);
        const length = std.mem.readInt(u24, plain[0..3], .big);
        if (length > max_frame_size) return error.FrameTooLarge;
        if (!std.mem.eql(u8, plain[3..6], &.{ 0xc2, 0x80, 0x80 })) return error.InvalidHeader;
        return length;
    }

    /// Return the exact body ciphertext and tag length for a validated header.
    pub fn bodySize(length: usize) usize {
        return std.mem.alignForward(usize, length, 16) + 16;
    }

    /// Authenticate and decrypt the body following its header; caller frees the result.
    pub fn decodeBody(self: *Framer, allocator: std.mem.Allocator, length: usize, body: []const u8) ![]u8 {
        if (length > max_frame_size or body.len != bodySize(length)) return error.InvalidFrame;
        const padded = body.len - 16;
        self.incoming_mac.update(body[0..padded]);
        const expected = macStep(&self.incoming_mac, self.mac_key, peek(self.incoming_mac)[0..16].*);
        if (!std.crypto.timing_safe.eql([16]u8, expected, body[padded..][0..16].*)) return error.BadBodyMac;
        const result = try allocator.dupe(u8, body[0..padded]);
        errdefer allocator.free(result);
        self.incoming_cipher.apply(result);
        return allocator.realloc(result, length);
    }
};

/// Compute Keccak over a small ordered set of byte strings.
fn digest(parts: []const []const u8) [32]u8 {
    var state = Keccak.init(.{});
    for (parts) |part| state.update(part);
    var result: [32]u8 = undefined;
    state.final(&result);
    return result;
}

/// Seed one directional MAC with its peer nonce and exact encrypted handshake.
fn initialMac(key: [32]u8, nonce: [32]u8, packet: []const u8) Keccak {
    var mixed: [32]u8 = undefined;
    for (&mixed, key, nonce) |*byte, left, right| byte.* = left ^ right;
    var state = Keccak.init(.{});
    state.update(&mixed);
    state.update(packet);
    return state;
}

/// Read a running Keccak digest without consuming its state.
fn peek(state: Keccak) [32]u8 {
    var copy = state;
    var result: [32]u8 = undefined;
    copy.final(&result);
    return result;
}

/// Advance one RLPx MAC using AES-256 over the current digest.
fn macStep(state: *Keccak, key: [32]u8, seed: [16]u8) [16]u8 {
    const prior = peek(state.*);
    var encrypted: [16]u8 = undefined;
    const aes = Aes.initEnc(key);
    aes.encrypt(&encrypted, prior[0..16]);
    for (&encrypted, seed) |*byte, other| byte.* ^= other;
    state.update(&encrypted);
    return peek(state.*)[0..16].*;
}

/// Continuous AES-256-CTR stream, including bytes across successive frames.
const Ctr = struct {
    aes: std.crypto.core.aes.AesEncryptCtx(Aes),
    counter: [16]u8 = .{0} ** 16,
    block: [16]u8 = .{0} ** 16,
    offset: usize = 16,

    /// Begin the stream at the RLPx all-zero IV.
    fn init(key: [32]u8) Ctr {
        return .{ .aes = Aes.initEnc(key) };
    }

    /// XOR bytes with the stream and retain its position for the next call.
    fn apply(self: *Ctr, bytes: []u8) void {
        for (bytes) |*byte| {
            if (self.offset == 16) {
                self.aes.encrypt(&self.block, &self.counter);
                var index: usize = self.counter.len;
                while (index > 0) {
                    index -= 1;
                    self.counter[index] +%= 1;
                    if (self.counter[index] != 0) break;
                }
                self.offset = 0;
            }
            byte.* ^= self.block[self.offset];
            self.offset += 1;
        }
    }
};

test "RLPx frames round trip in sequence and reject a changed MAC" {
    const a = std.testing.allocator;
    const auth = "auth packet";
    const ack = "ack packet";
    const outbound = Secrets.derive(.{1} ** 32, .{2} ** 32, .{3} ** 32, auth, ack, true);
    const inbound = Secrets.derive(.{1} ** 32, .{2} ** 32, .{3} ** 32, auth, ack, false);
    var sender = Framer.init(outbound);
    var receiver = Framer.init(inbound);
    for ([_][]const u8{ "hello", "transaction" }) |message| {
        const packet = try sender.encode(a, message);
        defer a.free(packet);
        const length = try receiver.decodeHeader(packet[0..32].*);
        const plain = try receiver.decodeBody(a, length, packet[32..]);
        defer a.free(plain);
        try std.testing.expectEqualStrings(message, plain);
    }
    const changed = try sender.encode(a, "bad");
    defer a.free(changed);
    changed[16] ^= 1;
    try std.testing.expectError(error.BadHeaderMac, receiver.decodeHeader(changed[0..32].*));
}

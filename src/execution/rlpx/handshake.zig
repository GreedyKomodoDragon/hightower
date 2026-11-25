// The RLPx auth exchange proves possession of the ENR identity key and agrees
// on ephemeral secp256k1 session material. Auth precedes ack; both exact wire
// packets seed directional frame MACs, so changing either breaks the session.
// The EIP-8 packets stay below 1024 bytes and carry one RLP list each.
//
// static ECDH + signed nonce -> auth -> ack -> encrypted frames
const std = @import("std");
const rlp = @import("rlp");
const ecies = @import("ecies.zig");
const frame = @import("frame.zig");
const crypto = @import("execution").crypto;

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const protocol_version: u8 = 4;

pub const Initiator = struct {
    local: Ecdsa.KeyPair,
    remote: Ecdsa.PublicKey,
    ephemeral: Ecdsa.KeyPair,
    nonce: [32]u8,
    auth: []u8,

    /// Free the outbound auth packet after sending it and processing ack.
    pub fn deinit(self: Initiator, allocator: std.mem.Allocator) void {
        allocator.free(self.auth);
    }

    /// Authenticate ack and derive the initiator's frame state.
    pub fn finish(self: Initiator, allocator: std.mem.Allocator, ack: []const u8) !frame.Secrets {
        const body = try ecies.decrypt(allocator, self.local.secret_key, ack);
        defer allocator.free(body);
        var value = try firstList(allocator, body);
        defer value.deinit(allocator);
        const items = value.list;
        if (items.len < 3) return error.InvalidAck;
        const remote_ephemeral = try publicKey(try bytes(items[0]));
        const remote_nonce = try fixed(32, try bytes(items[1]));
        _ = try version(items[2]);
        const shared = try ecies.agree(self.ephemeral.secret_key, remote_ephemeral);
        return frame.Secrets.derive(shared, self.nonce, remote_nonce, self.auth, ack, true);
    }
};

pub const Responder = struct {
    remote: Ecdsa.PublicKey,
    ack: []u8,
    secrets: frame.Secrets,

    /// Release the outbound ack packet after writing it.
    pub fn deinit(self: Responder, allocator: std.mem.Allocator) void {
        allocator.free(self.ack);
    }
};

/// Sign an auth message to a verified remote identity using fresh caller-owned entropy.
pub fn initiate(allocator: std.mem.Allocator, local: Ecdsa.KeyPair, remote: Ecdsa.PublicKey, ephemeral: Ecdsa.KeyPair, nonce: [32]u8, iv: [16]u8, ecies_ephemeral: Ecdsa.KeyPair) !Initiator {
    const static_shared = try ecies.agree(local.secret_key, remote);
    var challenge: [32]u8 = undefined;
    for (&challenge, static_shared, nonce) |*byte, shared, random| byte.* = shared ^ random;
    const signature = try ephemeral.signPrehashed(challenge, null);
    const signature_bytes = signature.toBytes();
    const ephemeral_public = ephemeral.public_key.toUncompressedSec1();
    var recovery_id: ?u8 = null;
    for (0..4) |candidate| {
        const recovered = crypto.recoverPublicKey(challenge, std.mem.readInt(u256, signature_bytes[0..32], .big), std.mem.readInt(u256, signature_bytes[32..64], .big), @intCast(candidate)) catch continue;
        if (std.mem.eql(u8, &recovered, &ephemeral_public)) {
            recovery_id = @intCast(candidate);
            break;
        }
    }
    var signed: [65]u8 = undefined;
    @memcpy(signed[0..64], &signature_bytes);
    signed[64] = recovery_id orelse return error.UnrecoverableSignature;
    const local_public = local.public_key.toUncompressedSec1();
    const body = try encodeFields(allocator, &.{ &signed, local_public[1..], &nonce, &.{protocol_version} });
    defer allocator.free(body);
    return .{ .local = local, .remote = remote, .ephemeral = ephemeral, .nonce = nonce, .auth = try ecies.encrypt(allocator, remote, ecies_ephemeral, iv, body) };
}

/// Verify auth, recover the remote ephemeral identity, and return an encrypted ack.
pub fn accept(allocator: std.mem.Allocator, local: Ecdsa.KeyPair, auth: []const u8, ephemeral: Ecdsa.KeyPair, nonce: [32]u8, iv: [16]u8, ecies_ephemeral: Ecdsa.KeyPair) !Responder {
    const body = try ecies.decrypt(allocator, local.secret_key, auth);
    defer allocator.free(body);
    var value = try firstList(allocator, body);
    defer value.deinit(allocator);
    const items = value.list;
    if (items.len < 4) return error.InvalidAuth;
    const signed = try fixed(65, try bytes(items[0]));
    const remote = try publicKey(try bytes(items[1]));
    const remote_nonce = try fixed(32, try bytes(items[2]));
    _ = try version(items[3]);
    const static_shared = try ecies.agree(local.secret_key, remote);
    var challenge: [32]u8 = undefined;
    for (&challenge, static_shared, remote_nonce) |*byte, shared, random| byte.* = shared ^ random;
    const recovered = try crypto.recoverPublicKey(challenge, std.mem.readInt(u256, signed[0..32], .big), std.mem.readInt(u256, signed[32..64], .big), signed[64]);
    const remote_ephemeral = try Ecdsa.PublicKey.fromSec1(&recovered);
    const shared = try ecies.agree(ephemeral.secret_key, remote_ephemeral);
    const ephemeral_public = ephemeral.public_key.toUncompressedSec1();
    const ack_body = try encodeFields(allocator, &.{ ephemeral_public[1..], &nonce, &.{protocol_version} });
    defer allocator.free(ack_body);
    const ack = try ecies.encrypt(allocator, remote, ecies_ephemeral, iv, ack_body);
    return .{ .remote = remote, .ack = ack, .secrets = frame.Secrets.derive(shared, remote_nonce, nonce, auth, ack, false) };
}

/// Encode the short fixed handshake fields as one canonical RLP list.
fn encodeFields(allocator: std.mem.Allocator, fields: []const []const u8) ![]u8 {
    var encoded = std.Io.Writer.Allocating.init(allocator);
    defer encoded.deinit();
    try rlp.rlp(&encoded.writer, fields);
    return encoded.toOwnedSlice();
}

/// Decode the first complete RLP list while allowing EIP-8 random padding.
fn firstList(allocator: std.mem.Allocator, plaintext: []const u8) !rlp.decode.Value {
    var reader = std.Io.Reader.fixed(plaintext);
    const header = try rlp.decode.readHeader(&reader);
    if (header.kind != .list) return error.InvalidHandshake;
    const total = std.math.add(usize, header.header_len, header.payload_len) catch return error.InvalidHandshake;
    if (total > plaintext.len) return error.InvalidHandshake;
    const value = try rlp.decode.decodeAll(allocator, plaintext[0..total]);
    if (value != .list) return error.InvalidHandshake;
    return value;
}

/// Return the owned bytes from one decoded RLP string field.
fn bytes(value: rlp.decode.Value) ![]const u8 {
    return switch (value) {
        .string => |item| item,
        else => error.InvalidHandshake,
    };
}

/// Read a fixed-width handshake field without accepting truncated values.
fn fixed(comptime size: usize, value: []const u8) ![size]u8 {
    if (value.len != size) return error.InvalidHandshake;
    return value[0..size].*;
}

/// Decode an uncompressed 64-byte RLPx public key.
fn publicKey(raw: []const u8) !Ecdsa.PublicKey {
    if (raw.len != 64) return error.InvalidPublicKey;
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    @memcpy(sec1[1..], raw);
    return Ecdsa.PublicKey.fromSec1(&sec1);
}

/// Accept any EIP-8 version integer because RLPx requires forward compatibility.
fn version(value: rlp.decode.Value) !u64 {
    const raw = try bytes(value);
    if (raw.len > 8 or (raw.len > 0 and raw[0] == 0)) return error.InvalidHandshake;
    var result: u64 = 0;
    for (raw) |byte| result = (result << 8) | byte;
    return result;
}

test "RLPx initiator and responder authenticate and agree on frame keys" {
    const a = std.testing.allocator;
    const alice = try Ecdsa.KeyPair.generateDeterministic(.{1} ** 32);
    const bob = try Ecdsa.KeyPair.generateDeterministic(.{2} ** 32);
    const a_ephemeral = try Ecdsa.KeyPair.generateDeterministic(.{3} ** 32);
    const b_ephemeral = try Ecdsa.KeyPair.generateDeterministic(.{4} ** 32);
    const a_ecies = try Ecdsa.KeyPair.generateDeterministic(.{5} ** 32);
    const b_ecies = try Ecdsa.KeyPair.generateDeterministic(.{6} ** 32);
    const started = try initiate(a, alice, bob.public_key, a_ephemeral, .{7} ** 32, .{8} ** 16, a_ecies);
    defer started.deinit(a);
    const replied = try accept(a, bob, started.auth, b_ephemeral, .{9} ** 32, .{10} ** 16, b_ecies);
    defer replied.deinit(a);
    try std.testing.expectEqualDeep(alice.public_key.toUncompressedSec1(), replied.remote.toUncompressedSec1());
    const initiator_keys = try started.finish(a, replied.ack);
    var sender = frame.Framer.init(initiator_keys);
    var receiver = frame.Framer.init(replied.secrets);
    const wire = try sender.encode(a, "hello");
    defer a.free(wire);
    const length = try receiver.decodeHeader(wire[0..32].*);
    const plain = try receiver.decodeBody(a, length, wire[32..]);
    defer a.free(plain);
    try std.testing.expectEqualStrings("hello", plain);
}

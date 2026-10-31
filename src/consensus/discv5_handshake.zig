// A discv5 WHOAREYOU challenge binds an ephemeral ECDH exchange to two ENR
// identities. Both nodes derive separate AES keys for each direction from the
// exact unmasked challenge bytes. The initiator proves its static ENR identity
// by signing that challenge and its ephemeral public key; the recipient must
// verify this proof before accepting any packet or using the session keys.
//
//   WHOAREYOU -> ephemeral ECDH -> directional keys -> authenticated session
// The challenge is exactly 63 bytes; each session key is 16 bytes. Packets
// stay within 1280 bytes and embedded signed ENRs within 300 bytes.
const std = @import("std");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Curve = std.crypto.ecc.Secp256k1;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Keccak = std.crypto.hash.sha3.Keccak256;
const AesGcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const packets = @import("discv5_packets.zig");
const enr = @import("enr.zig");
const agreement_label = "discovery v5 key agreement";
const proof_label = "discovery v5 identity proof";
const static_header_size: usize = 23;
const authdata_fixed_size: usize = 131;
const max_authdata_size: usize = authdata_fixed_size + 300;
const tag_size: usize = 16;

pub const Keys = struct { initiator: [16]u8, recipient: [16]u8 };
pub const Initiator = struct { ephemeral_public_key: [33]u8, keys: Keys };
pub const SentPacket = struct {
    bytes: []u8,
    keys: Keys,

    /// Release the encoded datagram after it has been sent.
    pub fn deinit(self: SentPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};
pub const ReceivedPacket = struct {
    record: enr.Record,
    enr_bytes: ?[]u8,
    nonce: [12]u8,
    plaintext: []u8,
    keys: Keys,

    /// Release the authenticated plaintext after processing the first message.
    pub fn deinit(self: ReceivedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.plaintext);
        if (self.enr_bytes) |bytes| allocator.free(bytes);
    }
};

/// Encode a handshake with the signed local ENR and an encrypted first message.
/// The caller supplies a fresh ephemeral secret, unique nonce, IV, and pending challenge.
pub fn encodePacket(allocator: std.mem.Allocator, initiator: Ecdsa.KeyPair, local_enr: []const u8, recipient: enr.Record, challenge: [63]u8, ephemeral_secret: Ecdsa.SecretKey, masking_iv: [16]u8, nonce: [12]u8, plaintext: []const u8) !SentPacket {
    const local = try enr.decode(allocator, local_enr);
    if (!std.mem.eql(u8, &local.node_id, &nodeId(initiator.public_key))) return error.InvalidNodeId;
    const started = try deriveInitiator(challenge, local.node_id, recipient.node_id, recipient.public_key, ephemeral_secret);
    const signature = try signIdProof(initiator, challenge, started.ephemeral_public_key, recipient.node_id);
    const authdata_size = authdata_fixed_size + local_enr.len;
    const header_size = static_header_size + authdata_size;
    if (plaintext.len == 0 or plaintext.len > packets.max_packet_size - 16 - header_size - tag_size) return error.InvalidMessageSize;
    var header: [static_header_size + max_authdata_size]u8 = undefined;
    @memcpy(header[0..6], "discv5");
    std.mem.writeInt(u16, header[6..8], 1, .big);
    header[8] = @intFromEnum(packets.Kind.handshake);
    @memcpy(header[9..21], &nonce);
    std.mem.writeInt(u16, header[21..23], @intCast(authdata_size), .big);
    @memcpy(header[23..55], &local.node_id);
    header[55] = 64;
    header[56] = 33;
    @memcpy(header[57..121], &signature);
    @memcpy(header[121..154], &started.ephemeral_public_key);
    @memcpy(header[154..header_size], local_enr);
    const datagram = try allocator.alloc(u8, 16 + header_size + plaintext.len + tag_size);
    errdefer allocator.free(datagram);
    @memcpy(datagram[0..16], &masking_iv);
    packets.mask(recipient.node_id, masking_iv, datagram[16 .. 16 + header_size], header[0..header_size]);
    var associated_data: [16 + static_header_size + max_authdata_size]u8 = undefined;
    @memcpy(associated_data[0..16], &masking_iv);
    @memcpy(associated_data[16 .. 16 + header_size], header[0..header_size]);
    AesGcm.encrypt(datagram[16 + header_size .. datagram.len - tag_size], datagram[datagram.len - tag_size ..][0..tag_size], plaintext, associated_data[0 .. 16 + header_size], nonce, started.keys.initiator);
    return .{ .bytes = datagram, .keys = started.keys };
}

/// Verify a pending challenge, ENR, identity proof, and encrypted first message.
/// A cached record must already be signature-verified; the caller consumes each challenge once.
pub fn decodePacket(allocator: std.mem.Allocator, recipient_id: [32]u8, recipient_secret: Ecdsa.SecretKey, challenge: [63]u8, cached_record: ?enr.Record, fork_digest: [4]u8, datagram: []const u8) !ReceivedPacket {
    const summary = try packets.inspect(recipient_id, datagram);
    if (summary.kind != .handshake or summary.authdata_size < authdata_fixed_size or summary.authdata_size > max_authdata_size) return error.InvalidPacketHeader;
    const header_size = static_header_size + summary.authdata_size;
    if (datagram.len <= 16 + header_size + tag_size) return error.InvalidPacketHeader;
    var header: [static_header_size + max_authdata_size]u8 = undefined;
    packets.mask(recipient_id, datagram[0..16].*, header[0..header_size], datagram[16 .. 16 + header_size]);
    if (header[55] != 64 or header[56] != 33) return error.InvalidPacketHeader;
    const source_id: [32]u8 = header[23..55].*;
    const record_bytes = header[154..header_size];
    const record = if (record_bytes.len > 0) try enr.decode(allocator, record_bytes) else cached_record orelse return error.MissingRecord;
    try enr.requireFork(record, fork_digest);
    if (!std.mem.eql(u8, &record.node_id, &source_id)) return error.InvalidNodeId;
    if (record_bytes.len == 0) {
        const advertised_sequence = std.mem.readInt(u64, challenge[55..63], .big);
        if (advertised_sequence == 0 or record.sequence != advertised_sequence) return error.StaleRecord;
    }
    const signature: [64]u8 = header[57..121].*;
    const ephemeral_public_key: [33]u8 = header[121..154].*;
    try verifyIdProof(source_id, record.public_key, signature, challenge, ephemeral_public_key, recipient_id);
    const keys = try deriveRecipient(challenge, source_id, recipient_id, ephemeral_public_key, recipient_secret);
    var associated_data: [16 + static_header_size + max_authdata_size]u8 = undefined;
    @memcpy(associated_data[0..16], datagram[0..16]);
    @memcpy(associated_data[16 .. 16 + header_size], header[0..header_size]);
    const ciphertext = datagram[16 + header_size .. datagram.len - tag_size];
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);
    try AesGcm.decrypt(plaintext, ciphertext, datagram[datagram.len - tag_size ..][0..tag_size].*, associated_data[0 .. 16 + header_size], summary.nonce, keys.initiator);
    const enr_bytes = if (record_bytes.len > 0) try allocator.dupe(u8, record_bytes) else null;
    return .{ .record = record, .enr_bytes = enr_bytes, .nonce = summary.nonce, .plaintext = plaintext, .keys = keys };
}

/// Derive keys as the initiator using a fresh ephemeral secret and a verified recipient ENR.
pub fn deriveInitiator(challenge: [63]u8, initiator_id: [32]u8, recipient_id: [32]u8, recipient_public_key: [33]u8, ephemeral_secret: Ecdsa.SecretKey) !Initiator {
    const recipient = try Ecdsa.PublicKey.fromSec1(&recipient_public_key);
    if (!std.mem.eql(u8, &nodeId(recipient), &recipient_id)) return error.InvalidNodeId;
    const ephemeral = try Ecdsa.KeyPair.fromSecretKey(ephemeral_secret);
    const shared = (try recipient.p.mul(ephemeral_secret.bytes, .big)).toCompressedSec1();
    return .{
        .ephemeral_public_key = ephemeral.public_key.toCompressedSec1(),
        .keys = deriveKeys(challenge, initiator_id, recipient_id, shared),
    };
}

/// Derive matching keys as the recipient after verifying the initiator's ID proof.
pub fn deriveRecipient(challenge: [63]u8, initiator_id: [32]u8, recipient_id: [32]u8, ephemeral_public_key: [33]u8, recipient_secret: Ecdsa.SecretKey) !Keys {
    const local = try Ecdsa.KeyPair.fromSecretKey(recipient_secret);
    if (!std.mem.eql(u8, &nodeId(local.public_key), &recipient_id)) return error.InvalidNodeId;
    const ephemeral = try Curve.fromSec1(&ephemeral_public_key);
    const shared = (try ephemeral.mul(recipient_secret.bytes, .big)).toCompressedSec1();
    return deriveKeys(challenge, initiator_id, recipient_id, shared);
}

/// Sign the challenge and ephemeral key with the initiator's static ENR key.
pub fn signIdProof(initiator: Ecdsa.KeyPair, challenge: [63]u8, ephemeral_public_key: [33]u8, recipient_id: [32]u8) ![64]u8 {
    return (try initiator.signPrehashed(proofDigest(challenge, ephemeral_public_key, recipient_id), null)).toBytes();
}

/// Verify the initiator's proof against the public key and node ID in its signed ENR.
pub fn verifyIdProof(initiator_id: [32]u8, initiator_public_key: [33]u8, signature: [64]u8, challenge: [63]u8, ephemeral_public_key: [33]u8, recipient_id: [32]u8) !void {
    const public_key = try Ecdsa.PublicKey.fromSec1(&initiator_public_key);
    if (!std.mem.eql(u8, &nodeId(public_key), &initiator_id)) return error.InvalidNodeId;
    try Ecdsa.Signature.fromBytes(signature).verifyPrehashed(proofDigest(challenge, ephemeral_public_key, recipient_id), public_key);
}

/// Compute Keccak-256 of an uncompressed secp256k1 point, the ENR node ID.
fn nodeId(public_key: Ecdsa.PublicKey) [32]u8 {
    const uncompressed = public_key.toUncompressedSec1();
    var id: [32]u8 = undefined;
    Keccak.hash(uncompressed[1..], &id, .{});
    return id;
}

/// Expand the compressed ECDH point into send and receive keys in initiator order.
fn deriveKeys(challenge: [63]u8, initiator_id: [32]u8, recipient_id: [32]u8, shared: [33]u8) Keys {
    var info: [agreement_label.len + 64]u8 = undefined;
    @memcpy(info[0..agreement_label.len], agreement_label);
    @memcpy(info[agreement_label.len .. agreement_label.len + 32], &initiator_id);
    @memcpy(info[agreement_label.len + 32 ..], &recipient_id);
    const prk = Hkdf.extract(&challenge, &shared);
    var data: [32]u8 = undefined;
    Hkdf.expand(&data, &info, prk);
    return .{ .initiator = data[0..16].*, .recipient = data[16..32].* };
}

/// Hash the discv5 identity-proof domain and its exact signed fields.
fn proofDigest(challenge: [63]u8, ephemeral_public_key: [33]u8, recipient_id: [32]u8) [32]u8 {
    var message: [proof_label.len + 63 + 33 + 32]u8 = undefined;
    @memcpy(message[0..proof_label.len], proof_label);
    @memcpy(message[proof_label.len .. proof_label.len + 63], &challenge);
    @memcpy(message[proof_label.len + 63 .. proof_label.len + 96], &ephemeral_public_key);
    @memcpy(message[proof_label.len + 96 ..], &recipient_id);
    var digest: [32]u8 = undefined;
    Sha256.hash(&message, &digest, .{});
    return digest;
}

test "WHOAREYOU keys agree and identity proof binds challenge, key, and recipient" {
    const initiator = try Ecdsa.KeyPair.generateDeterministic([_]u8{1} ** 32);
    const recipient = try Ecdsa.KeyPair.generateDeterministic([_]u8{2} ** 32);
    const ephemeral = try Ecdsa.KeyPair.generateDeterministic([_]u8{3} ** 32);
    const initiator_id = nodeId(initiator.public_key);
    const recipient_id = nodeId(recipient.public_key);
    const packet = packets.encodeWhoAreYou(initiator_id, [_]u8{4} ** 16, .{
        .request_nonce = [_]u8{5} ** 12,
        .id_nonce = [_]u8{6} ** 16,
        .enr_sequence = 1,
    });
    const challenge = try packets.challengeData(initiator_id, &packet);
    try std.testing.expectEqualSlices(u8, packet[0..16], challenge[0..16]);
    const started = try deriveInitiator(challenge, initiator_id, recipient_id, recipient.public_key.toCompressedSec1(), ephemeral.secret_key);
    const signature = try signIdProof(initiator, challenge, started.ephemeral_public_key, recipient_id);
    try verifyIdProof(initiator_id, initiator.public_key.toCompressedSec1(), signature, challenge, started.ephemeral_public_key, recipient_id);
    const received = try deriveRecipient(challenge, initiator_id, recipient_id, started.ephemeral_public_key, recipient.secret_key);
    try std.testing.expectEqualDeep(started.keys, received);
    try std.testing.expect(!std.mem.eql(u8, &received.initiator, &received.recipient));
    var wrong_challenge = challenge;
    wrong_challenge[0] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, verifyIdProof(initiator_id, initiator.public_key.toCompressedSec1(), signature, wrong_challenge, started.ephemeral_public_key, recipient_id));
    var wrong_ephemeral = started.ephemeral_public_key;
    wrong_ephemeral[1] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, verifyIdProof(initiator_id, initiator.public_key.toCompressedSec1(), signature, challenge, wrong_ephemeral, recipient_id));
    try std.testing.expectError(error.InvalidNodeId, verifyIdProof(recipient_id, initiator.public_key.toCompressedSec1(), signature, challenge, started.ephemeral_public_key, recipient_id));
    try std.testing.expectError(error.InvalidNodeId, deriveInitiator(challenge, initiator_id, initiator_id, recipient.public_key.toCompressedSec1(), ephemeral.secret_key));
}

test "discv5 ECDH and HKDF match the official wire vector" {
    // https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
    var ecdh_public_key: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ecdh_public_key, "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231");
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const shared = (try (try Curve.fromSec1(&ecdh_public_key)).mul(secret, .big)).toCompressedSec1();
    var expected_shared: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_shared, "033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e");
    try std.testing.expectEqual(expected_shared, shared);
    var challenge: [63]u8 = undefined;
    _ = try std.fmt.hexToBytes(&challenge, "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000");
    var initiator_id: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&initiator_id, "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
    var recipient_id: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&recipient_id, "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");
    // Key derivation uses a different destination public key than the ECDH vector.
    var destination_public_key: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&destination_public_key, "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91");
    const agreement_secret = (try (try Curve.fromSec1(&destination_public_key)).mul(secret, .big)).toCompressedSec1();
    const keys = deriveKeys(challenge, initiator_id, recipient_id, agreement_secret);
    var expected_initiator: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_initiator, "dccc82d81bd610f4f76d3ebe97a40571");
    var expected_recipient: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_recipient, "ac74bb8773749920b0d3a8881c173ec5");
    try std.testing.expectEqual(expected_initiator, keys.initiator);
    try std.testing.expectEqual(expected_recipient, keys.recipient);
    var expected_signature: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_signature, "94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6");
    const signing_key = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(secret));
    try Ecdsa.Signature.fromBytes(expected_signature).verifyPrehashed(proofDigest(challenge, ecdh_public_key, recipient_id), signing_key.public_key);
}

test "handshake packet verifies ENR and proof before delivering first message" {
    const allocator = std.testing.allocator;
    const initiator = try Ecdsa.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const recipient = try Ecdsa.KeyPair.generateDeterministic([_]u8{12} ** 32);
    const ephemeral = try Ecdsa.KeyPair.generateDeterministic([_]u8{13} ** 32);
    const fork_digest = [4]u8{ 1, 2, 3, 4 };
    const local = enr.Local{
        .sequence = 1,
        .ip = .{ 127, 0, 0, 1 },
        .udp_port = 9000,
        .tcp_port = 9001,
        .fork_id = .{ 1, 2, 3, 4, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 },
        .next_fork_digest = .{0} ** 4,
        .custody_group_count = 4,
    };
    const local_bytes = try enr.encode(allocator, initiator, local);
    defer allocator.free(local_bytes);
    const peer_bytes = try enr.encode(allocator, recipient, local);
    defer allocator.free(peer_bytes);
    const peer = try enr.decode(allocator, peer_bytes);
    const challenge_packet = packets.encodeWhoAreYou(nodeId(initiator.public_key), [_]u8{1} ** 16, .{
        .request_nonce = [_]u8{2} ** 12,
        .id_nonce = [_]u8{3} ** 16,
        .enr_sequence = 0,
    });
    const challenge = try packets.challengeData(nodeId(initiator.public_key), &challenge_packet);
    const sent = try encodePacket(allocator, initiator, local_bytes, peer, challenge, ephemeral.secret_key, [_]u8{4} ** 16, [_]u8{5} ** 12, &.{ 1, 2, 3 });
    defer sent.deinit(allocator);
    const received = try decodePacket(allocator, peer.node_id, recipient.secret_key, challenge, null, fork_digest, sent.bytes);
    defer received.deinit(allocator);
    try std.testing.expectEqual(nodeId(initiator.public_key), received.record.node_id);
    try std.testing.expectEqualDeep(sent.keys, received.keys);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, received.plaintext);
    const Session = @import("discv5_session.zig").Session;
    var outbound = try Session.init(allocator, std.testing.io, received.record.node_id, peer.node_id, sent.keys.initiator, sent.keys.recipient, 1);
    defer outbound.deinit();
    var inbound = try Session.init(allocator, std.testing.io, peer.node_id, received.record.node_id, received.keys.recipient, received.keys.initiator, 1);
    defer inbound.deinit();
    const next_packet = try outbound.send(&.{ 4, 5 });
    defer allocator.free(next_packet);
    const next_message = try inbound.receive(next_packet);
    defer next_message.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 4, 5 }, next_message.plaintext);
    try std.testing.expectError(error.InvalidForkContext, decodePacket(allocator, peer.node_id, recipient.secret_key, challenge, null, .{ 9, 2, 3, 4 }, sent.bytes));
    var altered_challenge = challenge;
    altered_challenge[0] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, decodePacket(allocator, peer.node_id, recipient.secret_key, altered_challenge, null, fork_digest, sent.bytes));
    const tampered = try allocator.dupe(u8, sent.bytes);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, decodePacket(allocator, peer.node_id, recipient.secret_key, challenge, null, fork_digest, tampered));
    const malformed = try allocator.dupe(u8, sent.bytes);
    defer allocator.free(malformed);
    var unmasked_head: [57]u8 = undefined;
    packets.mask(peer.node_id, malformed[0..16].*, &unmasked_head, malformed[16 .. 16 + unmasked_head.len]);
    unmasked_head[55] = 63;
    packets.mask(peer.node_id, malformed[0..16].*, malformed[16 .. 16 + unmasked_head.len], &unmasked_head);
    try std.testing.expectError(error.InvalidPacketHeader, decodePacket(allocator, peer.node_id, recipient.secret_key, challenge, null, fork_digest, malformed));
    try std.testing.expectError(error.InvalidPacketSize, decodePacket(allocator, peer.node_id, recipient.secret_key, challenge, null, fork_digest, sent.bytes[0..62]));
}

test "published handshake packet decrypts with a cached ENR" {
    // https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
    const allocator = std.testing.allocator;
    var initiator_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&initiator_secret, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    var recipient_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&recipient_secret, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628");
    const initiator = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(initiator_secret));
    const recipient = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(recipient_secret));
    const local = enr.Local{
        .sequence = 1,
        .ip = .{ 127, 0, 0, 1 },
        .udp_port = 9000,
        .tcp_port = 9001,
        .fork_id = .{ 1, 2, 3, 4, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 },
        .next_fork_digest = .{0} ** 4,
        .custody_group_count = 4,
    };
    const record_bytes = try enr.encode(allocator, initiator, local);
    defer allocator.free(record_bytes);
    const record = try enr.decode(allocator, record_bytes);
    var challenge: [63]u8 = undefined;
    _ = try std.fmt.hexToBytes(&challenge, "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001");
    const packet_hex =
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55" ++
        "ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
        "4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef" ++
        "268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb" ++
        "a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1" ++
        "f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83" ++
        "9cf8";
    var packet: [packet_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&packet, packet_hex);
    try std.testing.expectEqual(record.node_id, nodeId(initiator.public_key));
    const received = try decodePacket(allocator, nodeId(recipient.public_key), recipient.secret_key, challenge, record, .{ 1, 2, 3, 4 }, &packet);
    defer received.deinit(allocator);
    var expected_key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_key, "4f9fac6de7567d1e3b1241dffe90f662");
    try std.testing.expectEqual(expected_key, received.keys.initiator);
    const first_message = try @import("discv5_messages.zig").decode(allocator, received.plaintext);
    try std.testing.expectEqual(@as(u64, 1), first_message.ping.enr_sequence);
    try std.testing.expectError(error.MissingRecord, decodePacket(allocator, nodeId(recipient.public_key), recipient.secret_key, challenge, null, .{ 1, 2, 3, 4 }, &packet));
    var stale_record = record;
    stale_record.sequence = 2;
    try std.testing.expectError(error.StaleRecord, decodePacket(allocator, nodeId(recipient.public_key), recipient.secret_key, challenge, stale_record, .{ 1, 2, 3, 4 }, &packet));
}

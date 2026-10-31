// A discv5 WHOAREYOU challenge binds an ephemeral ECDH exchange to two ENR
// identities. Both nodes derive separate AES keys for each direction from the
// exact unmasked challenge bytes. The initiator proves its static ENR identity
// by signing that challenge and its ephemeral public key; the recipient must
// verify this proof before accepting any packet or using the session keys.
//
//   WHOAREYOU -> ephemeral ECDH -> directional keys -> authenticated session
// The challenge is exactly 63 bytes; each session key is 16 bytes.
const std = @import("std");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Curve = std.crypto.ecc.Secp256k1;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Keccak = std.crypto.hash.sha3.Keccak256;
const agreement_label = "discovery v5 key agreement";
const proof_label = "discovery v5 identity proof";

pub const Keys = struct { initiator: [16]u8, recipient: [16]u8 };
pub const Initiator = struct { ephemeral_public_key: [33]u8, keys: Keys };

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
    const packets = @import("discv5_packets.zig");
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

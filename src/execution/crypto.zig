// ECDSA lets a signed transaction recover its secp256k1 public key from the
// message hash, signature, and recovery parity. Transaction signatures are
// public data, so Zig's variable-time public point arithmetic is appropriate;
// recovery accepts only canonical nonzero scalars and low-s signatures.
// EXPERIMENTAL: sender recovery has limited fixture coverage and is not audited.
//
//   (hash, r, s, y parity) -> public key -> Keccak-256 -> 20-byte address
const std = @import("std");

pub const Address = [20]u8;
pub const Error = error{ InvalidSignature, InvalidRecoveryId, HighS };

const Curve = std.crypto.ecc.Secp256k1;
const Scalar = Curve.scalar.Scalar;
const scalar_order = Curve.scalar.field_order;

/// EXPERIMENTAL: Recovers an Ethereum address from a Keccak hash and ECDSA signature; not audited.
pub fn recoverAddress(message_hash: [32]u8, r_value: u256, s_value: u256, recovery_id: u8) Error!Address {
    if (recovery_id > 1) return error.InvalidRecoveryId;
    if (r_value == 0 or r_value >= scalar_order or s_value == 0 or s_value >= scalar_order)
        return error.InvalidSignature;
    if (s_value > scalar_order / 2) return error.HighS;

    const r_bytes = intToBytes(r_value);
    const s_bytes = intToBytes(s_value);
    const x = Curve.Fe.fromBytes(r_bytes, .big) catch return error.InvalidSignature;
    const y = Curve.recoverY(x, recovery_id == 1) catch return error.InvalidSignature;
    const recovery_point = Curve.fromAffineCoordinates(.{ .x = x, .y = y }) catch return error.InvalidSignature;

    var wide_hash: [48]u8 = [_]u8{0} ** 48;
    @memcpy(wide_hash[16..], &message_hash);
    const reduced_hash = Curve.scalar.reduce48(wide_hash, .big);
    const inverse_r = (Scalar.fromBytes(r_bytes, .big) catch return error.InvalidSignature).invert().toBytes(.big);
    const s_coefficient = Curve.scalar.mul(inverse_r, s_bytes, .big) catch return error.InvalidSignature;
    const hash_scalar = Scalar.fromBytes(reduced_hash, .big) catch return error.InvalidSignature;
    const inverse_hash = Curve.scalar.mul(inverse_r, hash_scalar.neg().toBytes(.big), .big) catch return error.InvalidSignature;

    const public_key = Curve.mulDoubleBasePublic(
        recovery_point,
        s_coefficient,
        Curve.basePoint,
        inverse_hash,
        .big,
    ) catch return error.InvalidSignature;
    const encoded = public_key.toUncompressedSec1();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(encoded[1..], &digest, .{});
    return digest[12..32].*;
}

/// Converts an unsigned integer to the fixed-width big-endian form used by secp256k1.
fn intToBytes(value: u256) [32]u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return bytes;
}

test "recovery rejects invalid IDs and scalar boundaries" {
    const hash = [_]u8{0} ** 32;
    const order = scalar_order;
    try std.testing.expectError(error.InvalidRecoveryId, recoverAddress(hash, 1, 1, 2));
    try std.testing.expectError(error.InvalidSignature, recoverAddress(hash, 0, 1, 0));
    try std.testing.expectError(error.InvalidSignature, recoverAddress(hash, order, 1, 0));
    try std.testing.expectError(error.InvalidSignature, recoverAddress(hash, 1, 0, 0));
    try std.testing.expectError(error.InvalidSignature, recoverAddress(hash, 1, order, 0));
    try std.testing.expectError(error.HighS, recoverAddress(hash, 1, order / 2 + 1, 0));
}

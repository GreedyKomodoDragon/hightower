// BLS12-381 signatures authenticate 32-byte consensus signing roots with
// compressed G1 public keys (48 bytes) and G2 signatures (96 bytes). Subgroup
// checks restrict points to the prime-order groups used by Ethereum's scheme.
// Verification does not mutate state; callers must verify before applying the
// signed operation and propagate errors. Aggregate keys must already have
// proofs of possession, as validator deposits provide. Ethereum permits an
// empty signer list only with the canonical infinity signature (the identity).
const blst = @import("blst");

pub const Error = error{
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
};

const ETHEREUM_BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Verifies the Ethereum consensus BLS signature scheme (public key in G1).
pub fn verify(public_key: [48]u8, message: [32]u8, signature: [96]u8) Error!void {
    const key = blst.P1_Affine.from(&public_key) catch return error.InvalidPublicKey;
    if (!key.in_group() or key.is_inf()) return error.InvalidPublicKey;

    const sig = blst.P2_Affine.from(&signature) catch return error.InvalidSignature;
    if (!sig.in_group() or sig.is_inf()) return error.InvalidSignature;

    if (sig.core_verify(&key, true, &message, ETHEREUM_BLS_DST, null) != .SUCCESS)
        return error.VerificationFailed;
}

/// Ethereum eth_fast_aggregate_verify, including its empty-participation rule.
pub fn verifyAggregate(public_keys: []const [48]u8, message: [32]u8, signature: [96]u8) Error!void {
    if (public_keys.len == 0) {
        var infinity = [_]u8{0} ** 96;
        infinity[0] = 0xc0;
        if (!@import("std").mem.eql(u8, &signature, &infinity)) return error.InvalidSignature;
        return;
    }
    var aggregate: ?blst.P1 = null;
    for (public_keys) |public_key| {
        const key = blst.P1_Affine.from(&public_key) catch return error.InvalidPublicKey;
        if (!key.in_group() or key.is_inf()) return error.InvalidPublicKey;
        if (aggregate) |*accumulator| {
            accumulator.aggregate(&key) catch return error.InvalidPublicKey;
        } else {
            aggregate = key.to_jacobian();
        }
    }
    const aggregate_key = aggregate.?.to_affine().compress();
    return verify(aggregate_key, message, signature);
}

test "empty aggregate requires the infinity signature" {
    const message = [_]u8{0} ** 32;
    var infinity = [_]u8{0} ** 96;
    infinity[0] = 0xc0;
    try verifyAggregate(&.{}, message, infinity);
    try @import("std").testing.expectError(error.InvalidSignature, verifyAggregate(&.{}, message, [_]u8{0} ** 96));
}

test "aggregate verification accepts two signers and rejects a changed message" {
    const message = [_]u8{0x33} ** 32;
    const seeds = [_][32]u8{ [_]u8{0x42} ** 32, [_]u8{0x43} ** 32 };
    var public_keys: [2][48]u8 = undefined;
    var signatures: [2]blst.P2 = undefined;
    for (seeds, 0..) |seed, index| {
        var secret_key = blst.SecretKey{};
        secret_key.keygen(&seed, null);
        defer secret_key.deinit();
        public_keys[index] = (try blst.P1.from(&secret_key)).compress();
        signatures[index] = blst.P2.hash_to(&message, ETHEREUM_BLS_DST, null);
        _ = signatures[index].sign_with(&secret_key);
    }
    const second = signatures[1].to_affine();
    try signatures[0].aggregate(&second);
    const signature = signatures[0].compress();
    try verifyAggregate(&public_keys, message, signature);
    var wrong_message = message;
    wrong_message[0] ^= 1;
    try @import("std").testing.expectError(error.VerificationFailed, verifyAggregate(&public_keys, wrong_message, signature));
}

test "Ethereum BLS verifier accepts a valid signature and rejects a changed message" {
    const ikm = [_]u8{0x42} ** 32;
    var secret_key = blst.SecretKey{};
    secret_key.keygen(&ikm, null);
    defer secret_key.deinit();

    const public_key = (try blst.P1.from(&secret_key)).compress();
    const message = [_]u8{0x24} ** 32;
    const signature = blst.P2.hash_to(&message, ETHEREUM_BLS_DST, null).sign_with(&secret_key).compress();
    try verify(public_key, message, signature);
    var infinity = [_]u8{0} ** 96;
    infinity[0] = 0xc0;
    for ([_][96]u8{ [_]u8{0} ** 96, infinity }) |invalid| {
        try @import("std").testing.expectError(error.InvalidSignature, verify(public_key, message, invalid));
        try @import("std").testing.expectError(error.InvalidSignature, verifyAggregate(&.{public_key}, message, invalid));
    }

    var wrong_message = message;
    wrong_message[0] ^= 1;
    try @import("std").testing.expectError(error.VerificationFailed, verify(public_key, wrong_message, signature));
}

test "Ethereum BLS verifier rejects malformed and infinity encodings" {
    const message = [_]u8{0} ** 32;
    try @import("std").testing.expectError(error.InvalidPublicKey, verify([_]u8{0} ** 48, message, [_]u8{0} ** 96));

    var infinity_key = [_]u8{0} ** 48;
    infinity_key[0] = 0xc0;
    try @import("std").testing.expectError(error.InvalidPublicKey, verify(infinity_key, message, [_]u8{0} ** 96));
}

// A blob commitment is a KZG commitment to blob data. Its versioned hash is
// SHA-256 with the first byte set to the blob hash version; transaction order
// must match the consensus block's commitment order. Version 1 is supported.
const std = @import("std");

/// Converts one 48-byte KZG commitment to its EIP-4844 versioned hash.
pub fn versionedHash(commitment: [48]u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &hash, .{});
    hash[0] = 1;
    return hash;
}

test "versioned hash sets the version byte" {
    const commitment = [_]u8{0} ** 48;
    const hash = versionedHash(commitment);
    try std.testing.expectEqual(@as(u8, 1), hash[0]);
}

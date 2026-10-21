// A Bloom filter is a fixed-size probabilistic set-membership structure. This
// Ethereum filter stores 2048 bits and inserts Keccak-derived positions for
// log addresses and topics. Insertions only set bits; queries can have false
// positives, but inserted values cannot be false negatives. Byte order and
// bit positions follow Ethereum's logs bloom encoding.
const std = @import("std");

/// Ethereum's 2048-bit bloom bytes as encoded in a receipt or block header.
pub const Bloom = [256]u8;

/// A fixed-size Ethereum Bloom filter over arbitrary byte strings.
pub const BloomFilter = struct {
    bits: Bloom = .{0} ** 256,

    /// Creates an empty Ethereum Bloom filter.
    pub fn init() BloomFilter {
        return .{};
    }

    /// Inserts a byte string by setting its three Keccak-derived bit positions.
    pub fn add(self: *BloomFilter, value: []const u8) void {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(value, &digest, .{});
        for (0..3) |i| {
            const bit = ((@as(u16, digest[i * 2]) << 8) | digest[i * 2 + 1]) & 2047;
            self.bits[255 - bit / 8] |= @as(u8, 1) << @as(u3, @intCast(bit % 8));
        }
    }

    /// Checks all three membership bits; a positive answer may be a false positive.
    pub fn mayContain(self: *const BloomFilter, value: []const u8) bool {
        var expected = BloomFilter.init();
        expected.add(value);
        for (expected.bits, self.bits) |bits, actual| if (bits != 0 and actual & bits != bits) return false;
        return true;
    }
};

// Keccak-256("abc") fixes the expected bit positions independently of the query method.
test "BloomFilter matches the canonical Keccak vector" {
    var filter = BloomFilter.init();
    filter.add("abc");
    var expected: Bloom = .{0} ** 256;
    expected[63] = 0x08;
    expected[80] = 0x04;
    expected[183] = 0x20;
    try std.testing.expectEqualSlices(u8, &expected, &filter.bits);
    try std.testing.expect(filter.mayContain("abc"));
    try std.testing.expect(!filter.mayContain("not present"));
}

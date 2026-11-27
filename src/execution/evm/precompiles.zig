// Precompiled contracts execute native operations at reserved addresses. Their
// gas is charged before input validation; a failed call consumes its frame gas.
// ModExp pricing changes at Osaka, while the point-evaluation contract begins
// at Cancun. Outputs are copied to the caller only after successful execution.
//
// address + calldata -> gas charge -> validation -> owned return bytes
// Supported addresses: 0x01 through 0x0a; BLS precompiles are separate work.
// Osaka caps each ModExp input length at 1024 bytes.
const std = @import("std");
const crypto = @import("../crypto.zig");
const bn254 = @import("bn254");
const ripemd160 = @import("ripemd160");
const ckzg = @import("ckzg");
// These indexes follow machine.Fork's declared order without importing it cyclically.
const cancun_fork_index: u8 = 3;
const osaka_fork_index: u8 = 5;

/// Reports whether an address is a precompile active at the supplied fork index.
pub fn active(address: [20]u8, fork: u8) bool {
    if (!std.mem.allEqual(u8, address[0..19], 0)) return false;
    return address[19] >= 1 and address[19] <= (if (fork >= cancun_fork_index) @as(u8, 10) else 9);
}

/// Returns owned output and remaining gas; invalid input burns all supplied gas.
pub fn run(allocator: std.mem.Allocator, address: u8, fork: u8, input: []const u8, gas: u64, settings: ?*const ckzg.Settings) !struct { output: []u8, remaining: u64 } {
    const cost = try gasCost(address, fork, input);
    if (cost > gas) return error.OutOfGas;
    const output = try execute(allocator, address, fork, input, settings);
    return .{ .output = output, .remaining = gas - cost };
}

/// Calculates the fork-specific precompile charge, saturating to out of gas.
fn gasCost(address: u8, fork: u8, input: []const u8) !u64 {
    const words = (input.len / 32) + @intFromBool(input.len % 32 != 0);
    const cost: u128 = switch (address) {
        1 => 3000,
        2 => 60 + @as(u128, words) * 12,
        3 => 600 + @as(u128, words) * 120,
        4 => 15 + @as(u128, words) * 3,
        5 => try modexpGas(fork, input),
        6 => 150,
        7 => 6000,
        8 => 45_000 + @as(u128, input.len / 192) * 34_000,
        9 => if (input.len == 213) std.mem.readInt(u32, input[0..4], .big) else 0,
        10 => 50_000,
        else => return error.InvalidPrecompile,
    };
    return std.math.cast(u64, cost) orelse error.OutOfGas;
}

/// Reads a right-padded 32-byte length word without accepting impossible offsets.
fn lengthWord(input: []const u8, offset: usize) u256 {
    var bytes: [32]u8 = .{0} ** 32;
    if (offset < input.len) @memcpy(bytes[0..@min(32, input.len - offset)], input[offset..][0..@min(32, input.len - offset)]);
    return std.mem.readInt(u256, &bytes, .big);
}

/// Applies EIP-2565 pricing before Osaka and EIP-7883 pricing from Osaka.
fn modexpGas(fork: u8, input: []const u8) !u128 {
    const base = lengthWord(input, 0);
    const exponent = lengthWord(input, 32);
    const modulus = lengthWord(input, 64);
    const size = @max(base, modulus);
    const words = (size +| 7) / 8;
    var head: [32]u8 = .{0} ** 32;
    const exponent_start = std.math.add(u256, 96, base) catch return error.OutOfGas;
    if (exponent_start < input.len) {
        const start: usize = @intCast(exponent_start);
        const count: usize = @intCast(@min(exponent, 32));
        @memcpy(head[0..@min(count, input.len - start)], input[start..][0..@min(count, input.len - start)]);
    }
    const head_value = if (exponent == 0) 0 else std.mem.readInt(u256, &head, .big) >> @intCast(8 * (32 - @as(usize, @intCast(@min(exponent, 32)))));
    const high_bits: u256 = if (head_value == 0) 0 else 255 - @clz(head_value);
    const excess = if (exponent > 32) (exponent - 32) *| (if (fork >= osaka_fork_index) @as(u256, 16) else 8) else 0;
    const iterations: u256 = @max(1, excess +| high_bits -| @intFromBool(exponent > 32 and head_value == 0));
    const complexity = if (fork >= osaka_fork_index) (if (size > 32) 2 *| words *| words else 16) else words *| words;
    const result = if (fork >= osaka_fork_index) complexity *| iterations else (complexity *| iterations) / 3;
    return @intCast(@min(@as(u256, std.math.maxInt(u128)), @max(if (fork >= osaka_fork_index) @as(u256, 500) else 200, result)));
}

/// Executes a validated operation and owns its return bytes.
fn execute(allocator: std.mem.Allocator, address: u8, fork: u8, input: []const u8, settings: ?*const ckzg.Settings) ![]u8 {
    switch (address) {
        1 => {
            var data: [128]u8 = .{0} ** 128;
            @memcpy(data[0..@min(input.len, 128)], input[0..@min(input.len, 128)]);
            var output: [32]u8 = .{0} ** 32;
            if (std.mem.allEqual(u8, data[32..63], 0) and (data[63] == 27 or data[63] == 28)) {
                const r = std.mem.readInt(u256, data[64..96], .big);
                const s = std.mem.readInt(u256, data[96..128], .big);
                const key = crypto.recoverPublicKey(data[0..32].*, r, s, data[63] - 27) catch null;
                if (key) |public_key| {
                    var hash: [32]u8 = undefined;
                    std.crypto.hash.sha3.Keccak256.hash(public_key[1..], &hash, .{});
                    @memcpy(output[12..], hash[12..]);
                    return allocator.dupe(u8, &output);
                }
            }
            return allocator.dupe(u8, &.{});
        },
        2 => {
            var output: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(input, &output, .{});
            return allocator.dupe(u8, &output);
        },
        3 => {
            var output: [32]u8 = .{0} ** 32;
            ripemd160.Ripemd160.hash(input, output[12..32], .{});
            return allocator.dupe(u8, &output);
        },
        4 => return allocator.dupe(u8, input),
        5 => return modexp(allocator, fork, input),
        6 => return allocator.dupe(u8, &(bn254.ecAdd(input) catch return error.InvalidPrecompile)),
        7 => return allocator.dupe(u8, &(bn254.ecMul(input) catch return error.InvalidPrecompile)),
        8 => return allocator.dupe(u8, &(bn254.ecPairing(allocator, input) catch |err| if (err == error.OutOfMemory) return err else return error.InvalidPrecompile)),
        9 => return blake2f(allocator, input),
        10 => return pointEvaluation(allocator, input, settings orelse return error.InvalidPrecompile),
        else => return error.InvalidPrecompile,
    }
}

/// Performs arbitrary-length modular exponentiation using Zig's managed big integers.
fn modexp(allocator: std.mem.Allocator, fork: u8, input: []const u8) ![]u8 {
    const base_len = std.math.cast(usize, lengthWord(input, 0)) orelse return error.InvalidPrecompile;
    const exp_len = std.math.cast(usize, lengthWord(input, 32)) orelse return error.InvalidPrecompile;
    const mod_len = std.math.cast(usize, lengthWord(input, 64)) orelse return error.InvalidPrecompile;
    if (fork >= osaka_fork_index and (base_len > 1024 or exp_len > 1024 or mod_len > 1024)) return error.InvalidPrecompile;
    const exp_start = std.math.add(usize, 96, base_len) catch return error.InvalidPrecompile;
    const mod_start = std.math.add(usize, exp_start, exp_len) catch return error.InvalidPrecompile;
    const Big = std.math.big.int.Managed;
    var base = try readBig(allocator, input, 96, base_len);
    defer base.deinit();
    var modulus = try readBig(allocator, input, mod_start, mod_len);
    defer modulus.deinit();
    const output = try allocator.alloc(u8, mod_len);
    errdefer allocator.free(output);
    @memset(output, 0);
    if (modulus.eqlZero()) return output;
    var value = try Big.initSet(allocator, 1);
    defer value.deinit();
    var quotient = try Big.init(allocator);
    defer quotient.deinit();
    var remainder = try Big.init(allocator);
    defer remainder.deinit();
    var product = try Big.init(allocator);
    defer product.deinit();
    try quotient.divTrunc(&remainder, &value, &modulus);
    try value.copy(remainder.toConst());
    try quotient.divTrunc(&remainder, &base, &modulus);
    try base.copy(remainder.toConst());
    for (0..exp_len) |i| {
        const byte = if (exp_start <= input.len and i < input.len - exp_start) input[exp_start + i] else 0;
        for (0..8) |bit| {
            try product.mul(&value, &value);
            try quotient.divTrunc(&remainder, &product, &modulus);
            try value.copy(remainder.toConst());
            if (byte & (@as(u8, 0x80) >> @intCast(bit)) != 0) {
                try product.mul(&value, &base);
                try quotient.divTrunc(&remainder, &product, &modulus);
                try value.copy(remainder.toConst());
            }
        }
    }
    const limbs = value.toConst().limbs;
    for (0..@min(output.len, limbs.len * @sizeOf(std.math.big.Limb))) |i| output[output.len - 1 - i] = @truncate(limbs[i / @sizeOf(std.math.big.Limb)] >> @intCast(8 * (i % @sizeOf(std.math.big.Limb))));
    return output;
}

/// Reads right-padded calldata into a nonnegative managed integer.
fn readBig(allocator: std.mem.Allocator, input: []const u8, start: usize, count: usize) !std.math.big.int.Managed {
    const Big = std.math.big.int.Managed;
    var result = try Big.initCapacity(allocator, (count + @sizeOf(std.math.big.Limb) - 1) / @sizeOf(std.math.big.Limb));
    errdefer result.deinit();
    try result.set(0);
    if (start < input.len) {
        const available = @min(count, input.len - start);
        for (input[start..][0..available]) |byte| {
            try result.shiftLeft(&result, 8);
            try result.addScalar(&result, byte);
        }
        if (count > available) try result.shiftLeft(&result, 8 * (count - available));
    }
    return result;
}

/// Verifies an EIP-4844 commitment opening against the repository's trusted setup.
fn pointEvaluation(allocator: std.mem.Allocator, input: []const u8, settings: *const ckzg.Settings) ![]u8 {
    if (input.len != 192) return error.InvalidPrecompile;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input[96..144], &digest, .{});
    digest[0] = 1;
    if (!std.mem.eql(u8, &digest, input[0..32])) return error.InvalidPrecompile;
    const commitment: ckzg.Bytes48 = .{ .bytes = input[96..144].* };
    const proof: ckzg.Bytes48 = .{ .bytes = input[144..192].* };
    const z: ckzg.Bytes32 = .{ .bytes = input[32..64].* };
    const y: ckzg.Bytes32 = .{ .bytes = input[64..96].* };
    if (!(settings.verifyKzgProof(&commitment, &z, &y, &proof) catch false)) return error.InvalidPrecompile;
    var output: [64]u8 = .{0} ** 64;
    std.mem.writeInt(u256, output[0..32], 4096, .big);
    std.mem.writeInt(u256, output[32..64], 52435875175126190479447740508185965837690552500527637822603658699938581184513, .big);
    return allocator.dupe(u8, &output);
}

/// Compresses one BLAKE2b block in the EIP-152 wire format.
fn blake2f(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len != 213 or input[212] > 1) return error.InvalidPrecompile;
    const iv = [_]u64{ 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
    const sigma = [10][16]u8{
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 }, .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 }, .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 }, .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 }, .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    };
    var h: [8]u64 = undefined;
    var m: [16]u64 = undefined;
    for (0..8) |i| h[i] = std.mem.readInt(u64, input[4 + i * 8 ..][0..8], .little);
    for (0..16) |i| m[i] = std.mem.readInt(u64, input[68 + i * 8 ..][0..8], .little);
    var v = h ++ iv;
    v[12] ^= std.mem.readInt(u64, input[196..204], .little);
    v[13] ^= std.mem.readInt(u64, input[204..212], .little);
    if (input[212] == 1) v[14] = ~v[14];
    const rounds = std.mem.readInt(u32, input[0..4], .big);
    for (0..rounds) |round| {
        const s = sigma[round % 10];
        mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    const output = try allocator.alloc(u8, 64);
    for (0..8) |i| std.mem.writeInt(u64, output[i * 8 ..][0..8], h[i] ^ v[i] ^ v[i + 8], .little);
    return output;
}

/// Performs one BLAKE2b quarter-round with wrapping 64-bit arithmetic.
fn mix(v: *[16]u64, a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) void {
    v[a] +%= v[b] +% x;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 32);
    v[c] +%= v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 24);
    v[a] +%= v[b] +% y;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 16);
    v[c] +%= v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 63);
}

/// Decodes a fixed test vector at compile time.
fn hexBytes(comptime digits: []const u8) [digits.len / 2]u8 {
    var bytes: [digits.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, digits) catch @panic("invalid hex test vector");
    return bytes;
}

test "precompile reference vectors and exact gas" {
    const a = std.testing.allocator;
    const cases = [_]struct { address: u8, input: []const u8, want: []const u8, cost: u64 }{
        .{ .address = 1, .input = &.{}, .want = &.{}, .cost = 3000 },
        .{ .address = 2, .input = "abc", .want = &hexBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), .cost = 72 },
        .{ .address = 3, .input = "abc", .want = &hexBytes("0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc"), .cost = 720 },
        .{ .address = 4, .input = "abc", .want = "abc", .cost = 18 },
        .{ .address = 6, .input = &.{}, .want = &([_]u8{0} ** 64), .cost = 150 },
        .{ .address = 7, .input = &.{}, .want = &([_]u8{0} ** 64), .cost = 6000 },
        .{ .address = 8, .input = &.{}, .want = &([_]u8{0} ** 31 ++ .{1}), .cost = 45_000 },
    };
    for (cases) |case| {
        const got = try run(a, case.address, 6, case.input, case.cost, null);
        defer a.free(got.output);
        try std.testing.expectEqual(@as(u64, 0), got.remaining);
        try std.testing.expectEqualSlices(u8, case.want, got.output);
        try std.testing.expectError(error.OutOfGas, run(a, case.address, 6, case.input, case.cost - 1, null));
    }
    var signature: [128]u8 = .{0} ** 128;
    @memcpy(signature[0..32], &hexBytes("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"));
    signature[63] = 28;
    @memcpy(signature[64..96], &hexBytes("73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"));
    @memcpy(signature[96..128], &hexBytes("eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549"));
    const recovered = try run(a, 1, 6, &signature, 3000, null);
    defer a.free(recovered.output);
    try std.testing.expectEqualSlices(u8, &hexBytes("000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"), recovered.output);
    var add: [128]u8 = .{0} ** 128;
    add[31] = 1;
    add[63] = 2;
    const sum = try run(a, 6, 6, &add, 150, null);
    defer a.free(sum.output);
    try std.testing.expectEqualSlices(u8, add[0..64], sum.output);
    var mul: [96]u8 = .{0} ** 96;
    @memcpy(mul[0..64], add[0..64]);
    mul[95] = 1;
    const product = try run(a, 7, 6, &mul, 6000, null);
    defer a.free(product.output);
    try std.testing.expectEqualSlices(u8, add[0..64], product.output);
    var pair: [192]u8 = .{0} ** 192;
    @memcpy(pair[0..64], add[0..64]);
    @memcpy(pair[64..192], &bn254.G2.toBytes(bn254.G2.Affine.generator));
    const nontrivial_pair = try run(a, 8, 6, &pair, 79_000, null);
    defer a.free(nontrivial_pair.output);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), nontrivial_pair.output);
    var mod_input: [99]u8 = .{0} ** 99;
    mod_input[31] = 1;
    mod_input[63] = 1;
    mod_input[95] = 1;
    mod_input[96] = 2;
    mod_input[97] = 5;
    mod_input[98] = 13;
    const mod_result = try run(a, 5, 6, &mod_input, 500, null);
    defer a.free(mod_result.output);
    try std.testing.expectEqualSlices(u8, &.{6}, mod_result.output);
    try std.testing.expectError(error.OutOfGas, run(a, 5, 6, &mod_input, 499, null));
    const old_cost = try run(a, 5, 3, &mod_input, 200, null);
    defer a.free(old_cost.output);
    try std.testing.expectEqualSlices(u8, &.{6}, old_cost.output);
    mod_input[63] = 0;
    mod_input[97] = 1;
    const zero_exp = try run(a, 5, 6, &mod_input, 500, null);
    defer a.free(zero_exp.output);
    try std.testing.expectEqualSlices(u8, &.{0}, zero_exp.output);
    mod_input[63] = 1;
    var repriced: [227]u8 = .{0} ** 227;
    repriced[31] = 64;
    repriced[63] = 3;
    repriced[95] = 64;
    repriced[160] = 1;
    repriced[162] = 1;
    try std.testing.expectEqual(@as(u64, 341), try gasCost(5, 3, &repriced));
    try std.testing.expectEqual(@as(u64, 2048), try gasCost(5, 6, &repriced));
    repriced[30] = 4;
    repriced[31] = 1;
    try std.testing.expectError(error.InvalidPrecompile, run(a, 5, 6, &repriced, 1_000_000, null));
    var point_address: [20]u8 = .{0} ** 20;
    point_address[19] = 10;
    try std.testing.expect(!active(point_address, 2));
    try std.testing.expect(active(point_address, cancun_fork_index));
    var blake: [213]u8 = .{0} ** 213;
    blake[3] = 12;
    @memcpy(blake[4..68], &hexBytes("48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"));
    @memcpy(blake[68..71], "abc");
    blake[196] = 3;
    blake[212] = 1;
    const compressed = try run(a, 9, 6, &blake, 12, null);
    defer a.free(compressed.output);
    try std.testing.expectEqualSlices(u8, &hexBytes("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"), compressed.output);
    blake[212] = 2;
    try std.testing.expectError(error.InvalidPrecompile, run(a, 9, 6, &blake, 12, null));
    try std.testing.expectError(error.InvalidPrecompile, run(a, 8, 6, &.{0}, 45_000, null));
    try std.testing.expectError(error.InvalidPrecompile, run(a, 6, 6, &([_]u8{0xff} ** 64), 150, null));
}

test "point evaluation accepts zero polynomial proof and rejects malformed input" {
    const a = std.testing.allocator;
    var settings = try ckzg.Settings.loadTrustedSetupFile("src/execution/trusted_setup.txt", 0);
    defer settings.deinit();
    var input: [192]u8 = .{0} ** 192;
    input[96] = 0xc0;
    input[144] = 0xc0;
    std.crypto.hash.sha2.Sha256.hash(input[96..144], input[0..32], .{});
    input[0] = 1;
    const result = try run(a, 10, 6, &input, 50_000, &settings);
    defer a.free(result.output);
    try std.testing.expectEqual(@as(usize, 64), result.output.len);
    try std.testing.expectEqual(@as(u256, 4096), std.mem.readInt(u256, result.output[0..32], .big));
    try std.testing.expectEqual(@as(u256, 52435875175126190479447740508185965837690552500527637822603658699938581184513), std.mem.readInt(u256, result.output[32..64], .big));
    try std.testing.expectError(error.OutOfGas, run(a, 10, 6, &input, 49_999, &settings));
    input[0] = 0;
    try std.testing.expectError(error.InvalidPrecompile, run(a, 10, 6, &input, 50_000, &settings));
    input[0] = 1;
    @memset(input[32..64], 0xff);
    try std.testing.expectError(error.InvalidPrecompile, run(a, 10, 6, &input, 50_000, &settings));
    try std.testing.expectError(error.InvalidPrecompile, run(a, 10, 6, input[0..191], 50_000, &settings));
}

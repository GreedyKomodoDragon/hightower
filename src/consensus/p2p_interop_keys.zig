// Prysm's mock-genesis key derivation hashes a little-endian validator index,
// reduces the digest modulo the BLS12-381 scalar field, and writes the result
// as a big-endian secret key. The fixture harness needs the same keys that
// `prysmctl testnet generate-genesis` used, because the validator client signs
// blocks with the matching secret keys.
//
//   index 0 -> sha256(uint32_le(0) || 28 zero bytes) -> mod r -> key-0.hex
//   index 1 -> sha256(uint32_le(1) || 28 zero bytes) -> mod r -> key-1.hex
const std = @import("std");
const blst = @import("blst");

/// Write deterministic mock-genesis validator keys as hex files.
pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 3) return error.UnexpectedArgument;
    const output_dir = args[1];
    const count = try std.fmt.parseInt(u32, args[2], 10);

    for (0..count) |index| {
        var input = [_]u8{0} ** 32;
        std.mem.writeInt(u32, input[0..4], @intCast(index), .little);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&input, &digest, .{});

        // Prysm interprets the digest little-endian before reducing modulo r.
        var reduced_input: [32]u8 = undefined;
        for (&reduced_input, digest) |*out, byte| out.* = byte;
        std.mem.reverse(u8, &reduced_input);

        var secret = blst.SecretKey{};
        if (!blst.c.scalar_from_be_bytes(&secret.key, &reduced_input, reduced_input.len)) return error.ZeroSecretKey;
        defer secret.deinit();
        if (!blst.c.sk_check(&secret.key)) return error.InvalidSecretKey;

        var encoded: [32]u8 = undefined;
        blst.c.bendian_from_scalar(&encoded, &secret.key);
        const name = try std.fmt.allocPrint(allocator, "key-{d}.hex", .{index});
        const path = try std.fs.path.join(allocator, &.{ output_dir, name });
        const text = try std.fmt.allocPrint(allocator, "0x{s}\n", .{std.fmt.bytesToHex(encoded, .lower)});
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = text });
    }
}

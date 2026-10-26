// A local interoperability probe drives one Osaka payload from an authenticated
// execution client. The supplied genesis hash is the forkchoice head; the
// builder returns a payload, then newPayload validates it before head change.
const std = @import("std");
const client_mod = @import("engine_client");
const consensus = @import("consensus");

/// Runs one authenticated builder and validation flow against a local engine.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.ExpectedUrlJwtFileAndGenesisHash;
    const secret_hex = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], a, .limited(128));
    const trimmed = std.mem.trim(u8, secret_hex, " \r\n\t");
    if (trimmed.len != 64) return error.InvalidJwtSecret;
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, trimmed);
    if (args[3].len != 66 or !std.mem.startsWith(u8, args[3], "0x")) return error.InvalidGenesisHash;
    var genesis: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&genesis, args[3][2..]);
    var client = try client_mod.Client.init(a, init.io, args[1], secret, .osaka);
    defer client.deinit();
    const engine = client.interface();
    const zero = [_]u8{0} ** 32;
    const attrs: consensus.PayloadAttributes = .{ .timestamp = 1, .prev_randao = zero, .fee_recipient = .{0} ** 20, .withdrawals = &.{}, .parent_beacon_block_root = zero };
    const state: consensus.ForkchoiceState = .{ .head_block_hash = genesis, .safe_block_hash = genesis, .finalized_block_hash = genesis };
    const update = try engine.forkchoiceUpdated(state, attrs);
    if (update.verdict.status != .valid) return error.ForkchoiceRejected;
    const built = try engine.getPayload(update.payload_id orelse return error.MissingPayloadId);
    const verdict = try engine.verify(.{ .payload = &built.payload, .versioned_hashes = &.{}, .parent_beacon_block_root = zero, .execution_requests = &built.requests });
    if (verdict.status != .valid) return error.PayloadRejected;
    const selected = try engine.forkchoiceUpdated(.{ .head_block_hash = built.payload.block_hash, .safe_block_hash = genesis, .finalized_block_hash = genesis }, null);
    if (selected.verdict.status != .valid) return error.HeadRejected;
    try std.Io.File.stdout().writeStreamingAll(init.io, "Osaka Engine API: capability exchange, forkchoiceUpdatedV3, getPayloadV5, newPayloadV4, and head selection succeeded\n");
}

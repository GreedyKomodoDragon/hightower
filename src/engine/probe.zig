// A local interoperability probe drives one Osaka payload from an authenticated
// builder. With a second URL it submits the Hightower-built payload to Geth;
// each engine must validate the payload before selecting it as head.
const std = @import("std");
const client_mod = @import("engine_client");
const consensus = @import("consensus");

/// Runs one authenticated builder and validation flow against a local engine.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 and args.len != 5) return error.ExpectedBuilderUrlOptionalValidatorUrlJwtFileAndGenesisHash;
    const offset: usize = if (args.len == 5) 1 else 0;
    const secret_hex = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2 + offset], a, .limited(128));
    const trimmed = std.mem.trim(u8, secret_hex, " \r\n\t");
    if (trimmed.len != 64) return error.InvalidJwtSecret;
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, trimmed);
    if (args[3 + offset].len != 66 or !std.mem.startsWith(u8, args[3 + offset], "0x")) return error.InvalidGenesisHash;
    var genesis: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&genesis, args[3 + offset][2..]);
    var client = try client_mod.Client.init(a, init.io, args[1], secret, .osaka);
    defer client.deinit();
    const engine = client.interface();
    var validator = if (args.len == 5) try client_mod.Client.init(a, init.io, args[2], secret, .osaka) else null;
    defer if (validator) |*other| other.deinit();
    const zero = [_]u8{0} ** 32;
    const attrs: consensus.PayloadAttributes = .{ .timestamp = 1, .prev_randao = zero, .fee_recipient = .{0} ** 20, .withdrawals = &.{}, .parent_beacon_block_root = zero };
    const state: consensus.ForkchoiceState = .{ .head_block_hash = genesis, .safe_block_hash = genesis, .finalized_block_hash = genesis };
    const update = try engine.forkchoiceUpdated(state, attrs);
    if (update.verdict.status != .valid) return error.ForkchoiceRejected;
    const built = try engine.getPayload(update.payload_id orelse return error.MissingPayloadId);
    const target = if (validator) |*other| other.interface() else engine;
    const verdict = try target.verify(.{ .payload = &built.payload, .versioned_hashes = &.{}, .parent_beacon_block_root = zero, .execution_requests = &built.requests });
    if (verdict.status != .valid) return error.PayloadRejected;
    const selected = try target.forkchoiceUpdated(.{ .head_block_hash = built.payload.block_hash, .safe_block_hash = genesis, .finalized_block_hash = genesis }, null);
    if (selected.verdict.status != .valid) return error.HeadRejected;
    try std.Io.File.stdout().writeStreamingAll(init.io, if (validator != null) "Osaka Engine API: Geth accepted Hightower payload and selected head\n" else "Osaka Engine API: capability exchange, forkchoiceUpdatedV3, getPayloadV5, newPayloadV4, and head selection succeeded\n");
}

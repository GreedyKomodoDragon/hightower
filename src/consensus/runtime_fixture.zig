// A Fulu anchor and its ordered successor blocks seed a local peer. The
// saved fork-choice head is slot 2; a second process can request both blocks.
// Pinned synthetic fixtures use a test Engine, while supplied Prysm blocks
// are checked against the paired execution client before storage.
//
//   anchor (0) -> successor (1) -> successor (2)
const std = @import("std");
const consensus = @import("consensus");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const engine_client = @import("engine_client");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

/// Run mainnet fixture work on a stack large enough for the fixed SSZ state arrays.
pub fn main(init: std.process.Init) !void {
    var task = Task{ .init = init };
    const thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 * 1024 }, Task.run, .{&task});
    thread.join();
    if (task.failure) |err| return err;
}

const Task = struct {
    init: std.process.Init,
    failure: ?anyerror = null,

    /// Preserve the worker's failure for the process entry point.
    fn run(self: *Task) void {
        writeFixture(self.init) catch |err| {
            self.failure = err;
        };
    }
};

/// Write an anchor and validated source snapshot into a chosen directory.
fn writeFixture(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2 and args.len != 8) return error.ExpectedOutputDirectoryAndOptionalSignedBlocks;
    const fixtures = consensus.fixtureRunner;
    try std.Io.Dir.cwd().createDirPath(init.io, args[1]);
    const dir = try std.Io.Dir.cwd().openDir(init.io, args[1], .{ .iterate = true });
    defer dir.close(init.io);
    const state = if (args.len == 8) blk: {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], allocator, .limited(64 * 1024 * 1024));
        var input: std.Io.Reader = .fixed(bytes);
        break :blk try ssz.deserialize(allocator, fulu.BeaconState, &input);
    } else try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    const block_bytes = if (args.len == 8) blk: {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[3], allocator, .limited(16 * 1024 * 1024));
        var input: std.Io.Reader = .fixed(bytes);
        const signed = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &input);
        break :blk try ssz.serializeAlloc(allocator, signed.message);
    } else try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    const state_bytes = try ssz.serializeAlloc(allocator, state);
    try dir.writeFile(init.io, .{ .sub_path = "anchor-state.ssz", .data = state_bytes });
    try dir.writeFile(init.io, .{ .sub_path = "anchor-block.ssz", .data = block_bytes });
    try dir.createDirPath(init.io, "source");
    const source = try dir.openDir(init.io, "source", .{ .iterate = true });
    defer source.close(init.io);
    var store = try consensus.initForkChoiceStore(allocator, &state, &block);
    defer store.deinit();
    var seed = [_]u8{0} ** 32;
    seed[31] = 1;
    const key = try Ecdsa.KeyPair.generateDeterministic(seed);
    const encoded = try consensus.ENR.encode(allocator, key, .{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 1, .tcp_port = 1, .fork_id = .{0} ** 16, .next_fork_digest = .{0} ** 4, .custody_group_count = 128 });
    const identity = (try consensus.ENR.decode(allocator, encoded)).node_id;
    var columns = try consensus.DataColumns.Store.open(allocator, init.io, source, "columns", state.genesis_validators_root, identity, 128);
    defer columns.deinit();
    var setup = @import("execution").kzg.Settings{};
    var fake_engine = consensus.TestEngine{ .status = .valid };
    var client: ?engine_client.Client = null;
    if (args.len == 8) {
        const raw = try std.Io.Dir.cwd().readFileAlloc(init.io, args[7], allocator, .limited(128));
        const hex = std.mem.trim(u8, raw, " \r\n\t");
        if (hex.len != 64) return error.InvalidJwtSecret;
        var secret: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&secret, hex);
        client = try engine_client.Client.init(allocator, init.io, args[6], secret, .osaka);
    }
    defer if (client) |*value| value.deinit();
    const engine = if (client) |*value| value.interface() else fake_engine.interface();
    var coordinator = consensus.PeerSync.Coordinator{ .allocator = allocator, .io = init.io, .dir = source, .store = &store, .columns = &columns, .settings = &setup, .engine = engine, .head = try merkle.HashTreeRoot(allocator, block), .next_slot = 1 };
    var fixture_hashes: [3][64]u8 = undefined;
    fixture_hashes[0] = std.fmt.bytesToHex(state.latest_execution_payload_header.block_hash, .lower);
    for (0..2) |index| {
        const next = if (args.len == 8) blk: {
            const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[4 + index], allocator, .limited(16 * 1024 * 1024));
            var input: std.Io.Reader = .fixed(bytes);
            break :blk try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &input);
        } else try fixtures.decodeBlock(allocator, fixtures.fork_choice_heavier_blocks[index]);
        fixture_hashes[index + 1] = std.fmt.bytesToHex(next.message.body.execution_payload.block_hash, .lower);
        _ = try coordinator.importBlocks(null, &.{next}, index + 1, 1);
    }
    const hashes = try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n", .{ fixture_hashes[0], fixture_hashes[1], fixture_hashes[2] });
    try dir.writeFile(init.io, .{ .sub_path = "execution.fixture-hashes", .data = hashes });
    const output = try std.fmt.allocPrint(allocator, "0x{s}\n", .{std.fmt.bytesToHex(coordinator.head, .lower)});
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

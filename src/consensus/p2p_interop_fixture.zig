// A Fulu block commits to blobs whose data-column sidecars carry availability
// samples. This loopback fixture relays one slot from a trusted local Prysm
// producer to a fresh Prysm node. It dials the producer, fetches the slot-1
// block and all 128 sidecars, closes that connection, then dials the fresh
// node, publishes the block and columns, and serves Req/Resp. The order matters because the
// relay has one active peer at a time. The producer is started by CI, so
// sidecar storage skips proposer and KZG checks that need parent state.
//
//   producer Prysm -> Hightower fetch -> disk columns
//   fresh Prysm <- Hightower gossip and Req/Resp <- block + columns
// One block is relayed; the fixture exits after a bounded serving window.
const std = @import("std");
const consensus = @import("consensus");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const wire = consensus.P2PWire;
const requests = consensus.P2PRequests;
const columns = consensus.DataColumns;

/// Relay one slot from a trusted producer ENR to a fresh consumer ENR.
pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 6) return error.UnexpectedArgument;
    const producer_enr_path = args[3];
    const consumer_enr_path = args[4];
    const result_path = args[5];
    if (args[1].len != 66 or !std.mem.startsWith(u8, args[1], "0x")) return error.InvalidGenesisRoot;
    if (args[2].len != 10 or !std.mem.startsWith(u8, args[2], "0x")) return error.InvalidForkVersion;
    var genesis_root: fulu.Root = undefined;
    _ = try std.fmt.hexToBytes(&genesis_root, args[1][2..]);
    var fulu_version: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fulu_version, args[2][2..]);
    const blob_schedule = [_]consensus.BlobParameters{.{ .epoch = 0, .max_blobs_per_block = 9 }};
    const digest = consensus.computeForkDigest(fulu_version, genesis_root, 0, &blob_schedule);

    var seed: [32]u8 = undefined;
    init.io.random(&seed);
    const key = try Ecdsa.KeyPair.generateDeterministic(seed);
    var fork_id = [_]u8{0} ** 16;
    @memcpy(fork_id[0..4], &digest);
    const local = consensus.ENR.Local{
        .sequence = 1,
        .ip = .{ 127, 0, 0, 1 },
        .udp_port = 0,
        .tcp_port = 1,
        .fork_id = fork_id,
        .next_fork_digest = .{0} ** 4,
        .custody_group_count = 128,
    };
    var discovery = try consensus.Discv5Discovery.Service.init(allocator, init.io, key, local, 16);
    defer discovery.deinit();

    const config = consensus.P2PIngress.Config{
        .genesis_validators_root = genesis_root,
        .fulu_version = fulu_version,
        .fulu_epoch = 0,
        .blob_schedule = &blob_schedule,
    };
    const Noop = struct {
        /// Accept a block after the transport and fork gates pass.
        fn block(_: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {}
        /// Accept an attestation after the transport and fork gates pass.
        fn attestation(_: *anyopaque, _: *const fulu.Attestation) !void {}
        /// Accept an aggregate after the transport and fork gates pass.
        fn aggregate(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    };
    var dummy: u8 = 0;
    var service = try consensus.P2PGossip.Service.init(
        allocator,
        config,
        digest,
        &.{},
        2,
        3,
        .{ .context = &dummy, .validate = Noop.block },
        .{ .context = &dummy, .validate = Noop.attestation },
        .{ .context = &dummy, .validate = Noop.aggregate },
        null,
    );
    defer service.deinit();

    const store_path = try std.fmt.allocPrint(allocator, "hightower-p2p-interop-{d}", .{std.Io.Clock.awake.now(init.io).nanoseconds});
    var store = try columns.Store.open(allocator, init.io, std.Io.Dir.cwd(), store_path, genesis_root, discovery.local_record.node_id, columns.column_count);
    defer store.deinit();
    defer std.Io.Dir.cwd().deleteTree(init.io, store_path) catch {};

    const producer_enr = try waitForEnr(allocator, init.io, producer_enr_path);
    try discovery.addTrusted(producer_enr);

    const status = consensus.P2PControl.Status{
        .fork_digest = digest,
        .finalized_root = .{0} ** 32,
        .finalized_epoch = 0,
        .head_root = .{0} ** 32,
        .head_slot = 0,
        .earliest_available_slot = 0,
    };
    const metadata = consensus.P2PControl.MetaData{
        .seq_number = 1,
        .attnets = .{ .data = [_]bool{false} ** 64 },
        .syncnets = .{ .data = [_]bool{false} ** 4 },
        .custody_group_count = 128,
    };

    var producer = try consensus.P2PPeer.Peer.dial(allocator, init.io, key, &discovery, &service, status, metadata, producer_enr.node_id, null);
    var fetched = try producer.fetchBlocksByRange(0, 2, 1);
    defer fetched.deinit();
    var selected: ?usize = null;
    for (fetched.items.items, 0..) |block, index| {
        if (block.message.slot == 1) selected = index;
    }
    const block_index = selected orelse return error.MissingSlotOne;
    const block = &fetched.items.items[block_index];
    const block_root = try merkle.HashTreeRoot(allocator, block.message);

    var indices: [columns.column_count]u64 = undefined;
    for (&indices, 0..) |*index, value| index.* = value;
    const request = requests.ByRangeRequest{ .start_slot = 1, .count = 1, .columns = .{ .data = &indices } };
    const request_ssz = try ssz.serializeAlloc(allocator, request);
    defer allocator.free(request_ssz);
    const encoded = try wire.encodePayload(allocator, request_ssz, wire.max_payload_size);
    defer allocator.free(encoded);
    var chunks = try producer.requestChunks(.columns_by_range, encoded, columns.column_count);
    defer chunks.deinit();
    var stored: usize = 0;
    for (chunks.items.items) |*chunk| {
        if (chunk.code != .success or chunk.fork_digest == null or !std.mem.eql(u8, &chunk.fork_digest.?, &digest)) return error.InvalidResponse;
        var reader: std.Io.Reader = .fixed(chunk.payload);
        const sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &reader);
        defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, sidecar);
        if (sidecar.signed_block_header.message.slot != 1) return error.WrongSlot;
        try store.putInterop(&sidecar, &block.message);
        stored += 1;
    }
    if (stored != columns.column_count) return error.MissingColumns;
    producer.deinit();

    const Lookup = struct {
        block: *const fulu.SignedBeaconBlock,
        root: fulu.Root,

        /// Return the retained block when its message root matches.
        fn byRoot(context: *anyopaque, root: fulu.Root) ?fulu.SignedBeaconBlock {
            const self: *@This() = @ptrCast(@alignCast(context));
            return if (std.mem.eql(u8, &self.root, &root)) self.block.* else null;
        }

        /// Return the retained root only at the relayed slot.
        fn atSlot(context: *anyopaque, slot: u64) ?fulu.Root {
            const self: *@This() = @ptrCast(@alignCast(context));
            return if (self.block.message.slot == slot) self.root else null;
        }
    };
    var lookup = Lookup{ .block = block, .root = block_root };
    const routes = consensus.P2PPeer.Routes{
        .blocks = .{ .context = &lookup, .by_root = Lookup.byRoot, .root_at_slot = Lookup.atSlot },
        .columns = &store,
        .canonical = .{ .context = &lookup, .root_at_slot = Lookup.atSlot },
    };

    const fresh_status = consensus.P2PControl.Status{
        .fork_digest = digest,
        .finalized_root = .{0} ** 32,
        .finalized_epoch = 0,
        .head_root = block_root,
        .head_slot = 1,
        .earliest_available_slot = 0,
    };
    const consumer_enr = try waitForEnr(allocator, init.io, consumer_enr_path);
    try discovery.addTrusted(consumer_enr);
    var consumer = connected: {
        for (0..3) |attempt| {
            const current = consensus.P2PPeer.Peer.dial(allocator, init.io, key, &discovery, &service, fresh_status, metadata, consumer_enr.node_id, routes) catch |err| {
                std.log.warn("fresh Prysm handshake attempt {d}: {s}", .{ attempt + 1, @errorName(err) });
                if (err != error.StatusTimeout or attempt == 2) return err;
                continue;
            };
            break :connected current;
        }
        unreachable;
    };
    defer consumer.deinit();
    const block_ssz = try ssz.serializeAlloc(allocator, block.*);
    defer allocator.free(block_ssz);

    // The fresh supernode announces every column it can accept. Poll that
    // advertisement instead of guessing when Prysm finishes starting up.
    const ready_deadline = std.Io.Clock.awake.now(init.io).nanoseconds + 30 * std.time.ns_per_s;
    while (true) {
        const columns_ready = if (consumer.remoteColumnMask()) |mask|
            mask[0] == std.math.maxInt(u64) and mask[1] == std.math.maxInt(u64)
        else
            false;
        if (consumer.remoteBlockSubscribed() and columns_ready) break;
        if (std.Io.Clock.awake.now(init.io).nanoseconds >= ready_deadline) return error.ConsumerSubscriptionsNotReady;
        consumer.step() catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
    }

    try consumer.publish(service.block_topic, block_ssz);
    for (0..columns.column_count) |index| {
        const sidecar_bytes = (try store.get(block_root, index)) orelse return error.MissingColumn;
        defer allocator.free(sidecar_bytes);
        const topic = try wire.topicName(allocator, digest, .data_column, @intCast(index));
        defer allocator.free(topic);
        try consumer.publish(topic, sidecar_bytes);
    }

    // Keep serving requests while Prysm imports the relayed block and columns.
    const serve_deadline = std.Io.Clock.awake.now(init.io).nanoseconds + 45 * std.time.ns_per_s;
    while (std.Io.Clock.awake.now(init.io).nanoseconds < serve_deadline) {
        consumer.step() catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
    }

    const result = try std.json.Stringify.valueAlloc(allocator, .{
        .slot = @as(u64, 1),
        .block_root = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.bytesToHex(block_root, .lower)}),
        .columns = stored,
    }, .{});
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = result_path, .data = result });
}

/// Wait for the harness to write a peer's signed ENR, then decode it.
fn waitForEnr(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !consensus.ENR.Record {
    while (true) {
        const raw = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(2048)) catch |err| switch (err) {
            error.FileNotFound => {
                try std.Io.sleep(io, .fromMilliseconds(100), .awake);
                continue;
            },
            else => return err,
        };
        defer allocator.free(raw);
        const text = std.mem.trim(u8, raw, " \r\n\t");
        if (text.len == 0) {
            try std.Io.sleep(io, .fromMilliseconds(100), .awake);
            continue;
        }
        const encoded = if (std.mem.startsWith(u8, text, "enr:")) text[4..] else text;
        const length = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch return error.InvalidEnr;
        const bytes = try allocator.alloc(u8, length);
        defer allocator.free(bytes);
        std.base64.url_safe_no_pad.Decoder.decode(bytes, encoded) catch return error.InvalidEnr;
        return consensus.ENR.decode(allocator, bytes);
    }
}

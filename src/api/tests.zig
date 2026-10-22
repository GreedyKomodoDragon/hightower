// A fork-choice head selects the canonical branch; checkpoint roots identify
// finalized or justified history. API tests use a validated anchor and a local
// HTTP client after that store is initialized, then check identifier routing
// and the JSON shape exposed to external readers.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const ssz = @import("ssz");
const consensus = @import("consensus");
const api = @import("api");
const fixtures = consensus.fixtureRunner;

/// Treat fixture execution payloads as valid after consensus checks them.
fn validPayload(_: *anyopaque, _: consensus.NewPayloadRequest) anyerror!consensus.PayloadStatus {
    return .valid;
}

/// Mark pinned fixture block data available for import.
fn available(_: *anyopaque, _: fulu.Root) anyerror!bool {
    return true;
}

test "Beacon API resolves canonical roots and rejects invalid requests" {
    const allocator = std.testing.allocator;
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    var store = try consensus.initForkChoiceStore(allocator, &state, &block);
    defer store.deinit();
    const metadata = api.Metadata{ .genesis_fork_version = .{ 0, 0, 0, 0 } };
    const paths = [_][]const u8{
        "/eth/v1/node/health",                "/eth/v1/node/syncing",                            "/eth/v1/beacon/genesis",
        "/eth/v1/beacon/blocks/head/root",    "/eth/v1/beacon/blocks/finalized/root",            "/eth/v1/beacon/blocks/genesis/root",
        "/eth/v1/beacon/blocks/0/root",       "/eth/v1/beacon/states/head/root",                 "/eth/v1/beacon/states/justified/root",
        "/eth/v1/beacon/states/genesis/root", "/eth/v1/beacon/states/head/finality_checkpoints",
    };
    for (paths) |path| {
        const response = try api.dispatch(allocator, &store, metadata, path);
        defer response.deinit(allocator);
        try std.testing.expectEqual(std.http.Status.ok, response.status);
        if (response.body.len != 0) {
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, response.body, .{});
            defer parsed.deinit();
            try std.testing.expect(parsed.value.object.contains("data"));
            const data = parsed.value.object.get("data").?.object;
            if (std.mem.eql(u8, path, "/eth/v1/node/syncing")) {
                try std.testing.expect(data.contains("head_slot") and data.contains("sync_distance") and data.contains("is_syncing") and data.contains("is_optimistic") and data.contains("el_offline"));
                try std.testing.expectEqualStrings("0", data.get("head_slot").?.string);
                try std.testing.expectEqualStrings("0", data.get("sync_distance").?.string);
            } else if (std.mem.eql(u8, path, "/eth/v1/beacon/genesis")) {
                try std.testing.expect(data.contains("genesis_time") and data.contains("genesis_validators_root") and data.contains("genesis_fork_version"));
                try std.testing.expectEqual(@as(usize, 66), data.get("genesis_validators_root").?.string.len);
                try std.testing.expectEqual(@as(usize, 10), data.get("genesis_fork_version").?.string.len);
            } else if (std.mem.endsWith(u8, path, "/finality_checkpoints")) {
                try std.testing.expect(data.contains("previous_justified") and data.contains("current_justified") and data.contains("finalized"));
                const checkpoint = data.get("current_justified").?.object;
                try std.testing.expectEqualStrings("0", checkpoint.get("epoch").?.string);
                try std.testing.expectEqual(@as(usize, 66), checkpoint.get("root").?.string.len);
            } else {
                try std.testing.expect(data.contains("root"));
                try std.testing.expectEqual(@as(usize, 66), data.get("root").?.string.len);
            }
            if (std.mem.startsWith(u8, path, "/eth/v1/beacon/blocks/") or std.mem.startsWith(u8, path, "/eth/v1/beacon/states/")) {
                try std.testing.expect(parsed.value.object.contains("execution_optimistic") and parsed.value.object.contains("finalized"));
            }
        }
    }
    const cases = [_]struct { path: []const u8, status: std.http.Status }{
        .{ .path = "/eth/v1/beacon/blocks/nope/root", .status = .bad_request },
        .{ .path = "/eth/v1/beacon/blocks/0x1234/root", .status = .bad_request },
        .{ .path = "/eth/v1/beacon/blocks/999/root", .status = .not_found },
        .{ .path = "/eth/v1/beacon/states/999/root", .status = .not_found },
    };
    for (cases) |case| {
        const response = try api.dispatch(allocator, &store, metadata, case.path);
        defer response.deinit(allocator);
        try std.testing.expectEqual(case.status, response.status);
    }
    const block_root = try consensus.getForkChoiceHead(&store);
    const block_path = try std.fmt.allocPrint(allocator, "/eth/v1/beacon/blocks/0x{s}/root", .{std.fmt.bytesToHex(block_root, .lower)});
    defer allocator.free(block_path);
    const by_block_root = try api.dispatch(allocator, &store, metadata, block_path);
    defer by_block_root.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.ok, by_block_root.status);
    const state_root = try merkle.HashTreeRoot(allocator, state);
    const state_path = try std.fmt.allocPrint(allocator, "/eth/v1/beacon/states/0x{s}/root", .{std.fmt.bytesToHex(state_root, .lower)});
    defer allocator.free(state_path);
    const by_state_root = try api.dispatch(allocator, &store, metadata, state_path);
    defer by_state_root.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.ok, by_state_root.status);
    const unknown_root = try api.dispatch(allocator, &store, metadata, "/eth/v1/beacon/blocks/0x0000000000000000000000000000000000000000000000000000000000000000/root");
    defer unknown_root.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.not_found, unknown_root.status);
    const unavailable = try api.dispatch(allocator, null, metadata, "/eth/v1/beacon/genesis");
    defer unavailable.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.service_unavailable, unavailable.status);
    var not_ready = metadata;
    not_ready.ready = false;
    const unavailable_store = try api.dispatch(allocator, &store, not_ready, "/eth/v1/beacon/blocks/head/root");
    defer unavailable_store.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.service_unavailable, unavailable_store.status);
    var syncing = metadata;
    syncing.is_syncing = true;
    const health = try api.dispatch(allocator, &store, syncing, "/eth/v1/node/health");
    defer health.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.partial_content, health.status);
}

test "Beacon API returns a JSON response over a local connection" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(block_bytes);
    var block_reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &block_reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    var store = try consensus.initForkChoiceStore(allocator, &state, &block);
    defer store.deinit();
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    var write_buffer: [256]u8 = undefined;
    var client_writer = client_stream.writer(io, &write_buffer);
    try client_writer.interface.writeAll("GET /eth/v1/node/syncing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try client_writer.interface.flush();
    try api.serveConnection(allocator, io, server_stream, &store, .{ .genesis_fork_version = .{ 0, 0, 0, 0 } });
    var buffer: [4096]u8 = undefined;
    var reader = client_stream.reader(io, &buffer);
    const response = try reader.interface.allocRemaining(allocator, .limited(4096));
    defer allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expect(std.mem.indexOf(u8, response, "content-type: application/json") != null);
    const body_start = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.MissingBody;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, response[body_start + 4 ..], .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("data").?.object.contains("head_slot"));
}

test "Beacon API accepts stored noncanonical block and state roots" {
    const allocator = std.testing.allocator;
    const state = try fixtures.decodeState(allocator, fixtures.fork_choice_anchor_state);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, fixtures.fork_choice_anchor_block);
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    var store = try consensus.initForkChoiceStore(allocator, &state, &block);
    defer store.deinit();
    var context: u8 = 0;
    const engine = consensus.ExecutionEngine{ .context = &context, .verify_and_notify_new_payload = validPayload };
    const availability = consensus.DataAvailabilityCheck{ .context = &context, .is_available = available };
    for (fixtures.fork_choice_heavier_blocks, [_]u64{ 6, 12, 18, 18 }) |bytes, time| {
        try consensus.onForkChoiceTick(&store, time);
        const signed = try fixtures.decodeBlock(allocator, bytes);
        defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
        try consensus.onForkChoiceBlock(&store, signed, engine, availability);
    }
    const head = try consensus.getForkChoiceHead(&store);
    var roots = store.blocks.keyIterator();
    while (roots.next()) |root| {
        var canonical = head;
        var on_head_chain = false;
        for (0..store.blocks.count()) |_| {
            if (std.mem.eql(u8, root, &canonical)) {
                on_head_chain = true;
                break;
            }
            const parent = store.blocks.get(canonical).?.parent_root;
            if (!store.blocks.contains(parent)) break;
            canonical = parent;
        }
        if (on_head_chain) continue;
        const path = try std.fmt.allocPrint(allocator, "/eth/v1/beacon/blocks/0x{s}/root", .{std.fmt.bytesToHex(root.*, .lower)});
        defer allocator.free(path);
        const response = try api.dispatch(allocator, &store, .{ .genesis_fork_version = .{ 0, 0, 0, 0 } }, path);
        defer response.deinit(allocator);
        try std.testing.expectEqual(std.http.Status.ok, response.status);
        const branch_state = store.block_states.get(root.*).?;
        const state_root = try merkle.HashTreeRoot(allocator, branch_state);
        const state_path = try std.fmt.allocPrint(allocator, "/eth/v1/beacon/states/0x{s}/root", .{std.fmt.bytesToHex(state_root, .lower)});
        defer allocator.free(state_path);
        const state_response = try api.dispatch(allocator, &store, .{ .genesis_fork_version = .{ 0, 0, 0, 0 } }, state_path);
        defer state_response.deinit(allocator);
        try std.testing.expectEqual(std.http.Status.ok, state_response.status);
        return;
    }
    return error.MissingNoncanonicalBranch;
}

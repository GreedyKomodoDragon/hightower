// The Beacon API exposes read-only views of the validated fork-choice store.
// A block root identifies one branch, while a decimal slot selects the block
// on the current canonical head chain. A state root identifies a post-state;
// finality checkpoints describe epochs and roots recorded in that state.
// Imports and ticks must finish before a caller exposes the store to a request.
// shortcut: one connection is served at a time; add runtime coordination when
// the node owns concurrent imports in FULU-028.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const fork_choice = @import("fork_choice.zig");

pub const Metadata = struct {
    ready: bool = true,
    is_syncing: bool = false,
    sync_distance: u64 = 0,
    genesis_fork_version: [4]u8,
};

pub const Response = struct {
    status: std.http.Status,
    body: []u8,

    /// Release the JSON body allocated for this response.
    pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }
};

/// Resolve one bounded GET target against a stable, validated store.
pub fn dispatch(allocator: std.mem.Allocator, store: ?*const fork_choice.Store, metadata: Metadata, target: []const u8) !Response {
    if (target.len > 1024) return reply(allocator, .bad_request, "invalid request target");
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    if (std.mem.eql(u8, path, "/eth/v1/node/health")) {
        if (!metadata.ready or store == null) return reply(allocator, .service_unavailable, "service unavailable");
        return .{ .status = if (metadata.is_syncing) .partial_content else .ok, .body = try allocator.dupe(u8, "") };
    }
    if (!metadata.ready or store == null) return reply(allocator, .service_unavailable, "service unavailable");
    const chain = store.?;
    const head = fork_choice.getHead(chain) catch return reply(allocator, .service_unavailable, "service unavailable");
    const head_block = chain.blocks.get(head) orelse return reply(allocator, .service_unavailable, "service unavailable");
    if (std.mem.eql(u8, path, "/eth/v1/node/syncing")) return .{ .status = .ok, .body = try std.fmt.allocPrint(allocator, "{{\"data\":{{\"head_slot\":\"{d}\",\"sync_distance\":\"{d}\",\"is_syncing\":{s},\"is_optimistic\":false,\"el_offline\":false}}}}", .{ head_block.slot, metadata.sync_distance, if (metadata.is_syncing) "true" else "false" }) };
    if (std.mem.eql(u8, path, "/eth/v1/beacon/genesis")) {
        const genesis = chain.block_states.get(chain.finalized_checkpoint.root) orelse return reply(allocator, .service_unavailable, "service unavailable");
        return .{ .status = .ok, .body = try std.fmt.allocPrint(allocator, "{{\"data\":{{\"genesis_time\":\"{d}\",\"genesis_validators_root\":\"0x{s}\",\"genesis_fork_version\":\"0x{s}\"}}}}", .{ chain.genesis_time, std.fmt.bytesToHex(genesis.genesis_validators_root, .lower), std.fmt.bytesToHex(metadata.genesis_fork_version, .lower) }) };
    }
    const block_prefix = "/eth/v1/beacon/blocks/";
    const state_prefix = "/eth/v1/beacon/states/";
    if (std.mem.startsWith(u8, path, block_prefix) and std.mem.endsWith(u8, path, "/root")) {
        const id = path[block_prefix.len .. path.len - "/root".len];
        const root = resolveBlock(chain, head, id) catch |err| return idError(allocator, err);
        return .{ .status = .ok, .body = try std.fmt.allocPrint(allocator, "{{\"data\":{{\"root\":\"0x{s}\"}},\"execution_optimistic\":false,\"finalized\":{s}}}", .{ std.fmt.bytesToHex(root, .lower), if (isFinalized(chain, root)) "true" else "false" }) };
    }
    if (std.mem.startsWith(u8, path, state_prefix)) {
        const finality = std.mem.endsWith(u8, path, "/finality_checkpoints");
        const state_root = std.mem.endsWith(u8, path, "/root");
        if (!finality and !state_root) return reply(allocator, .not_found, "not found");
        const suffix_len: usize = if (finality) "/finality_checkpoints".len else "/root".len;
        const id = path[state_prefix.len .. path.len - suffix_len];
        const resolved = resolveState(allocator, chain, head, id) catch |err| return idError(allocator, err);
        if (state_root) return .{ .status = .ok, .body = try std.fmt.allocPrint(allocator, "{{\"data\":{{\"root\":\"0x{s}\"}},\"execution_optimistic\":false,\"finalized\":{s}}}", .{ std.fmt.bytesToHex(resolved.root, .lower), if (isFinalized(chain, resolved.block_root)) "true" else "false" }) };
        const state = resolved.state;
        return .{ .status = .ok, .body = try std.fmt.allocPrint(allocator, "{{\"data\":{{\"previous_justified\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"current_justified\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"finalized\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"execution_optimistic\":false,\"finalized\":{s}}}", .{ state.previous_justified_checkpoint.epoch, std.fmt.bytesToHex(state.previous_justified_checkpoint.root, .lower), state.current_justified_checkpoint.epoch, std.fmt.bytesToHex(state.current_justified_checkpoint.root, .lower), state.finalized_checkpoint.epoch, std.fmt.bytesToHex(state.finalized_checkpoint.root, .lower), if (isFinalized(chain, resolved.block_root)) "true" else "false" }) };
    }
    return reply(allocator, .not_found, "not found");
}

/// Serve one TCP connection with an 8 KiB header bound and no request body.
pub fn serveConnection(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, store: ?*const fork_choice.Store, metadata: Metadata) !void {
    defer stream.close(io);
    var read_buffer: [8192]u8 = undefined;
    var write_buffer: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var writer = stream.writer(io, &write_buffer);
    var server = std.http.Server.init(&reader.interface, &writer.interface);
    var request = server.receiveHead() catch return;
    const result = if (request.head.method != .GET)
        try reply(allocator, .method_not_allowed, "GET required")
    else if (request.head.content_length orelse 0 != 0 or request.head.transfer_encoding != .none)
        try reply(allocator, .payload_too_large, "request body unsupported")
    else
        try dispatch(allocator, store, metadata, request.head.target);
    defer result.deinit(allocator);
    try request.respond(result.body, .{ .status = result.status, .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }} });
}

/// Accept connections until the caller closes or cancels the listening socket.
pub fn serve(allocator: std.mem.Allocator, io: std.Io, listener: *std.Io.net.Server, store: ?*const fork_choice.Store, metadata: Metadata) !void {
    while (true) {
        const stream = try listener.accept(io);
        serveConnection(allocator, io, stream, store, metadata) catch {};
    }
}

/// Resolve a block identifier, selecting the canonical block for a slot.
fn resolveBlock(store: *const fork_choice.Store, head: fulu.Root, id: []const u8) !fulu.Root {
    if (std.mem.eql(u8, id, "head")) return head;
    if (std.mem.eql(u8, id, "finalized")) return store.finalized_checkpoint.root;
    if (std.mem.eql(u8, id, "genesis")) return genesisRoot(store, head);
    if (std.mem.startsWith(u8, id, "0x")) {
        if (id.len != 66) return error.MalformedId;
        var root: fulu.Root = undefined;
        _ = std.fmt.hexToBytes(&root, id[2..]) catch return error.MalformedId;
        if (!store.blocks.contains(root)) return error.UnknownId;
        return root;
    }
    const slot = parseSlot(id) catch return error.MalformedId;
    var current = head;
    for (0..store.blocks.count()) |_| {
        const block = store.blocks.get(current) orelse return error.UnknownId;
        if (block.slot == slot) return current;
        if (block.slot < slot or !store.blocks.contains(block.parent_root)) return error.UnknownId;
        current = block.parent_root;
    }
    return error.UnknownId;
}

/// Walk to the single stored anchor, which is the available genesis block.
fn genesisRoot(store: *const fork_choice.Store, head: fulu.Root) !fulu.Root {
    var current = head;
    for (0..store.blocks.count()) |_| {
        const block = store.blocks.get(current) orelse return error.UnknownId;
        if (!store.blocks.contains(block.parent_root)) return if (block.slot == 0) current else error.UnknownId;
        current = block.parent_root;
    }
    return error.UnknownId;
}

const ResolvedState = struct { root: fulu.Root, block_root: fulu.Root, state: fulu.BeaconState };

/// Resolve a state by keyword, canonical block slot, or post-state root.
fn resolveState(allocator: std.mem.Allocator, store: *const fork_choice.Store, head: fulu.Root, id: []const u8) !ResolvedState {
    var block_root: fulu.Root = undefined;
    if (std.mem.startsWith(u8, id, "0x")) {
        if (id.len != 66) return error.MalformedId;
        var wanted: fulu.Root = undefined;
        _ = std.fmt.hexToBytes(&wanted, id[2..]) catch return error.MalformedId;
        var states = store.block_states.iterator();
        while (states.next()) |entry| {
            const root = try merkle.HashTreeRoot(allocator, entry.value_ptr.*);
            if (std.mem.eql(u8, &root, &wanted)) return .{ .root = root, .block_root = entry.key_ptr.*, .state = entry.value_ptr.* };
        }
        return error.UnknownId;
    }
    block_root = if (std.mem.eql(u8, id, "justified")) store.justified_checkpoint.root else try resolveBlock(store, head, id);
    const state = store.block_states.get(block_root) orelse return error.UnknownId;
    return .{ .root = try merkle.HashTreeRoot(allocator, state), .block_root = block_root, .state = state };
}

/// Parse a nonempty decimal slot without signs, separators, or overflow.
fn parseSlot(id: []const u8) !u64 {
    if (id.len == 0) return error.MalformedId;
    for (id) |digit| if (digit < '0' or digit > '9') return error.MalformedId;
    return std.fmt.parseInt(u64, id, 10) catch error.MalformedId;
}

/// Report whether a block is at or before the finalized checkpoint on its chain.
fn isFinalized(store: *const fork_choice.Store, root: fulu.Root) bool {
    var current = store.finalized_checkpoint.root;
    for (0..store.blocks.count()) |_| {
        if (std.mem.eql(u8, &current, &root)) return true;
        const block = store.blocks.get(current) orelse return false;
        if (!store.blocks.contains(block.parent_root)) return false;
        current = block.parent_root;
    }
    return false;
}

/// Turn an identifier failure into a Beacon API error response.
fn idError(allocator: std.mem.Allocator, err: anyerror) !Response {
    return switch (err) {
        error.MalformedId => reply(allocator, .bad_request, "invalid identifier"),
        error.UnknownId => reply(allocator, .not_found, "not found"),
        else => err,
    };
}

/// Allocate the common Beacon API error shape.
fn reply(allocator: std.mem.Allocator, status: std.http.Status, message: []const u8) !Response {
    return .{ .status = status, .body = try std.fmt.allocPrint(allocator, "{{\"code\":{d},\"message\":\"{s}\"}}", .{ @intFromEnum(status), message }) };
}

test "Beacon API resolves canonical roots and rejects invalid requests" {
    const allocator = std.testing.allocator;
    const ssz = @import("ssz");
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(block_bytes);
    var reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    var store = try fork_choice.initStore(allocator, &state, &block);
    defer store.deinit();
    const metadata = Metadata{ .genesis_fork_version = .{ 0, 0, 0, 0 } };
    const paths = [_][]const u8{
        "/eth/v1/node/health",                "/eth/v1/node/syncing",                            "/eth/v1/beacon/genesis",
        "/eth/v1/beacon/blocks/head/root",    "/eth/v1/beacon/blocks/finalized/root",            "/eth/v1/beacon/blocks/genesis/root",
        "/eth/v1/beacon/blocks/0/root",       "/eth/v1/beacon/states/head/root",                 "/eth/v1/beacon/states/justified/root",
        "/eth/v1/beacon/states/genesis/root", "/eth/v1/beacon/states/head/finality_checkpoints",
    };
    for (paths) |path| {
        const response = try dispatch(allocator, &store, metadata, path);
        defer response.deinit(allocator);
        try std.testing.expectEqual(std.http.Status.ok, response.status);
        if (response.body.len != 0) {
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, response.body, .{});
            defer parsed.deinit();
            try std.testing.expect(parsed.value.object.contains("data"));
            const data = parsed.value.object.get("data").?.object;
            if (std.mem.eql(u8, path, "/eth/v1/node/syncing")) {
                try std.testing.expect(data.contains("head_slot") and data.contains("sync_distance") and data.contains("is_syncing") and data.contains("is_optimistic") and data.contains("el_offline"));
            } else if (std.mem.eql(u8, path, "/eth/v1/beacon/genesis")) {
                try std.testing.expect(data.contains("genesis_time") and data.contains("genesis_validators_root") and data.contains("genesis_fork_version"));
            } else if (std.mem.endsWith(u8, path, "/finality_checkpoints")) {
                try std.testing.expect(data.contains("previous_justified") and data.contains("current_justified") and data.contains("finalized"));
            } else {
                try std.testing.expect(data.contains("root"));
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
        const response = try dispatch(allocator, &store, metadata, case.path);
        defer response.deinit(allocator);
        try std.testing.expectEqual(case.status, response.status);
    }
    const block_root = try fork_choice.getHead(&store);
    const block_path = try std.fmt.allocPrint(allocator, "/eth/v1/beacon/blocks/0x{s}/root", .{std.fmt.bytesToHex(block_root, .lower)});
    defer allocator.free(block_path);
    const by_block_root = try dispatch(allocator, &store, metadata, block_path);
    defer by_block_root.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.ok, by_block_root.status);
    const state_root = try merkle.HashTreeRoot(allocator, state);
    const state_path = try std.fmt.allocPrint(allocator, "/eth/v1/beacon/states/0x{s}/root", .{std.fmt.bytesToHex(state_root, .lower)});
    defer allocator.free(state_path);
    const by_state_root = try dispatch(allocator, &store, metadata, state_path);
    defer by_state_root.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.ok, by_state_root.status);
    const unknown_root = try dispatch(allocator, &store, metadata, "/eth/v1/beacon/blocks/0x0000000000000000000000000000000000000000000000000000000000000000/root");
    defer unknown_root.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.not_found, unknown_root.status);
    const unavailable = try dispatch(allocator, null, metadata, "/eth/v1/beacon/genesis");
    defer unavailable.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.service_unavailable, unavailable.status);
    var not_ready = metadata;
    not_ready.ready = false;
    const unavailable_store = try dispatch(allocator, &store, not_ready, "/eth/v1/beacon/blocks/head/root");
    defer unavailable_store.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.service_unavailable, unavailable_store.status);
    var syncing = metadata;
    syncing.is_syncing = true;
    const health = try dispatch(allocator, &store, syncing, "/eth/v1/node/health");
    defer health.deinit(allocator);
    try std.testing.expectEqual(std.http.Status.partial_content, health.status);
}

test "Beacon API returns a JSON response over a local connection" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ssz = @import("ssz");
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const block_bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_fork_choice/basic/anchor_block.ssz_snappy"));
    defer allocator.free(block_bytes);
    var block_reader: std.Io.Reader = .fixed(block_bytes);
    const block = try ssz.deserialize(allocator, fulu.BeaconBlock, &block_reader);
    defer ssz.freeDecoded(allocator, fulu.BeaconBlock, block);
    var store = try fork_choice.initStore(allocator, &state, &block);
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
    try serveConnection(allocator, io, server_stream, &store, .{ .genesis_fork_version = .{ 0, 0, 0, 0 } });
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

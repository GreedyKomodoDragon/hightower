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
const consensus = @import("consensus");

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
pub fn dispatch(allocator: std.mem.Allocator, store: ?*const consensus.ForkChoiceStore, metadata: Metadata, target: []const u8) !Response {
    if (target.len > 1024) return reply(allocator, .bad_request, "invalid request target");
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    // shortcut: route matching scans each endpoint, use the router in https://github.com/GreedyKomodoDragon/hightower/issues/111 when implemented.
    if (std.mem.eql(u8, path, "/eth/v1/node/health")) {
        if (!metadata.ready or store == null) return reply(allocator, .service_unavailable, "service unavailable");
        return .{ .status = if (metadata.is_syncing) .partial_content else .ok, .body = try allocator.dupe(u8, "") };
    }
    if (!metadata.ready or store == null) return reply(allocator, .service_unavailable, "service unavailable");
    const chain = store.?;
    const head = consensus.getForkChoiceHead(chain) catch return reply(allocator, .service_unavailable, "service unavailable");
    const head_block = chain.blocks.get(head) orelse return reply(allocator, .service_unavailable, "service unavailable");
    if (std.mem.eql(u8, path, "/eth/v1/node/syncing")) {
        var head_slot_buffer: [20]u8 = undefined;
        var distance_buffer: [20]u8 = undefined;
        return jsonResponse(allocator, .ok, .{ .data = .{
            .head_slot = decimal(head_block.slot, &head_slot_buffer),
            .sync_distance = decimal(metadata.sync_distance, &distance_buffer),
            .is_syncing = metadata.is_syncing,
            .is_optimistic = false,
            .el_offline = false,
        } });
    }
    if (std.mem.eql(u8, path, "/eth/v1/beacon/genesis")) {
        const genesis = chain.block_states.get(chain.finalized_checkpoint.root) orelse return reply(allocator, .service_unavailable, "service unavailable");
        var time_buffer: [20]u8 = undefined;
        return jsonResponse(allocator, .ok, .{ .data = .{
            .genesis_time = decimal(chain.genesis_time, &time_buffer),
            .genesis_validators_root = hexBytes(32, genesis.genesis_validators_root),
            .genesis_fork_version = hexBytes(4, metadata.genesis_fork_version),
        } });
    }
    const block_prefix = "/eth/v1/beacon/blocks/";
    const state_prefix = "/eth/v1/beacon/states/";
    if (std.mem.startsWith(u8, path, block_prefix) and std.mem.endsWith(u8, path, "/root")) {
        const id = path[block_prefix.len .. path.len - "/root".len];
        const root = resolveBlock(chain, head, id) catch |err| return idError(allocator, err);
        return jsonResponse(allocator, .ok, .{ .data = .{ .root = hexBytes(32, root) }, .execution_optimistic = false, .finalized = isFinalized(chain, root) });
    }
    if (std.mem.startsWith(u8, path, state_prefix)) {
        const finality = std.mem.endsWith(u8, path, "/finality_checkpoints");
        const state_root = std.mem.endsWith(u8, path, "/root");
        if (!finality and !state_root) return reply(allocator, .not_found, "not found");
        const suffix_len: usize = if (finality) "/finality_checkpoints".len else "/root".len;
        const id = path[state_prefix.len .. path.len - suffix_len];
        const resolved = resolveState(allocator, chain, head, id) catch |err| return idError(allocator, err);
        if (state_root) return jsonResponse(allocator, .ok, .{ .data = .{ .root = hexBytes(32, resolved.root) }, .execution_optimistic = false, .finalized = isFinalized(chain, resolved.block_root) });
        const state = resolved.state;
        var epoch_buffers: [3][20]u8 = undefined;
        return jsonResponse(allocator, .ok, .{
            .data = .{
                .previous_justified = jsonCheckpoint(state.previous_justified_checkpoint, &epoch_buffers[0]),
                .current_justified = jsonCheckpoint(state.current_justified_checkpoint, &epoch_buffers[1]),
                .finalized = jsonCheckpoint(state.finalized_checkpoint, &epoch_buffers[2]),
            },
            .execution_optimistic = false,
            .finalized = isFinalized(chain, resolved.block_root),
        });
    }
    return reply(allocator, .not_found, "not found");
}

/// Serve one TCP connection with an 8 KiB header bound and no request body.
pub fn serveConnection(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, store: ?*const consensus.ForkChoiceStore, metadata: Metadata) !void {
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
pub fn serve(allocator: std.mem.Allocator, io: std.Io, listener: *std.Io.net.Server, store: ?*const consensus.ForkChoiceStore, metadata: Metadata) !void {
    while (true) {
        const stream = try listener.accept(io);
        serveConnection(allocator, io, stream, store, metadata) catch {};
    }
}

/// Resolve a block identifier, selecting the canonical block for a slot.
fn resolveBlock(store: *const consensus.ForkChoiceStore, head: fulu.Root, id: []const u8) !fulu.Root {
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
fn genesisRoot(store: *const consensus.ForkChoiceStore, head: fulu.Root) !fulu.Root {
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
fn resolveState(allocator: std.mem.Allocator, store: *const consensus.ForkChoiceStore, head: fulu.Root, id: []const u8) !ResolvedState {
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
fn isFinalized(store: *const consensus.ForkChoiceStore, root: fulu.Root) bool {
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
    return jsonResponse(allocator, status, .{ .code = @intFromEnum(status), .message = message });
}

/// Serialize a typed response body, leaving the returned bytes owned by the caller.
fn jsonResponse(allocator: std.mem.Allocator, status: std.http.Status, payload: anytype) !Response {
    return .{ .status = status, .body = try std.json.Stringify.valueAlloc(allocator, payload, .{}) };
}

/// Format a consensus integer as the Beacon API's decimal string.
fn decimal(value: u64, buffer: *[20]u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{d}", .{value}) catch unreachable;
}

/// Format fixed bytes as a lower-case 0x-prefixed JSON string.
fn hexBytes(comptime n: usize, bytes: [n]u8) [2 + n * 2]u8 {
    var result: [2 + n * 2]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    const digits = std.fmt.bytesToHex(bytes, .lower);
    @memcpy(result[2..], &digits);
    return result;
}

const JsonCheckpoint = struct { epoch: []const u8, root: [66]u8 };

/// Convert a checkpoint to the public epoch/root JSON shape.
fn jsonCheckpoint(checkpoint: fulu.Checkpoint, buffer: *[20]u8) JsonCheckpoint {
    return .{ .epoch = decimal(checkpoint.epoch, buffer), .root = hexBytes(32, checkpoint.root) };
}

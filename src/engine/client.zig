// The consensus engine sends authenticated JSON-RPC to a local execution
// client. New payload validation comes before forkchoice; only a VALID verdict
// permits beacon state transition. A payload build is tied to the chosen
// head and fork, and its borrowed data lives until the next client call.
//
// newPayload -> verdict -> forkchoiceUpdated -> payload ID -> getPayload
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const consensus = @import("consensus");
const wire = @import("engine_wire");
const jwt = @import("engine_jwt");

pub const Fork = enum { paris, shanghai, cancun, prague, osaka };

/// Selects the wire method generation for an active execution fork.
pub fn versions(fork: Fork) struct { new_payload: u8, forkchoice: u8, get_payload: u8 } {
    return switch (fork) {
        .paris => .{ .new_payload = 1, .forkchoice = 1, .get_payload = 1 },
        .shanghai => .{ .new_payload = 2, .forkchoice = 2, .get_payload = 2 },
        .cancun => .{ .new_payload = 3, .forkchoice = 3, .get_payload = 3 },
        .prague => .{ .new_payload = 4, .forkchoice = 3, .get_payload = 4 },
        .osaka => .{ .new_payload = 4, .forkchoice = 3, .get_payload = 5 },
    };
}

/// Owns the HTTP connection pool and the most recent decoded response.
pub const Client = struct {
    allocator: std.mem.Allocator,
    http: std.http.Client,
    arena: std.heap.ArenaAllocator,
    built_arena: std.heap.ArenaAllocator,
    url: []const u8,
    secret: [32]u8,
    fork: Fork,

    /// Creates a client and requires all methods needed by the selected fork.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, url: []const u8, secret: [32]u8, fork: Fork) !Client {
        var self: Client = .{ .allocator = allocator, .http = .{ .allocator = allocator, .io = io }, .arena = std.heap.ArenaAllocator.init(allocator), .built_arena = std.heap.ArenaAllocator.init(allocator), .url = url, .secret = secret, .fork = fork };
        errdefer self.deinit();
        const a = self.arena.allocator();
        const result = try self.call("engine_exchangeCapabilities", &.{wire.array(a)});
        if (result != .array) return error.InvalidEngineResponse;
        const v = versions(fork);
        const needed = [_][]const u8{
            try std.fmt.allocPrint(a, "engine_newPayloadV{d}", .{v.new_payload}),
            try std.fmt.allocPrint(a, "engine_forkchoiceUpdatedV{d}", .{v.forkchoice}),
            try std.fmt.allocPrint(a, "engine_getPayloadV{d}", .{v.get_payload}),
        };
        for (needed) |name| {
            var found = false;
            for (result.array.items) |item| {
                if (item == .string and std.mem.eql(u8, item.string, name)) found = true;
            }
            if (!found) return error.MissingEngineCapability;
        }
        return self;
    }

    /// Releases response storage and HTTP connections.
    pub fn deinit(self: *Client) void {
        self.arena.deinit();
        self.built_arena.deinit();
        self.http.deinit();
    }

    /// Exposes the authenticated callbacks to consensus processing.
    pub fn interface(self: *Client) consensus.ExecutionEngine {
        return .{ .context = self, .verify_and_notify_new_payload = newPayload, .forkchoice_updated = forkchoiceUpdated, .get_payload = getPayload };
    }

    /// Sends the fork-specific payload shape and decodes the engine verdict.
    fn newPayload(context: *anyopaque, request: consensus.NewPayloadRequest) anyerror!consensus.PayloadVerdict {
        const self: *Client = @ptrCast(@alignCast(context));
        _ = self.arena.reset(.free_all);
        const a = self.arena.allocator();
        const v = versions(self.fork);
        var params = wire.array(a);
        try params.array.append(try wire.payloadJson(a, request.payload.*, v.new_payload));
        if (v.new_payload >= 3) {
            var hashes = wire.array(a);
            for (request.versioned_hashes) |hash| try hashes.array.append(try wire.hex(a, &hash));
            try params.array.append(hashes);
            try params.array.append(try wire.hex(a, &request.parent_beacon_block_root));
        }
        if (v.new_payload >= 4) try params.array.append(try requestsJson(a, request.execution_requests.*));
        const name = try std.fmt.allocPrint(a, "engine_newPayloadV{d}", .{v.new_payload});
        return parseVerdict(try self.call(name, params.array.items));
    }

    /// Chooses head, safe, and finalized execution blocks and starts a build.
    fn forkchoiceUpdated(context: *anyopaque, state: consensus.ForkchoiceState, attrs: ?consensus.PayloadAttributes) anyerror!consensus.ForkchoiceResult {
        const self: *Client = @ptrCast(@alignCast(context));
        _ = self.arena.reset(.free_all);
        const a = self.arena.allocator();
        const v = versions(self.fork);
        var choice = wire.object();
        try wire.put(a, &choice, "headBlockHash", try wire.hex(a, &state.head_block_hash));
        try wire.put(a, &choice, "safeBlockHash", try wire.hex(a, &state.safe_block_hash));
        try wire.put(a, &choice, "finalizedBlockHash", try wire.hex(a, &state.finalized_block_hash));
        var attributes: wire.Value = .null;
        if (attrs) |value| {
            attributes = wire.object();
            try wire.put(a, &attributes, "timestamp", try wire.number(a, value.timestamp));
            try wire.put(a, &attributes, "prevRandao", try wire.hex(a, &value.prev_randao));
            try wire.put(a, &attributes, "suggestedFeeRecipient", try wire.hex(a, &value.fee_recipient));
            if (v.forkchoice >= 2) {
                var withdrawals = wire.array(a);
                for (value.withdrawals) |w| {
                    var item = wire.object();
                    try wire.put(a, &item, "index", try wire.number(a, w.index));
                    try wire.put(a, &item, "validatorIndex", try wire.number(a, w.validator_index));
                    try wire.put(a, &item, "address", try wire.hex(a, &w.address));
                    try wire.put(a, &item, "amount", try wire.number(a, w.amount));
                    try withdrawals.array.append(item);
                }
                try wire.put(a, &attributes, "withdrawals", withdrawals);
            }
            if (v.forkchoice >= 3) try wire.put(a, &attributes, "parentBeaconBlockRoot", try wire.hex(a, &value.parent_beacon_block_root));
        }
        const name = try std.fmt.allocPrint(a, "engine_forkchoiceUpdatedV{d}", .{v.forkchoice});
        const response = try self.call(name, &.{ choice, attributes });
        const verdict = try parseVerdict(try wire.field(response, "payloadStatus"));
        const id_value = try wire.field(response, "payloadId");
        const id: ?u64 = if (id_value == .null) null else std.mem.readInt(u64, &(try wire.fixed(8, id_value)), .big);
        return .{ .verdict = verdict, .payload_id = id };
    }

    /// Decodes a previously requested builder payload and its blob commitments.
    fn getPayload(context: *anyopaque, id: u64) anyerror!consensus.BuiltPayload {
        const self: *Client = @ptrCast(@alignCast(context));
        _ = self.arena.reset(.free_all);
        _ = self.built_arena.reset(.free_all);
        const a = self.arena.allocator();
        const owner = self.built_arena.allocator();
        const v = versions(self.fork);
        var id_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_bytes, id, .big);
        const name = try std.fmt.allocPrint(a, "engine_getPayloadV{d}", .{v.get_payload});
        const response = try self.call(name, &.{try wire.hex(a, &id_bytes)});
        const payload_value = if (v.get_payload == 1) response else try wire.field(response, "executionPayload");
        const payload = try wire.parsePayload(owner, payload_value, @min(v.get_payload, 3));
        if (v.get_payload >= 2) _ = try wire.quantity(u256, try wire.field(response, "blockValue"));
        var commitments: []fulu.KZGCommitment = &.{};
        if (v.get_payload >= 3) {
            if (try wire.field(response, "shouldOverrideBuilder") != .bool) return error.InvalidEngineResponse;
            const bundle = try wire.field(response, "blobsBundle");
            const cs = try wire.field(bundle, "commitments");
            const bs = try wire.field(bundle, "blobs");
            const ps = try wire.field(bundle, "proofs");
            if (cs != .array or bs != .array or ps != .array or cs.array.items.len != bs.array.items.len) return error.InvalidEngineResponse;
            if (v.get_payload == 5 and ps.array.items.len != bs.array.items.len * 128) return error.InvalidEngineResponse;
            if (v.get_payload < 5 and ps.array.items.len != bs.array.items.len) return error.InvalidEngineResponse;
            for (bs.array.items) |item| {
                const blob = try wire.string(item);
                if (blob.len != 2 + 131_072 * 2 or !std.mem.startsWith(u8, blob, "0x")) return error.InvalidEngineResponse;
            }
            for (ps.array.items) |item| _ = try wire.fixed(48, item);
            commitments = try owner.alloc(fulu.KZGCommitment, cs.array.items.len);
            for (cs.array.items, commitments) |item, *dest| dest.* = try wire.fixed(48, item);
        }
        const requests = if (v.get_payload >= 4) try parseRequests(owner, try wire.field(response, "executionRequests")) else emptyRequests();
        return .{ .payload = payload, .commitments = commitments, .requests = requests };
    }

    /// Sends a bounded JSON-RPC request and rejects protocol or transport errors.
    fn call(self: *Client, method: []const u8, params: []const wire.Value) !wire.Value {
        const a = self.arena.allocator();
        var request = wire.object();
        try wire.put(a, &request, "jsonrpc", .{ .string = "2.0" });
        try wire.put(a, &request, "id", .{ .integer = 1 });
        try wire.put(a, &request, "method", .{ .string = method });
        var values = wire.array(a);
        for (params) |param| try values.array.append(param);
        try wire.put(a, &request, "params", values);
        const body = try std.json.Stringify.valueAlloc(a, request, .{});
        const now = std.Io.Timestamp.toSeconds(std.Io.Clock.real.now(self.http.io));
        const bearer = try jwt.sign(a, self.secret, now);
        var output = std.Io.Writer.Allocating.init(a);
        const result = try self.http.fetch(.{ .location = .{ .url = self.url }, .method = .POST, .payload = body, .response_writer = &output.writer, .extra_headers = &.{ .{ .name = "authorization", .value = bearer }, .{ .name = "content-type", .value = "application/json" } }, .keep_alive = false });
        if (result.status != .ok) return error.EngineHttpStatus;
        if (output.written().len > 32 * 1024 * 1024) return error.EngineResponseTooLarge;
        const parsed = std.json.parseFromSlice(wire.Value, a, output.written(), .{ .allocate = .alloc_always }) catch return error.InvalidEngineResponse;
        const root = parsed.value;
        if (root != .object) return error.InvalidEngineResponse;
        const id = try wire.field(root, "id");
        if (id != .integer or id.integer != 1) return error.InvalidEngineResponse;
        const protocol = try wire.field(root, "jsonrpc");
        if (protocol != .string or !std.mem.eql(u8, protocol.string, "2.0")) return error.InvalidEngineResponse;
        if (root.object.get("error")) |_| return error.EngineProtocolError;
        return wire.field(root, "result");
    }
};

/// Parses an Engine API payload status including the last valid ancestor.
fn parseVerdict(value: wire.Value) !consensus.PayloadVerdict {
    const status = try wire.string(try wire.field(value, "status"));
    const parsed: consensus.PayloadStatus = if (std.mem.eql(u8, status, "VALID")) .valid else if (std.mem.eql(u8, status, "INVALID")) .invalid else if (std.mem.eql(u8, status, "SYNCING")) .syncing else if (std.mem.eql(u8, status, "ACCEPTED")) .accepted else if (std.mem.eql(u8, status, "INVALID_BLOCK_HASH")) .invalid_block_hash else return error.InvalidEngineResponse;
    const hash = try wire.field(value, "latestValidHash");
    return .{ .status = parsed, .latest_valid_hash = if (hash == .null) null else try wire.fixed(32, hash) };
}

/// Encodes EIP-7685 request lists in type order, skipping empty types.
fn requestsJson(a: std.mem.Allocator, requests: fulu.ExecutionRequests) !wire.Value {
    var out = wire.array(a);
    inline for (.{ requests.deposits, requests.withdrawals, requests.consolidations }, 0..) |list, i| {
        if (list.data.len != 0) {
            const encoded = try ssz.serializeAlloc(a, list);
            const raw = try a.alloc(u8, encoded.len + 1);
            raw[0] = i;
            @memcpy(raw[1..], encoded);
            try out.array.append(try wire.hex(a, raw));
        }
    }
    return out;
}

/// Decodes typed EIP-7685 request lists from builder output.
pub fn parseRequests(a: std.mem.Allocator, value: wire.Value) !fulu.ExecutionRequests {
    if (value != .array or value.array.items.len > 3) return error.InvalidEngineResponse;
    var result = emptyRequests();
    var previous: i8 = -1;
    for (value.array.items) |item| {
        const raw = try wire.bytes(a, item, 8 * 1024 * 1024);
        if (raw.len <= 1 or raw[0] > 2 or raw[0] <= previous) return error.InvalidEngineResponse;
        previous = @intCast(raw[0]);
        var reader: std.Io.Reader = .fixed(raw[1..]);
        switch (raw[0]) {
            0 => result.deposits = try ssz.deserialize(a, @TypeOf(result.deposits), &reader),
            1 => result.withdrawals = try ssz.deserialize(a, @TypeOf(result.withdrawals), &reader),
            2 => result.consolidations = try ssz.deserialize(a, @TypeOf(result.consolidations), &reader),
            else => unreachable,
        }
    }
    return result;
}

/// Supplies the zero-request value used before Prague.
fn emptyRequests() fulu.ExecutionRequests {
    return .{ .deposits = .{ .data = &.{} }, .withdrawals = .{ .data = &.{} }, .consolidations = .{ .data = &.{} } };
}

test "fork method selection includes Osaka builder V5" {
    try std.testing.expectEqual(@as(u8, 1), versions(.paris).new_payload);
    try std.testing.expectEqual(@as(u8, 2), versions(.shanghai).forkchoice);
    try std.testing.expectEqual(@as(u8, 3), versions(.cancun).get_payload);
    try std.testing.expectEqual(@as(u8, 4), versions(.prague).get_payload);
    try std.testing.expectEqual(@as(u8, 5), versions(.osaka).get_payload);
    var client: Client = undefined;
    _ = client.interface();
}

test "Engine verdict mapping keeps pending and invalid block hash distinct" {
    const a = std.testing.allocator;
    for ([_]struct { text: []const u8, expected: consensus.PayloadStatus }{
        .{ .text = "VALID", .expected = .valid },
        .{ .text = "INVALID", .expected = .invalid },
        .{ .text = "SYNCING", .expected = .syncing },
        .{ .text = "ACCEPTED", .expected = .accepted },
        .{ .text = "INVALID_BLOCK_HASH", .expected = .invalid_block_hash },
    }) |case| {
        var value = wire.object();
        try wire.put(a, &value, "status", .{ .string = case.text });
        try wire.put(a, &value, "latestValidHash", .null);
        try std.testing.expectEqual(case.expected, (try parseVerdict(value)).status);
        value.object.deinit(a);
    }
}

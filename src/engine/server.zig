// The authenticated Engine API accepts execution payloads before beacon fork
// choice commits them. Validation runs on a clone of the parent post-state;
// the canonical chain changes only after a valid forkchoice update. A local
// builder derives a fork-appropriate payload from the selected parent, pool,
// and supplied withdrawals. In-memory stages are bounded to 32 direct children;
// Prague deposit logs and queue outputs are checked against typed requests.
//
// parent snapshot -> validate payload -> staged hash -> forkchoice -> canonical
const std = @import("std");
const fulu = @import("fulu");
const execution = @import("execution");
const rlp = @import("rlp");
const ckzg = @import("ckzg");
const wire = @import("engine_wire");
const jwt = @import("engine_jwt");
const client = @import("engine_client");

const Value = wire.Value;
const max_body = 32 * 1024 * 1024;

/// Maps the configured execution fork to its Engine API method generations.
fn methodVersions(fork: execution.transition.Fork) !@TypeOf(client.versions(.osaka)) {
    return switch (fork) {
        .paris => client.versions(.paris),
        .shanghai => client.versions(.shanghai),
        .cancun => client.versions(.cancun),
        .prague => client.versions(.prague),
        .osaka, .fulu => client.versions(.osaka),
        .london => error.UnsupportedFork,
    };
}

/// Returns the execution blob ceiling for a configured fork.
fn maxBlobs(fork: execution.transition.Fork) u64 {
    return switch (fork) {
        .cancun => 6,
        .prague, .osaka => 9,
        .fulu => 21,
        else => 0,
    };
}

/// Adds a verified pool sidecar to blob-proof and Osaka cell-proof bundles.
fn appendSidecar(a: std.mem.Allocator, settings: *const execution.kzg.Settings, sidecar: []const u8, blobs: *std.ArrayList([]const u8), commitments: *std.ArrayList([48]u8), blob_proofs: *std.ArrayList([48]u8), cell_proofs: *std.ArrayList([48]u8)) !void {
    if (sidecar.len < 2 or sidecar[0] != 3) return error.InvalidBlobSidecar;
    var decoded = try rlp.decode.decodeAll(a, sidecar[1..]);
    defer decoded.deinit(a);
    const items = switch (decoded) {
        .list => |list| list,
        else => return error.InvalidBlobSidecar,
    };
    if (items.len != 4 and items.len != 5) return error.InvalidBlobSidecar;
    const offset: usize = if (items.len == 5) 1 else 0;
    const source_blobs = switch (items[1 + offset]) {
        .list => |list| list,
        else => return error.InvalidBlobSidecar,
    };
    const source_commitments = switch (items[2 + offset]) {
        .list => |list| list,
        else => return error.InvalidBlobSidecar,
    };
    const source_proofs = switch (items[3 + offset]) {
        .list => |list| list,
        else => return error.InvalidBlobSidecar,
    };
    if (source_blobs.len != source_commitments.len or source_proofs.len != source_blobs.len * (if (offset == 1) @as(usize, ckzg.CELLS_PER_EXT_BLOB) else 1)) return error.InvalidBlobSidecar;
    for (source_blobs, source_commitments, 0..) |blob_item, commitment_item, i| {
        const blob_raw = switch (blob_item) {
            .string => |raw| raw,
            else => return error.InvalidBlobSidecar,
        };
        const commitment_raw = switch (commitment_item) {
            .string => |raw| raw,
            else => return error.InvalidBlobSidecar,
        };
        if (blob_raw.len != ckzg.BYTES_PER_BLOB or commitment_raw.len != 48) return error.InvalidBlobSidecar;
        const blob: ckzg.Blob = .{ .bytes = blob_raw[0..ckzg.BYTES_PER_BLOB].* };
        const commitment: ckzg.Bytes48 = .{ .bytes = commitment_raw[0..48].* };
        try blobs.append(a, try a.dupe(u8, blob_raw));
        try commitments.append(a, commitment.bytes);
        if (offset == 0) {
            const proof_raw = switch (source_proofs[i]) {
                .string => |raw| raw,
                else => return error.InvalidBlobSidecar,
            };
            if (proof_raw.len != 48) return error.InvalidBlobSidecar;
            try blob_proofs.append(a, proof_raw[0..48].*);
            var cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
            var proofs: [ckzg.CELLS_PER_EXT_BLOB]ckzg.KzgProof = undefined;
            try settings.computeCellsAndKzgProofs(&cells, &proofs, &blob);
            for (proofs) |proof| try cell_proofs.append(a, proof.bytes);
        } else {
            const proof = try settings.computeBlobKzgProof(&blob, &commitment);
            try blob_proofs.append(a, proof.bytes);
            for (source_proofs[i * ckzg.CELLS_PER_EXT_BLOB ..][0..ckzg.CELLS_PER_EXT_BLOB]) |item| {
                const proof_raw = switch (item) {
                    .string => |raw| raw,
                    else => return error.InvalidBlobSidecar,
                };
                if (proof_raw.len != 48) return error.InvalidBlobSidecar;
                try cell_proofs.append(a, proof_raw[0..48].*);
            }
        }
    }
}

const Candidate = struct {
    arena: std.heap.ArenaAllocator,
    payload: fulu.ExecutionPayload,
    hashes: []execution.Hash,
    parent_beacon_root: execution.Hash,
    requests_hash: execution.Hash,
    requests: []const []const u8,
    header: execution.Header,
    world: execution.state.State,

    /// Frees staged payload fields and their blob hashes.
    fn deinit(self: *Candidate) void {
        self.world.deinit();
        self.arena.deinit();
    }
};

const Build = struct {
    arena: std.heap.ArenaAllocator,
    payload: fulu.ExecutionPayload,
    id: u64,
    blobs: [][]const u8,
    commitments: [][48]u8,
    blob_proofs: [][48]u8,
    cell_proofs: [][48]u8,
    requests: [][]const u8,

    /// Frees the builder's borrowed payload fields.
    fn deinit(self: *Build) void {
        self.arena.deinit();
    }
};

/// Owns staged payloads while borrowing a canonical chain, world, and pool.
pub const Server = struct {
    allocator: std.mem.Allocator,
    chain: *execution.chain.Chain,
    world: *execution.state.State,
    pool: *execution.pool.Pool,
    settings: ?*const execution.kzg.Settings = null,
    secret: [32]u8,
    staged: std.ArrayList(Candidate) = .empty,
    build: ?Build = null,
    next_id: u64 = 1,

    /// Releases staged payloads without changing canonical state.
    pub fn deinit(self: *Server) void {
        for (self.staged.items) |*candidate| candidate.deinit();
        self.staged.deinit(self.allocator);
        if (self.build) |*pending| pending.deinit();
    }

    /// Authenticates and dispatches one bounded Engine JSON-RPC message.
    pub fn dispatch(self: *Server, allocator: std.mem.Allocator, bearer: []const u8, body: []const u8, now: i64) ![]u8 {
        try jwt.verify(allocator, self.secret, bearer, now);
        if (body.len > max_body) return error.RequestTooLarge;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const parsed = std.json.parseFromSlice(Value, a, body, .{ .allocate = .alloc_always }) catch return errorBody(allocator, a, .null, -32700, "parse error");
        const root = parsed.value;
        if (root != .object) return errorBody(allocator, a, .null, -32600, "invalid request");
        const id = root.object.get("id") orelse Value.null;
        const version = root.object.get("jsonrpc") orelse return errorBody(allocator, a, id, -32600, "invalid request");
        if (version != .string or !std.mem.eql(u8, version.string, "2.0")) return errorBody(allocator, a, id, -32600, "invalid request");
        const method_value = root.object.get("method") orelse return errorBody(allocator, a, id, -32600, "invalid request");
        if (method_value != .string) return errorBody(allocator, a, id, -32600, "invalid request");
        const params = root.object.get("params") orelse return errorBody(allocator, a, id, -32602, "invalid params");
        if (params != .array) return errorBody(allocator, a, id, -32602, "invalid params");
        const name = method_value.string;
        const result = self.method(a, name, params.array.items) catch |err| {
            const code: i64 = switch (err) {
                error.InvalidParams => -32602,
                error.InvalidForkchoiceState => -38002,
                error.InvalidPayloadAttributes => -38003,
                error.UnsupportedFork => -38005,
                error.UnknownPayload => -38001,
                error.MethodNotFound => -32601,
                else => -32000,
            };
            return errorBody(allocator, a, id, code, @errorName(err));
        };
        var response = try responseBase(a, id);
        try wire.put(a, &response, "result", result);
        return allocator.dupe(u8, try std.json.Stringify.valueAlloc(a, response, .{}));
    }

    /// Serves one authenticated POST request on a dedicated Engine API port.
    pub fn serveConnection(self: *Server, allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream) !void {
        defer stream.close(io);
        var read_buffer: [8192]u8 = undefined;
        var write_buffer: [8192]u8 = undefined;
        var body_buffer: [8192]u8 = undefined;
        var reader = stream.reader(io, &read_buffer);
        var writer = stream.writer(io, &write_buffer);
        var http = std.http.Server.init(&reader.interface, &writer.interface);
        var request = http.receiveHead() catch return;
        const headers: []const std.http.Header = &.{.{ .name = "content-type", .value = "application/json" }};
        if (request.head.method != .POST or !std.mem.eql(u8, request.head.target, "/")) return request.respond("not found", .{ .status = .not_found, .keep_alive = false });
        var bearer: ?[]const u8 = null;
        var it = request.iterateHeaders();
        while (it.next()) |header| if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            if (bearer != null) return request.respond("unauthorized", .{ .status = .unauthorized, .keep_alive = false });
            bearer = header.value;
        };
        const now = std.Io.Timestamp.toSeconds(std.Io.Clock.real.now(io));
        jwt.verify(allocator, self.secret, bearer orelse "", now) catch return request.respond("unauthorized", .{ .status = .unauthorized, .keep_alive = false });
        if ((request.head.content_length orelse 0) > max_body) return request.respond("request too large", .{ .status = .payload_too_large, .keep_alive = false });
        const body_reader = request.readerExpectContinue(&body_buffer) catch return;
        const body = body_reader.allocRemaining(allocator, .limited(max_body)) catch return request.respond("request too large", .{ .status = .payload_too_large, .keep_alive = false });
        defer allocator.free(body);
        const response = self.dispatch(allocator, bearer.?, body, now) catch return request.respond("bad request", .{ .status = .bad_request, .keep_alive = false });
        defer allocator.free(response);
        try request.respond(response, .{ .status = .ok, .keep_alive = false, .extra_headers = headers });
    }

    /// Accepts authenticated connections until the listener closes.
    pub fn serve(self: *Server, allocator: std.mem.Allocator, io: std.Io, listener: *std.Io.net.Server) !void {
        while (true) {
            const stream = try listener.accept(io);
            self.serveConnection(allocator, io, stream) catch {};
        }
    }

    /// Routes the method generation required by the configured execution fork.
    fn method(self: *Server, a: std.mem.Allocator, name: []const u8, params: []const Value) !Value {
        if (std.mem.eql(u8, name, "engine_exchangeCapabilities")) {
            if (params.len != 1 or params[0] != .array) return error.InvalidParams;
            var capabilities = wire.array(a);
            for ([_][]const u8{ "engine_newPayloadV1", "engine_newPayloadV2", "engine_newPayloadV3", "engine_newPayloadV4", "engine_forkchoiceUpdatedV1", "engine_forkchoiceUpdatedV2", "engine_forkchoiceUpdatedV3", "engine_getPayloadV1", "engine_getPayloadV2", "engine_getPayloadV3", "engine_getPayloadV4", "engine_getPayloadV5" }) |capability| try capabilities.array.append(.{ .string = capability });
            return capabilities;
        }
        const versions = try methodVersions(self.chain.fork);
        if (std.mem.eql(u8, name, try std.fmt.allocPrint(a, "engine_newPayloadV{d}", .{versions.new_payload}))) return self.newPayload(a, params, versions.new_payload);
        if (std.mem.eql(u8, name, try std.fmt.allocPrint(a, "engine_forkchoiceUpdatedV{d}", .{versions.forkchoice}))) return self.forkchoiceUpdated(a, params);
        if (std.mem.eql(u8, name, try std.fmt.allocPrint(a, "engine_getPayloadV{d}", .{versions.get_payload}))) return self.getPayload(a, params, versions.get_payload);
        if (std.mem.startsWith(u8, name, "engine_newPayloadV") or std.mem.startsWith(u8, name, "engine_forkchoiceUpdatedV") or std.mem.startsWith(u8, name, "engine_getPayloadV")) return error.UnsupportedFork;
        return error.MethodNotFound;
    }

    /// Validates against a cloned parent state and stages a valid direct child.
    fn newPayload(self: *Server, a: std.mem.Allocator, params: []const Value, version: u8) !Value {
        if (params.len != (if (version < 3) @as(usize, 1) else if (version == 3) @as(usize, 3) else @as(usize, 4))) return error.InvalidParams;
        if (version >= 3 and params[1] != .array) return error.InvalidParams;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        var retained = false;
        defer if (!retained) arena.deinit();
        const owner = arena.allocator();
        const payload = try wire.parsePayload(owner, params[0], @min(version, 3));
        const beacon_root = if (version >= 3) try wire.fixed(32, params[2]) else [_]u8{0} ** 32;
        if (version >= 4) _ = client.parseRequests(owner, params[3]) catch |err| {
            if (err == error.OutOfMemory) return err;
            return error.InvalidParams;
        };
        const requests: []const []const u8 = if (version >= 4) blk: {
            const values = try owner.alloc([]const u8, params[3].array.items.len);
            for (params[3].array.items, values) |item, *raw| raw.* = try wire.bytes(owner, item, 8 * 1024 * 1024);
            break :blk values;
        } else &.{};
        const requests_hash = try execution.transition.requestsHash(a, requests);
        const hashes = try owner.alloc(execution.Hash, if (version >= 3) params[1].array.items.len else 0);
        if (version >= 3) {
            for (params[1].array.items, hashes) |item, *hash| hash.* = try wire.fixed(32, item);
        }
        const header = try payloadHeader(a, payload, beacon_root, requests_hash);
        const computed = try execution.transition.headerHash(a, self.chain.fork, header);
        if (!std.mem.eql(u8, &computed, &payload.block_hash)) return status(a, "INVALID_BLOCK_HASH", null);
        var known_parent: ?execution.Header = if (self.chain.byHash(payload.parent_hash)) |record| record.header else null;
        if (known_parent == null) for (self.staged.items) |candidate| {
            if (std.mem.eql(u8, &candidate.payload.block_hash, &payload.parent_hash)) known_parent = candidate.header;
        };
        for (payload.transactions.data) |raw| {
            var decoded = execution.parse(execution.Transaction, a, raw.data) catch |err| {
                if (err == error.OutOfMemory) return err;
                return status(a, "INVALID", if (known_parent != null) payload.parent_hash else null);
            };
            decoded.deinit();
        }
        if (self.chain.byHash(payload.block_hash) != null) return status(a, "VALID", payload.block_hash);
        const parent = self.chain.latest();
        if (!std.mem.eql(u8, &payload.parent_hash, &parent.hash)) {
            const ancestor = known_parent orelse return status(a, "SYNCING", null);
            if (payload.block_number != ancestor.number +| 1 or payload.timestamp <= ancestor.timestamp or payload.gas_used > payload.gas_limit) return status(a, "INVALID", payload.parent_hash);
            // shortcut: side branches are syntax and header checked only; execute them when reorganization support is added.
            return status(a, "ACCEPTED", null);
        }
        const txs = try a.alloc([]const u8, payload.transactions.data.len);
        for (payload.transactions.data, txs) |raw, *out| out.* = raw.data;
        const withdrawals = try a.alloc(execution.Withdrawal, payload.withdrawals.data.len);
        for (payload.withdrawals.data, withdrawals) |w, *out| out.* = .{ .index = w.index, .validator_index = w.validator_index, .address = w.address, .amount = w.amount };
        var trial = try parent.world.clone(self.allocator);
        var retained_trial = false;
        defer if (!retained_trial) trial.deinit();
        const older_hashes = try self.chain.olderHashes(a);
        var result = execution.transition.applyBlock(a, &trial, .{ .fork = self.chain.fork, .parent_fork = self.chain.fork, .chain_id = self.chain.chain_id, .older_hashes = older_hashes, .max_blobs_per_block = maxBlobs(self.chain.fork), .expected_blob_hashes = hashes, .expected_requests = if (version >= 4) requests else null }, parent.header, header, txs, withdrawals) catch |err| {
            if (err == error.OutOfMemory) return err;
            if (err == error.UnsupportedRequestQueues or err == error.UnsupportedDepositContract) return status(a, "SYNCING", null);
            return status(a, "INVALID", parent.hash);
        };
        result.deinit();
        for (self.staged.items) |candidate| if (std.mem.eql(u8, &candidate.payload.block_hash, &payload.block_hash)) return status(a, "VALID", payload.block_hash);
        if (self.staged.items.len == 32) {
            var oldest = self.staged.orderedRemove(0);
            oldest.deinit();
        }
        try self.staged.append(self.allocator, .{ .arena = arena, .payload = payload, .hashes = hashes, .parent_beacon_root = beacon_root, .requests_hash = requests_hash, .requests = requests, .header = header, .world = trial });
        retained = true;
        retained_trial = true;
        return status(a, "VALID", payload.block_hash);
    }

    /// Commits a staged child only after validating the selected head and markers.
    fn forkchoiceUpdated(self: *Server, a: std.mem.Allocator, params: []const Value) !Value {
        if (params.len != 2) return error.InvalidParams;
        const choice = params[0];
        const head = try wire.fixed(32, try wire.field(choice, "headBlockHash"));
        const safe = try wire.fixed(32, try wire.field(choice, "safeBlockHash"));
        const finalized = try wire.fixed(32, try wire.field(choice, "finalizedBlockHash"));
        var selected: ?*Candidate = null;
        if (!std.mem.eql(u8, &head, &self.chain.latest().hash)) {
            for (self.staged.items) |*candidate| if (std.mem.eql(u8, &candidate.payload.block_hash, &head)) {
                selected = candidate;
            };
            const candidate = selected orelse return choiceResult(a, "SYNCING", null, null);
            if (!std.mem.eql(u8, &candidate.payload.parent_hash, &self.chain.latest().hash)) return choiceResult(a, "SYNCING", null, null);
        }
        if (!std.mem.allEqual(u8, &safe, 0) and self.chain.byHash(safe) == null and !std.mem.eql(u8, &safe, &head)) return error.InvalidForkchoiceState;
        if (!std.mem.allEqual(u8, &finalized, 0) and self.chain.byHash(finalized) == null and !std.mem.eql(u8, &finalized, &head)) return error.InvalidForkchoiceState;
        const head_number = if (selected) |candidate| candidate.header.number else self.chain.latest().header.number;
        const safe_number: u64 = if (std.mem.allEqual(u8, &safe, 0)) 0 else if (std.mem.eql(u8, &safe, &head)) head_number else self.chain.byHash(safe).?.header.number;
        const finalized_number: u64 = if (std.mem.allEqual(u8, &finalized, 0)) 0 else if (std.mem.eql(u8, &finalized, &head)) head_number else self.chain.byHash(finalized).?.header.number;
        if (safe_number > head_number or finalized_number > safe_number or (std.mem.allEqual(u8, &safe, 0) and !std.mem.allEqual(u8, &finalized, 0))) return error.InvalidForkchoiceState;
        const parent_header = if (selected) |candidate| candidate.header else self.chain.latest().header;
        const parent_world = if (selected) |candidate| &candidate.world else &self.chain.latest().world;
        if (selected) |candidate| {
            const p = candidate.payload;
            const txs = try a.alloc([]const u8, p.transactions.data.len);
            for (p.transactions.data, txs) |raw, *out| out.* = raw.data;
            const withdrawals = try a.alloc(execution.Withdrawal, p.withdrawals.data.len);
            for (p.withdrawals.data, withdrawals) |w, *out| out.* = .{ .index = w.index, .validator_index = w.validator_index, .address = w.address, .amount = w.amount };
            try self.chain.append(self.world, candidate.header, txs, withdrawals, candidate.hashes, candidate.requests);
            self.pool.prune(self.world);
        }
        var pending: ?Build = if (params[1] == .null) null else self.startBuild(a, params[1], parent_header, head, parent_world) catch |err| {
            if (err == error.InvalidParams) return error.InvalidPayloadAttributes;
            return err;
        };
        errdefer if (pending) |*build| build.deinit();
        var id: ?u64 = null;
        if (pending) |build| {
            if (self.build) |*old| old.deinit();
            id = build.id;
            self.build = build;
            self.next_id +%= 1;
            pending = null;
        }
        return choiceResult(a, "VALID", head, id);
    }

    /// Prepares a payload build from a validated parent without changing canonical state.
    fn startBuild(self: *Server, a: std.mem.Allocator, value: Value, parent_header: execution.Header, parent_hash: execution.Hash, parent_world: *const execution.state.State) !Build {
        const timestamp = try wire.quantity(u64, try wire.field(value, "timestamp"));
        if (timestamp <= parent_header.timestamp) return error.InvalidParams;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const owner = arena.allocator();
        const active = try methodVersions(self.chain.fork);
        const ws = if (active.forkchoice >= 2) try wire.field(value, "withdrawals") else wire.array(owner);
        if (ws != .array or ws.array.items.len > 16) return error.InvalidParams;
        const withdrawals = try owner.alloc(fulu.Withdrawal, ws.array.items.len);
        for (ws.array.items, withdrawals) |item, *out| out.* = .{
            .index = try wire.quantity(u64, try wire.field(item, "index")),
            .validator_index = try wire.quantity(u64, try wire.field(item, "validatorIndex")),
            .address = try wire.fixed(20, try wire.field(item, "address")),
            .amount = try wire.quantity(u64, try wire.field(item, "amount")),
        };
        const fee_recipient = try wire.fixed(20, try wire.field(value, "suggestedFeeRecipient"));
        const prev_randao = try wire.fixed(32, try wire.field(value, "prevRandao"));
        const number = try std.math.add(u64, parent_header.number, 1);
        const base_fee = try execution.transition.nextBaseFee(parent_header.gas_limit, parent_header.gas_used, parent_header.base_fee_per_gas);
        const excess_blob_gas = if (active.forkchoice >= 3) (parent_header.excess_blob_gas +| parent_header.blob_gas_used) -| (if (self.chain.fork == .cancun) @as(u64, 393_216) else @as(u64, 786_432)) else 0;
        var trial = try parent_world.clone(a);
        defer trial.deinit();
        const older_hashes = try self.chain.olderHashes(a);
        const staged_parent = !std.mem.eql(u8, &parent_hash, &self.chain.latest().hash);
        const hash_count = @min(@as(usize, 256), 1 + older_hashes.len + @as(usize, @intFromBool(staged_parent)));
        const block_hashes = try a.alloc(execution.Hash, hash_count);
        block_hashes[0] = parent_hash;
        if (staged_parent) block_hashes[1] = self.chain.latest().hash;
        @memcpy(block_hashes[1 + @as(usize, @intFromBool(staged_parent)) ..], older_hashes[0 .. hash_count - 1 - @as(usize, @intFromBool(staged_parent))]);
        const context: execution.transition.Context = .{ .fork = self.chain.fork, .chain_id = self.chain.chain_id, .coinbase = fee_recipient, .number = number, .timestamp = timestamp, .gas_limit = parent_header.gas_limit, .base_fee = base_fee, .prev_randao = prev_randao, .blob_base_fee = if (active.forkchoice >= 3) try execution.transition.blobBaseFee(self.chain.fork, excess_blob_gas) else null, .block_hashes = block_hashes };
        const root = if (active.forkchoice >= 3) try wire.fixed(32, try wire.field(value, "parentBeaconBlockRoot")) else [_]u8{0} ** 32;
        try execution.transition.applySystemTransitions(a, &trial, context, parent_hash, root);
        const selected = try self.pool.select(a, &trial, context, parent_header.gas_limit, maxBlobs(self.chain.fork));
        const Tx = std.meta.Child(@FieldType(@FieldType(fulu.ExecutionPayload, "transactions"), "data"));
        const transactions = try owner.alloc(Tx, selected.len);
        var blobs: std.ArrayList([]const u8) = .empty;
        var commitments: std.ArrayList([48]u8) = .empty;
        var blob_proofs: std.ArrayList([48]u8) = .empty;
        var cell_proofs: std.ArrayList([48]u8) = .empty;
        var receipts = try a.alloc(execution.Receipt, selected.len);
        var outcomes = try a.alloc(execution.transition.Outcome, selected.len);
        var completed: usize = 0;
        defer for (outcomes[0..completed]) |*outcome| outcome.deinit();
        var gas_used: u64 = 0;
        for (selected, 0..) |raw, i| {
            if (raw.len != 0 and raw[0] == 3) {
                var tx_hash: execution.Hash = undefined;
                std.crypto.hash.sha3.Keccak256.hash(raw, &tx_hash, .{});
                const entry = self.pool.get(tx_hash) orelse return error.MissingBlobSidecar;
                try appendSidecar(owner, self.settings orelse return error.KzgUnavailable, entry.sidecar orelse return error.MissingBlobSidecar, &blobs, &commitments, &blob_proofs, &cell_proofs);
                if (blobs.items.len > maxBlobs(self.chain.fork)) return error.TooManyBlobs;
            }
            transactions[i] = .{ .data = try owner.dupe(u8, raw) };
            outcomes[i] = try execution.transition.applyTransaction(a, &trial, context, raw, parent_header.gas_limit - gas_used, gas_used);
            completed += 1;
            receipts[i] = outcomes[i].receipt;
            gas_used += outcomes[i].gas_used;
        }
        for (withdrawals) |w| {
            const amount = try std.math.mul(u256, w.amount, 1_000_000_000);
            try trial.setBalance(w.address, try std.math.add(u256, trial.getBalance(w.address), amount));
        }
        const requests = try execution.transition.processExecutionRequests(owner, &trial, context, receipts);
        const zero: execution.Hash = .{0} ** 32;
        var p: fulu.ExecutionPayload = .{
            .parent_hash = parent_hash,
            .fee_recipient = fee_recipient,
            .state_root = try trial.stateRoot(),
            .receipts_root = try execution.receiptsRoot(a, receipts),
            .logs_bloom = execution.receiptsBloom(receipts),
            .prev_randao = prev_randao,
            .block_number = number,
            .gas_limit = parent_header.gas_limit,
            .gas_used = gas_used,
            .timestamp = timestamp,
            .extra_data = .{ .data = &.{} },
            .base_fee_per_gas = base_fee,
            .block_hash = zero,
            .transactions = .{ .data = transactions },
            .withdrawals = .{ .data = withdrawals },
            .blob_gas_used = try std.math.mul(u64, @intCast(blobs.items.len), 131_072),
            .excess_blob_gas = excess_blob_gas,
        };
        const header = try payloadHeader(a, p, root, try execution.transition.requestsHash(a, requests));
        p.block_hash = try execution.transition.headerHash(a, self.chain.fork, header);
        return .{ .arena = arena, .payload = p, .id = self.next_id, .blobs = try blobs.toOwnedSlice(owner), .commitments = try commitments.toOwnedSlice(owner), .blob_proofs = try blob_proofs.toOwnedSlice(owner), .cell_proofs = try cell_proofs.toOwnedSlice(owner), .requests = requests };
    }

    /// Returns Osaka builder output with an empty cell-proof bundle.
    fn getPayload(self: *Server, a: std.mem.Allocator, params: []const Value, version: u8) !Value {
        if (params.len != 1) return error.InvalidParams;
        const raw = try wire.fixed(8, params[0]);
        const id = std.mem.readInt(u64, &raw, .big);
        const build = self.build orelse return error.UnknownPayload;
        if (build.id != id) return error.UnknownPayload;
        const payload = try wire.payloadJson(a, build.payload, @min(version, 3));
        if (version == 1) return payload;
        var out = wire.object();
        try wire.put(a, &out, "executionPayload", payload);
        try wire.put(a, &out, "blockValue", try wire.number(a, @as(u8, 0)));
        if (version >= 3) {
            try wire.put(a, &out, "shouldOverrideBuilder", .{ .bool = false });
            var bundle = wire.object();
            var blob_values = wire.array(a);
            for (build.blobs) |blob| try blob_values.array.append(try wire.hex(a, blob));
            try wire.put(a, &bundle, "blobs", blob_values);
            var commitment_values = wire.array(a);
            for (build.commitments) |commitment| try commitment_values.array.append(try wire.hex(a, &commitment));
            try wire.put(a, &bundle, "commitments", commitment_values);
            var proof_values = wire.array(a);
            for (if (version == 5) build.cell_proofs else build.blob_proofs) |proof| try proof_values.array.append(try wire.hex(a, &proof));
            try wire.put(a, &bundle, "proofs", proof_values);
            try wire.put(a, &out, "blobsBundle", bundle);
        }
        if (version >= 4) {
            var requests = wire.array(a);
            for (build.requests) |request| try requests.array.append(try wire.hex(a, request));
            try wire.put(a, &out, "executionRequests", requests);
        }
        return out;
    }
};

/// Returns the request commitment for no execution requests.
fn emptyRequestsHash() !execution.Hash {
    var hash: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&.{}, &hash, .{});
    return hash;
}

/// Constructs an execution header from payload fields and derived trie roots.
fn payloadHeader(a: std.mem.Allocator, p: fulu.ExecutionPayload, beacon_root: execution.Hash, requests_hash: execution.Hash) !execution.Header {
    const txs = try a.alloc([]const u8, p.transactions.data.len);
    for (p.transactions.data, txs) |raw, *out| out.* = raw.data;
    const ws = try a.alloc([]const u8, p.withdrawals.data.len);
    for (p.withdrawals.data, ws) |w, *out| out.* = try execution.encode(a, execution.Withdrawal{ .index = w.index, .validator_index = w.validator_index, .address = w.address, .amount = w.amount });
    var ommers: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&.{0xc0}, &ommers, .{});
    return .{ .parent_hash = p.parent_hash, .ommers_hash = ommers, .fee_recipient = p.fee_recipient, .state_root = p.state_root, .transactions_root = try execution.trie.orderedRoot(a, txs), .receipts_root = p.receipts_root, .logs_bloom = p.logs_bloom, .difficulty = 0, .number = p.block_number, .gas_limit = p.gas_limit, .gas_used = p.gas_used, .timestamp = p.timestamp, .extra_data = p.extra_data.data, .prev_randao = p.prev_randao, .nonce = .{0} ** 8, .base_fee_per_gas = p.base_fee_per_gas, .withdrawals_root = try execution.trie.orderedRoot(a, ws), .blob_gas_used = p.blob_gas_used, .excess_blob_gas = p.excess_blob_gas, .parent_beacon_block_root = beacon_root, .requests_hash = requests_hash };
}

/// Creates a payload verdict with the optional last valid hash.
fn status(a: std.mem.Allocator, name: []const u8, latest: ?execution.Hash) !Value {
    var out = wire.object();
    try wire.put(a, &out, "status", .{ .string = name });
    try wire.put(a, &out, "latestValidHash", if (latest) |hash| try wire.hex(a, &hash) else .null);
    try wire.put(a, &out, "validationError", .null);
    return out;
}

/// Wraps a forkchoice verdict and optional eight-byte build identifier.
fn choiceResult(a: std.mem.Allocator, name: []const u8, latest: ?execution.Hash, id: ?u64) !Value {
    var out = wire.object();
    try wire.put(a, &out, "payloadStatus", try status(a, name, latest));
    if (id) |number| {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(u64, &raw, number, .big);
        try wire.put(a, &out, "payloadId", try wire.hex(a, &raw));
    } else try wire.put(a, &out, "payloadId", .null);
    return out;
}

/// Starts a JSON-RPC 2.0 response with the request identifier.
fn responseBase(a: std.mem.Allocator, id: Value) !Value {
    var out = wire.object();
    try wire.put(a, &out, "jsonrpc", .{ .string = "2.0" });
    try wire.put(a, &out, "id", id);
    return out;
}

test "blob sidecars supply both V1 and Osaka V2 proof bundles" {
    const a = std.testing.allocator;
    var settings = try execution.kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    const blob: ckzg.Blob = .{ .bytes = .{0} ** ckzg.BYTES_PER_BLOB };
    const commitment: [48]u8 = .{0xc0} ++ (.{0} ** 47);
    var versioned_hash: execution.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &versioned_hash, .{});
    versioned_hash[0] = 1;
    const tx: execution.Blob = .{ .chain_id = 1, .nonce = 0, .max_priority_fee_per_gas = 1, .max_fee_per_gas = 2, .gas_limit = 100_000, .to = .{0x22} ** 20, .value = 0, .data = &.{}, .access_list = &.{}, .max_fee_per_blob_gas = 1, .blob_versioned_hashes = &.{versioned_hash}, .y_parity = 0, .r = 1, .s = 1 };
    const blob_array = [1][ckzg.BYTES_PER_BLOB]u8{blob.bytes};
    const commitments = [1][48]u8{commitment};
    var cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
    var computed: [ckzg.CELLS_PER_EXT_BLOB]ckzg.KzgProof = undefined;
    try settings.computeCellsAndKzgProofs(&cells, &computed, &blob);
    var cell_bytes: [ckzg.CELLS_PER_EXT_BLOB][48]u8 = undefined;
    for (computed, 0..) |item, i| cell_bytes[i] = item.bytes;
    for ([_]bool{ false, true }) |v2| {
        const encoded = if (v2) try execution.encode(a, .{ tx, @as(u8, 1), blob_array, commitments, cell_bytes }) else try execution.encode(a, .{ tx, blob_array, commitments, [1][48]u8{commitment} });
        defer a.free(encoded);
        const raw = try a.alloc(u8, encoded.len + 1);
        defer a.free(raw);
        raw[0] = 3;
        @memcpy(raw[1..], encoded);
        var blobs: std.ArrayList([]const u8) = .empty;
        defer {
            for (blobs.items) |item| a.free(item);
            blobs.deinit(a);
        }
        var cs: std.ArrayList([48]u8) = .empty;
        defer cs.deinit(a);
        var proof_v1: std.ArrayList([48]u8) = .empty;
        defer proof_v1.deinit(a);
        var proof_v2: std.ArrayList([48]u8) = .empty;
        defer proof_v2.deinit(a);
        try appendSidecar(a, &settings, raw, &blobs, &cs, &proof_v1, &proof_v2);
        try std.testing.expectEqual(@as(usize, 1), blobs.items.len);
        try std.testing.expectEqual(@as(usize, 1), cs.items.len);
        try std.testing.expectEqual(@as(usize, 1), proof_v1.items.len);
        try std.testing.expectEqual(@as(usize, ckzg.CELLS_PER_EXT_BLOB), proof_v2.items.len);
        try std.testing.expectEqual(commitment, cs.items[0]);
    }
}

/// Encodes a JSON-RPC error without changing Engine state.
fn errorBody(allocator: std.mem.Allocator, a: std.mem.Allocator, id: Value, code: i64, message: []const u8) ![]u8 {
    var detail = wire.object();
    try wire.put(a, &detail, "code", .{ .integer = code });
    try wire.put(a, &detail, "message", .{ .string = message });
    var response = try responseBase(a, id);
    try wire.put(a, &response, "error", detail);
    return allocator.dupe(u8, try std.json.Stringify.valueAlloc(a, response, .{}));
}

test "authenticated capabilities do not change canonical head" {
    const a = std.testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    var header = std.mem.zeroes(execution.Header);
    header.state_root = try world.stateRoot();
    header.gas_limit = 30_000_000;
    header.base_fee_per_gas = 1;
    var chain = try execution.chain.Chain.init(a, 1, .fulu, header, &world);
    defer chain.deinit();
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    const secret = [_]u8{0x42} ** 32;
    var server: Server = .{ .allocator = a, .chain = &chain, .world = &world, .pool = &pool, .secret = secret };
    defer server.deinit();
    const bearer = try jwt.sign(a, secret, 1_000);
    defer a.free(bearer);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var request = wire.object();
    try wire.put(temp, &request, "jsonrpc", .{ .string = "2.0" });
    try wire.put(temp, &request, "id", .{ .integer = 1 });
    try wire.put(temp, &request, "method", .{ .string = "engine_exchangeCapabilities" });
    var params = wire.array(temp);
    try params.array.append(wire.array(temp));
    try wire.put(temp, &request, "params", params);
    const response = try server.dispatch(a, bearer, try std.json.Stringify.valueAlloc(temp, request, .{}), 1_000);
    defer a.free(response);
    const capabilities = try wire.field((try std.json.parseFromSlice(Value, temp, response, .{})).value, "result");
    var found = false;
    for (capabilities.array.items) |capability| if (std.mem.eql(u8, try wire.string(capability), "engine_getPayloadV5")) {
        found = true;
    };
    try std.testing.expect(found);
    const malformed = try server.dispatch(a, bearer, "{", 1_000);
    defer a.free(malformed);
    const parse_error = try wire.field(try wire.field((try std.json.parseFromSlice(Value, temp, malformed, .{})).value, "error"), "code");
    try std.testing.expectEqual(@as(i64, -32700), parse_error.integer);
    request.object.getPtr("id").?.* = .{ .integer = 2 };
    request.object.getPtr("method").?.* = .{ .string = "engine_newPayloadV4" };
    request.object.getPtr("params").?.* = wire.array(temp);
    const bad_params = try server.dispatch(a, bearer, try std.json.Stringify.valueAlloc(temp, request, .{}), 1_000);
    defer a.free(bad_params);
    const params_error = try wire.field(try wire.field((try std.json.parseFromSlice(Value, temp, bad_params, .{})).value, "error"), "code");
    try std.testing.expectEqual(@as(i64, -32602), params_error.integer);
    try std.testing.expectEqual(@as(usize, 1), chain.records.items.len);
    try std.testing.expectError(error.Unauthorized, server.dispatch(a, "Bearer bad", "", 1_000));
}

/// Exercises one fork's build, validation, and canonical commit sequence.
fn checkBuiltFork(fork: execution.transition.Fork) !void {
    const a = std.testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    const system_setter = [_]u8{ 0x5f, 0x35, 0x5f, 0x55, 0x00 };
    const queue_setter = [_]u8{ 0x5f, 0x54, 0x60, 0x01, 0x01, 0x5f, 0x55, 0x00 };
    const queue_output = [_]u8{ 0x60, 0x4c, 0x60, 0x00, 0xf3 };
    if (@intFromEnum(fork) >= @intFromEnum(execution.transition.Fork.cancun)) _ = try world.setCode(.{ 0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22, 0xd0, 0xbe, 0xac, 0x02 }, &system_setter);
    if (@intFromEnum(fork) >= @intFromEnum(execution.transition.Fork.prague)) {
        _ = try world.setCode(.{ 0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35 }, &system_setter);
        _ = try world.setCode(execution.transition.withdrawal_requests_address, if (fork == .prague or fork == .osaka) &queue_output else &queue_setter);
        _ = try world.setCode(execution.transition.consolidation_requests_address, &queue_setter);
    }
    var header = std.mem.zeroes(execution.Header);
    header.state_root = try world.stateRoot();
    header.gas_limit = 30_000_000;
    header.base_fee_per_gas = 1;
    var chain = try execution.chain.Chain.init(a, 1, fork, header, &world);
    defer chain.deinit();
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    var server: Server = .{ .allocator = a, .chain = &chain, .world = &world, .pool = &pool, .secret = .{0x42} ** 32 };
    defer server.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const genesis = chain.latest().hash;
    const zero = [_]u8{0} ** 32;
    const beacon_root = [_]u8{0x55} ** 32;
    var choice = wire.object();
    try wire.put(temp, &choice, "headBlockHash", try wire.hex(temp, &genesis));
    try wire.put(temp, &choice, "safeBlockHash", try wire.hex(temp, &genesis));
    try wire.put(temp, &choice, "finalizedBlockHash", try wire.hex(temp, &genesis));
    var attrs = wire.object();
    try wire.put(temp, &attrs, "timestamp", try wire.number(temp, @as(u64, 1)));
    try wire.put(temp, &attrs, "prevRandao", try wire.hex(temp, &zero));
    try wire.put(temp, &attrs, "suggestedFeeRecipient", try wire.hex(temp, &([_]u8{0} ** 20)));
    const versions = try methodVersions(fork);
    if (versions.forkchoice >= 2) try wire.put(temp, &attrs, "withdrawals", wire.array(temp));
    if (versions.forkchoice >= 3) try wire.put(temp, &attrs, "parentBeaconBlockRoot", try wire.hex(temp, &beacon_root));
    const started = try server.forkchoiceUpdated(temp, &.{ choice, attrs });
    const id = try wire.field(started, "payloadId");
    const built = try server.getPayload(temp, &.{id}, versions.get_payload);
    const p = if (versions.get_payload == 1) built else try wire.field(built, "executionPayload");
    if (versions.get_payload >= 4) try std.testing.expectEqual(@as(usize, @intFromBool(fork == .prague or fork == .osaka)), (try wire.field(built, "executionRequests")).array.items.len);
    try std.testing.expectEqual(@as(usize, 1), chain.records.items.len);
    var params = wire.array(temp);
    try params.array.append(p);
    if (versions.new_payload >= 3) {
        try params.array.append(wire.array(temp));
        try params.array.append(try wire.hex(temp, &beacon_root));
    }
    if (versions.new_payload >= 4) try params.array.append(try wire.field(built, "executionRequests"));
    const original_hash = try wire.field(p, "blockHash");
    params.array.items[0].object.getPtr("blockHash").?.* = try wire.hex(temp, &zero);
    const rejected = try server.newPayload(temp, params.array.items, versions.new_payload);
    try std.testing.expectEqualStrings("INVALID_BLOCK_HASH", try wire.string(try wire.field(rejected, "status")));
    try std.testing.expectEqual(@as(usize, 1), chain.records.items.len);
    params.array.items[0].object.getPtr("blockHash").?.* = original_hash;
    if (fork == .osaka) {
        const fake = [_]u8{1} ++ [_]u8{0x7f} ** 76;
        var changed = wire.array(temp);
        try changed.array.append(try wire.hex(temp, &fake));
        params.array.items[3] = changed;
        const claimed = try wire.parsePayload(temp, params.array.items[0], 3);
        const forged_hash = try execution.transition.headerHash(temp, fork, try payloadHeader(temp, claimed, beacon_root, try execution.transition.requestsHash(temp, &.{&fake})));
        params.array.items[0].object.getPtr("blockHash").?.* = try wire.hex(temp, &forged_hash);
        const mismatched = try server.newPayload(temp, params.array.items, versions.new_payload);
        try std.testing.expectEqualStrings("INVALID", try wire.string(try wire.field(mismatched, "status")));
        try std.testing.expectEqual(@as(usize, 1), chain.records.items.len);
        params.array.items[0].object.getPtr("blockHash").?.* = original_hash;
        params.array.items[3] = try wire.field(built, "executionRequests");
    }
    const accepted = try server.newPayload(temp, params.array.items, versions.new_payload);
    try std.testing.expectEqualStrings("VALID", try wire.string(try wire.field(accepted, "status")));
    try std.testing.expectEqual(@as(usize, 1), chain.records.items.len);
    try wire.put(temp, &choice, "headBlockHash", try wire.field(p, "blockHash"));
    choice.object.getPtr("safeBlockHash").?.* = try wire.hex(temp, &([_]u8{0x77} ** 32));
    try std.testing.expectError(error.InvalidForkchoiceState, server.forkchoiceUpdated(temp, &.{ choice, .null }));
    try std.testing.expectEqual(@as(usize, 1), chain.records.items.len);
    choice.object.getPtr("safeBlockHash").?.* = try wire.hex(temp, &genesis);
    var request = wire.object();
    try wire.put(temp, &request, "jsonrpc", .{ .string = "2.0" });
    try wire.put(temp, &request, "id", .{ .integer = 7 });
    try wire.put(temp, &request, "method", .{ .string = try std.fmt.allocPrint(temp, "engine_forkchoiceUpdatedV{d}", .{versions.forkchoice}) });
    var request_params = wire.array(temp);
    try request_params.array.append(choice);
    try request_params.array.append(attrs);
    try wire.put(temp, &request, "params", request_params);
    const bearer = try jwt.sign(temp, server.secret, 1_000);
    const body = try std.json.Stringify.valueAlloc(temp, request, .{});
    const invalid_attrs = try server.dispatch(a, bearer, body, 1_000);
    defer a.free(invalid_attrs);
    try std.testing.expect(std.mem.indexOf(u8, invalid_attrs, "-38003") != null);
    try std.testing.expectEqual(@as(usize, 2), chain.records.items.len);
    const committed = try server.forkchoiceUpdated(temp, &.{ choice, .null });
    try std.testing.expectEqualStrings("VALID", try wire.string(try wire.field(try wire.field(committed, "payloadStatus"), "status")));
    try std.testing.expectEqual(@as(usize, 2), chain.records.items.len);
    const older = try chain.olderHashes(temp);
    try std.testing.expectEqualSlices(execution.Hash, &.{genesis}, older);
    const payload_value = &params.array.items[0];
    payload_value.object.getPtr("extraData").?.* = try wire.hex(temp, &.{0x01});
    const request_hash = if (versions.new_payload >= 4) try execution.transition.requestsHash(temp, server.staged.items[0].requests) else try emptyRequestsHash();
    const side_payload = try wire.parsePayload(temp, payload_value.*, @min(versions.new_payload, 3));
    const side_hash = try execution.transition.headerHash(temp, fork, try payloadHeader(temp, side_payload, beacon_root, request_hash));
    payload_value.object.getPtr("blockHash").?.* = try wire.hex(temp, &side_hash);
    const side = try server.newPayload(temp, params.array.items, versions.new_payload);
    try std.testing.expectEqualStrings("ACCEPTED", try wire.string(try wire.field(side, "status")));
    try std.testing.expect((try wire.field(side, "latestValidHash")) == .null);
    var txs = try wire.field(payload_value.*, "transactions");
    try txs.array.append(try wire.hex(temp, &.{}));
    payload_value.object.getPtr("transactions").?.* = txs;
    const empty_tx = try server.newPayload(temp, params.array.items, versions.new_payload);
    try std.testing.expectEqualStrings("INVALID", try wire.string(try wire.field(empty_tx, "status")));
    try std.testing.expectEqualStrings(try wire.string(try wire.hex(temp, &genesis)), try wire.string(try wire.field(empty_tx, "latestValidHash")));
    payload_value.object.getPtr("blockHash").?.* = try wire.hex(temp, &zero);
    const wrong_hash_and_tx = try server.newPayload(temp, params.array.items, versions.new_payload);
    try std.testing.expectEqualStrings("INVALID_BLOCK_HASH", try wire.string(try wire.field(wrong_hash_and_tx, "status")));
    payload_value.object.getPtr("blockHash").?.* = try wire.hex(temp, &side_hash);
    payload_value.object.getPtr("transactions").?.* = wire.array(temp);
    payload_value.object.getPtr("parentHash").?.* = try wire.hex(temp, &([_]u8{0x77} ** 32));
    const orphan_payload = try wire.parsePayload(temp, payload_value.*, @min(versions.new_payload, 3));
    const orphan_hash = try execution.transition.headerHash(temp, fork, try payloadHeader(temp, orphan_payload, beacon_root, request_hash));
    payload_value.object.getPtr("blockHash").?.* = try wire.hex(temp, &orphan_hash);
    const unknown = try server.newPayload(temp, params.array.items, versions.new_payload);
    try std.testing.expectEqualStrings("SYNCING", try wire.string(try wire.field(unknown, "status")));
    try std.testing.expectEqual(@as(usize, 2), chain.records.items.len);
}

test "every Engine fork builds, validates, and commits a payload" {
    for ([_]execution.transition.Fork{ .paris, .shanghai, .cancun, .prague, .osaka, .fulu }) |fork| try checkBuiltFork(fork);
}

test "partial request queue deployment cannot validate or build Osaka payloads" {
    const a = std.testing.allocator;
    var world = execution.state.State.init(a);
    defer world.deinit();
    _ = try world.setCode(execution.transition.withdrawal_requests_address, &.{0x00});
    var genesis = std.mem.zeroes(execution.Header);
    genesis.state_root = try world.stateRoot();
    genesis.gas_limit = 30_000_000;
    genesis.base_fee_per_gas = 1;
    var chain = try execution.chain.Chain.init(a, 1, .osaka, genesis, &world);
    defer chain.deinit();
    var pool = execution.pool.Pool.init(a, .{});
    defer pool.deinit();
    var server: Server = .{ .allocator = a, .chain = &chain, .world = &world, .pool = &pool, .secret = .{0x42} ** 32 };
    defer server.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const parent_hash = chain.latest().hash;
    const zero: execution.Hash = .{0} ** 32;
    var p: fulu.ExecutionPayload = .{ .parent_hash = parent_hash, .fee_recipient = .{0} ** 20, .state_root = genesis.state_root, .receipts_root = zero, .logs_bloom = .{0} ** 256, .prev_randao = zero, .block_number = 1, .gas_limit = genesis.gas_limit, .gas_used = 0, .timestamp = 1, .extra_data = .{ .data = &.{} }, .base_fee_per_gas = 1, .block_hash = zero, .transactions = .{ .data = &.{} }, .withdrawals = .{ .data = &.{} }, .blob_gas_used = 0, .excess_blob_gas = 0 };
    p.block_hash = try execution.transition.headerHash(temp, .osaka, try payloadHeader(temp, p, zero, try emptyRequestsHash()));
    const response = try server.newPayload(temp, &.{ try wire.payloadJson(temp, p, 3), wire.array(temp), try wire.hex(temp, &zero), wire.array(temp) }, 4);
    try std.testing.expectEqualStrings("SYNCING", try wire.string(try wire.field(response, "status")));
    var attrs = wire.object();
    try wire.put(temp, &attrs, "timestamp", try wire.number(temp, @as(u64, 1)));
    try wire.put(temp, &attrs, "prevRandao", try wire.hex(temp, &zero));
    try wire.put(temp, &attrs, "suggestedFeeRecipient", try wire.hex(temp, &([_]u8{0} ** 20)));
    try wire.put(temp, &attrs, "withdrawals", wire.array(temp));
    try wire.put(temp, &attrs, "parentBeaconBlockRoot", try wire.hex(temp, &zero));
    try std.testing.expectError(error.UnsupportedRequestQueues, server.startBuild(temp, attrs, genesis, parent_hash, &chain.latest().world));
    try std.testing.expectEqual(@as(usize, 1), chain.records.items.len);
}

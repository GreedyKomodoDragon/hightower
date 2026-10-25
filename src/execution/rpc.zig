// Execution JSON-RPC reads canonical in-memory blocks and post-states. A raw
// transaction enters the pool only after signature and sidecar validation.
// Calls run against a state snapshot and always discard their writes; gas
// estimation probes the same execution path in bounded binary search order.
//
// HTTP POST -> JSON-RPC method -> canonical index or pool -> JSON response
// This server handles one request at a time and limits bodies, batches, and logs.
const std = @import("std");
const execution = @import("execution.zig");
const chain_mod = @import("chain.zig");
const pool_mod = @import("pool.zig");
const transition = @import("transition.zig");
const ckzg = @import("ckzg");

const Value = std.json.Value;
const max_body = 8 * 1024 * 1024;
const max_batch = 20;
const max_log_blocks = 1000;
const max_log_results = 10_000;

/// Owns no chain data; callers keep these dependencies alive while serving.
pub const Server = struct {
    chain: *chain_mod.Chain,
    pool: *pool_mod.Pool,
    world: *execution.state.State,
    settings: ?*const ckzg.Settings = null,
    revert_data: ?[]const u8 = null,

    /// Parses one bounded JSON-RPC body and returns an owned response body.
    pub fn dispatch(self: *Server, allocator: std.mem.Allocator, body: []const u8) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const result = if (body.len > max_body) try rpcError(a, .null, -32600, "request too large", null) else blk: {
            const parsed = std.json.parseFromSlice(Value, a, body, .{ .allocate = .alloc_always }) catch break :blk try rpcError(a, .null, -32700, "parse error", null);
            const root = parsed.value;
            if (root == .array) {
                if (root.array.items.len == 0 or root.array.items.len > max_batch) break :blk try rpcError(a, .null, -32600, "invalid batch", null);
                var responses = array(a);
                for (root.array.items) |request| try responses.array.append(try self.handle(a, request));
                break :blk responses;
            }
            break :blk try self.handle(a, root);
        };
        const encoded = try std.json.Stringify.valueAlloc(a, result, .{});
        return allocator.dupe(u8, encoded);
    }

    /// Serves one HTTP POST with a limit that fits six hex-encoded blob sidecars.
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
        if (request.head.method != .POST) return request.respond("POST required", .{ .status = .method_not_allowed, .keep_alive = false, .extra_headers = headers });
        if (!std.mem.eql(u8, request.head.target, "/")) return request.respond("not found", .{ .status = .not_found, .keep_alive = false, .extra_headers = headers });
        if (request.head.content_length) |length| {
            if (length > max_body) {
                if (length <= 2 * max_body) {
                    const oversized_reader = request.readerExpectContinue(&body_buffer) catch return;
                    oversized_reader.discardAll64(length) catch {};
                }
                return request.respond("request too large", .{ .status = .payload_too_large, .keep_alive = false, .extra_headers = headers });
            }
        }
        const body_reader = request.readerExpectContinue(&body_buffer) catch return;
        const body = body_reader.allocRemaining(allocator, .limited(max_body)) catch |err| {
            if (err == error.StreamTooLong) return request.respond("request too large", .{ .status = .payload_too_large, .keep_alive = false, .extra_headers = headers });
            return err;
        };
        defer allocator.free(body);
        const response = try self.dispatch(allocator, body);
        defer allocator.free(response);
        try request.respond(response, .{ .status = .ok, .keep_alive = false, .extra_headers = headers });
    }

    /// Accepts HTTP connections until the listener closes.
    pub fn serve(self: *Server, allocator: std.mem.Allocator, io: std.Io, listener: *std.Io.net.Server) !void {
        while (true) {
            const stream = try listener.accept(io);
            self.serveConnection(allocator, io, stream) catch {};
        }
    }

    /// Handles one request and preserves its JSON-RPC id on method errors.
    fn handle(self: *Server, allocator: std.mem.Allocator, request: Value) !Value {
        if (request != .object) return rpcError(allocator, .null, -32600, "invalid request", null);
        const id = request.object.get("id") orelse Value.null;
        const version = request.object.get("jsonrpc") orelse return rpcError(allocator, id, -32600, "invalid request", null);
        if (version != .string or !std.mem.eql(u8, version.string, "2.0")) return rpcError(allocator, id, -32600, "invalid request", null);
        const method_value = request.object.get("method") orelse return rpcError(allocator, id, -32600, "invalid request", null);
        if (method_value != .string) return rpcError(allocator, id, -32600, "invalid request", null);
        const params = request.object.get("params") orelse Value{ .array = std.json.Array.init(allocator) };
        if (params != .array) return rpcError(allocator, id, -32602, "invalid params", null);
        self.revert_data = null;
        const result = self.method(allocator, method_value.string, params.array.items) catch |err| {
            return switch (err) {
                error.MethodNotFound => rpcError(allocator, id, -32601, "method not found", null),
                error.InvalidParams => rpcError(allocator, id, -32602, "invalid params", null),
                error.UnknownBlock => rpcError(allocator, id, -32001, "unknown block", null),
                error.ExecutionReverted => rpcError(allocator, id, 3, "execution reverted", self.revert_data),
                error.LogRangeTooLarge, error.TooManyLogs => rpcError(allocator, id, -32005, "query limit exceeded", null),
                else => rpcError(allocator, id, -32000, @errorName(err), null),
            };
        };
        var response = object(allocator);
        try put(allocator, &response, "jsonrpc", string("2.0"));
        try put(allocator, &response, "id", id);
        try put(allocator, &response, "result", result);
        return response;
    }

    /// Resolves the methods in FULU-057 against canonical state and the pool.
    fn method(self: *Server, a: std.mem.Allocator, name: []const u8, params: []const Value) !Value {
        if (std.mem.eql(u8, name, "eth_chainId")) {
            try noParams(params);
            return quantity(a, self.chain.chain_id);
        }
        if (std.mem.eql(u8, name, "eth_blockNumber")) {
            try noParams(params);
            return quantity(a, self.chain.latest().header.number);
        }
        if (std.mem.eql(u8, name, "eth_getBlockByHash") or std.mem.eql(u8, name, "eth_getBlockByNumber")) {
            if (params.len != 2 or params[1] != .bool) return error.InvalidParams;
            const record = if (std.mem.eql(u8, name, "eth_getBlockByHash")) self.chain.byHash(try parseHash(try asString(params[0]))) else try self.block(try asString(params[0]));
            return if (record) |found| try self.blockJson(a, found, params[1].bool) else .null;
        }
        if (std.mem.eql(u8, name, "eth_getBalance")) {
            if (params.len < 1 or params.len > 2) return error.InvalidParams;
            const address = try parseAddress(try asString(params[0]));
            const record = if (params.len == 2) (try self.block(try asString(params[1]))) orelse return error.UnknownBlock else self.chain.latest();
            return quantity(a, record.world.getBalance(address));
        }
        if (std.mem.eql(u8, name, "eth_call") or std.mem.eql(u8, name, "eth_estimateGas")) {
            if (params.len < 1 or params.len > 2 or params[0] != .object) return error.InvalidParams;
            const record = if (params.len == 2) (try self.block(try asString(params[1]))) orelse return error.UnknownBlock else self.chain.latest();
            const call = try parseCall(a, params[0], record.header.gas_limit);
            if (std.mem.eql(u8, name, "eth_call")) {
                const output = try self.runCall(a, record, call, call.gas);
                return string(try hex(a, output));
            }
            const intrinsic = try callIntrinsic(call.data);
            var lo: u64 = intrinsic;
            var hi: u64 = call.gas;
            if (lo > hi) return error.IntrinsicGasTooLow;
            _ = try self.runCall(a, record, call, hi);
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (self.runCall(a, record, call, mid)) |_| hi = mid else |err| switch (err) {
                    error.OutOfGas, error.IntrinsicGasTooLow => lo = mid + 1,
                    else => return err,
                }
            }
            return quantity(a, lo);
        }
        if (std.mem.eql(u8, name, "eth_sendRawTransaction")) {
            if (params.len != 1) return error.InvalidParams;
            const raw = try parseHex(a, try asString(params[0]));
            const header = self.chain.latest().header;
            const tx_context = self.context(header);
            const hash = try self.pool.admit(self.world, tx_context, self.settings, raw);
            return string(try hex(a, &hash));
        }
        if (std.mem.eql(u8, name, "eth_getTransactionReceipt")) {
            if (params.len != 1) return error.InvalidParams;
            const hash = try parseHash(try asString(params[0]));
            const found = self.chain.transaction(hash) orelse return .null;
            return self.receiptJson(a, found.record, found.index);
        }
        if (std.mem.eql(u8, name, "eth_getLogs")) {
            if (params.len != 1 or params[0] != .object) return error.InvalidParams;
            return self.logsJson(a, params[0]);
        }
        return error.MethodNotFound;
    }

    /// Resolves latest, earliest, pending, or a canonical hexadecimal block number.
    fn block(self: *Server, tag: []const u8) !?*const chain_mod.Record {
        if (std.mem.eql(u8, tag, "latest") or std.mem.eql(u8, tag, "pending")) return self.chain.latest();
        if (std.mem.eql(u8, tag, "earliest")) return &self.chain.records.items[0];
        return self.chain.byNumber(try parseQuantity(u64, tag));
    }

    /// Builds an EVM host context from a stored block header.
    fn context(self: *Server, header: execution.Header) transition.Context {
        return .{ .fork = self.chain.fork, .chain_id = self.chain.chain_id, .coinbase = header.fee_recipient, .number = header.number, .timestamp = header.timestamp, .gas_limit = header.gas_limit, .base_fee = header.base_fee_per_gas, .prev_randao = header.prev_randao, .blob_base_fee = transition.blobBaseFee(self.chain.fork, header.excess_blob_gas) catch null };
    }

    /// Runs an unsigned call on a discarded snapshot and returns its output bytes.
    fn runCall(self: *Server, a: std.mem.Allocator, record: *const chain_mod.Record, call: Call, gas: u64) ![]const u8 {
        const intrinsic = try callIntrinsic(call.data);
        if (gas < intrinsic) return error.IntrinsicGasTooLow;
        const scratch = record.world.allocator;
        var world = try record.world.clone(scratch);
        defer world.deinit();
        if (call.value > world.getBalance(call.from)) return error.InsufficientBalance;
        if (call.value != 0) {
            try world.setBalance(call.from, world.getBalance(call.from) - call.value);
            try world.setBalance(call.to, std.math.add(u256, world.getBalance(call.to), call.value) catch return error.BalanceOverflow);
        }
        var machine = execution.evm.Machine.init(scratch, &world);
        defer machine.deinit();
        const header = record.header;
        try machine.configure(.{ .fork = self.chain.fork, .origin = call.from, .gas_price = header.base_fee_per_gas, .coinbase = header.fee_recipient, .timestamp = header.timestamp, .number = header.number, .prev_randao = std.mem.readInt(u256, &header.prev_randao, .big), .gas_limit = header.gas_limit, .chain_id = self.chain.chain_id, .base_fee = header.base_fee_per_gas, .blob_base_fee = transition.blobBaseFee(self.chain.fork, header.excess_blob_gas) catch 0 }, call.from, call.to, &.{});
        var result = try machine.run(.{ .code = world.getExecutionCode(call.to), .gas = gas - intrinsic, .caller = call.from, .callee = call.to, .value = call.value, .data = call.data });
        defer result.deinit(scratch);
        switch (result.status) {
            .success => return a.dupe(u8, result.output),
            .revert => {
                self.revert_data = try hex(a, result.output);
                return error.ExecutionReverted;
            },
            .fault => return error.OutOfGas,
        }
    }

    /// Serializes one canonical block in the execution-apis field shape.
    fn blockJson(self: *Server, a: std.mem.Allocator, record: *const chain_mod.Record, full: bool) !Value {
        const h = record.header;
        var out = object(a);
        try put(a, &out, "number", try quantity(a, h.number));
        try put(a, &out, "hash", string(try hex(a, &record.hash)));
        try put(a, &out, "parentHash", string(try hex(a, &h.parent_hash)));
        try put(a, &out, "nonce", string(try hex(a, &h.nonce)));
        try put(a, &out, "sha3Uncles", string(try hex(a, &h.ommers_hash)));
        try put(a, &out, "logsBloom", string(try hex(a, &h.logs_bloom)));
        try put(a, &out, "transactionsRoot", string(try hex(a, &h.transactions_root)));
        try put(a, &out, "stateRoot", string(try hex(a, &h.state_root)));
        try put(a, &out, "receiptsRoot", string(try hex(a, &h.receipts_root)));
        try put(a, &out, "miner", string(try hex(a, &h.fee_recipient)));
        try put(a, &out, "difficulty", try quantity(a, h.difficulty));
        try put(a, &out, "totalDifficulty", try quantity(a, h.difficulty));
        try put(a, &out, "extraData", string(try hex(a, h.extra_data)));
        try put(a, &out, "gasLimit", try quantity(a, h.gas_limit));
        try put(a, &out, "gasUsed", try quantity(a, h.gas_used));
        try put(a, &out, "timestamp", try quantity(a, h.timestamp));
        try put(a, &out, "mixHash", string(try hex(a, &h.prev_randao)));
        try put(a, &out, "baseFeePerGas", try quantity(a, h.base_fee_per_gas));
        try put(a, &out, "withdrawalsRoot", string(try hex(a, &h.withdrawals_root)));
        try put(a, &out, "blobGasUsed", try quantity(a, h.blob_gas_used));
        try put(a, &out, "excessBlobGas", try quantity(a, h.excess_blob_gas));
        try put(a, &out, "parentBeaconBlockRoot", string(try hex(a, &h.parent_beacon_block_root)));
        try put(a, &out, "requestsHash", string(try hex(a, &h.requests_hash)));
        var txs = array(a);
        const parsed = try a.alloc(execution.Transaction, record.transactions.len);
        for (record.transactions, 0..) |raw, i| {
            const decoded = try execution.parse(execution.Transaction, a, raw);
            parsed[i] = decoded.value;
            if (full) try txs.array.append(try self.transactionJson(a, record, i)) else {
                var hash: execution.Hash = undefined;
                std.crypto.hash.sha3.Keccak256.hash(raw, &hash, .{});
                try txs.array.append(string(try hex(a, &hash)));
            }
        }
        try put(a, &out, "transactions", txs);
        try put(a, &out, "uncles", array(a));
        var withdrawals = array(a);
        for (record.withdrawals) |item| {
            var value = object(a);
            try put(a, &value, "index", try quantity(a, item.index));
            try put(a, &value, "validatorIndex", try quantity(a, item.validator_index));
            try put(a, &value, "address", string(try hex(a, &item.address)));
            try put(a, &value, "amount", try quantity(a, item.amount));
            try withdrawals.array.append(value);
        }
        try put(a, &out, "withdrawals", withdrawals);
        const encoded = try execution.encode(a, execution.Block{ .header = h, .transactions = parsed, .withdrawals = record.withdrawals });
        try put(a, &out, "size", try quantity(a, encoded.len));
        return out;
    }

    /// Serializes a canonical signed transaction with its block coordinates.
    fn transactionJson(self: *Server, a: std.mem.Allocator, record: *const chain_mod.Record, index: usize) !Value {
        const raw = record.transactions[index];
        var decoded = try execution.parse(execution.Transaction, a, raw);
        defer decoded.deinit();
        const tx = decoded.value;
        const fields = try transition.fields(tx, self.chain.fork);
        const sender = try execution.recoverSender(a, tx, self.chain.chain_id);
        var hash: execution.Hash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(raw, &hash, .{});
        var out = object(a);
        try put(a, &out, "hash", string(try hex(a, &hash)));
        try put(a, &out, "blockHash", string(try hex(a, &record.hash)));
        try put(a, &out, "blockNumber", try quantity(a, record.header.number));
        try put(a, &out, "transactionIndex", try quantity(a, index));
        try put(a, &out, "from", string(try hex(a, &sender)));
        try put(a, &out, "to", if (fields.to) |to| string(try hex(a, &to)) else .null);
        try put(a, &out, "nonce", try quantity(a, fields.nonce));
        try put(a, &out, "gas", try quantity(a, fields.gas_limit));
        try put(a, &out, "value", try quantity(a, fields.value));
        try put(a, &out, "input", string(try hex(a, fields.data)));
        const tag: u8 = switch (tx) {
            .legacy => 0,
            .access_list => 1,
            .dynamic_fee => 2,
            .blob => 3,
            .set_code => 4,
        };
        try put(a, &out, "type", try quantity(a, tag));
        try put(a, &out, "gasPrice", try quantity(a, @min(fields.max_fee, record.header.base_fee_per_gas +| fields.priority_fee)));
        if (tag >= 2) {
            try put(a, &out, "maxFeePerGas", try quantity(a, fields.max_fee));
            try put(a, &out, "maxPriorityFeePerGas", try quantity(a, fields.priority_fee));
        }
        if (tag != 0) {
            try put(a, &out, "chainId", try quantity(a, self.chain.chain_id));
            var access = array(a);
            for (fields.access_list) |entry| {
                var item = object(a);
                try put(a, &item, "address", string(try hex(a, &entry.address)));
                var keys = array(a);
                for (entry.storage_keys) |key| try keys.array.append(string(try hex(a, &key)));
                try put(a, &item, "storageKeys", keys);
                try access.array.append(item);
            }
            try put(a, &out, "accessList", access);
        }
        if (tag == 3) {
            try put(a, &out, "maxFeePerBlobGas", try quantity(a, fields.blob_fee_cap.?));
            var hashes = array(a);
            for (fields.blob_hashes) |blob_hash| try hashes.array.append(string(try hex(a, &blob_hash)));
            try put(a, &out, "blobVersionedHashes", hashes);
        }
        if (tag == 4) {
            var authorizations = array(a);
            for (fields.authorizations) |auth| {
                var item = object(a);
                try put(a, &item, "chainId", try quantity(a, auth.chain_id));
                try put(a, &item, "address", string(try hex(a, &auth.address)));
                try put(a, &item, "nonce", try quantity(a, auth.nonce));
                try put(a, &item, "yParity", try quantity(a, auth.y_parity));
                try put(a, &item, "r", try quantity(a, auth.r));
                try put(a, &item, "s", try quantity(a, auth.s));
                try authorizations.array.append(item);
            }
            try put(a, &out, "authorizationList", authorizations);
        }
        switch (tx) {
            .legacy => |v| {
                try put(a, &out, "v", try quantity(a, v.v));
                try put(a, &out, "r", try quantity(a, v.r));
                try put(a, &out, "s", try quantity(a, v.s));
            },
            inline else => |v| {
                try put(a, &out, "v", try quantity(a, v.y_parity));
                try put(a, &out, "yParity", try quantity(a, v.y_parity));
                try put(a, &out, "r", try quantity(a, v.r));
                try put(a, &out, "s", try quantity(a, v.s));
            },
        }
        return out;
    }

    /// Serializes one transaction receipt and its indexed logs.
    fn receiptJson(self: *Server, a: std.mem.Allocator, record: *const chain_mod.Record, index: usize) !Value {
        const receipts = record.receipts();
        if (index >= receipts.len) return .null;
        const payload = switch (receipts[index]) {
            inline else => |v| v,
        };
        const previous: u64 = if (index == 0) 0 else switch (receipts[index - 1]) {
            inline else => |v| v.cumulative_gas_used,
        };
        const tx = try self.transactionJson(a, record, index);
        var out = object(a);
        for ([_][]const u8{ "transactionHash", "transactionIndex", "blockHash", "blockNumber", "from", "to", "type" }) |key| {
            const source = if (std.mem.eql(u8, key, "transactionHash")) "hash" else key;
            try put(a, &out, key, tx.object.get(source).?);
        }
        try put(a, &out, "contractAddress", .null);
        try put(a, &out, "cumulativeGasUsed", try quantity(a, payload.cumulative_gas_used));
        try put(a, &out, "gasUsed", try quantity(a, payload.cumulative_gas_used - previous));
        try put(a, &out, "effectiveGasPrice", tx.object.get("gasPrice").?);
        try put(a, &out, "status", try quantity(a, payload.status));
        try put(a, &out, "logsBloom", string(try hex(a, &payload.logs_bloom)));
        if (receipts[index] == .blob) {
            const fields = try transition.fields((try execution.parse(execution.Transaction, a, record.transactions[index])).value, self.chain.fork);
            try put(a, &out, "blobGasUsed", try quantity(a, fields.blob_hashes.len * 131_072));
            try put(a, &out, "blobGasPrice", try quantity(a, try transition.blobBaseFee(self.chain.fork, record.header.excess_blob_gas)));
        }
        var log_index: usize = 0;
        for (receipts[0..index]) |receipt| log_index += switch (receipt) {
            inline else => |v| v.logs.len,
        };
        var logs = array(a);
        for (payload.logs) |log| {
            try logs.array.append(try logJson(a, record, index, log_index, log));
            log_index += 1;
        }
        try put(a, &out, "logs", logs);
        return out;
    }

    /// Filters canonical logs by range, address, and positional topic alternatives.
    fn logsJson(self: *Server, a: std.mem.Allocator, filter: Value) !Value {
        const obj = filter.object;
        try validateLogFilter(obj);
        const specified_hash = obj.get("blockHash");
        if (specified_hash != null and (obj.get("fromBlock") != null or obj.get("toBlock") != null)) return error.InvalidParams;
        const from: u64 = if (specified_hash) |v| blk: {
            const record = self.chain.byHash(try parseHash(try asString(v))) orelse return array(a);
            break :blk record.header.number;
        } else if (obj.get("fromBlock")) |v| try self.logBound(try asString(v)) else self.chain.latest().header.number;
        const to: u64 = if (specified_hash != null) from else if (obj.get("toBlock")) |v| try self.logBound(try asString(v)) else self.chain.latest().header.number;
        if (to >= from and to - from >= max_log_blocks) return error.LogRangeTooLarge;
        var result = array(a);
        if (to < from) return result;
        for (self.chain.records.items) |*record| {
            if (record.header.number < from or record.header.number > to) continue;
            var block_log_index: usize = 0;
            for (record.receipts(), 0..) |receipt, tx_index| {
                const logs = switch (receipt) {
                    inline else => |v| v.logs,
                };
                for (logs) |log| {
                    if (try logMatches(obj, log)) {
                        if (result.array.items.len >= max_log_results) return error.TooManyLogs;
                        try result.array.append(try logJson(a, record, tx_index, block_log_index, log));
                    }
                    block_log_index += 1;
                }
            }
        }
        return result;
    }

    /// Resolves a log range endpoint without requiring that future block to exist.
    fn logBound(self: *Server, tag: []const u8) !u64 {
        if (std.mem.eql(u8, tag, "latest") or std.mem.eql(u8, tag, "pending")) return self.chain.latest().header.number;
        if (std.mem.eql(u8, tag, "earliest")) return self.chain.records.items[0].header.number;
        return parseQuantity(u64, tag);
    }
};

const Call = struct { from: execution.Address, to: execution.Address, gas: u64, value: u256, data: []const u8 };

/// Serializes a log with block and transaction coordinates.
fn logJson(a: std.mem.Allocator, record: *const chain_mod.Record, tx_index: usize, log_index: usize, log: execution.Log) !Value {
    var tx_hash: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(record.transactions[tx_index], &tx_hash, .{});
    var out = object(a);
    try put(a, &out, "address", string(try hex(a, &log.address)));
    var topics = array(a);
    for (log.topics) |topic| try topics.array.append(string(try hex(a, &topic)));
    try put(a, &out, "topics", topics);
    try put(a, &out, "data", string(try hex(a, log.data)));
    try put(a, &out, "blockNumber", try quantity(a, record.header.number));
    try put(a, &out, "transactionHash", string(try hex(a, &tx_hash)));
    try put(a, &out, "transactionIndex", try quantity(a, tx_index));
    try put(a, &out, "blockHash", string(try hex(a, &record.hash)));
    try put(a, &out, "logIndex", try quantity(a, log_index));
    try put(a, &out, "removed", .{ .bool = false });
    return out;
}

/// Applies Ethereum address and positional topic filters to one log.
fn logMatches(filter: std.json.ObjectMap, log: execution.Log) !bool {
    if (filter.get("address")) |address| {
        if (address == .string) {
            const wanted = try parseAddress(address.string);
            if (!std.mem.eql(u8, &wanted, &log.address)) return false;
        } else if (address == .array) {
            var found = false;
            for (address.array.items) |item| {
                const wanted = try parseAddress(try asString(item));
                if (std.mem.eql(u8, &wanted, &log.address)) found = true;
            }
            if (!found) return false;
        } else return error.InvalidParams;
    }
    if (filter.get("topics")) |topics| {
        if (topics != .array or topics.array.items.len > 4) return error.InvalidParams;
        if (topics.array.items.len > log.topics.len) return false;
        for (topics.array.items, 0..) |position, i| {
            if (position == .null) continue;
            if (position == .string) {
                const wanted = try parseHash(position.string);
                if (!std.mem.eql(u8, &wanted, &log.topics[i])) return false;
            } else if (position == .array) {
                var found = false;
                for (position.array.items) |option| {
                    if (option == .null) {
                        found = true;
                        continue;
                    }
                    const wanted = try parseHash(try asString(option));
                    if (std.mem.eql(u8, &wanted, &log.topics[i])) found = true;
                }
                if (!found) return false;
            } else return error.InvalidParams;
        }
    }
    return true;
}

/// Validates log filter shapes even when the selected range contains no logs.
fn validateLogFilter(filter: std.json.ObjectMap) !void {
    if (filter.get("address")) |address| {
        if (address == .string) {
            _ = try parseAddress(address.string);
        } else if (address == .array) {
            for (address.array.items) |item| _ = try parseAddress(try asString(item));
        } else return error.InvalidParams;
    }
    if (filter.get("topics")) |topics| {
        if (topics != .array or topics.array.items.len > 4) return error.InvalidParams;
        for (topics.array.items) |position| {
            if (position == .null) continue;
            if (position == .string) {
                _ = try parseHash(position.string);
            } else if (position == .array) {
                for (position.array.items) |option| if (option != .null) {
                    _ = try parseHash(try asString(option));
                };
            } else return error.InvalidParams;
        }
    }
}

/// Parses the fields needed for an unsigned call or gas estimate.
fn parseCall(a: std.mem.Allocator, value: Value, default_gas: u64) !Call {
    const obj = value.object;
    const to = try parseAddress(try asString(obj.get("to") orelse return error.InvalidParams));
    const from: execution.Address = if (obj.get("from")) |v| try parseAddress(try asString(v)) else .{0} ** 20;
    const gas = if (obj.get("gas")) |v| try parseQuantity(u64, try asString(v)) else default_gas;
    const amount = if (obj.get("value")) |v| try parseQuantity(u256, try asString(v)) else 0;
    const data = if (obj.get("data") orelse obj.get("input")) |v| try parseHex(a, try asString(v)) else &.{};
    return .{ .from = from, .to = to, .gas = @min(gas, default_gas), .value = amount, .data = data };
}

/// Calculates basic transaction intrinsic gas for call estimation.
fn callIntrinsic(data: []const u8) !u64 {
    var gas: u64 = 21_000;
    for (data) |byte| gas = std.math.add(u64, gas, if (byte == 0) 4 else 16) catch return error.GasOverflow;
    return gas;
}

/// Reads a JSON string argument.
fn asString(value: Value) ![]const u8 {
    return if (value == .string) value.string else error.InvalidParams;
}

/// Requires an empty parameter list.
fn noParams(params: []const Value) !void {
    if (params.len != 0) return error.InvalidParams;
}

/// Parses a canonical 0x-prefixed JSON-RPC quantity.
fn parseQuantity(comptime T: type, value: []const u8) !T {
    if (value.len < 3 or !std.mem.startsWith(u8, value, "0x") or (value.len > 3 and value[2] == '0')) return error.InvalidParams;
    return std.fmt.parseInt(T, value[2..], 16) catch error.InvalidParams;
}

/// Decodes a 20-byte JSON-RPC address.
fn parseAddress(value: []const u8) !execution.Address {
    return parseFixed(20, value);
}

/// Decodes a 32-byte JSON-RPC hash.
fn parseHash(value: []const u8) !execution.Hash {
    return parseFixed(32, value);
}

/// Decodes a fixed-width 0x-prefixed hexadecimal value.
fn parseFixed(comptime len: usize, value: []const u8) ![len]u8 {
    if (value.len != 2 + len * 2 or !std.mem.startsWith(u8, value, "0x")) return error.InvalidParams;
    var out: [len]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, value[2..]) catch return error.InvalidParams;
    return out;
}

/// Decodes a byte string with an even number of hexadecimal digits.
fn parseHex(a: std.mem.Allocator, value: []const u8) ![]u8 {
    if (value.len < 2 or value.len % 2 != 0 or !std.mem.startsWith(u8, value, "0x")) return error.InvalidParams;
    const out = try a.alloc(u8, (value.len - 2) / 2);
    _ = std.fmt.hexToBytes(out, value[2..]) catch return error.InvalidParams;
    return out;
}

/// Encodes bytes as a JSON-RPC data string.
fn hex(a: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const digits = "0123456789abcdef";
    const out = try a.alloc(u8, bytes.len * 2 + 2);
    out[0] = '0';
    out[1] = 'x';
    for (bytes, 0..) |byte, i| {
        out[2 + i * 2] = digits[byte >> 4];
        out[3 + i * 2] = digits[byte & 15];
    }
    return out;
}

/// Encodes an integer without leading zeroes as a JSON-RPC quantity.
fn quantity(a: std.mem.Allocator, number: anytype) !Value {
    return string(try std.fmt.allocPrint(a, "0x{x}", .{number}));
}

/// Wraps a string as a dynamic JSON value.
fn string(value: []const u8) Value {
    return .{ .string = value };
}

/// Creates an empty dynamic JSON object.
fn object(_: std.mem.Allocator) Value {
    return .{ .object = .empty };
}

/// Creates an empty dynamic JSON array.
fn array(a: std.mem.Allocator) Value {
    return .{ .array = std.json.Array.init(a) };
}

/// Inserts one JSON object property.
fn put(a: std.mem.Allocator, value: *Value, key: []const u8, item: Value) !void {
    try value.object.put(a, key, item);
}

/// Creates a JSON-RPC error response with optional revert data.
fn rpcError(a: std.mem.Allocator, id: Value, code: i64, message: []const u8, data: ?[]const u8) !Value {
    var detail = object(a);
    try put(a, &detail, "code", .{ .integer = code });
    try put(a, &detail, "message", string(message));
    if (data) |bytes| try put(a, &detail, "data", string(bytes));
    var response = object(a);
    try put(a, &response, "jsonrpc", string("2.0"));
    try put(a, &response, "id", id);
    try put(a, &response, "error", detail);
    return response;
}

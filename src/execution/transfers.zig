// Finalized execution blocks form an ordered, immutable receipt stream. A
// cursor names the last emitted canonical block and its configured contract.
// Output precedes the durable cursor write, so a crash can replay one block.
//
// finalized path -> receipt logs -> JSON lines -> synced block cursor
const std = @import("std");
const execution = @import("execution.zig");

const cursor_key = "transfer/cursor";
const transfer_signature = "Transfer(address,address,uint256)";

pub const Stream = struct {
    allocator: std.mem.Allocator,
    store: *execution.durable.Store,
    chain: *execution.chain.Chain,
    contract: execution.Address,
    output: *const fn (*anyopaque, []const u8) anyerror!void,
    context: *anyopaque,

    /// Emits newly finalized canonical blocks and persists each completed block.
    pub fn catchUp(self: *Stream) !void {
        const saved = try self.store.db.get(self.allocator, cursor_key);
        defer if (saved) |bytes| self.allocator.free(bytes);
        const genesis = self.chain.records.items[0];
        var cursor = genesis.hash;
        if (saved) |bytes| {
            if (bytes.len != 52) return error.CorruptTransferCursor;
            if (!std.mem.eql(u8, bytes[0..20], &self.contract)) return error.TransferContractMismatch;
            cursor = bytes[20..52].*;
        } else {
            if (self.chain.history_floor > genesis.header.number) return error.TransferHistoryPruned;
            try self.saveCursor(cursor);
        }
        const finalized = self.chain.byHash(self.chain.finalized_hash) orelse return;
        const previous = self.chain.byHash(cursor) orelse return error.TransferHistoryPruned;
        if (previous.header.number < self.chain.history_floor and previous.header.number < finalized.header.number) return error.TransferHistoryPruned;
        if (previous.header.number > finalized.header.number) return error.CorruptTransferCursor;
        var path = try self.chain.path(self.allocator, finalized.hash);
        defer path.deinit(self.allocator);
        var seen = false;
        for (path.items) |index| {
            const record = &self.chain.records.items[index];
            if (!seen) {
                if (std.mem.eql(u8, &record.hash, &cursor)) seen = true;
                continue;
            }
            try self.emitBlock(record);
            try self.saveCursor(record.hash);
        }
        if (!seen) return error.CorruptTransferCursor;
    }

    /// Writes the configured contract and completed canonical block atomically.
    fn saveCursor(self: *Stream, hash: execution.Hash) !void {
        var value: [52]u8 = undefined;
        @memcpy(value[0..20], &self.contract);
        @memcpy(value[20..52], &hash);
        try self.store.db.put(cursor_key, &value);
    }

    /// Emits successful ERC-20 Transfer logs in receipt and log order.
    fn emitBlock(self: *Stream, record: *const execution.chain.Record) !void {
        // SAFETY: Keccak fills the digest before comparison.
        var topic: execution.Hash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(transfer_signature, &topic, .{});
        var log_index: usize = 0;
        for (record.receipts(), 0..) |receipt, tx_index| {
            const body = switch (receipt) {
                inline else => |value| value,
            };
            for (body.logs) |log| {
                defer log_index += 1;
                if (body.status != 1 or !std.mem.eql(u8, &log.address, &self.contract) or log.topics.len != 3 or log.data.len != 32 or !std.mem.eql(u8, &log.topics[0], &topic)) continue;
                // SAFETY: Keccak fills the digest before serialization.
                var transaction_hash: execution.Hash = undefined;
                std.crypto.hash.sha3.Keccak256.hash(record.transactions[tx_index], &transaction_hash, .{});
                var arena = std.heap.ArenaAllocator.init(self.allocator);
                defer arena.deinit();
                const a = arena.allocator();
                const event = .{
                    .id = try std.fmt.allocPrint(a, "0x{s}:{d}", .{ std.fmt.bytesToHex(record.hash, .lower), log_index }),
                    .contract = try std.fmt.allocPrint(a, "0x{s}", .{std.fmt.bytesToHex(self.contract, .lower)}),
                    .from = try std.fmt.allocPrint(a, "0x{s}", .{std.fmt.bytesToHex(log.topics[1][12..], .lower)}),
                    .to = try std.fmt.allocPrint(a, "0x{s}", .{std.fmt.bytesToHex(log.topics[2][12..], .lower)}),
                    .amount = try std.fmt.allocPrint(a, "0x{s}", .{std.fmt.bytesToHex(log.data[0..32].*, .lower)}),
                    .block_hash = try std.fmt.allocPrint(a, "0x{s}", .{std.fmt.bytesToHex(record.hash, .lower)}),
                    .transaction_hash = try std.fmt.allocPrint(a, "0x{s}", .{std.fmt.bytesToHex(transaction_hash, .lower)}),
                    .block_number = record.header.number,
                    .log_index = log_index,
                };
                const line = try std.json.Stringify.valueAlloc(a, event, .{});
                try self.output(self.context, try std.fmt.allocPrint(a, "{s}\n", .{line}));
            }
        }
    }
};

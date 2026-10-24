// A transaction spends sender gas and value before its EVM frame runs. A failed
// frame keeps the nonce and gas charge, while reverting its value transfer and
// storage writes. Ordered receipts commit cumulative gas; withdrawals and any
// pre-Merge issuance follow transactions before the state root is checked.
//
// parent header -> transaction 0 -> ... -> withdrawal 0 -> roots -> commit
// A block snapshot rolls back all earlier transactions if a later check fails.
// Supported forks: London, Cancun, and Prague-shaped Fulu. Blob and set-code
// transactions, contract creation, and precompiles require capabilities not yet
// provided by this EVM.
const std = @import("std");
const execution = @import("execution.zig");
const state = execution.state;
const evm = execution.evm;

pub const Fork = evm.Fork;
pub const Context = struct {
    fork: Fork,
    chain_id: u256,
    coinbase: execution.Address,
    number: u64,
    timestamp: u64,
    gas_limit: u64,
    base_fee: u256,
    prev_randao: execution.Hash = .{0} ** 32,
    difficulty: u256 = 0,
    blob_base_fee: ?u256 = null,
};

/// Owns a receipt's logs and return bytes until deinit.
pub const Outcome = struct {
    arena: std.heap.ArenaAllocator,
    receipt: execution.Receipt,
    gas_used: u64,
    output: []const u8,
    /// Releases all receipt logs and return data.
    pub fn deinit(self: *Outcome) void {
        self.arena.deinit();
    }
};

/// Owns ordered transaction receipts and computed block commitments.
pub const BlockResult = struct {
    arena: std.heap.ArenaAllocator,
    receipts: []execution.Receipt,
    state_root: execution.Hash,
    transactions_root: execution.Hash,
    receipts_root: execution.Hash,
    withdrawals_root: ?execution.Hash,
    logs_bloom: execution.Bloom,
    gas_used: u64,
    /// Releases all receipts and their logs.
    pub fn deinit(self: *BlockResult) void {
        self.arena.deinit();
    }
};

const TxFields = struct {
    nonce: u64,
    gas_limit: u64,
    to: ?execution.Address,
    value: u256,
    data: []const u8,
    access_list: []const execution.Access,
    max_fee: u256,
    priority_fee: u256,
};

/// Selects executable transaction fields and rejects envelopes without execution support.
fn fields(tx: execution.Transaction, fork: Fork) !TxFields {
    return switch (tx) {
        .legacy => |v| .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.to, .value = v.value, .data = v.data, .access_list = &.{}, .max_fee = v.gas_price, .priority_fee = v.gas_price },
        .access_list => |v| .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.to, .value = v.value, .data = v.data, .access_list = v.access_list, .max_fee = v.gas_price, .priority_fee = v.gas_price },
        .dynamic_fee => |v| .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.to, .value = v.value, .data = v.data, .access_list = v.access_list, .max_fee = v.max_fee_per_gas, .priority_fee = v.max_priority_fee_per_gas },
        .blob => if (fork == .london) error.UnsupportedTransactionType else error.UnsupportedBlobTransaction,
        .set_code => if (fork != .fulu) error.UnsupportedTransactionType else error.UnsupportedSetCodeTransaction,
    };
}

/// Computes intrinsic gas including access-list entries and Prague's calldata floor.
fn intrinsicGas(tx: TxFields, fork: Fork) !u64 {
    var gas: u64 = if (tx.to == null) 53_000 else 21_000;
    var tokens: u64 = 0;
    for (tx.data) |byte| {
        gas = try std.math.add(u64, gas, if (byte == 0) 4 else 16);
        tokens = try std.math.add(u64, tokens, if (byte == 0) 1 else 4);
    }
    for (tx.access_list) |entry| {
        gas = try std.math.add(u64, gas, 2400);
        gas = try std.math.add(u64, gas, try std.math.mul(u64, @intCast(entry.storage_keys.len), 1900));
    }
    if (fork == .fulu) gas = @max(gas, try std.math.add(u64, 21_000, try std.math.mul(u64, tokens, 10)));
    return gas;
}

/// Returns the Prague minimum gas spent for calldata tokens.
fn calldataFloor(data: []const u8) !u64 {
    var gas: u64 = 21_000;
    for (data) |byte| gas = try std.math.add(u64, gas, if (byte == 0) 10 else 40);
    return gas;
}

const ValidatedTx = struct {
    fields: TxFields,
    sender: execution.Address,
    recipient: execution.Address,
    intrinsic_gas: u64,
    max_cost: u256,
    effective_price: u256,
};

const FrameOutcome = struct {
    success: bool,
    gas_remaining: u64,
    refund: u64,
    logs: []const execution.Log,
    output: []const u8,
};

/// Checks every transaction rule that can reject input before any state mutation.
fn validateTransaction(allocator: std.mem.Allocator, world: *state.State, context: Context, tx: execution.Transaction, available_gas: u64) !ValidatedTx {
    const f = try fields(tx, context.fork);
    const sender = try execution.recoverSender(allocator, tx, context.chain_id);
    if (world.getNonce(sender) != f.nonce) return error.InvalidNonce;
    if (f.gas_limit > available_gas) return error.BlockGasLimitExceeded;
    const intrinsic = intrinsicGas(f, context.fork) catch return error.IntrinsicGasOverflow;
    if (f.gas_limit < intrinsic) return error.IntrinsicGasTooLow;
    if (f.priority_fee > f.max_fee or f.max_fee < context.base_fee) return error.InvalidFee;
    const max_cost = std.math.mul(u256, f.max_fee, f.gas_limit) catch return error.InsufficientBalance;
    const upfront = std.math.add(u256, max_cost, f.value) catch return error.InsufficientBalance;
    if (world.getBalance(sender) < upfront) return error.InsufficientBalance;
    if (f.nonce == std.math.maxInt(u64)) return error.InvalidNonce;
    const recipient = f.to orelse return error.UnsupportedContractCreation;
    const precompile_limit: u8 = switch (context.fork) {
        .london => 9,
        .cancun => 10,
        .fulu => 17,
    };
    if (recipient[19] != 0 and recipient[19] <= precompile_limit and std.mem.allEqual(u8, recipient[0..19], 0)) return error.UnsupportedExecution;
    return .{ .fields = f, .sender = sender, .recipient = recipient, .intrinsic_gas = intrinsic, .max_cost = max_cost, .effective_price = @min(f.max_fee, std.math.add(u256, context.base_fee, f.priority_fee) catch std.math.maxInt(u256)) };
}

/// Executes the value transfer and EVM frame, copying logs before the machine is released.
fn executeFrame(allocator: std.mem.Allocator, owner: std.mem.Allocator, world: *state.State, context: Context, tx: ValidatedTx) !FrameOutcome {
    const frame = try world.snapshot();
    var frame_open = true;
    errdefer if (frame_open) world.revert(frame) catch {};
    if (tx.fields.value != 0) {
        try world.setBalance(tx.sender, world.getBalance(tx.sender) - tx.fields.value);
        try world.setBalance(tx.recipient, std.math.add(u256, world.getBalance(tx.recipient), tx.fields.value) catch return error.BalanceOverflow);
    }
    var machine = evm.Machine.init(allocator, world);
    defer machine.deinit();
    const access = try owner.alloc(evm.Access, tx.fields.access_list.len);
    for (tx.fields.access_list, 0..) |item, i| {
        const keys = try owner.alloc(u256, item.storage_keys.len);
        for (item.storage_keys, 0..) |key, j| keys[j] = std.mem.readInt(u256, &key, .big);
        access[i] = .{ .address = item.address, .storage_keys = keys };
    }
    try machine.configure(.{ .fork = context.fork, .origin = tx.sender, .gas_price = tx.effective_price, .coinbase = context.coinbase, .timestamp = context.timestamp, .number = context.number, .prev_randao = if (context.fork == .london) context.difficulty else std.mem.readInt(u256, &context.prev_randao, .big), .gas_limit = context.gas_limit, .chain_id = context.chain_id, .base_fee = context.base_fee, .blob_base_fee = context.blob_base_fee orelse 0, .blob_base_fee_supported = context.blob_base_fee != null }, tx.sender, tx.recipient, access);
    var result = try machine.run(.{ .code = world.getCode(tx.recipient), .gas = tx.fields.gas_limit - tx.intrinsic_gas, .caller = tx.sender, .callee = tx.recipient, .value = tx.fields.value, .data = tx.fields.data });
    defer result.deinit(allocator);
    if (result.status == .fault and (result.status.fault == .unsupported_precompile or result.status.fault == .unsupported_opcode)) return error.UnsupportedExecution;
    const success = result.status == .success;
    if (success) {
        try world.commit(frame);
    } else {
        try world.revert(frame);
    }
    frame_open = false;
    const spent = tx.fields.gas_limit - result.gas_remaining;
    const logs = try owner.alloc(execution.Log, if (success) machine.emittedLogs().len else 0);
    for (logs, machine.emittedLogs()) |*dest, source| dest.* = .{ .address = source.address, .topics = try owner.dupe(execution.Hash, source.topics[0..source.topic_count]), .data = try owner.dupe(u8, source.data) };
    return .{ .success = success, .gas_remaining = result.gas_remaining, .refund = if (success) machine.cappedRefund(spent) else 0, .logs = logs, .output = try owner.dupe(u8, result.output) };
}

/// Refunds unused gas to the sender and pays only the priority fee to coinbase.
fn settleFees(world: *state.State, context: Context, tx: ValidatedTx, gas_used: u64) !void {
    const actual_cost = std.math.mul(u256, tx.effective_price, gas_used) catch return error.BalanceOverflow;
    try world.setBalance(tx.sender, std.math.add(u256, world.getBalance(tx.sender), tx.max_cost - actual_cost) catch return error.BalanceOverflow);
    const tip = std.math.mul(u256, tx.effective_price - context.base_fee, gas_used) catch return error.BalanceOverflow;
    try world.setBalance(context.coinbase, std.math.add(u256, world.getBalance(context.coinbase), tip) catch return error.BalanceOverflow);
}

/// Applies one signed encoded transaction, leaving state untouched for invalid input.
pub fn applyTransaction(allocator: std.mem.Allocator, world: *state.State, context: Context, raw: []const u8, available_gas: u64, cumulative_gas: u64) !Outcome {
    var decoded = try execution.parse(execution.Transaction, allocator, raw);
    defer decoded.deinit();
    const tx = try validateTransaction(allocator, world, context, decoded.value, available_gas);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const snap = try world.snapshot();
    var open = true;
    errdefer if (open) world.revert(snap) catch {};
    try world.setBalance(tx.sender, world.getBalance(tx.sender) - tx.max_cost);
    try world.setNonce(tx.sender, tx.fields.nonce + 1);
    const frame = try executeFrame(allocator, arena.allocator(), world, context, tx);
    const spent = tx.fields.gas_limit - frame.gas_remaining;
    const floor = if (context.fork == .fulu) try calldataFloor(tx.fields.data) else 0;
    const gas_used = @max(spent - frame.refund, floor);
    try settleFees(world, context, tx, gas_used);
    const payload: execution.ReceiptPayload = .{ .status = if (frame.success) 1 else 0, .cumulative_gas_used = std.math.add(u64, cumulative_gas, gas_used) catch return error.BlockGasLimitExceeded, .logs = frame.logs, .logs_bloom = execution.logsBloom(frame.logs) };
    const receipt: execution.Receipt = switch (decoded.value) {
        .legacy => .{ .legacy = payload },
        .access_list => .{ .access_list = payload },
        .dynamic_fee => .{ .dynamic_fee = payload },
        else => unreachable,
    };
    try world.commit(snap);
    open = false;
    return .{ .arena = arena, .receipt = receipt, .gas_used = gas_used, .output = frame.output };
}

/// Calculates EIP-1559's next base fee from the parent gas target.
fn nextBaseFee(parent_gas_limit: u64, parent_gas_used: u64, parent_base_fee: u256) !u256 {
    const target = parent_gas_limit / 2;
    if (target == 0 or parent_gas_used == target) return parent_base_fee;
    if (parent_gas_used > target) {
        const change: u256 = @intCast(@min(std.math.maxInt(u256), @max(1, (@as(u512, parent_base_fee) * (parent_gas_used - target) / target) / 8)));
        return std.math.add(u256, parent_base_fee, change) catch error.BaseFeeOverflow;
    }
    const change: u256 = @intCast(@min(std.math.maxInt(u256), (@as(u512, parent_base_fee) * (target - parent_gas_used) / target) / 8));
    return parent_base_fee -| change;
}

/// Rejects headers and withdrawals that cannot follow the supplied parent and fork.
fn validateBlockHeader(fork: Fork, parent: execution.Header, header: execution.Header, withdrawals: []const execution.Withdrawal) !void {
    if (header.number != std.math.add(u64, parent.number, 1) catch return error.InvalidBlockNumber) return error.InvalidBlockNumber;
    if (header.timestamp <= parent.timestamp) return error.InvalidTimestamp;
    if (parent.gas_used > parent.gas_limit) return error.InvalidParentGasUsed;
    if (header.gas_limit < 5000 or @abs(@as(i128, header.gas_limit) - @as(i128, parent.gas_limit)) >= parent.gas_limit / 1024) return error.InvalidGasLimit;
    if (header.base_fee_per_gas != try nextBaseFee(parent.gas_limit, parent.gas_used, parent.base_fee_per_gas)) return error.InvalidBaseFee;
    if (fork == .london and withdrawals.len != 0) return error.UnsupportedWithdrawals;
}

/// Runs transactions in order and copies their logs into the block-owned arena.
fn applyBlockTransactions(allocator: std.mem.Allocator, world: *state.State, context: Context, transactions: []const []const u8, receipts: []execution.Receipt) !u64 {
    var gas_used: u64 = 0;
    for (transactions, 0..) |raw, i| {
        var outcome = try applyTransaction(allocator, world, context, raw, context.gas_limit - gas_used, gas_used);
        defer outcome.deinit();
        receipts[i] = outcome.receipt;
        gas_used += outcome.gas_used;
        const payload = switch (receipts[i]) {
            inline else => |p| p,
        };
        const logs = try allocator.alloc(execution.Log, payload.logs.len);
        for (logs, payload.logs) |*dest, source| dest.* = .{ .address = source.address, .topics = try allocator.dupe(execution.Hash, source.topics), .data = try allocator.dupe(u8, source.data) };
        switch (receipts[i]) {
            inline else => |*p| p.logs = logs,
        }
    }
    return gas_used;
}

/// Credits London issuance and then each consensus withdrawal in block order.
fn applyBlockCredits(world: *state.State, fork: Fork, coinbase: execution.Address, withdrawals: []const execution.Withdrawal) !void {
    if (fork == .london) {
        try world.setBalance(coinbase, std.math.add(u256, world.getBalance(coinbase), 2_000_000_000_000_000_000) catch return error.BalanceOverflow);
    }
    for (withdrawals) |withdrawal| {
        const amount = std.math.mul(u256, withdrawal.amount, 1_000_000_000) catch return error.BalanceOverflow;
        try world.setBalance(withdrawal.address, std.math.add(u256, world.getBalance(withdrawal.address), amount) catch return error.BalanceOverflow);
    }
}

/// Computes ordered trie roots, bloom, and post-state root for the completed block.
fn blockResult(arena: *std.heap.ArenaAllocator, world: *state.State, fork: Fork, transactions: []const []const u8, withdrawals: []const execution.Withdrawal, receipts: []execution.Receipt, gas_used: u64) !BlockResult {
    const allocator = arena.allocator();
    const tx_root = try execution.trie.orderedRoot(allocator, transactions);
    const receipts_root = try execution.receiptsRoot(allocator, receipts);
    const bloom = execution.receiptsBloom(receipts);
    const withdrawals_root: ?execution.Hash = if (fork == .london) null else blk: {
        const encoded = try allocator.alloc([]const u8, withdrawals.len);
        for (withdrawals, 0..) |withdrawal, i| encoded[i] = try execution.encode(allocator, withdrawal);
        break :blk try execution.trie.orderedRoot(allocator, encoded);
    };
    return .{ .arena = arena.*, .receipts = receipts, .state_root = try world.stateRoot(), .transactions_root = tx_root, .receipts_root = receipts_root, .withdrawals_root = withdrawals_root, .logs_bloom = bloom, .gas_used = gas_used };
}

/// Requires every computed commitment to match the block's claimed header.
fn verifyBlockCommitments(header: execution.Header, result: BlockResult) !void {
    if (!std.mem.eql(u8, &result.transactions_root, &header.transactions_root) or !std.mem.eql(u8, &result.receipts_root, &header.receipts_root) or !std.mem.eql(u8, &result.state_root, &header.state_root) or !std.mem.eql(u8, &result.logs_bloom, &header.logs_bloom)) return error.InvalidCommitment;
    if (result.withdrawals_root) |root| if (!std.mem.eql(u8, &root, &header.withdrawals_root)) return error.InvalidCommitment;
}

/// Applies ordered transactions and withdrawals, checking all claimed roots atomically.
pub fn applyBlock(allocator: std.mem.Allocator, world: *state.State, fork: Fork, chain_id: u256, parent: execution.Header, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal) !BlockResult {
    try validateBlockHeader(fork, parent, header, withdrawals);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const receipts = try arena.allocator().alloc(execution.Receipt, transactions.len);
    const snapshot = try world.snapshot();
    var open = true;
    errdefer if (open) world.revert(snapshot) catch {};
    const context: Context = .{ .fork = fork, .chain_id = chain_id, .coinbase = header.fee_recipient, .number = header.number, .timestamp = header.timestamp, .gas_limit = header.gas_limit, .base_fee = header.base_fee_per_gas, .prev_randao = header.prev_randao, .difficulty = header.difficulty };
    const gas_used = try applyBlockTransactions(arena.allocator(), world, context, transactions, receipts);
    if (gas_used != header.gas_used) return error.InvalidGasUsed;
    try applyBlockCredits(world, fork, header.fee_recipient, withdrawals);
    const result = try blockResult(&arena, world, fork, transactions, withdrawals, receipts, gas_used);
    try verifyBlockCommitments(header, result);
    try world.commit(snapshot);
    open = false;
    return result;
}

// A transaction spends sender gas and value before its EVM frame runs. A failed
// frame keeps the nonce and gas charge, while reverting its value transfer and
// storage writes. Ordered receipts commit cumulative gas; withdrawals and any
// pre-Merge issuance follow transactions before the state root is checked.
// Cancun beacon roots and Prague parent hashes enter system contracts before
// transactions, so EVM reads and the final state commitment see those writes.
//
// parent header -> system calls -> transactions -> withdrawals -> roots -> commit
// A block snapshot rolls back all earlier transactions if a later check fails.
// Supported forks: London through Osaka/Fulu, with request-producing system
// transitions still pending. Contract creation and precompiles are separate.
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
    block_hashes: ?[]const execution.Hash = null,
};

/// Selects block rules; callers supply up to 255 validated older hashes, newest first.
pub const BlockContext = struct {
    fork: Fork,
    parent_fork: Fork,
    chain_id: u256,
    older_hashes: []const execution.Hash = &.{},
    max_blobs_per_block: u64 = 21,
    expected_blob_hashes: []const execution.Hash = &.{},
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
    blob_hashes: []const execution.Hash = &.{},
    blob_fee_cap: ?u256 = null,
    authorizations: []const execution.Authorization = &.{},
};

/// Selects fields common to all transaction envelopes and checks fork availability.
pub fn fields(tx: execution.Transaction, fork: Fork) !TxFields {
    return switch (tx) {
        .legacy => |v| .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.to, .value = v.value, .data = v.data, .access_list = &.{}, .max_fee = v.gas_price, .priority_fee = v.gas_price },
        .access_list => |v| .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.to, .value = v.value, .data = v.data, .access_list = v.access_list, .max_fee = v.gas_price, .priority_fee = v.gas_price },
        .dynamic_fee => |v| .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.to, .value = v.value, .data = v.data, .access_list = v.access_list, .max_fee = v.max_fee_per_gas, .priority_fee = v.max_priority_fee_per_gas },
        .blob => |v| if (@intFromEnum(fork) < @intFromEnum(Fork.cancun)) error.UnsupportedTransactionType else .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.to, .value = v.value, .data = v.data, .access_list = v.access_list, .max_fee = v.max_fee_per_gas, .priority_fee = v.max_priority_fee_per_gas, .blob_hashes = v.blob_versioned_hashes, .blob_fee_cap = v.max_fee_per_blob_gas },
        .set_code => |v| if (@intFromEnum(fork) < @intFromEnum(Fork.prague)) error.UnsupportedTransactionType else .{ .nonce = v.nonce, .gas_limit = v.gas_limit, .to = v.destination, .value = v.value, .data = v.data, .access_list = v.access_list, .max_fee = v.max_fee_per_gas, .priority_fee = v.max_priority_fee_per_gas, .authorizations = v.authorization_list },
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
    gas = try std.math.add(u64, gas, try std.math.mul(u64, @intCast(tx.authorizations.len), 25_000));
    if (@intFromEnum(fork) >= @intFromEnum(Fork.prague)) gas = @max(gas, try std.math.add(u64, 21_000, try std.math.mul(u64, tokens, 10)));
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
    blob_gas: u64,
};

/// Metadata needed to order and price a transaction before it enters a block.
pub const Admission = struct {
    sender: execution.Address,
    nonce: u64,
    gas_limit: u64,
    max_fee: u256,
    priority_fee: u256,
    blob_fee_cap: ?u256,
    blob_count: u8 = 0,
};

/// Reuses transition validation for a future nonce without changing canonical state.
pub fn validatePending(allocator: std.mem.Allocator, world: *state.State, context: Context, raw: []const u8) !Admission {
    var decoded = try execution.parse(execution.Transaction, allocator, raw);
    defer decoded.deinit();
    const f = try fields(decoded.value, context.fork);
    const sender = try execution.recoverSender(allocator, decoded.value, context.chain_id);
    if (f.nonce < world.getNonce(sender)) return error.InvalidNonce;
    const snap = try world.snapshot();
    defer world.revert(snap) catch {};
    try world.setNonce(sender, f.nonce);
    _ = try validateTransaction(allocator, world, context, decoded.value, context.gas_limit);
    return .{ .sender = sender, .nonce = f.nonce, .gas_limit = f.gas_limit, .max_fee = f.max_fee, .priority_fee = f.priority_fee, .blob_fee_cap = f.blob_fee_cap, .blob_count = @intCast(f.blob_hashes.len) };
}

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
    if (f.blob_fee_cap != null) {
        if (f.blob_hashes.len == 0 or f.blob_hashes.len > 6) return error.InvalidBlobCount;
        for (f.blob_hashes) |hash| if (hash[0] != 1) return error.InvalidBlobVersion;
        if (f.blob_fee_cap.? < (context.blob_base_fee orelse return error.UnsupportedBlobTransaction)) return error.InvalidBlobFee;
    }
    if (switch (tx) {
        .set_code => true,
        else => false,
    } and f.authorizations.len == 0) return error.EmptyAuthorizationList;
    const blob_gas = std.math.mul(u64, @intCast(f.blob_hashes.len), 131_072) catch return error.InvalidBlobCount;
    const gas_cost = std.math.mul(u256, f.max_fee, f.gas_limit) catch return error.InsufficientBalance;
    const blob_cost = std.math.mul(u256, f.blob_fee_cap orelse 0, blob_gas) catch return error.InsufficientBalance;
    const max_cost = std.math.add(u256, gas_cost, blob_cost) catch return error.InsufficientBalance;
    const upfront = std.math.add(u256, max_cost, f.value) catch return error.InsufficientBalance;
    if (world.getBalance(sender) < upfront) return error.InsufficientBalance;
    if (f.nonce == std.math.maxInt(u64)) return error.InvalidNonce;
    const sender_code = world.getCode(sender);
    if (sender_code.len != 0 and (@intFromEnum(context.fork) < @intFromEnum(Fork.prague) or state.delegationTarget(sender_code) == null)) return error.InvalidSenderCode;
    const recipient = f.to orelse return error.UnsupportedContractCreation;
    const precompile_limit: u8 = switch (context.fork) {
        .london, .paris, .shanghai => 9,
        .cancun => 10,
        .prague, .osaka, .fulu => 17,
    };
    if (recipient[19] != 0 and recipient[19] <= precompile_limit and std.mem.allEqual(u8, recipient[0..19], 0)) return error.UnsupportedExecution;
    return .{ .fields = f, .sender = sender, .recipient = recipient, .intrinsic_gas = intrinsic, .max_cost = max_cost, .effective_price = @min(f.max_fee, std.math.add(u256, context.base_fee, f.priority_fee) catch std.math.maxInt(u256)), .blob_gas = blob_gas };
}

const AuthorizationEffects = struct { refund: u64, warmed: []const execution.Address };

/// Applies valid EIP-7702 tuples in order after the sender nonce has advanced.
fn applyAuthorizations(allocator: std.mem.Allocator, world: *state.State, chain_id: u256, authorizations: []const execution.Authorization) !AuthorizationEffects {
    var refund: u64 = 0;
    var warmed: std.ArrayList(execution.Address) = .empty;
    for (authorizations) |auth| {
        if ((auth.chain_id != 0 and auth.chain_id != chain_id) or auth.nonce == std.math.maxInt(u64)) continue;
        const encoded = try execution.encode(allocator, .{ auth.chain_id, auth.address, auth.nonce });
        defer allocator.free(encoded);
        const message = try allocator.alloc(u8, encoded.len + 1);
        defer allocator.free(message);
        message[0] = 5;
        @memcpy(message[1..], encoded);
        var hash: execution.Hash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(message, &hash, .{});
        const authority = execution.crypto.recoverAddress(hash, auth.r, auth.s, auth.y_parity) catch continue;
        try warmed.append(allocator, authority);
        const code = world.getCode(authority);
        if ((code.len != 0 and state.delegationTarget(code) == null) or world.getNonce(authority) != auth.nonce) continue;
        if (try world.getAccount(authority)) |account| {
            if (account.nonce != 0 or account.balance != 0 or !std.mem.eql(u8, &account.code_hash, &state.EMPTY_CODE_HASH) or !std.mem.eql(u8, &account.storage_root, &state.EMPTY_STORAGE_ROOT))
                refund = std.math.add(u64, refund, 12_500) catch return error.GasOverflow;
        }
        if (std.mem.allEqual(u8, &auth.address, 0)) {
            _ = try world.setCode(authority, &.{});
        } else {
            var designation: [23]u8 = .{ 0xef, 0x01, 0x00 } ++ ([_]u8{0} ** 20);
            @memcpy(designation[3..], &auth.address);
            _ = try world.setCode(authority, &designation);
        }
        try world.setNonce(authority, auth.nonce + 1);
    }
    return .{ .refund = refund, .warmed = try warmed.toOwnedSlice(allocator) };
}

/// Executes the value transfer and EVM frame, copying logs before the machine is released.
fn executeFrame(allocator: std.mem.Allocator, owner: std.mem.Allocator, world: *state.State, context: Context, tx: ValidatedTx, effects: AuthorizationEffects) !FrameOutcome {
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
    try machine.configure(.{ .fork = context.fork, .origin = tx.sender, .gas_price = tx.effective_price, .coinbase = context.coinbase, .timestamp = context.timestamp, .number = context.number, .prev_randao = if (context.fork == .london) context.difficulty else std.mem.readInt(u256, &context.prev_randao, .big), .gas_limit = context.gas_limit, .chain_id = context.chain_id, .base_fee = context.base_fee, .blob_base_fee = context.blob_base_fee orelse 0, .blob_base_fee_supported = context.blob_base_fee != null, .blob_hashes = tx.fields.blob_hashes, .block_hashes = context.block_hashes }, tx.sender, tx.recipient, access);
    machine.refund += effects.refund;
    for (effects.warmed) |address| _ = try machine.touchAccount(address);
    var result = try machine.run(.{ .code = world.getExecutionCode(tx.recipient), .gas = tx.fields.gas_limit - tx.intrinsic_gas, .caller = tx.sender, .callee = tx.recipient, .value = tx.fields.value, .data = tx.fields.data });
    defer result.deinit(allocator);
    if (result.status == .fault and (result.status.fault == .unsupported_precompile or result.status.fault == .unsupported_opcode or result.status.fault == .missing_context)) return error.UnsupportedExecution;
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
    return .{ .success = success, .gas_remaining = result.gas_remaining, .refund = machine.cappedRefund(spent), .logs = logs, .output = try owner.dupe(u8, result.output) };
}

/// Refunds unused gas to the sender and pays only the priority fee to coinbase.
fn settleFees(world: *state.State, context: Context, tx: ValidatedTx, gas_used: u64) !void {
    const execution_cost = std.math.mul(u256, tx.effective_price, gas_used) catch return error.BalanceOverflow;
    const blob_cost = std.math.mul(u256, context.blob_base_fee orelse 0, tx.blob_gas) catch return error.BalanceOverflow;
    const actual_cost = std.math.add(u256, execution_cost, blob_cost) catch return error.BalanceOverflow;
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
    const effects = try applyAuthorizations(arena.allocator(), world, context.chain_id, tx.fields.authorizations);
    const frame = try executeFrame(allocator, arena.allocator(), world, context, tx, effects);
    const spent = tx.fields.gas_limit - frame.gas_remaining;
    const floor = if (@intFromEnum(context.fork) >= @intFromEnum(Fork.prague)) try calldataFloor(tx.fields.data) else 0;
    const gas_used = @max(spent - frame.refund, floor);
    try settleFees(world, context, tx, gas_used);
    const payload: execution.ReceiptPayload = .{ .status = if (frame.success) 1 else 0, .cumulative_gas_used = std.math.add(u64, cumulative_gas, gas_used) catch return error.BlockGasLimitExceeded, .logs = frame.logs, .logs_bloom = execution.logsBloom(frame.logs) };
    const receipt: execution.Receipt = switch (decoded.value) {
        .legacy => .{ .legacy = payload },
        .access_list => .{ .access_list = payload },
        .dynamic_fee => .{ .dynamic_fee = payload },
        .blob => .{ .blob = payload },
        .set_code => .{ .set_code = payload },
    };
    try world.commit(snap);
    open = false;
    return .{ .arena = arena, .receipt = receipt, .gas_used = gas_used, .output = frame.output };
}

/// Calculates EIP-1559's next base fee from the parent gas target.
pub fn nextBaseFee(parent_gas_limit: u64, parent_gas_used: u64, parent_base_fee: u256) !u256 {
    const target = parent_gas_limit / 2;
    if (target == 0 or parent_gas_used == target) return parent_base_fee;
    if (parent_gas_used > target) {
        const change: u256 = @intCast(@min(std.math.maxInt(u256), @max(1, (@as(u512, parent_base_fee) * (parent_gas_used - target) / target) / 8)));
        return std.math.add(u256, parent_base_fee, change) catch error.BaseFeeOverflow;
    }
    const change: u256 = @intCast(@min(std.math.maxInt(u256), (@as(u512, parent_base_fee) * (target - parent_gas_used) / target) / 8));
    return parent_base_fee -| change;
}

/// Hashes exactly the header fields active in the selected fork.
pub fn headerHash(allocator: std.mem.Allocator, fork: Fork, header: execution.Header) !execution.Hash {
    const prefix = .{ header.parent_hash, header.ommers_hash, header.fee_recipient, header.state_root, header.transactions_root, header.receipts_root, header.logs_bloom, header.difficulty, header.number, header.gas_limit, header.gas_used, header.timestamp, header.extra_data, header.prev_randao, header.nonce, header.base_fee_per_gas };
    const encoded = switch (fork) {
        .london, .paris => try execution.encode(allocator, prefix),
        .shanghai => try execution.encode(allocator, prefix ++ .{header.withdrawals_root}),
        .cancun => try execution.encode(allocator, prefix ++ .{ header.withdrawals_root, header.blob_gas_used, header.excess_blob_gas, header.parent_beacon_block_root }),
        .prague, .osaka, .fulu => try execution.encode(allocator, prefix ++ .{ header.withdrawals_root, header.blob_gas_used, header.excess_blob_gas, header.parent_beacon_block_root, header.requests_hash }),
    };
    defer allocator.free(encoded);
    var hash: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(encoded, &hash, .{});
    return hash;
}

/// Calculates the EIP-4844 blob base fee using the active fork's update fraction.
pub fn blobBaseFee(fork: Fork, excess_blob_gas: u64) !u256 {
    if (@intFromEnum(fork) < @intFromEnum(Fork.cancun)) return error.UnsupportedBlobBaseFee;
    const denominator: u512 = if (fork == .cancun) 3_338_477 else 5_007_716;
    var term: u512 = denominator;
    var sum: u512 = 0;
    var index: u512 = 1;
    while (term != 0) : (index += 1) {
        sum = std.math.add(u512, sum, term) catch return error.BlobBaseFeeOverflow;
        const numerator = std.math.mul(u512, term, excess_blob_gas) catch return error.BlobBaseFeeOverflow;
        term = numerator / (denominator * index);
    }
    const fee = sum / denominator;
    if (fee > std.math.maxInt(u256)) return error.BlobBaseFeeOverflow;
    return @intCast(fee);
}

/// Rejects headers and withdrawals that cannot follow the supplied parent and fork.
fn validateBlockHeader(allocator: std.mem.Allocator, block: BlockContext, parent: execution.Header, header: execution.Header, withdrawals: []const execution.Withdrawal) !execution.Hash {
    if (@intFromEnum(block.parent_fork) > @intFromEnum(block.fork)) return error.InvalidForkOrder;
    const parent_hash = try headerHash(allocator, block.parent_fork, parent);
    if (!std.mem.eql(u8, &header.parent_hash, &parent_hash)) return error.InvalidParentHash;
    if (header.number != std.math.add(u64, parent.number, 1) catch return error.InvalidBlockNumber) return error.InvalidBlockNumber;
    if (header.timestamp <= parent.timestamp) return error.InvalidTimestamp;
    if (parent.gas_used > parent.gas_limit) return error.InvalidParentGasUsed;
    if (header.gas_limit < 5000 or @abs(@as(i128, header.gas_limit) - @as(i128, parent.gas_limit)) >= parent.gas_limit / 1024) return error.InvalidGasLimit;
    if (header.base_fee_per_gas != try nextBaseFee(parent.gas_limit, parent.gas_used, parent.base_fee_per_gas)) return error.InvalidBaseFee;
    if (@intFromEnum(block.fork) < @intFromEnum(Fork.shanghai) and withdrawals.len != 0) return error.UnsupportedWithdrawals;
    if (@intFromEnum(block.fork) >= @intFromEnum(Fork.cancun)) {
        const target: u64 = if (block.fork == .cancun) 393_216 else 786_432;
        const prior: u64 = if (@intFromEnum(block.parent_fork) < @intFromEnum(Fork.cancun)) 0 else std.math.add(u64, parent.excess_blob_gas, parent.blob_gas_used) catch return error.InvalidExcessBlobGas;
        if (header.excess_blob_gas != prior -| target) return error.InvalidExcessBlobGas;
        const max_blobs: u64 = if (block.fork == .cancun) 6 else block.max_blobs_per_block;
        const max_blob_gas = std.math.mul(u64, max_blobs, 131_072) catch return error.InvalidBlobGasUsed;
        if (header.blob_gas_used > max_blob_gas or header.blob_gas_used % 131_072 != 0) return error.InvalidBlobGasUsed;
    }
    return parent_hash;
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
    const withdrawals_root: ?execution.Hash = if (@intFromEnum(fork) < @intFromEnum(Fork.shanghai)) null else blk: {
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

const system_address: execution.Address = .{0xff} ** 19 ++ .{0xfe};
const beacon_roots_address: execution.Address = .{ 0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22, 0xd0, 0xbe, 0xac, 0x02 };
const history_address: execution.Address = .{ 0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35 };

/// Executes a fork's pre-transaction contract call; absent predeploy code is a no-op.
fn runSystemCall(allocator: std.mem.Allocator, world: *state.State, context: Context, address: execution.Address, input: []const u8) !void {
    const code = world.getCode(address);
    if (code.len == 0) return;
    var machine = evm.Machine.init(allocator, world);
    defer machine.deinit();
    try machine.configure(.{ .fork = context.fork, .origin = system_address, .gas_price = 0, .coinbase = context.coinbase, .timestamp = context.timestamp, .number = context.number, .prev_randao = std.mem.readInt(u256, &context.prev_randao, .big), .gas_limit = context.gas_limit, .chain_id = context.chain_id, .base_fee = context.base_fee, .blob_base_fee = context.blob_base_fee orelse 0, .blob_base_fee_supported = context.blob_base_fee != null, .block_hashes = context.block_hashes }, system_address, address, &.{});
    var result = try machine.run(.{ .code = code, .gas = 30_000_000, .caller = system_address, .callee = address, .data = input });
    defer result.deinit(allocator);
    if (result.status != .success) return error.InvalidSystemCall;
}

/// Applies Cancun beacon-root and Prague parent-hash writes before user transactions.
pub fn applySystemTransitions(allocator: std.mem.Allocator, world: *state.State, context: Context, parent_hash: execution.Hash, parent_beacon_root: execution.Hash) !void {
    if (@intFromEnum(context.fork) >= @intFromEnum(Fork.cancun)) try runSystemCall(allocator, world, context, beacon_roots_address, &parent_beacon_root);
    if (@intFromEnum(context.fork) >= @intFromEnum(Fork.prague)) try runSystemCall(allocator, world, context, history_address, &parent_hash);
}

/// Applies ordered transactions and withdrawals, checking all claimed roots atomically.
pub fn applyBlock(allocator: std.mem.Allocator, world: *state.State, block: BlockContext, parent: execution.Header, header: execution.Header, transactions: []const []const u8, withdrawals: []const execution.Withdrawal) !BlockResult {
    const parent_hash = try validateBlockHeader(allocator, block, parent, header, withdrawals);
    if (block.older_hashes.len > 255) return error.TooManyAncestorHashes;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const receipts = try arena.allocator().alloc(execution.Receipt, transactions.len);
    const block_hashes = try arena.allocator().alloc(execution.Hash, block.older_hashes.len + 1);
    block_hashes[0] = parent_hash;
    @memcpy(block_hashes[1..], block.older_hashes);
    const snapshot = try world.snapshot();
    var open = true;
    errdefer if (open) world.revert(snapshot) catch {};
    const context: Context = .{ .fork = block.fork, .chain_id = block.chain_id, .coinbase = header.fee_recipient, .number = header.number, .timestamp = header.timestamp, .gas_limit = header.gas_limit, .base_fee = header.base_fee_per_gas, .prev_randao = header.prev_randao, .difficulty = header.difficulty, .blob_base_fee = if (@intFromEnum(block.fork) < @intFromEnum(Fork.cancun)) null else try blobBaseFee(block.fork, header.excess_blob_gas), .block_hashes = block_hashes };
    try applySystemTransitions(arena.allocator(), world, context, parent_hash, header.parent_beacon_block_root);
    const gas_used = try applyBlockTransactions(arena.allocator(), world, context, transactions, receipts);
    var blob_gas_used: u64 = 0;
    var blob_index: usize = 0;
    for (transactions) |raw| {
        var decoded = try execution.parse(execution.Transaction, arena.allocator(), raw);
        defer decoded.deinit();
        if (decoded.value == .blob) {
            const hashes = decoded.value.blob.blob_versioned_hashes;
            blob_gas_used = std.math.add(u64, blob_gas_used, @as(u64, @intCast(hashes.len)) * 131_072) catch return error.InvalidBlobGasUsed;
            for (hashes) |hash| {
                if (blob_index >= block.expected_blob_hashes.len or !std.mem.eql(u8, &hash, &block.expected_blob_hashes[blob_index])) return error.InvalidVersionedHashes;
                blob_index += 1;
            }
        }
    }
    if (blob_index != block.expected_blob_hashes.len) return error.InvalidVersionedHashes;
    if (blob_gas_used != header.blob_gas_used) return error.InvalidBlobGasUsed;
    if (gas_used != header.gas_used) return error.InvalidGasUsed;
    try applyBlockCredits(world, block.fork, header.fee_recipient, withdrawals);
    const result = try blockResult(&arena, world, block.fork, transactions, withdrawals, receipts, gas_used);
    try verifyBlockCommitments(header, result);
    try world.commit(snapshot);
    open = false;
    return result;
}

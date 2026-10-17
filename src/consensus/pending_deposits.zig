// A deposit adds stake to a validator, or introduces a new validator by public
// key. Fulu queues deposits instead of applying them when they enter a block:
// finality must cover their slot, and per-epoch churn limits newly consumed
// stake. Older legacy deposits also take priority over newer requests.
//
//   pending queue -> finalized and within limits? -> top up / create validator
//                 -> otherwise keep the unprocessed suffix for a later epoch
//
// Existing validators receive a balance top-up. A new validator needs a valid
// BLS proof of possession and starts with a future activation epoch; adding
// stake does not make it an active proposer immediately. Deposits for exiting
// validators can be postponed until their withdrawal is complete.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const helpers = @import("helpers.zig");
const domains = @import("domains.zig");
const bls = @import("bls.zig");

const DepositMessage = struct {
    pubkey: fulu.BLSPubkey,
    withdrawal_credentials: fulu.Bytes32,
    amount: fulu.Gwei,
};

pub fn processPendingDeposits(allocator: std.mem.Allocator, state: *fulu.BeaconState) !void {
    const current_epoch = helpers.getCurrentEpoch(state);
    const finalized_slot = try helpers.computeStartSlotAtEpoch(state.finalized_checkpoint.epoch);
    const next_epoch = std.math.add(u64, current_epoch, 1) catch return error.InvalidState;
    const total_active_balance = helpers.getTotalActiveBalance(state.validators.data, current_epoch) catch return error.InvalidState;
    const churn = @min(helpers.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, @max(helpers.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, total_active_balance / helpers.CHURN_LIMIT_QUOTIENT) / helpers.EFFECTIVE_BALANCE_INCREMENT * helpers.EFFECTIVE_BALANCE_INCREMENT);
    const available = std.math.add(u64, state.deposit_balance_to_consume, churn) catch return error.InvalidState;
    var processed_amount: u64 = 0;
    var processed: usize = 0;
    var churn_reached = false;
    var postponed = std.ArrayList(fulu.PendingDeposit).empty;
    defer postponed.deinit(allocator);
    const pending = state.pending_deposits.data;

    for (pending) |deposit| {
        if (deposit.slot > 0 and state.eth1_deposit_index < state.deposit_requests_start_index) break;
        if (deposit.slot > finalized_slot or processed >= 16) break;
        const existing_index = findValidator(state.validators.data, deposit.pubkey);
        if (existing_index) |index| {
            const validator = state.validators.data[index];
            if (validator.exit_epoch < std.math.maxInt(u64)) {
                if (validator.withdrawable_epoch >= next_epoch) {
                    try postponed.append(allocator, deposit);
                    processed += 1;
                    continue;
                }
                try applyDeposit(allocator, state, deposit, existing_index);
                processed += 1;
                continue;
            }
        }
        if (deposit.amount > available - processed_amount) {
            churn_reached = true;
            break;
        }
        processed_amount += deposit.amount;
        try applyDeposit(allocator, state, deposit, existing_index);
        processed += 1;
    }
    const new_pending = try allocator.alloc(fulu.PendingDeposit, pending.len - processed + postponed.items.len);
    @memcpy(new_pending[0 .. pending.len - processed], pending[processed..]);
    @memcpy(new_pending[pending.len - processed ..], postponed.items);
    allocator.free(@constCast(pending));
    state.pending_deposits.data = new_pending;
    state.deposit_balance_to_consume = if (churn_reached) available - processed_amount else 0;
}

fn findValidator(validators: []const fulu.Validator, pubkey: fulu.BLSPubkey) ?usize {
    for (validators, 0..) |validator, index| {
        if (std.mem.eql(u8, &validator.pubkey, &pubkey)) return index;
    }
    return null;
}

fn appendOwned(comptime T: type, allocator: std.mem.Allocator, slice: *[]const T, item: T) !void {
    const old = slice.*;
    const new = try allocator.alloc(T, old.len + 1);
    @memcpy(new[0..old.len], old);
    new[old.len] = item;
    allocator.free(@constCast(old));
    slice.* = new;
}

fn applyDeposit(allocator: std.mem.Allocator, state: *fulu.BeaconState, deposit: fulu.PendingDeposit, existing_index: ?usize) !void {
    if (existing_index) |index| {
        @constCast(state.balances.data)[index] =
            std.math.add(u64, state.balances.data[index], deposit.amount) catch return error.BalanceOverflow;
        return;
    }
    const message = DepositMessage{
        .pubkey = deposit.pubkey,
        .withdrawal_credentials = deposit.withdrawal_credentials,
        .amount = deposit.amount,
    };
    const message_root = try merkle.HashTreeRoot(allocator, message);
    const domain = domains.computeDomain(helpers.DOMAIN_DEPOSIT, helpers.GENESIS_FORK_VERSION, [_]u8{0} ** 32);
    const signing_root = domains.computeSigningRoot(message_root, domain);
    bls.verify(deposit.pubkey, signing_root, deposit.signature) catch return;

    const max_balance: u64 = if (deposit.withdrawal_credentials[0] == 0x02)
        helpers.MAX_EFFECTIVE_BALANCE_ELECTRA
    else
        helpers.MAX_EFFECTIVE_BALANCE;
    const max_epoch = std.math.maxInt(u64);
    try appendOwned(fulu.Validator, allocator, &state.validators.data, .{
        .pubkey = deposit.pubkey,
        .withdrawal_credentials = deposit.withdrawal_credentials,
        .effective_balance = @min(deposit.amount - deposit.amount % 1_000_000_000, max_balance),
        .slashed = false,
        .activation_eligibility_epoch = max_epoch,
        .activation_epoch = max_epoch,
        .exit_epoch = max_epoch,
        .withdrawable_epoch = max_epoch,
    });
    try appendOwned(u64, allocator, &state.balances.data, deposit.amount);
    try appendOwned(u8, allocator, &state.previous_epoch_participation.data, 0);
    try appendOwned(u8, allocator, &state.current_epoch_participation.data, 0);
    try appendOwned(u64, allocator, &state.inactivity_scores.data, 0);
}

test "pending deposits match pinned finalized and churn fixtures" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "process_pending_deposits_multiple_pending_deposits_below_churn",
        "process_pending_deposits_not_finalized",
    }) |name| {
        const case = fixtures.find(name).?;
        var state = try fixtures.decodeState(allocator, case.pre_epoch.?);
        defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
        const expected = try fixtures.decodeState(allocator, case.post_epoch.?);
        defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, expected);
        if (std.mem.eql(u8, name, "process_pending_deposits_not_finalized")) {
            // Finality runs earlier in the epoch and finalizes the first deposit's slot.
            state.finalized_checkpoint = expected.finalized_checkpoint;
        }
        try processPendingDeposits(allocator, &state);
        const actual_balances = try merkle.HashTreeRoot(allocator, state.balances);
        const expected_balances = try merkle.HashTreeRoot(allocator, expected.balances);
        if (std.mem.eql(u8, name, "process_pending_deposits_not_finalized")) {
            // This post-epoch state also includes rewards applied before pending deposits.
            try std.testing.expectEqual(expected.balances.data[expected.balances.data.len - 1], state.balances.data[state.balances.data.len - 1]);
            const actual_new_validator = try merkle.HashTreeRoot(allocator, state.validators.data[state.validators.data.len - 1]);
            const expected_new_validator = try merkle.HashTreeRoot(allocator, expected.validators.data[expected.validators.data.len - 1]);
            try std.testing.expectEqualSlices(u8, &expected_new_validator, &actual_new_validator);
        } else {
            try std.testing.expectEqualSlices(u8, &expected_balances, &actual_balances);
        }
        const actual_pending = try merkle.HashTreeRoot(allocator, state.pending_deposits);
        const expected_pending = try merkle.HashTreeRoot(allocator, expected.pending_deposits);
        try std.testing.expectEqualSlices(u8, &expected_pending, &actual_pending);
        try std.testing.expectEqual(expected.deposit_balance_to_consume, state.deposit_balance_to_consume);
        try std.testing.expectEqual(expected.validators.data.len, state.validators.data.len);
    }
}

// Genesis turns ordered Eth1 deposits into the first validator registry.
// Each deposit proof commits to its prefix of the deposit tree; a valid proof
// advances the deposit index, while only a valid new-key signature adds a
// validator. Repeated keys top up the existing balance. After activations,
// the validator root fixes the chain identity and seeds Fulu committees.
//
//   Eth1 hash + deposits -> validators -> active set -> committees/lookahead
//
// Deposit proofs use the contract's 32-level tree plus one length-mix level.
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const preset = @import("consensus_preset").Config;
const helpers = @import("helpers.zig");
const deposits_mod = @import("pending_deposits.zig");
const epoch = @import("epoch.zig");

/// Build an owned Fulu genesis state from chronological deposits with valid contract proofs.
pub fn initializeBeaconStateFromEth1(
    allocator: std.mem.Allocator,
    eth1_block_hash: fulu.Hash32,
    eth1_timestamp: u64,
    deposits: []const fulu.Deposit,
) !fulu.BeaconState {
    if (deposits.len > (@as(u64, 1) << 32)) return error.TooManyDeposits;
    const genesis_time = std.math.add(u64, eth1_timestamp, preset.GENESIS_DELAY) catch return error.InvalidTimestamp;
    var state: fulu.BeaconState = std.mem.zeroes(fulu.BeaconState);
    errdefer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    state.genesis_time = genesis_time;
    state.fork = .{ .previous_version = preset.ELECTRA_FORK_VERSION, .current_version = preset.FULU_FORK_VERSION, .epoch = 0 };
    state.eth1_data.block_hash = eth1_block_hash;
    state.eth1_data.deposit_count = @intCast(deposits.len);
    state.latest_block_header.body_root = try merkle.HashTreeRoot(allocator, std.mem.zeroes(fulu.GenesisBlockBody));
    state.randao_mixes = [_]fulu.Bytes32{eth1_block_hash} ** preset.EPOCHS_PER_HISTORICAL_VECTOR;
    state.deposit_requests_start_index = std.math.maxInt(u64);
    state.earliest_exit_epoch = helpers.EPOCH_OFFSET + helpers.MAX_SEED_LOOKAHEAD + 1;
    state.earliest_consolidation_epoch = helpers.EPOCH_OFFSET + helpers.MAX_SEED_LOOKAHEAD;

    const data = try allocator.alloc(fulu.DepositData, deposits.len);
    defer allocator.free(data);
    for (deposits, 0..) |deposit, index| {
        data[index] = deposit.data;
        state.eth1_data.deposit_root = try merkle.HashTreeRoot(allocator, fulu.DepositDataList{ .data = data[0 .. index + 1] });
        const leaf = try merkle.HashTreeRoot(allocator, deposit.data);
        if (!merkle.verifyMerkleProof(leaf, &deposit.proof, (@as(u64, 1) << 33) + index, state.eth1_data.deposit_root))
            return error.InvalidDepositProof;
        const existing = deposits_mod.findValidator(state.validators.data, deposit.data.pubkey);
        try deposits_mod.applyDeposit(allocator, &state, .{
            .pubkey = deposit.data.pubkey,
            .withdrawal_credentials = deposit.data.withdrawal_credentials,
            .amount = deposit.data.amount,
            .signature = deposit.data.signature,
            .slot = 0,
        }, existing);
        state.eth1_deposit_index += 1;
    }
    for (@constCast(state.validators.data), state.balances.data) |*validator, balance| {
        validator.effective_balance = @min(balance - balance % helpers.EFFECTIVE_BALANCE_INCREMENT, helpers.MAX_EFFECTIVE_BALANCE);
        if (validator.effective_balance == helpers.MAX_EFFECTIVE_BALANCE) {
            validator.activation_eligibility_epoch = 0;
            validator.activation_epoch = 0;
        }
    }
    state.genesis_validators_root = try merkle.HashTreeRoot(allocator, state.validators);
    var pending: std.ArrayList(fulu.PendingDeposit) = .empty;
    defer pending.deinit(allocator);
    for (@constCast(state.validators.data), @constCast(state.balances.data)) |*validator, *balance| {
        if (validator.activation_epoch != helpers.FAR_FUTURE_EPOCH) continue;
        var infinity = [_]u8{0} ** 96;
        infinity[0] = 0xc0;
        try pending.append(allocator, .{
            .pubkey = validator.pubkey,
            .withdrawal_credentials = validator.withdrawal_credentials,
            .amount = balance.*,
            .signature = infinity,
            .slot = 0,
        });
        balance.* = 0;
        validator.effective_balance = 0;
    }
    state.pending_deposits.data = try pending.toOwnedSlice(allocator);
    const total_active = try helpers.getTotalActiveBalance(state.validators.data, 0);
    const churn = @max(helpers.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, total_active / helpers.CHURN_LIMIT_QUOTIENT) /
        helpers.EFFECTIVE_BALANCE_INCREMENT * helpers.EFFECTIVE_BALANCE_INCREMENT;
    state.exit_balance_to_consume = @min(churn, helpers.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT);
    state.consolidation_balance_to_consume = churn - state.exit_balance_to_consume;
    state.current_sync_committee = try epoch.computeSyncCommittee(allocator, &state, 0);
    state.next_sync_committee = state.current_sync_committee;
    for (0..2) |offset| {
        const indices = try helpers.computeProposerIndices(allocator, state, offset);
        @memcpy(state.proposer_lookahead[offset * helpers.SLOTS_PER_EPOCH ..][0..helpers.SLOTS_PER_EPOCH], &indices);
    }
    return state;
}

/// Hash two SSZ tree nodes in their left-to-right order for test proofs.
fn hashPair(left: fulu.Root, right: fulu.Root) fulu.Root {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);
    var root: fulu.Root = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &root, .{});
    return root;
}

/// Form a two-leaf contract proof against a prefix of one or two deposits.
fn testProof(first_leaf: fulu.Root, index: usize, count: usize) [33]fulu.Root {
    var proof: [33]fulu.Root = undefined;
    var zero = [_]u8{0} ** 32;
    proof[0] = if (index == 0) zero else first_leaf;
    for (1..32) |level| {
        zero = hashPair(zero, zero);
        proof[level] = zero;
    }
    proof[32] = [_]u8{0} ** 32;
    std.mem.writeInt(u64, proof[32][0..8], count, .little);
    return proof;
}

test "genesis accepts duplicate deposits, ignores invalid new signatures, and rejects bad proofs" {
    const allocator = std.testing.allocator;
    const blst = @import("blst");
    const bls = @import("bls.zig");
    const domains = @import("domains.zig");
    const seed = [_]u8{0x42} ** 32;
    var secret = blst.SecretKey{};
    secret.keygen(&seed, null);
    defer secret.deinit();
    const pubkey = try bls.publicKey(&secret);
    const message = .{ .pubkey = pubkey, .withdrawal_credentials = [_]u8{0} ** 32, .amount = @as(u64, 32_000_000_000) };
    const message_root = try merkle.HashTreeRoot(allocator, message);
    const domain = @import("domains.zig").computeDomain(helpers.DOMAIN_DEPOSIT, preset.GENESIS_FORK_VERSION, [_]u8{0} ** 32);
    const signature = bls.sign(&secret, domains.computeSigningRoot(message_root, domain));
    const first_data: fulu.DepositData = .{ .pubkey = pubkey, .withdrawal_credentials = message.withdrawal_credentials, .amount = message.amount, .signature = signature };
    const first_leaf = try merkle.HashTreeRoot(allocator, first_data);
    const first: fulu.Deposit = .{ .data = first_data, .proof = testProof(first_leaf, 0, 1) };
    const second_data: fulu.DepositData = .{ .pubkey = pubkey, .withdrawal_credentials = message.withdrawal_credentials, .amount = 1_000_000_000, .signature = [_]u8{0} ** 96 };
    const second: fulu.Deposit = .{ .data = second_data, .proof = testProof(first_leaf, 1, 2) };
    const eth1_hash = [_]u8{0x31} ** 32;

    const state = try initializeBeaconStateFromEth1(allocator, eth1_hash, 1_600_000_000, &.{ first, second });
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    try std.testing.expectEqual(@as(usize, 1), state.validators.data.len);
    try std.testing.expectEqual(@as(u64, 33_000_000_000), state.balances.data[0]);
    try std.testing.expectEqual(@as(u64, 2), state.eth1_deposit_index);
    try std.testing.expectEqual(@as(u64, 1_600_000_000 + preset.GENESIS_DELAY), state.genesis_time);
    var first_slot = state;
    try @import("transition.zig").processSlots(allocator, &first_slot, 1, null);
    try std.testing.expectEqual(@as(u64, 1), first_slot.slot);
    const genesis_root = try merkle.HashTreeRoot(allocator, state);
    const first_slot_root = try merkle.HashTreeRoot(allocator, first_slot);
    try std.testing.expect(!std.mem.eql(u8, &genesis_root, &first_slot_root));
    const again = try initializeBeaconStateFromEth1(allocator, eth1_hash, 1_600_000_000, &.{ first, second });
    defer ssz.freeDecoded(allocator, fulu.BeaconState, again);
    try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, state), try merkle.HashTreeRoot(allocator, again));

    var bad_proof = first;
    bad_proof.proof[0][0] ^= 1;
    try std.testing.expectError(error.InvalidDepositProof, initializeBeaconStateFromEth1(allocator, eth1_hash, 1_600_000_000, &.{bad_proof}));

    var invalid_signature = first;
    invalid_signature.data.signature = [_]u8{0} ** 96;
    invalid_signature.proof = testProof(try merkle.HashTreeRoot(allocator, invalid_signature.data), 0, 1);
    try std.testing.expectError(error.NoEligibleProposer, initializeBeaconStateFromEth1(allocator, eth1_hash, 1_600_000_000, &.{invalid_signature}));

    var ignored = second;
    ignored.data.pubkey = [_]u8{0x55} ** 48;
    ignored.proof = testProof(first_leaf, 1, 2);
    const with_ignored = try initializeBeaconStateFromEth1(allocator, eth1_hash, 1_600_000_000, &.{ first, ignored });
    defer ssz.freeDecoded(allocator, fulu.BeaconState, with_ignored);
    try std.testing.expectEqual(@as(usize, 1), with_ignored.validators.data.len);
    try std.testing.expectEqual(@as(u64, 2), with_ignored.eth1_deposit_index);
}

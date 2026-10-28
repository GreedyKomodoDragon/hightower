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

// A deposit tree has 2^32 leaves. The frontier keeps one completed subtree
// per height; appending and obtaining each length-mixed prefix root take 32
// hashes regardless of the number of earlier deposits.
const DepositTree = struct {
    branch: [32]fulu.Root = undefined,
    zero_hashes: [32]fulu.Root = undefined,
    full_root: fulu.Root = undefined,
    count: u64 = 0,

    /// Initialize the empty subtree roots for every height of the contract tree.
    fn init() DepositTree {
        var tree: DepositTree = .{};
        tree.zero_hashes[0] = [_]u8{0} ** 32;
        for (1..32) |height| tree.zero_hashes[height] = hashPair(tree.zero_hashes[height - 1], tree.zero_hashes[height - 1]);
        return tree;
    }

    /// Append one deposit leaf in chronological order; at capacity keep the completed root.
    fn append(self: *DepositTree, leaf: fulu.Root) void {
        var size = self.count;
        var node = leaf;
        for (0..32) |height| {
            if (size & 1 == 0) {
                self.branch[height] = node;
                break;
            }
            node = hashPair(self.branch[height], node);
            size >>= 1;
        }
        self.count += 1;
        if (self.count == (@as(u64, 1) << 32)) self.full_root = node;
    }

    /// Return the SSZ list root after the most recently appended leaf.
    fn root(self: *const DepositTree) fulu.Root {
        var size = self.count;
        var node = [_]u8{0} ** 32;
        if (size == (@as(u64, 1) << 32)) {
            node = self.full_root;
        } else {
            for (0..32) |height| {
                node = if (size & 1 == 1)
                    hashPair(self.branch[height], node)
                else
                    hashPair(node, self.zero_hashes[height]);
                size >>= 1;
            }
        }
        var length = [_]u8{0} ** 32;
        std.mem.writeInt(u64, length[0..8], self.count, .little);
        return hashPair(node, length);
    }
};

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

    var tree = DepositTree.init();
    var validator_indices = std.AutoHashMap(fulu.BLSPubkey, usize).init(allocator);
    defer validator_indices.deinit();
    var validators: std.ArrayList(fulu.Validator) = .empty;
    defer validators.deinit(allocator);
    var balances: std.ArrayList(fulu.Gwei) = .empty;
    defer balances.deinit(allocator);
    for (deposits, 0..) |deposit, index| {
        const leaf = try merkle.HashTreeRoot(allocator, deposit.data);
        tree.append(leaf);
        state.eth1_data.deposit_root = tree.root();
        if (!merkle.verifyMerkleProof(leaf, &deposit.proof, (@as(u64, 1) << 33) + index, state.eth1_data.deposit_root))
            return error.InvalidDepositProof;
        const entry: fulu.PendingDeposit = .{
            .pubkey = deposit.data.pubkey,
            .withdrawal_credentials = deposit.data.withdrawal_credentials,
            .amount = deposit.data.amount,
            .signature = deposit.data.signature,
            .slot = 0,
        };
        if (validator_indices.get(entry.pubkey)) |existing| {
            balances.items[existing] = std.math.add(u64, balances.items[existing], entry.amount) catch return error.BalanceOverflow;
        } else if (try deposits_mod.validNewDepositSignature(allocator, entry)) {
            const validator_index = validators.items.len;
            try validators.append(allocator, .{
                .pubkey = entry.pubkey,
                .withdrawal_credentials = entry.withdrawal_credentials,
                .effective_balance = @min(entry.amount - entry.amount % helpers.EFFECTIVE_BALANCE_INCREMENT, helpers.MAX_EFFECTIVE_BALANCE),
                .slashed = false,
                .activation_eligibility_epoch = helpers.FAR_FUTURE_EPOCH,
                .activation_epoch = helpers.FAR_FUTURE_EPOCH,
                .exit_epoch = helpers.FAR_FUTURE_EPOCH,
                .withdrawable_epoch = helpers.FAR_FUTURE_EPOCH,
            });
            try balances.append(allocator, entry.amount);
            try validator_indices.put(entry.pubkey, validator_index);
        }
        state.eth1_deposit_index += 1;
    }
    state.validators.data = try validators.toOwnedSlice(allocator);
    state.balances.data = try balances.toOwnedSlice(allocator);
    state.previous_epoch_participation.data = try allocator.alloc(u8, state.validators.data.len);
    @memset(@constCast(state.previous_epoch_participation.data), 0);
    state.current_epoch_participation.data = try allocator.alloc(u8, state.validators.data.len);
    @memset(@constCast(state.current_epoch_participation.data), 0);
    state.inactivity_scores.data = try allocator.alloc(u64, state.validators.data.len);
    @memset(@constCast(state.inactivity_scores.data), 0);
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

/// Hash two SSZ tree nodes in their left-to-right order for the frontier and proofs.
fn hashPair(left: fulu.Root, right: fulu.Root) fulu.Root {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);
    var root: fulu.Root = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &root, .{});
    return root;
}

test "incremental deposit roots match SSZ list roots across changing tree heights" {
    const allocator = std.testing.allocator;
    var tree = DepositTree.init();
    var data: [17]fulu.DepositData = undefined;
    for (&data, 0..) |*deposit, index| {
        deposit.* = std.mem.zeroes(fulu.DepositData);
        deposit.amount = @intCast(index + 1);
        tree.append(try merkle.HashTreeRoot(allocator, deposit.*));
        const expected = try merkle.HashTreeRoot(allocator, fulu.DepositDataList{ .data = data[0 .. index + 1] });
        try std.testing.expectEqual(expected, tree.root());
    }
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

    const second_seed = [_]u8{0x43} ** 32;
    var second_secret = blst.SecretKey{};
    second_secret.keygen(&second_seed, null);
    defer second_secret.deinit();
    const second_pubkey = try bls.publicKey(&second_secret);
    const second_message = .{ .pubkey = second_pubkey, .withdrawal_credentials = message.withdrawal_credentials, .amount = message.amount };
    const second_message_root = try merkle.HashTreeRoot(allocator, second_message);
    const distinct_data: fulu.DepositData = .{
        .pubkey = second_pubkey,
        .withdrawal_credentials = message.withdrawal_credentials,
        .amount = message.amount,
        .signature = bls.sign(&second_secret, domains.computeSigningRoot(second_message_root, domain)),
    };
    const distinct: fulu.Deposit = .{ .data = distinct_data, .proof = testProof(first_leaf, 1, 2) };
    const with_distinct = try initializeBeaconStateFromEth1(allocator, eth1_hash, 1_600_000_000, &.{ first, distinct });
    defer ssz.freeDecoded(allocator, fulu.BeaconState, with_distinct);
    try std.testing.expectEqual(@as(usize, 2), with_distinct.validators.data.len);
    try std.testing.expectEqual(second_pubkey, with_distinct.validators.data[1].pubkey);
}

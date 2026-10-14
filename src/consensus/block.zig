// A BeaconBlock is the consensus-layer proposal for one slot. Its body also
// carries an execution payload, whose transactions need an execution engine's
// verdict; a valid beacon signature alone cannot establish payload validity.
// This transition advances empty slots, verifies the proposer and parent, then
// applies the supported block fields in the order this implementation uses:
//
//   slots -> proposer signature -> header -> withdrawal eligibility
//         -> execution payload -> RANDAO -> Eth1 vote -> sync aggregate
//         -> compare the resulting BeaconState root with block.state_root
//
// RANDAO is proposer-supplied randomness mixed into future validator selection;
// a sync aggregate is a small committee's signature on the previous slot's
// recorded block root.
// Nonempty operation lists and withdrawals fail explicitly. Processing mutates
// the allocator-owned state as it goes, so callers must discard it on any error.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const bls = @import("bls.zig");
const domains = @import("domains.zig");
const helpers = @import("helpers.zig");
const transition = @import("transition.zig");
const epoch = @import("epoch.zig");
const engine_api = @import("execution_engine.zig");

/// Applies a signed block to an allocator-owned state. Discard the state on error.
pub fn stateTransition(allocator: std.mem.Allocator, state: *fulu.BeaconState, signed: fulu.SignedBeaconBlock, engine: engine_api.ExecutionEngine) !void {
    const block = signed.message;
    try transition.processSlots(allocator, state, block.slot, epoch.processEpoch);
    if (block.proposer_index >= state.validators.data.len) return error.InvalidProposer;
    const block_root = try merkle.HashTreeRoot(allocator, block);
    const domain = domains.getDomain(state.*, helpers.DOMAIN_BEACON_PROPOSER, helpers.computeEpochAtSlot(block.slot));
    try bls.verify(state.validators.data[block.proposer_index].pubkey, domains.computeSigningRoot(block_root, domain), signed.signature);
    try processBlock(allocator, state, block, engine);
    const state_root = try merkle.HashTreeRoot(allocator, state.*);
    if (!std.mem.eql(u8, &state_root, &block.state_root)) return error.InvalidStateRoot;
}

fn processBlock(allocator: std.mem.Allocator, state: *fulu.BeaconState, block: fulu.BeaconBlock, engine: engine_api.ExecutionEngine) !void {
    if (block.slot != state.slot or block.slot <= state.latest_block_header.slot) return error.InvalidSlot;
    if (block.proposer_index != state.proposer_lookahead[state.slot % helpers.SLOTS_PER_EPOCH] or
        block.proposer_index >= state.validators.data.len or state.validators.data[block.proposer_index].slashed)
        return error.InvalidProposer;
    const parent_root = try merkle.HashTreeRoot(allocator, state.latest_block_header);
    if (!std.mem.eql(u8, &parent_root, &block.parent_root)) return error.InvalidParentRoot;
    if (hasUnsupportedOperations(block.body)) return error.UnsupportedOperations;
    if (state.eth1_data.deposit_count != state.eth1_deposit_index) return error.DepositsRequired;

    const body_root = try merkle.HashTreeRoot(allocator, block.body);
    state.latest_block_header = .{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        .parent_root = block.parent_root,
        .state_root = [_]u8{0} ** 32,
        .body_root = body_root,
    };
    try processEmptyWithdrawals(state, block.body.execution_payload);
    try processExecutionPayload(allocator, state, block.body, engine);
    try processRandao(state, block.body.randao_reveal);
    try processEth1Data(allocator, state, block.body.eth1_data);
    try processSyncAggregate(state, block.body.sync_aggregate);
}

fn hasUnsupportedOperations(body: fulu.BeaconBlockBody) bool {
    return body.proposer_slashings.data.len != 0 or body.attester_slashings.data.len != 0 or
        body.attestations.data.len != 0 or body.deposits.data.len != 0 or
        body.voluntary_exits.data.len != 0 or body.bls_to_execution_changes.data.len != 0 or
        body.execution_requests.deposits.data.len != 0 or body.execution_requests.withdrawals.data.len != 0 or
        body.execution_requests.consolidations.data.len != 0;
}

fn processEmptyWithdrawals(state: *fulu.BeaconState, payload: fulu.ExecutionPayload) !void {
    if (state.pending_partial_withdrawals.data.len != 0 or payload.withdrawals.data.len != 0)
        return error.UnsupportedWithdrawals;
    const count = state.validators.data.len;
    if (count == 0 or state.next_withdrawal_validator_index >= count) return error.InvalidState;
    const current_epoch = helpers.computeEpochAtSlot(state.slot);
    const sweep = @min(count, 16);
    for (0..sweep) |offset| {
        const index = (state.next_withdrawal_validator_index + offset) % count;
        const validator = state.validators.data[index];
        const balance = state.balances.data[index];
        const execution_credential = validator.withdrawal_credentials[0] == 0x01 or validator.withdrawal_credentials[0] == 0x02;
        if (execution_credential and ((validator.withdrawable_epoch <= current_epoch and balance > 0) or
            (balance > validator.effective_balance and validator.exit_epoch == std.math.maxInt(u64))))
            return error.UnsupportedWithdrawals;
    }
    state.next_withdrawal_validator_index = @intCast((state.next_withdrawal_validator_index + 16) % count);
}

fn processExecutionPayload(allocator: std.mem.Allocator, state: *fulu.BeaconState, body: fulu.BeaconBlockBody, engine: engine_api.ExecutionEngine) !void {
    const payload = body.execution_payload;
    if (!std.mem.eql(u8, &payload.parent_hash, &state.latest_execution_payload_header.block_hash)) return error.InvalidExecutionParent;
    const current_epoch = helpers.computeEpochAtSlot(state.slot);
    if (!std.mem.eql(u8, &payload.prev_randao, &state.randao_mixes[current_epoch % helpers.EPOCHS_PER_HISTORICAL_VECTOR])) return error.InvalidPrevRandao;
    const slot_time = std.math.mul(u64, state.slot, 6) catch return error.InvalidTimestamp;
    const expected_time = std.math.add(u64, state.genesis_time, slot_time) catch return error.InvalidTimestamp;
    if (payload.timestamp != expected_time) return error.InvalidTimestamp;
    if (body.blob_kzg_commitments.data.len > 9) return error.TooManyBlobs;
    const versioned_hashes = try allocator.alloc(fulu.Root, body.blob_kzg_commitments.data.len);
    defer allocator.free(versioned_hashes);
    for (body.blob_kzg_commitments.data, versioned_hashes) |commitment, *hash| {
        std.crypto.hash.sha2.Sha256.hash(&commitment, hash, .{});
        hash[0] = 1;
    }
    const status = try engine.verify(.{
        .payload = &body.execution_payload,
        .versioned_hashes = versioned_hashes,
        .parent_beacon_block_root = state.latest_block_header.parent_root,
        .execution_requests = &body.execution_requests,
    });
    switch (status) {
        .valid => {},
        .invalid => return error.InvalidExecutionPayload,
        .syncing => return error.ExecutionPayloadUnverified,
    }
    const transactions_root = try merkle.HashTreeRoot(allocator, payload.transactions);
    const withdrawals_root = try merkle.HashTreeRoot(allocator, payload.withdrawals);
    const extra_data = try allocator.dupe(u8, payload.extra_data.data);
    allocator.free(@constCast(state.latest_execution_payload_header.extra_data.data));
    state.latest_execution_payload_header = .{
        .parent_hash = payload.parent_hash,
        .fee_recipient = payload.fee_recipient,
        .state_root = payload.state_root,
        .receipts_root = payload.receipts_root,
        .logs_bloom = payload.logs_bloom,
        .prev_randao = payload.prev_randao,
        .block_number = payload.block_number,
        .gas_limit = payload.gas_limit,
        .gas_used = payload.gas_used,
        .timestamp = payload.timestamp,
        .extra_data = .{ .data = extra_data },
        .base_fee_per_gas = payload.base_fee_per_gas,
        .block_hash = payload.block_hash,
        .transactions_root = transactions_root,
        .withdrawals_root = withdrawals_root,
        .blob_gas_used = payload.blob_gas_used,
        .excess_blob_gas = payload.excess_blob_gas,
    };
}

fn processRandao(state: *fulu.BeaconState, reveal: fulu.BLSSignature) !void {
    const current_epoch = helpers.computeEpochAtSlot(state.slot);
    const domain = domains.getDomain(state.*, helpers.DOMAIN_RANDAO, current_epoch);
    var epoch_chunk = [_]u8{0} ** 32;
    std.mem.writeInt(u64, epoch_chunk[0..8], current_epoch, .little);
    const signing_root = domains.computeSigningRoot(epoch_chunk, domain);
    const proposer = state.validators.data[state.proposer_lookahead[state.slot % helpers.SLOTS_PER_EPOCH]];
    try bls.verify(proposer.pubkey, signing_root, reveal);
    var reveal_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&reveal, &reveal_hash, .{});
    const mix = &state.randao_mixes[current_epoch % helpers.EPOCHS_PER_HISTORICAL_VECTOR];
    for (mix, reveal_hash) |*byte, hash_byte| byte.* ^= hash_byte;
}

fn processEth1Data(allocator: std.mem.Allocator, state: *fulu.BeaconState, vote: fulu.Eth1Data) !void {
    const old_votes = state.eth1_data_votes.data;
    if (old_votes.len >= 32) return error.Eth1VotingPeriodFull;
    const votes = try allocator.alloc(fulu.Eth1Data, old_votes.len + 1);
    @memcpy(votes[0..old_votes.len], old_votes);
    votes[old_votes.len] = vote;
    allocator.free(@constCast(old_votes));
    state.eth1_data_votes.data = votes;
    var matching: usize = 0;
    for (votes) |existing| if (std.meta.eql(existing, vote)) {
        matching += 1;
    };
    if (matching * 2 > 4 * helpers.SLOTS_PER_EPOCH) state.eth1_data = vote;
}

fn processSyncAggregate(state: *fulu.BeaconState, aggregate: fulu.SyncAggregate) !void {
    if (state.slot == 0) return error.InvalidSlot;
    const previous_slot = state.slot - 1;
    const domain = domains.getDomain(state.*, helpers.DOMAIN_SYNC_COMMITTEE, helpers.computeEpochAtSlot(previous_slot));
    const block_root = state.block_roots[previous_slot % state.block_roots.len];
    const signing_root = domains.computeSigningRoot(block_root, domain);
    var participants: [32]fulu.BLSPubkey = undefined;
    var participant_count: usize = 0;
    for (aggregate.sync_committee_bits.data, 0..) |bit, index| {
        if (bit) {
            participants[participant_count] = state.current_sync_committee.pubkeys[index];
            participant_count += 1;
        }
    }
    try bls.verifyAggregate(participants[0..participant_count], signing_root, aggregate.sync_committee_signature);
    const current_epoch = helpers.computeEpochAtSlot(state.slot);
    const total_active_balance = helpers.getTotalActiveBalance(state.validators.data, current_epoch) catch return error.InvalidState;
    const active_increments = total_active_balance / helpers.EFFECTIVE_BALANCE_INCREMENT;
    const base_reward_per_increment = helpers.EFFECTIVE_BALANCE_INCREMENT * helpers.BASE_REWARD_FACTOR / std.math.sqrt(total_active_balance);
    const total_base_rewards = base_reward_per_increment * active_increments;
    const max_participant_rewards = total_base_rewards * 2 / 64 / helpers.SLOTS_PER_EPOCH;
    const participant_reward: u64 = @intCast(max_participant_rewards / 32);
    const proposer_reward: u64 = participant_reward * 8 / (64 - 8);
    const proposer_index = state.proposer_lookahead[state.slot % helpers.SLOTS_PER_EPOCH];
    for (state.current_sync_committee.pubkeys, aggregate.sync_committee_bits.data) |pubkey, bit| {
        var validator_index: ?usize = null;
        for (state.validators.data, 0..) |validator, index| {
            if (std.mem.eql(u8, &validator.pubkey, &pubkey)) {
                validator_index = index;
                break;
            }
        }
        const index = validator_index orelse return error.InvalidSyncCommittee;
        if (bit) {
            @constCast(state.balances.data)[index] = std.math.add(u64, state.balances.data[index], participant_reward) catch return error.BalanceOverflow;
            @constCast(state.balances.data)[proposer_index] = std.math.add(u64, state.balances.data[proposer_index], proposer_reward) catch return error.BalanceOverflow;
        } else {
            @constCast(state.balances.data)[index] -|= participant_reward;
        }
    }
}

test "pinned empty block transitions and incorrect state root rejects" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    var fake_engine: engine_api.TestEngine = .{ .status = .valid };
    for ([_][]const u8{ "empty_block_transition", "invalid_incorrect_state_root" }) |name| {
        const case = fixtures.find(name).?;
        var state = try fixtures.decodeState(allocator, case.pre.?);
        defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
        const signed = try fixtures.decodeBlock(allocator, case.input.?);
        defer @import("ssz").freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
        if (case.expectation == .reject) {
            try std.testing.expectError(error.InvalidStateRoot, stateTransition(allocator, &state, signed, fake_engine.interface()));
        } else {
            const expected = try fixtures.decodeState(allocator, case.post.?);
            defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, expected);
            try stateTransition(allocator, &state, signed, fake_engine.interface());
            const actual_root = try merkle.HashTreeRoot(allocator, state);
            const expected_root = try merkle.HashTreeRoot(allocator, expected);
            try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
        }
    }
}

test "execution engine invalid and syncing results reject the block" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("empty_block_transition").?;
    const signed = try fixtures.decodeBlock(allocator, case.input.?);
    defer @import("ssz").freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    for ([_]engine_api.PayloadStatus{ .invalid, .syncing }) |status| {
        var state = try fixtures.decodeState(allocator, case.pre.?);
        defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
        var fake_engine: engine_api.TestEngine = .{ .status = status };
        const expected_error = if (status == .invalid) error.InvalidExecutionPayload else error.ExecutionPayloadUnverified;
        try std.testing.expectError(expected_error, stateTransition(allocator, &state, signed, fake_engine.interface()));
    }
}

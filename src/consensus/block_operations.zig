// Block operations can slash or exit validators, update participation, or add
// future deposits and withdrawals. Verify signed consensus operations before
// mutating state; execution requests are already authenticated by the engine
// and invalid requests are ignored as required by Electra. Fulu keeps the old
// deposit field in the SSZ body but requires it to be empty.
//
//   proposer slashings -> attester slashings -> attestations -> exits
//       -> BLS changes -> deposit requests -> withdrawal requests
//       -> consolidation requests
// Operation lists use their Fulu SSZ bounds selected by the compile-time
// preset, and the legacy deposit list is rejected because Fulu forbids it.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const bls = @import("bls.zig");
const domains = @import("domains.zig");
const helpers = @import("helpers.zig");
const epoch = @import("epoch.zig");
const preset = @import("consensus_preset").Config;

pub fn processOperations(allocator: std.mem.Allocator, state: *fulu.BeaconState, body: fulu.BeaconBlockBody) !void {
    for (body.proposer_slashings.data) |operation| try processProposerSlashing(allocator, state, operation);
    for (body.attester_slashings.data) |operation| try processAttesterSlashing(allocator, state, operation);
    for (body.attestations.data) |operation| try processAttestation(allocator, state, operation);
    if (body.deposits.data.len != 0) return error.UnsupportedLegacyDeposits;
    for (body.voluntary_exits.data) |operation| try processVoluntaryExit(allocator, state, operation);
    for (body.bls_to_execution_changes.data) |operation| try processBLSToExecutionChange(allocator, state, operation);
    for (body.execution_requests.deposits.data) |operation| try processDepositRequest(allocator, state, operation);
    for (body.execution_requests.withdrawals.data) |operation| try processWithdrawalRequest(allocator, state, operation);
    for (body.execution_requests.consolidations.data) |operation| try processConsolidationRequest(allocator, state, operation);
}

pub fn processProposerSlashing(allocator: std.mem.Allocator, state: *fulu.BeaconState, slashing: fulu.ProposerSlashing) !void {
    const first = slashing.signed_header_1.message;
    const second = slashing.signed_header_2.message;
    if (first.slot != second.slot or first.proposer_index != second.proposer_index or
        std.meta.eql(first, second) or first.proposer_index >= state.validators.data.len)
        return error.InvalidProposerSlashing;
    const epoch_number = helpers.computeEpochAtSlot(first.slot);
    const validator = state.validators.data[first.proposer_index];
    if (!helpers.isSlashableValidator(validator, epoch_number)) return error.InvalidProposerSlashing;
    const domain = domains.getDomain(state.*, helpers.DOMAIN_BEACON_PROPOSER, epoch_number);
    const first_root = try merkle.HashTreeRoot(allocator, first);
    try bls.verify(validator.pubkey, domains.computeSigningRoot(first_root, domain), slashing.signed_header_1.signature);
    const second_root = try merkle.HashTreeRoot(allocator, second);
    try bls.verify(validator.pubkey, domains.computeSigningRoot(second_root, domain), slashing.signed_header_2.signature);
    try slashValidator(state, first.proposer_index);
}

pub fn processAttesterSlashing(allocator: std.mem.Allocator, state: *fulu.BeaconState, slashing: fulu.AttesterSlashing) !void {
    const first = slashing.attestation_1;
    const second = slashing.attestation_2;
    if (!isSlashableAttestationData(first.data, second.data)) return error.InvalidAttesterSlashing;
    try validateIndexedAttestation(allocator, state, first);
    try validateIndexedAttestation(allocator, state, second);

    var slashable = std.ArrayList(fulu.ValidatorIndex).empty;
    defer slashable.deinit(allocator);
    var first_index: usize = 0;
    var second_index: usize = 0;
    const current_epoch = helpers.getCurrentEpoch(state);
    while (first_index < first.attesting_indices.data.len and second_index < second.attesting_indices.data.len) {
        const first_validator = first.attesting_indices.data[first_index];
        const second_validator = second.attesting_indices.data[second_index];
        if (first_validator < second_validator) {
            first_index += 1;
        } else if (second_validator < first_validator) {
            second_index += 1;
        } else {
            if (first_validator >= state.validators.data.len) return error.InvalidAttesterSlashing;
            if (helpers.isSlashableValidator(state.validators.data[first_validator], current_epoch))
                try slashable.append(allocator, first_validator);
            first_index += 1;
            second_index += 1;
        }
    }
    if (slashable.items.len == 0) return error.InvalidAttesterSlashing;
    for (slashable.items) |index| try slashValidator(state, index);
}

/// Validate sorted validator indices and the aggregate attester signature.
pub fn validateIndexedAttestation(allocator: std.mem.Allocator, state: *const fulu.BeaconState, attestation: fulu.IndexedAttestation) !void {
    const indices = attestation.attesting_indices.data;
    if (indices.len == 0) return error.InvalidIndexedAttestation;
    var pubkeys = try allocator.alloc(fulu.BLSPubkey, indices.len);
    defer allocator.free(pubkeys);
    for (indices, 0..) |index, i| {
        if (index >= state.validators.data.len or (i != 0 and indices[i - 1] >= index))
            return error.InvalidIndexedAttestation;
        pubkeys[i] = state.validators.data[index].pubkey;
    }
    const root = try merkle.HashTreeRoot(allocator, attestation.data);
    const domain = domains.getDomain(state.*, helpers.DOMAIN_BEACON_ATTESTER, attestation.data.target.epoch);
    try bls.verifyAggregate(pubkeys, domains.computeSigningRoot(root, domain), attestation.signature);
}

/// Report whether two votes are a double vote or surround vote.
pub fn isSlashableAttestationData(first: fulu.AttestationData, second: fulu.AttestationData) bool {
    if (first.target.epoch == second.target.epoch and !std.meta.eql(first, second)) return true;
    return (first.source.epoch < second.source.epoch and second.target.epoch < first.target.epoch) or
        (second.source.epoch < first.source.epoch and first.target.epoch < second.target.epoch);
}

fn slashValidator(state: *fulu.BeaconState, index: fulu.ValidatorIndex) !void {
    if (index >= state.validators.data.len or index >= state.balances.data.len) return error.InvalidState;
    const current_epoch = helpers.getCurrentEpoch(state);
    try epoch.initiateValidatorExit(state, index, current_epoch);
    const validator = &@constCast(state.validators.data)[index];
    validator.slashed = true;
    validator.withdrawable_epoch = @max(validator.withdrawable_epoch, current_epoch + helpers.EPOCHS_PER_SLASHINGS_VECTOR);
    const slashings_index = current_epoch % helpers.EPOCHS_PER_SLASHINGS_VECTOR;
    state.slashings[slashings_index] = std.math.add(u64, state.slashings[slashings_index], validator.effective_balance) catch return error.BalanceOverflow;
    @constCast(state.balances.data)[index] -|= validator.effective_balance / preset.MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA;

    const proposer_index = state.proposer_lookahead[state.slot % helpers.SLOTS_PER_EPOCH];
    if (proposer_index >= state.balances.data.len) return error.InvalidState;
    const whistleblower_reward = validator.effective_balance / helpers.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
    const proposer_reward = whistleblower_reward * helpers.PROPOSER_WEIGHT / helpers.WEIGHT_DENOMINATOR;
    @constCast(state.balances.data)[proposer_index] = std.math.add(u64, state.balances.data[proposer_index], proposer_reward) catch return error.BalanceOverflow;
    @constCast(state.balances.data)[proposer_index] = std.math.add(u64, state.balances.data[proposer_index], whistleblower_reward - proposer_reward) catch return error.BalanceOverflow;
}

/// Validate an included attestation and credit its participants and proposer.
pub fn processAttestation(allocator: std.mem.Allocator, state: *fulu.BeaconState, attestation: fulu.Attestation) !void {
    const data = attestation.data;
    const current_epoch = helpers.getCurrentEpoch(state);
    const target_epoch = data.target.epoch;
    if ((target_epoch != current_epoch and target_epoch != helpers.computePreviousEpoch(current_epoch)) or
        target_epoch != helpers.computeEpochAtSlot(data.slot) or data.index != 0 or
        data.slot > state.slot or state.slot - data.slot < preset.MIN_ATTESTATION_INCLUSION_DELAY or state.slot - data.slot > helpers.SLOTS_PER_EPOCH)
        return error.InvalidAttestation;

    const attesting = try getAttestingIndices(allocator, state, attestation);
    defer allocator.free(attesting);
    const indexed = fulu.IndexedAttestation{
        .attesting_indices = .{ .data = attesting },
        .data = data,
        .signature = attestation.signature,
    };
    try validateIndexedAttestation(allocator, state, indexed);

    const block_root = state.block_roots[data.slot % state.block_roots.len];
    const source_index: usize = helpers.TIMELY_SOURCE_FLAG_INDEX;
    const target_index: usize = helpers.TIMELY_TARGET_FLAG_INDEX;
    const head_index: usize = helpers.TIMELY_HEAD_FLAG_INDEX;
    var flags: [3]bool = .{ false, false, false };
    const delay = state.slot - data.slot;
    flags[source_index] = data.source.epoch == helpers.computePreviousEpoch(target_epoch) and
        std.meta.eql(data.source.root, if (target_epoch == current_epoch) state.current_justified_checkpoint.root else state.previous_justified_checkpoint.root);
    flags[target_index] = std.meta.eql(data.target.root, blockRootAtEpoch(state, target_epoch) catch return error.InvalidAttestation);
    flags[head_index] = std.meta.eql(data.beacon_block_root, block_root) and delay == preset.MIN_ATTESTATION_INCLUSION_DELAY;
    if (delay > std.math.sqrt(helpers.SLOTS_PER_EPOCH)) flags[source_index] = false;
    if (delay > helpers.SLOTS_PER_EPOCH) flags[target_index] = false;

    const participation = if (target_epoch == current_epoch)
        @constCast(state.current_epoch_participation.data)
    else
        @constCast(state.previous_epoch_participation.data);
    if (participation.len != state.validators.data.len) return error.InvalidState;
    const total_active_balance = try helpers.getTotalActiveBalance(state.validators.data, current_epoch);
    const denominator = (helpers.WEIGHT_DENOMINATOR - helpers.PROPOSER_WEIGHT) * helpers.WEIGHT_DENOMINATOR / helpers.PROPOSER_WEIGHT;
    var proposer_reward_numerator: u128 = 0;
    for (attesting) |index| {
        if (index >= participation.len) return error.InvalidAttestation;
        for (0..helpers.PARTICIPATION_FLAG_WEIGHTS.len) |flag_index| {
            if (!flags[flag_index]) continue;
            const mask = @as(u8, 1) << @as(u3, @intCast(flag_index));
            if (participation[index] & mask != 0) continue;
            participation[index] |= mask;
            const base = baseReward(state.validators.data[index].effective_balance, total_active_balance);
            proposer_reward_numerator += @as(u128, base) * helpers.PARTICIPATION_FLAG_WEIGHTS[flag_index];
        }
    }
    const proposer_reward: u64 = @intCast(proposer_reward_numerator / denominator);
    const proposer = state.proposer_lookahead[state.slot % helpers.SLOTS_PER_EPOCH];
    if (proposer >= state.balances.data.len) return error.InvalidState;
    @constCast(state.balances.data)[proposer] = std.math.add(u64, state.balances.data[proposer], proposer_reward) catch return error.BalanceOverflow;
}

/// Return sorted attesters selected by Fulu committee and aggregation bits; caller frees them.
pub fn getAttestingIndices(allocator: std.mem.Allocator, state: *const fulu.BeaconState, attestation: fulu.Attestation) ![]fulu.ValidatorIndex {
    const committees = try getCommitteeIndices(allocator, &attestation.committee_bits.data);
    defer allocator.free(committees);
    if (committees.len == 0) return error.InvalidAttestation;
    var attesting = std.ArrayList(fulu.ValidatorIndex).empty;
    errdefer attesting.deinit(allocator);
    // Aggregation bits concatenate the selected committees in committee-index order.
    var offset: usize = 0;
    for (committees) |committee_index| {
        const committee = try helpers.getBeaconCommittee(allocator, state, attestation.data.slot, committee_index);
        defer allocator.free(committee);
        if (attestation.aggregation_bits.data.len < offset + committee.len) return error.InvalidAttestation;
        var participants: usize = 0;
        for (committee, 0..) |validator_index, i| {
            if (attestation.aggregation_bits.data[offset + i]) {
                try attesting.append(allocator, validator_index);
                participants += 1;
            }
        }
        if (participants == 0) return error.InvalidAttestation;
        offset += committee.len;
    }
    if (offset != attestation.aggregation_bits.data.len) return error.InvalidAttestation;
    // Indexed attestations require strictly increasing validator indices for signature checks.
    std.mem.sort(fulu.ValidatorIndex, attesting.items, {}, std.sort.asc(fulu.ValidatorIndex));
    for (attesting.items, 0..) |index, i| {
        if (index >= state.validators.data.len or (i != 0 and attesting.items[i - 1] == index)) return error.InvalidAttestation;
    }
    return attesting.toOwnedSlice(allocator);
}

fn getCommitteeIndices(allocator: std.mem.Allocator, bits: []const bool) ![]usize {
    var indices = std.ArrayList(usize).empty;
    errdefer indices.deinit(allocator);
    for (bits, 0..) |bit, index| if (bit) try indices.append(allocator, index);
    return indices.toOwnedSlice(allocator);
}

fn blockRootAtEpoch(state: *const fulu.BeaconState, epoch_number: fulu.Epoch) !fulu.Root {
    const slot = try helpers.computeStartSlotAtEpoch(epoch_number);
    return state.block_roots[slot % state.block_roots.len];
}

fn baseReward(effective_balance: u64, total_active_balance: u64) u64 {
    const per_increment = helpers.EFFECTIVE_BALANCE_INCREMENT * helpers.BASE_REWARD_FACTOR / std.math.sqrt(total_active_balance);
    return per_increment * (effective_balance / helpers.EFFECTIVE_BALANCE_INCREMENT);
}

pub fn processVoluntaryExit(allocator: std.mem.Allocator, state: *fulu.BeaconState, signed_exit: fulu.SignedVoluntaryExit) !void {
    const exit = signed_exit.message;
    if (exit.validator_index >= state.validators.data.len or exit.validator_index >= state.balances.data.len)
        return error.InvalidVoluntaryExit;
    const validator = state.validators.data[exit.validator_index];
    const current_epoch = helpers.getCurrentEpoch(state);
    if (!helpers.isActiveValidator(validator, current_epoch) or validator.exit_epoch != helpers.FAR_FUTURE_EPOCH or
        current_epoch < exit.epoch or current_epoch - validator.activation_epoch < preset.SHARD_COMMITTEE_PERIOD or
        pendingBalanceToWithdraw(state, exit.validator_index) != 0)
        return error.InvalidVoluntaryExit;
    const root = try merkle.HashTreeRoot(allocator, exit);
    const domain = domains.computeDomain(helpers.DOMAIN_VOLUNTARY_EXIT, preset.CAPELLA_FORK_VERSION, state.genesis_validators_root);
    try bls.verify(validator.pubkey, domains.computeSigningRoot(root, domain), signed_exit.signature);
    try epoch.initiateValidatorExit(state, exit.validator_index, current_epoch);
}

pub fn processBLSToExecutionChange(allocator: std.mem.Allocator, state: *fulu.BeaconState, signed_change: fulu.SignedBLSToExecutionChange) !void {
    const change = signed_change.message;
    if (change.validator_index >= state.validators.data.len) return error.InvalidBLSToExecutionChange;
    const validator = state.validators.data[change.validator_index];
    var withdrawal_root: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&change.from_bls_pubkey, &withdrawal_root, .{});
    if (!std.mem.eql(u8, validator.withdrawal_credentials[1..], withdrawal_root[1..]) or validator.withdrawal_credentials[0] != 0)
        return error.InvalidBLSToExecutionChange;
    const root = try merkle.HashTreeRoot(allocator, change);
    const domain = domains.computeDomain(helpers.DOMAIN_BLS_TO_EXECUTION_CHANGE, helpers.GENESIS_FORK_VERSION, state.genesis_validators_root);
    try bls.verify(change.from_bls_pubkey, domains.computeSigningRoot(root, domain), signed_change.signature);
    var credentials = validator.withdrawal_credentials;
    credentials[0] = 1;
    @memset(credentials[1..12], 0);
    @memcpy(credentials[12..], &change.to_execution_address);
    @constCast(state.validators.data)[change.validator_index].withdrawal_credentials = credentials;
}

pub fn processDepositRequest(allocator: std.mem.Allocator, state: *fulu.BeaconState, request: fulu.DepositRequest) !void {
    if (state.pending_deposits.data.len >= preset.PENDING_DEPOSITS_LIMIT) return error.PendingDepositsFull;
    if (state.deposit_requests_start_index == helpers.FAR_FUTURE_EPOCH)
        state.deposit_requests_start_index = request.index;
    try append(fulu.PendingDeposit, allocator, &state.pending_deposits.data, .{
        .pubkey = request.pubkey,
        .withdrawal_credentials = request.withdrawal_credentials,
        .amount = request.amount,
        .signature = request.signature,
        .slot = state.slot,
    });
}

pub fn processWithdrawalRequest(allocator: std.mem.Allocator, state: *fulu.BeaconState, request: fulu.WithdrawalRequest) !void {
    const full_exit = request.amount == 0;
    if (state.pending_partial_withdrawals.data.len >= preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT and !full_exit) return;
    const index = findValidator(state.validators.data, request.validator_pubkey) orelse return;
    const validator = state.validators.data[index];
    const current_epoch = helpers.getCurrentEpoch(state);
    if ((validator.withdrawal_credentials[0] != 1 and validator.withdrawal_credentials[0] != 2) or
        !std.mem.eql(u8, validator.withdrawal_credentials[12..], &request.source_address) or
        !helpers.isActiveValidator(validator, current_epoch) or validator.exit_epoch != helpers.FAR_FUTURE_EPOCH or
        current_epoch - validator.activation_epoch < preset.SHARD_COMMITTEE_PERIOD)
        return;
    const pending = pendingBalanceToWithdraw(state, @intCast(index));
    if (full_exit) {
        if (pending == 0) try epoch.initiateValidatorExit(state, @intCast(index), current_epoch);
        return;
    }
    if (validator.withdrawal_credentials[0] != 2 or validator.effective_balance < helpers.MIN_ACTIVATION_BALANCE or
        state.balances.data[index] <= helpers.MIN_ACTIVATION_BALANCE + pending)
        return;
    const amount = @min(state.balances.data[index] - helpers.MIN_ACTIVATION_BALANCE - pending, request.amount);
    const exit_epoch = try computeExitEpochAndUpdateChurn(state, amount);
    const withdrawable_epoch = std.math.add(u64, exit_epoch, helpers.MIN_VALIDATOR_WITHDRAWABILITY_DELAY) catch return error.InvalidState;
    try append(fulu.PendingPartialWithdrawal, allocator, &state.pending_partial_withdrawals.data, .{
        .validator_index = @intCast(index),
        .amount = amount,
        .withdrawable_epoch = withdrawable_epoch,
    });
}

pub fn processConsolidationRequest(allocator: std.mem.Allocator, state: *fulu.BeaconState, request: fulu.ConsolidationRequest) !void {
    if (std.mem.eql(u8, &request.source_pubkey, &request.target_pubkey)) {
        const index = findValidator(state.validators.data, request.source_pubkey) orelse return;
        const validator = state.validators.data[index];
        const current_epoch = helpers.getCurrentEpoch(state);
        if (!std.mem.eql(u8, validator.withdrawal_credentials[12..], &request.source_address) or
            validator.withdrawal_credentials[0] != 1 or !helpers.isActiveValidator(validator, current_epoch) or
            validator.exit_epoch != helpers.FAR_FUTURE_EPOCH)
            return;
        @constCast(state.validators.data)[index].withdrawal_credentials[0] = 2;
        const balance = state.balances.data[index];
        if (balance > helpers.MIN_ACTIVATION_BALANCE) {
            if (state.pending_deposits.data.len >= preset.PENDING_DEPOSITS_LIMIT) return error.PendingDepositsFull;
            const excess = balance - helpers.MIN_ACTIVATION_BALANCE;
            @constCast(state.balances.data)[index] = helpers.MIN_ACTIVATION_BALANCE;
            var infinity = [_]u8{0} ** 96;
            infinity[0] = 0xc0;
            try append(fulu.PendingDeposit, allocator, &state.pending_deposits.data, .{
                .pubkey = validator.pubkey,
                .withdrawal_credentials = @constCast(state.validators.data)[index].withdrawal_credentials,
                .amount = excess,
                .signature = infinity,
                .slot = 0,
            });
        }
        return;
    }
    if (state.pending_consolidations.data.len >= preset.PENDING_CONSOLIDATIONS_LIMIT or consolidationChurnLimit(state) <= helpers.MIN_ACTIVATION_BALANCE) return;
    const source_index = findValidator(state.validators.data, request.source_pubkey) orelse return;
    const target_index = findValidator(state.validators.data, request.target_pubkey) orelse return;
    const source = state.validators.data[source_index];
    const target = state.validators.data[target_index];
    const current_epoch = helpers.getCurrentEpoch(state);
    if ((source.withdrawal_credentials[0] != 1 and source.withdrawal_credentials[0] != 2) or
        !std.mem.eql(u8, source.withdrawal_credentials[12..], &request.source_address) or target.withdrawal_credentials[0] != 2 or
        !helpers.isActiveValidator(source, current_epoch) or !helpers.isActiveValidator(target, current_epoch) or
        source.exit_epoch != helpers.FAR_FUTURE_EPOCH or target.exit_epoch != helpers.FAR_FUTURE_EPOCH or
        current_epoch - source.activation_epoch < preset.SHARD_COMMITTEE_PERIOD or pendingBalanceToWithdraw(state, @intCast(source_index)) != 0)
        return;
    const exit_epoch = try computeConsolidationEpochAndUpdateChurn(state, source.effective_balance);
    const withdrawable_epoch = std.math.add(u64, exit_epoch, helpers.MIN_VALIDATOR_WITHDRAWABILITY_DELAY) catch return error.InvalidState;
    @constCast(state.validators.data)[source_index].exit_epoch = exit_epoch;
    @constCast(state.validators.data)[source_index].withdrawable_epoch = withdrawable_epoch;
    try append(fulu.PendingConsolidation, allocator, &state.pending_consolidations.data, .{
        .source_index = @intCast(source_index),
        .target_index = @intCast(target_index),
    });
}

fn pendingBalanceToWithdraw(state: *const fulu.BeaconState, index: fulu.ValidatorIndex) u64 {
    var total: u128 = 0;
    for (state.pending_partial_withdrawals.data) |withdrawal| {
        if (withdrawal.validator_index == index) total += withdrawal.amount;
    }
    return @intCast(@min(total, std.math.maxInt(u64)));
}

fn findValidator(validators: []const fulu.Validator, pubkey: fulu.BLSPubkey) ?usize {
    for (validators, 0..) |validator, index| if (std.mem.eql(u8, &validator.pubkey, &pubkey)) return index;
    return null;
}

fn append(comptime T: type, allocator: std.mem.Allocator, values: *[]const T, value: T) !void {
    const old = values.*;
    const updated = try allocator.alloc(T, old.len + 1);
    @memcpy(updated[0..old.len], old);
    updated[old.len] = value;
    if (old.len != 0) allocator.free(@constCast(old));
    values.* = updated;
}

fn balanceChurnLimit(state: *const fulu.BeaconState) u64 {
    const current_epoch = helpers.getCurrentEpoch(state);
    const total = helpers.getTotalActiveBalance(state.validators.data, current_epoch) catch return 0;
    const raw = @max(helpers.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, total / helpers.CHURN_LIMIT_QUOTIENT);
    return raw - raw % helpers.EFFECTIVE_BALANCE_INCREMENT;
}

fn consolidationChurnLimit(state: *const fulu.BeaconState) u64 {
    const balance_churn = balanceChurnLimit(state);
    const activation_exit = @min(helpers.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, balance_churn);
    return balance_churn - activation_exit;
}

fn computeExitEpochAndUpdateChurn(state: *fulu.BeaconState, amount: u64) !fulu.Epoch {
    var earliest = @max(state.earliest_exit_epoch, try helpers.computeActivationExitEpoch(helpers.getCurrentEpoch(state)));
    const churn = @min(helpers.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, balanceChurnLimit(state));
    if (churn == 0) return error.InvalidState;
    var consume = if (state.earliest_exit_epoch < earliest) churn else state.exit_balance_to_consume;
    if (amount > consume) {
        const additional = (amount - consume - 1) / churn + 1;
        earliest = std.math.add(u64, earliest, additional) catch return error.InvalidState;
        consume = std.math.add(u64, consume, additional * churn) catch return error.InvalidState;
    }
    state.exit_balance_to_consume = consume - amount;
    state.earliest_exit_epoch = earliest;
    return earliest;
}

fn computeConsolidationEpochAndUpdateChurn(state: *fulu.BeaconState, amount: u64) !fulu.Epoch {
    var earliest = @max(state.earliest_consolidation_epoch, try helpers.computeActivationExitEpoch(helpers.getCurrentEpoch(state)));
    const churn = consolidationChurnLimit(state);
    if (churn == 0) return error.InvalidState;
    var consume = if (state.earliest_consolidation_epoch < earliest) churn else state.consolidation_balance_to_consume;
    if (amount > consume) {
        const additional = (amount - consume - 1) / churn + 1;
        earliest = std.math.add(u64, earliest, additional) catch return error.InvalidState;
        consume = std.math.add(u64, consume, additional * churn) catch return error.InvalidState;
    }
    state.consolidation_balance_to_consume = consume - amount;
    state.earliest_consolidation_epoch = earliest;
    return earliest;
}

pub fn processWithdrawals(allocator: std.mem.Allocator, state: *fulu.BeaconState, payload: fulu.ExecutionPayload) !void {
    const expected = try getExpectedWithdrawals(allocator, state);
    defer allocator.free(expected.items);
    if (expected.items.len != payload.withdrawals.data.len) return error.InvalidWithdrawals;
    for (expected.items, payload.withdrawals.data) |expected_withdrawal, actual_withdrawal| {
        if (!std.meta.eql(expected_withdrawal, actual_withdrawal)) return error.InvalidWithdrawals;
    }
    for (expected.items) |withdrawal| {
        if (withdrawal.validator_index >= state.balances.data.len) return error.InvalidState;
        @constCast(state.balances.data)[withdrawal.validator_index] -|= withdrawal.amount;
    }
    const pending = state.pending_partial_withdrawals.data;
    const remaining = try allocator.dupe(fulu.PendingPartialWithdrawal, pending[expected.processed_partials..]);
    if (pending.len != 0) allocator.free(@constCast(pending));
    state.pending_partial_withdrawals.data = remaining;
    if (expected.items.len != 0) state.next_withdrawal_index = expected.items[expected.items.len - 1].index + 1;
    if (expected.items.len == preset.MAX_WITHDRAWALS_PER_PAYLOAD) {
        state.next_withdrawal_validator_index = (expected.items[expected.items.len - 1].validator_index + 1) % state.validators.data.len;
    } else if (state.validators.data.len != 0) {
        state.next_withdrawal_validator_index = (state.next_withdrawal_validator_index + preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) % state.validators.data.len;
    }
}

const ExpectedWithdrawals = struct {
    items: []fulu.Withdrawal,
    processed_partials: usize,
};

fn getExpectedWithdrawals(allocator: std.mem.Allocator, state: *const fulu.BeaconState) !ExpectedWithdrawals {
    var withdrawals = std.ArrayList(fulu.Withdrawal).empty;
    errdefer withdrawals.deinit(allocator);
    const current_epoch = helpers.getCurrentEpoch(state);
    var withdrawal_index = state.next_withdrawal_index;
    var processed_partials: usize = 0;
    for (state.pending_partial_withdrawals.data) |pending| {
        if (pending.withdrawable_epoch > current_epoch or processed_partials == preset.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP or
            withdrawals.items.len == preset.MAX_WITHDRAWALS_PER_PAYLOAD) break;
        if (pending.validator_index >= state.validators.data.len or pending.validator_index >= state.balances.data.len) return error.InvalidState;
        const validator = state.validators.data[pending.validator_index];
        const prior = totalForValidator(withdrawals.items, pending.validator_index);
        const balance = state.balances.data[pending.validator_index] -| prior;
        if (validator.exit_epoch == helpers.FAR_FUTURE_EPOCH and validator.effective_balance >= helpers.MIN_ACTIVATION_BALANCE and balance > helpers.MIN_ACTIVATION_BALANCE) {
            const amount = @min(balance - helpers.MIN_ACTIVATION_BALANCE, pending.amount);
            try withdrawals.append(allocator, .{
                .index = withdrawal_index,
                .validator_index = pending.validator_index,
                .address = addressFromCredentials(validator.withdrawal_credentials),
                .amount = amount,
            });
            withdrawal_index += 1;
        }
        processed_partials += 1;
    }
    const validator_count = state.validators.data.len;
    const sweep = @min(validator_count, preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    var validator_index: usize = if (validator_count == 0) 0 else @intCast(state.next_withdrawal_validator_index);
    if (validator_count != 0) for (0..sweep) |_| {
        const index = validator_index;
        const validator = state.validators.data[index];
        const balance = state.balances.data[index] -| totalForValidator(withdrawals.items, @intCast(index));
        const max_balance = if (validator.withdrawal_credentials[0] == 2) helpers.MAX_EFFECTIVE_BALANCE_ELECTRA else helpers.MIN_ACTIVATION_BALANCE;
        const full = (validator.withdrawal_credentials[0] == 1 or validator.withdrawal_credentials[0] == 2) and validator.withdrawable_epoch <= current_epoch and balance > 0;
        const partial = (validator.withdrawal_credentials[0] == 1 or validator.withdrawal_credentials[0] == 2) and validator.effective_balance == max_balance and balance > max_balance;
        if (full or partial) {
            try withdrawals.append(allocator, .{
                .index = withdrawal_index,
                .validator_index = @intCast(index),
                .address = addressFromCredentials(validator.withdrawal_credentials),
                .amount = if (full) balance else balance - max_balance,
            });
            withdrawal_index += 1;
        }
        if (withdrawals.items.len == preset.MAX_WITHDRAWALS_PER_PAYLOAD) break;
        validator_index = (validator_index + 1) % validator_count;
    };
    return .{ .items = try withdrawals.toOwnedSlice(allocator), .processed_partials = processed_partials };
}

fn totalForValidator(withdrawals: []const fulu.Withdrawal, index: fulu.ValidatorIndex) u64 {
    var total: u128 = 0;
    for (withdrawals) |withdrawal| if (withdrawal.validator_index == index) {
        total += withdrawal.amount;
    };
    return @intCast(@min(total, std.math.maxInt(u64)));
}

fn addressFromCredentials(credentials: fulu.Bytes32) fulu.ExecutionAddress {
    var address: fulu.ExecutionAddress = undefined;
    @memcpy(&address, credentials[12..32]);
    return address;
}

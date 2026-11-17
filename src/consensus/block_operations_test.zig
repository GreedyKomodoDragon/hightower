// These vectors come from the pinned Fulu minimal-preset operation suites.
// Applying isolated operations here checks signatures and state changes; the
// block transition fixture separately checks their place in the body order.
const std = @import("std");
const fulu = @import("fulu");
const merkle = @import("merkle");
const ssz = @import("ssz");
const fixtures = @import("fixture_runner.zig");
const operations = @import("block_operations.zig");
const block = @import("block.zig");
const helpers = @import("helpers.zig");
const bls = @import("bls.zig");
const domains = @import("domains.zig");
const blst = @import("blst");
const preset = @import("consensus_preset");

fn decodeValue(comptime T: type, allocator: std.mem.Allocator, compressed: []const u8) !T {
    const bytes = try fixtures.decode(allocator, compressed);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, T, &reader);
}

fn expectStateRoot(allocator: std.mem.Allocator, actual: fulu.BeaconState, expected: fulu.BeaconState) !void {
    const actual_root = try merkle.HashTreeRoot(allocator, actual);
    const expected_root = try merkle.HashTreeRoot(allocator, expected);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

fn runValid(comptime T: type, process: anytype, comptime directory: []const u8, comptime input_name: []const u8) !void {
    const allocator = std.testing.allocator;
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const input = try decodeValue(T, allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/" ++ input_name ++ ".ssz_snappy"));
    defer ssz.freeDecoded(allocator, T, input);
    const expected = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/post.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, expected);
    try process(allocator, &state, input);
    try expectStateRoot(allocator, state, expected);
}

fn runInvalid(comptime T: type, process: anytype, comptime directory: []const u8, comptime input_name: []const u8, expected_error: anyerror) !void {
    const allocator = std.testing.allocator;
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const input = try decodeValue(T, allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/" ++ input_name ++ ".ssz_snappy"));
    defer ssz.freeDecoded(allocator, T, input);
    try std.testing.expectError(expected_error, process(allocator, &state, input));
}

fn runIgnored(comptime T: type, process: anytype, comptime directory: []const u8, comptime input_name: []const u8) !void {
    const allocator = std.testing.allocator;
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const input = try decodeValue(T, allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/" ++ input_name ++ ".ssz_snappy"));
    defer ssz.freeDecoded(allocator, T, input);
    const expected = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/" ++ directory ++ "/post.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, expected);
    try process(allocator, &state, input);
    try expectStateRoot(allocator, state, expected);
}

fn processSyncAggregate(allocator: std.mem.Allocator, state: *fulu.BeaconState, aggregate: fulu.SyncAggregate) !void {
    try block.processSyncAggregate(allocator, state, aggregate);
}

test "pinned Fulu block header fixtures validate proposer and parent" {
    try runValid(fulu.BeaconBlock, block.processBlockHeader, "block_header_valid", "block");
    try runInvalid(fulu.BeaconBlock, block.processBlockHeader, "block_header_invalid", "block", error.InvalidProposer);
}

test "pinned proposer slashing fixtures verify both headers" {
    try runValid(fulu.ProposerSlashing, operations.processProposerSlashing, "proposer_slashing_valid", "proposer_slashing");
    try runInvalid(fulu.ProposerSlashing, operations.processProposerSlashing, "proposer_slashing_invalid", "proposer_slashing", error.InvalidSignature);
}

test "pinned attester slashing fixtures validate indices and aggregate signatures" {
    try runValid(fulu.AttesterSlashing, operations.processAttesterSlashing, "attester_slashing_valid", "attester_slashing");
    try runInvalid(fulu.AttesterSlashing, operations.processAttesterSlashing, "attester_slashing_invalid", "attester_slashing", error.InvalidSignature);
}

test "pinned attestation fixtures update participation and reject empty participants" {
    try runValid(fulu.Attestation, operations.processAttestation, "attestation_valid", "attestation");
    try runInvalid(fulu.Attestation, operations.processAttestation, "attestation_invalid", "attestation", error.InvalidAttestation);
}

test "attestation source checkpoint mismatch leaves state unchanged" {
    const allocator = std.testing.allocator;
    const input = try decodeValue(fulu.Attestation, allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.Attestation, input);
    for (0..2) |mismatch| {
        var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
        defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
        const checkpoint = if (input.data.target.epoch == helpers.getCurrentEpoch(&state)) &state.current_justified_checkpoint else &state.previous_justified_checkpoint;
        try std.testing.expectEqualDeep(input.data.source, checkpoint.*);
        if (mismatch == 0) checkpoint.epoch += 1 else checkpoint.root[0] ^= 1;
        const before = try merkle.HashTreeRoot(allocator, state);
        try std.testing.expectError(error.InvalidAttestation, operations.processAttestation(allocator, &state, input));
        try std.testing.expectEqual(before, try merkle.HashTreeRoot(allocator, state));
    }
}

test "attestation flags require matching target before head" {
    const allocator = std.testing.allocator;
    const input = try decodeValue(fulu.Attestation, allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.Attestation, input);
    for (0..4) |mismatch| {
        var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
        defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
        if (mismatch == 3) state.slot = input.data.slot + std.math.sqrt(helpers.SLOTS_PER_EPOCH) + 1;
        var vote = input;
        const bits = try allocator.dupe(bool, input.aggregation_bits.data);
        defer allocator.free(bits);
        @memset(bits, false);
        bits[0] = true;
        vote.aggregation_bits.data = bits;
        const indices = try operations.getAttestingIndices(allocator, &state, vote);
        defer allocator.free(indices);
        try std.testing.expectEqual(@as(usize, 1), indices.len);
        var key = blst.SecretKey{};
        defer key.deinit();
        key.keygen(&([_]u8{0x50} ** 32), null);
        @constCast(state.validators.data)[indices[0]].pubkey = try bls.publicKey(&key);
        if (mismatch == 1) vote.data.target.root[0] ^= 1;
        if (mismatch == 2) vote.data.beacon_block_root[0] ^= 1;
        const root = try merkle.HashTreeRoot(allocator, vote.data);
        vote.signature = bls.sign(&key, domains.computeSigningRoot(root, domains.getDomain(state, helpers.DOMAIN_BEACON_ATTESTER, vote.data.target.epoch)));
        try operations.processAttestation(allocator, &state, vote);
        const participation = if (input.data.target.epoch == helpers.getCurrentEpoch(&state)) state.current_epoch_participation.data else state.previous_epoch_participation.data;
        const expected: u8 = switch (mismatch) {
            0 => 0b111,
            1 => 0b001,
            2 => 0b011,
            else => 0b010,
        };
        try std.testing.expectEqual(expected, participation[indices[0]]);
    }
}

test "attestation accepts an older justified source checkpoint" {
    const allocator = std.testing.allocator;
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var vote = try decodeValue(fulu.Attestation, allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.Attestation, vote);
    vote.data.target.epoch = 2;
    vote.data.slot = try helpers.computeStartSlotAtEpoch(vote.data.target.epoch);
    state.slot = vote.data.slot + 1;
    vote.data.target.root = state.block_roots[vote.data.slot % state.block_roots.len];
    vote.data.beacon_block_root = vote.data.target.root;
    state.current_justified_checkpoint = vote.data.source;
    try std.testing.expect(vote.data.source.epoch < vote.data.target.epoch - 1);
    @memset(@constCast(vote.aggregation_bits.data), false);
    @constCast(vote.aggregation_bits.data)[0] = true;
    const indices = try operations.getAttestingIndices(allocator, &state, vote);
    defer allocator.free(indices);
    try std.testing.expectEqual(@as(usize, 1), indices.len);
    var key = blst.SecretKey{};
    defer key.deinit();
    key.keygen(&([_]u8{0x51} ** 32), null);
    @constCast(state.validators.data)[indices[0]].pubkey = try bls.publicKey(&key);
    const root = try merkle.HashTreeRoot(allocator, vote.data);
    vote.signature = bls.sign(&key, domains.computeSigningRoot(root, domains.getDomain(state, helpers.DOMAIN_BEACON_ATTESTER, vote.data.target.epoch)));
    try operations.processAttestation(allocator, &state, vote);
    try std.testing.expectEqual(@as(u8, 0b111), state.current_epoch_participation.data[indices[0]]);
}

test "previous epoch attestation stays timely at and beyond one epoch delay" {
    if (preset.name != .minimal) return;
    const allocator = std.testing.allocator;
    for (0..2) |extra_delay| {
        var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
        defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
        var vote = try decodeValue(fulu.Attestation, allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
        defer ssz.freeDecoded(allocator, fulu.Attestation, vote);
        vote.data.target.epoch = 2;
        vote.data.slot = try helpers.computeStartSlotAtEpoch(vote.data.target.epoch);
        state.slot = vote.data.slot + helpers.SLOTS_PER_EPOCH + extra_delay;
        state.previous_justified_checkpoint = vote.data.source;
        vote.data.target.root = state.block_roots[vote.data.slot % state.block_roots.len];
        vote.data.beacon_block_root = vote.data.target.root;
        @memset(@constCast(vote.aggregation_bits.data), false);
        @constCast(vote.aggregation_bits.data)[0] = true;
        const indices = try operations.getAttestingIndices(allocator, &state, vote);
        defer allocator.free(indices);
        try std.testing.expectEqual(@as(usize, 1), indices.len);
        var key = blst.SecretKey{};
        defer key.deinit();
        key.keygen(&([_]u8{0x52} ** 32), null);
        @constCast(state.validators.data)[indices[0]].pubkey = try bls.publicKey(&key);
        const root = try merkle.HashTreeRoot(allocator, vote.data);
        vote.signature = bls.sign(&key, domains.computeSigningRoot(root, domains.getDomain(state, helpers.DOMAIN_BEACON_ATTESTER, vote.data.target.epoch)));
        try operations.processAttestation(allocator, &state, vote);
        try std.testing.expectEqual(@as(u8, 0b010), state.previous_epoch_participation.data[indices[0]]);

        var invalid = vote;
        invalid.data.slot = state.slot + 1;
        try std.testing.expectError(error.InvalidAttestation, operations.processAttestation(allocator, &state, invalid));
        invalid.data.slot = state.slot;
        invalid.data.target.epoch = helpers.getCurrentEpoch(&state);
        try std.testing.expectError(error.InvalidAttestation, operations.processAttestation(allocator, &state, invalid));
        invalid.data.slot = vote.data.slot;
        try std.testing.expectError(error.InvalidAttestation, operations.processAttestation(allocator, &state, invalid));
    }
}

test "pinned mainnet delayed attestations match reference post states" {
    if (preset.name != .mainnet) return;
    var failure: ?anyerror = null;
    const worker = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 * 1024 }, struct {
        /// Run the mainnet state check on a stack sized for its fixed SSZ arrays.
        fn run(result: *?anyerror) void {
            checkMainnetAttestations() catch |err| {
                std.debug.print("mainnet attestation fixture: {s}\n", .{@errorName(err)});
                result.* = err;
            };
        }
    }.run, .{&failure});
    worker.join();
    if (failure) |err| return err;
}

/// Compare pinned mainnet attestations with their upstream post states.
fn checkMainnetAttestations() !void {
    const allocator = std.testing.allocator;
    const directory = "fixtures/fulu_block_operations_mainnet/correct_attestation_included_at_one_epoch_delay/";
    const vote = try decodeValue(fulu.Attestation, allocator, @embedFile(directory ++ "attestation.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.Attestation, vote);
    for (0..2) |extra_delay| {
        var state = try fixtures.decodeState(allocator, @embedFile(directory ++ "pre.ssz_snappy"));
        defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
        var expected = try fixtures.decodeState(allocator, @embedFile(directory ++ "post.ssz_snappy"));
        defer ssz.freeDecoded(allocator, fulu.BeaconState, expected);
        if (extra_delay == 1) {
            // The next slot stays in the same epoch and pays the same pinned proposer.
            state.slot += 1;
            expected.slot += 1;
            const proposer = state.proposer_lookahead[(state.slot - 1) % helpers.SLOTS_PER_EPOCH];
            state.proposer_lookahead[state.slot % helpers.SLOTS_PER_EPOCH] = proposer;
            expected.proposer_lookahead[expected.slot % helpers.SLOTS_PER_EPOCH] = proposer;
        }
        try std.testing.expectEqual(helpers.computePreviousEpoch(helpers.getCurrentEpoch(&state)), vote.data.target.epoch);
        try std.testing.expectEqual(helpers.SLOTS_PER_EPOCH + extra_delay, state.slot - vote.data.slot);
        const indices = try operations.getAttestingIndices(allocator, &state, vote);
        defer allocator.free(indices);
        try operations.processAttestation(allocator, &state, vote);
        try expectStateRoot(allocator, state, expected);
        for (indices) |index| try std.testing.expectEqual(@as(u8, 0b010), state.previous_epoch_participation.data[index]);
    }
}

test "pinned voluntary exit fixtures enforce eligibility and signature" {
    try runValid(fulu.SignedVoluntaryExit, operations.processVoluntaryExit, "voluntary_exit_valid", "voluntary_exit");
    try runInvalid(fulu.SignedVoluntaryExit, operations.processVoluntaryExit, "voluntary_exit_invalid", "voluntary_exit", error.VerificationFailed);
}

test "pinned BLS change fixtures require the genesis-domain signature" {
    try runValid(fulu.SignedBLSToExecutionChange, operations.processBLSToExecutionChange, "bls_change_valid", "address_change");
    try runInvalid(fulu.SignedBLSToExecutionChange, operations.processBLSToExecutionChange, "bls_change_invalid", "address_change", error.InvalidSignature);
}

test "pinned deposit request fixtures enqueue without consensus signature checks" {
    try runValid(fulu.DepositRequest, operations.processDepositRequest, "deposit_request_valid", "deposit_request");
    try runValid(fulu.DepositRequest, operations.processDepositRequest, "deposit_request_engine_invalid", "deposit_request");
}

test "pinned withdrawal requests queue valid exits and ignore unauthorized requests" {
    try runValid(fulu.WithdrawalRequest, operations.processWithdrawalRequest, "withdrawal_request_valid", "withdrawal_request");
    try runIgnored(fulu.WithdrawalRequest, operations.processWithdrawalRequest, "withdrawal_request_ignored", "withdrawal_request");
}

test "pinned consolidation requests queue valid consolidations and ignore unauthorized requests" {
    try runValid(fulu.ConsolidationRequest, operations.processConsolidationRequest, "consolidation_request_valid", "consolidation_request");
    try runIgnored(fulu.ConsolidationRequest, operations.processConsolidationRequest, "consolidation_request_ignored", "consolidation_request");
}

test "pinned withdrawal fixtures compare payload withdrawals with consensus output" {
    try runValid(fulu.ExecutionPayload, operations.processWithdrawals, "withdrawals_valid", "execution_payload");
    try runInvalid(fulu.ExecutionPayload, operations.processWithdrawals, "withdrawals_invalid", "execution_payload", error.InvalidWithdrawals);
}

test "pinned sync aggregate fixtures verify participation signatures" {
    try runValid(fulu.SyncAggregate, processSyncAggregate, "sync_aggregate_valid", "sync_aggregate");
    try runInvalid(fulu.SyncAggregate, processSyncAggregate, "sync_aggregate_invalid", "sync_aggregate", error.InvalidSignature);
}

test "sync aggregate rejects a committee key removed from the validator registry" {
    const allocator = std.testing.allocator;
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/sync_aggregate_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const aggregate = try decodeValue(fulu.SyncAggregate, allocator, @embedFile("fixtures/fulu_block_operations/sync_aggregate_valid/sync_aggregate.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SyncAggregate, aggregate);
    const key = state.current_sync_committee.pubkeys[0];
    for (@constCast(state.validators.data)) |*validator| {
        if (std.mem.eql(u8, &validator.pubkey, &key)) validator.pubkey = [_]u8{0xff} ** 48;
    }
    try std.testing.expectError(error.InvalidSyncCommittee, block.processSyncAggregate(allocator, &state, aggregate));
}

test "Fulu block operations reject legacy deposit bodies" {
    const allocator = std.testing.allocator;
    const case = fixtures.find("empty_block_transition").?;
    var state = try fixtures.decodeState(allocator, case.pre.?);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const signed_block = try decodeValue(fulu.SignedBeaconBlock, allocator, @embedFile("fixtures/fulu_transition/empty_block_transition/blocks_0.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed_block);
    var invalid_body = signed_block.message.body;
    var one_deposit = [_]fulu.Deposit{undefined};
    invalid_body.deposits.data = &one_deposit;
    try std.testing.expectError(error.UnsupportedLegacyDeposits, operations.processOperations(allocator, &state, invalid_body));
}

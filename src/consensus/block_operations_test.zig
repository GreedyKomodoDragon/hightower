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

fn processSyncAggregate(_: std.mem.Allocator, state: *fulu.BeaconState, aggregate: fulu.SyncAggregate) !void {
    try block.processSyncAggregate(state, aggregate);
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

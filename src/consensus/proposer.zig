// A Fulu proposer builds a beacon block from trusted parent state at one slot.
// The parent is cloned before slot and epoch changes; builder payloads and pool
// operations are borrowed until the signed result is deep-copied. Ordering is:
//
//   slots -> payload/withdrawals -> block prefix -> pool selection
//         -> full block transition -> state root -> proposer signature
// The returned signed block owns its SSZ lists. Caller state and pool change
// only through a separate accepted-block notification.
const std = @import("std");
const blst = @import("blst");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const bls = @import("bls.zig");
const domains = @import("domains.zig");
const helpers = @import("helpers.zig");
const transition = @import("transition.zig");
const epoch = @import("epoch.zig");
const block_processing = @import("block.zig");
const operations = @import("block_operations.zig");
const engine_api = @import("execution_engine.zig");
const pool_api = @import("operation_pool.zig");
const preset = @import("consensus_preset").Config;

/// Propose an owned signed block; free it with ssz.freeDecoded on success.
pub fn propose(
    allocator: std.mem.Allocator,
    parent: *const fulu.BeaconState,
    slot: fulu.Slot,
    key: *blst.SecretKey,
    pool: *const pool_api.Pool,
    engine: engine_api.ExecutionEngine,
    forkchoice: engine_api.ForkchoiceState,
    sync_aggregate: fulu.SyncAggregate,
    fee_recipient: fulu.ExecutionAddress,
    graffiti: fulu.Bytes32,
) !fulu.SignedBeaconBlock {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp = arena.allocator();
    var state = try pool_api.copyValue(temp, fulu.BeaconState, parent.*);
    try transition.processSlots(temp, &state, slot, epoch.processEpoch);
    const proposer_index = state.proposer_lookahead[slot % helpers.SLOTS_PER_EPOCH];
    if (proposer_index >= state.validators.data.len or state.validators.data[proposer_index].slashed) return error.InvalidProposer;
    if (!std.mem.eql(u8, &state.validators.data[proposer_index].pubkey, &(try bls.publicKey(key)))) return error.WrongProposerKey;
    const parent_root = try merkle.HashTreeRoot(temp, state.latest_block_header);
    const current_epoch = helpers.computeEpochAtSlot(slot);
    const randao_domain = domains.getDomain(state, helpers.DOMAIN_RANDAO, current_epoch);
    var epoch_chunk = [_]u8{0} ** 32;
    std.mem.writeInt(u64, epoch_chunk[0..8], current_epoch, .little);
    const reveal = bls.sign(key, domains.computeSigningRoot(epoch_chunk, randao_domain));
    const withdrawals = try operations.expectedWithdrawals(temp, &state);
    const timestamp = std.math.add(u64, state.genesis_time, std.math.mul(u64, slot, preset.SECONDS_PER_SLOT) catch return error.InvalidTimestamp) catch return error.InvalidTimestamp;
    const attrs: engine_api.PayloadAttributes = .{
        .timestamp = timestamp,
        .prev_randao = state.randao_mixes[current_epoch % helpers.EPOCHS_PER_HISTORICAL_VECTOR],
        .fee_recipient = fee_recipient,
        .withdrawals = withdrawals,
        .parent_beacon_block_root = parent_root,
    };
    if (!std.mem.eql(u8, &forkchoice.head_block_hash, &state.latest_execution_payload_header.block_hash)) return error.InvalidExecutionHead;
    const choice = try engine.forkchoiceUpdated(forkchoice, attrs);
    switch (choice.verdict.status) {
        .valid => {},
        .invalid, .invalid_block_hash => return error.InvalidExecutionPayload,
        .syncing, .accepted => return error.ExecutionPayloadUnverified,
    }
    const built = try engine.getPayload(choice.payload_id orelse return error.MissingPayloadId);
    if (!std.mem.eql(u8, &built.payload.fee_recipient, &fee_recipient)) return error.InvalidFeeRecipient;
    if (built.payload.withdrawals.data.len != withdrawals.len) return error.InvalidWithdrawals;
    for (built.payload.withdrawals.data, withdrawals) |actual, expected| if (!std.meta.eql(actual, expected)) return error.InvalidWithdrawals;
    if (built.commitments.len > @as(usize, @intCast(helpers.getBlobParameters(current_epoch, &helpers.BLOB_SCHEDULE).max_blobs_per_block))) return error.TooManyBlobs;
    var message: fulu.BeaconBlock = .{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = parent_root,
        .state_root = [_]u8{0} ** 32,
        .body = .{
            .randao_reveal = reveal,
            .eth1_data = state.eth1_data,
            .graffiti = graffiti,
            .proposer_slashings = .{ .data = &.{} },
            .attester_slashings = .{ .data = &.{} },
            .attestations = .{ .data = &.{} },
            .deposits = .{ .data = &.{} },
            .voluntary_exits = .{ .data = &.{} },
            .sync_aggregate = sync_aggregate,
            .execution_payload = built.payload,
            .bls_to_execution_changes = .{ .data = &.{} },
            .blob_kzg_commitments = .{ .data = built.commitments },
            .execution_requests = built.requests,
        },
    };
    var selection_state = try pool_api.copyValue(temp, fulu.BeaconState, state);
    try block_processing.processBlockPrefix(temp, &selection_state, message, engine);
    const selected = try pool.select(temp, &selection_state);
    message.body.proposer_slashings.data = selected.proposer_slashings;
    message.body.attester_slashings.data = selected.attester_slashings;
    message.body.attestations.data = selected.attestations;
    message.body.voluntary_exits.data = selected.voluntary_exits;
    message.body.bls_to_execution_changes.data = selected.bls_changes;
    try block_processing.processBlock(temp, &state, message, engine);
    message.state_root = try merkle.HashTreeRoot(temp, state);
    const block_root = try merkle.HashTreeRoot(temp, message);
    const domain = domains.getDomain(state, helpers.DOMAIN_BEACON_PROPOSER, current_epoch);
    const signed: fulu.SignedBeaconBlock = .{ .message = message, .signature = bls.sign(key, domains.computeSigningRoot(block_root, domain)) };
    return pool_api.copyValue(allocator, fulu.SignedBeaconBlock, signed);
}

test "wrong proposer key leaves trusted state and pool untouched" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, fixtures.find("empty_block_transition").?.pre.?);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const before = try merkle.HashTreeRoot(allocator, state);
    const fixture_block = try fixtures.decodeBlock(allocator, fixtures.find("empty_block_transition").?.input.?);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, fixture_block);
    var key = blst.SecretKey{};
    const seed = [_]u8{0x42} ** 32;
    key.keygen(&seed, null);
    defer key.deinit();
    var pool = pool_api.Pool.init(allocator);
    defer pool.deinit();
    var test_engine: engine_api.TestEngine = .{ .status = .valid };
    const head = state.latest_execution_payload_header.block_hash;
    const choice: engine_api.ForkchoiceState = .{ .head_block_hash = head, .safe_block_hash = head, .finalized_block_hash = head };
    try std.testing.expectError(error.WrongProposerKey, propose(allocator, &state, fixture_block.message.slot, &key, &pool, test_engine.interface(), choice, fixture_block.message.body.sync_aggregate, [_]u8{0} ** 20, [_]u8{0} ** 32));
    try std.testing.expectEqual(before, try merkle.HashTreeRoot(allocator, state));
    try std.testing.expectEqual(@as(usize, 0), pool.attestations.items.len);
}

/// Exercise production and full validation from one pinned pre-state.
fn checkProducedBlock(compressed: []const u8, cross_epoch: bool) !void {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var parent = try fixtures.decodeState(allocator, compressed);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, parent);
    const template = try fixtures.decodeBlock(allocator, fixtures.find("empty_block_transition").?.input.?);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, template);
    const slot = if (cross_epoch) (parent.slot / helpers.SLOTS_PER_EPOCH + 2) * helpers.SLOTS_PER_EPOCH else parent.slot + 1;
    if (cross_epoch) try std.testing.expect(slot > parent.slot + 1);
    var advanced = try pool_api.copyValue(allocator, fulu.BeaconState, parent);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, advanced);
    try transition.processSlots(allocator, &advanced, slot, epoch.processEpoch);
    const proposer_index = advanced.proposer_lookahead[slot % helpers.SLOTS_PER_EPOCH];
    const old_key = parent.validators.data[proposer_index].pubkey;
    var key = blst.SecretKey{};
    const seed = [_]u8{0x65} ** 32;
    key.keygen(&seed, null);
    defer key.deinit();
    const new_key = try bls.publicKey(&key);
    @constCast(parent.validators.data)[proposer_index].pubkey = new_key;
    for (&parent.current_sync_committee.pubkeys) |*pubkey| if (std.mem.eql(u8, pubkey, &old_key)) {
        pubkey.* = new_key;
    };
    for (&parent.next_sync_committee.pubkeys) |*pubkey| if (std.mem.eql(u8, pubkey, &old_key)) {
        pubkey.* = new_key;
    };
    const before = try merkle.HashTreeRoot(allocator, parent);
    var payload = template.message.body.execution_payload;
    payload.parent_hash = parent.latest_execution_payload_header.block_hash;
    const epoch_number = helpers.computeEpochAtSlot(slot);
    payload.prev_randao = advanced.randao_mixes[epoch_number % helpers.EPOCHS_PER_HISTORICAL_VECTOR];
    payload.timestamp = parent.genesis_time + slot * preset.SECONDS_PER_SLOT;
    payload.withdrawals.data = try operations.expectedWithdrawals(allocator, &advanced);
    defer allocator.free(payload.withdrawals.data);
    payload.fee_recipient = [_]u8{0x31} ** 20;
    var infinity = [_]u8{0} ** 96;
    infinity[0] = 0xc0;
    const sync: fulu.SyncAggregate = .{ .sync_committee_bits = .{ .data = [_]bool{false} ** preset.SYNC_COMMITTEE_SIZE }, .sync_committee_signature = infinity };
    const deposit: fulu.DepositRequest = .{ .pubkey = [_]u8{0x21} ** 48, .withdrawal_credentials = [_]u8{0x22} ** 32, .amount = 32_000_000_000, .signature = [_]u8{0x23} ** 96, .index = 0 };
    const requests: fulu.ExecutionRequests = .{ .deposits = .{ .data = &.{deposit} }, .withdrawals = .{ .data = &.{} }, .consolidations = .{ .data = &.{} } };
    const commitments = [_]fulu.KZGCommitment{[_]u8{0x43} ** 48};
    var test_engine: engine_api.TestEngine = .{ .status = .valid, .built = .{ .payload = payload, .commitments = &commitments, .requests = requests } };
    const head = parent.latest_execution_payload_header.block_hash;
    const choice: engine_api.ForkchoiceState = .{ .head_block_hash = head, .safe_block_hash = head, .finalized_block_hash = head };
    var pool = pool_api.Pool.init(allocator);
    defer pool.deinit();
    const signed = try propose(allocator, &parent, slot, &key, &pool, test_engine.interface(), choice, sync, payload.fee_recipient, [_]u8{0x7a} ** 32);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, signed);
    try std.testing.expectEqual(before, try merkle.HashTreeRoot(allocator, parent));
    try std.testing.expectEqualSlices(fulu.Withdrawal, payload.withdrawals.data, signed.message.body.execution_payload.withdrawals.data);
    try std.testing.expectEqualSlices(fulu.KZGCommitment, &commitments, signed.message.body.blob_kzg_commitments.data);
    try std.testing.expectEqual(@as(usize, 1), signed.message.body.execution_requests.deposits.data.len);
    try std.testing.expectEqual(deposit, signed.message.body.execution_requests.deposits.data[0]);
    try std.testing.expectEqual(payload.timestamp, test_engine.requested_timestamp.?);
    try std.testing.expectEqual(parent.latest_execution_payload_header.block_hash, test_engine.head.?);
    try std.testing.expect(!std.mem.eql(u8, &test_engine.head.?, &signed.message.parent_root));
    try std.testing.expectEqual(payload.fee_recipient, test_engine.requested_fee_recipient.?);
    try std.testing.expectEqual(payload.withdrawals.data.len, test_engine.requested_withdrawal_count.?);
    var replay = try pool_api.copyValue(allocator, fulu.BeaconState, parent);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, replay);
    try block_processing.stateTransition(allocator, &replay, signed, test_engine.interface());
    const again = try propose(allocator, &parent, slot, &key, &pool, test_engine.interface(), choice, sync, payload.fee_recipient, [_]u8{0x7a} ** 32);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, again);
    try std.testing.expectEqual(try merkle.HashTreeRoot(allocator, signed.message), try merkle.HashTreeRoot(allocator, again.message));
    test_engine.status = .invalid;
    try std.testing.expectError(error.InvalidExecutionPayload, propose(allocator, &parent, slot, &key, &pool, test_engine.interface(), choice, sync, payload.fee_recipient, [_]u8{0x7a} ** 32));
    try std.testing.expectEqual(before, try merkle.HashTreeRoot(allocator, parent));
}

test "produced ordinary block round trips through state transition" {
    const fixtures = @import("fixture_runner.zig");
    try checkProducedBlock(fixtures.find("empty_block_transition").?.pre.?, false);
}

test "produced epoch-boundary block round trips through state transition" {
    const fixtures = @import("fixture_runner.zig");
    try checkProducedBlock(fixtures.find("over_epoch_boundary").?.pre.?, true);
}

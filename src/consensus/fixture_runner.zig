const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const snappy = @import("snappy.zig");

pub const Kind = enum { slots, epoch_processing, block };
pub const Expectation = enum { post_state, reject };

pub const FixtureCase = struct {
    name: []const u8,
    suite: []const u8,
    kind: Kind,
    expectation: Expectation,
    pre: ?[]const u8 = null,
    post: ?[]const u8 = null,
    input: ?[]const u8 = null,
    pre_epoch: ?[]const u8 = null,
    post_epoch: ?[]const u8 = null,
    // Some epoch vectors capture the whole ordered process_epoch result;
    // handler vectors use pre/post and compare only the handler-owned fields.
    full_epoch: bool = false,
    metadata: ?[]const u8 = null,
};

pub const selected = [_]FixtureCase{
    .{ .name = "slots_1", .suite = "sanity/slots", .kind = .slots, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/slots_1/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/slots_1/post.ssz_snappy"), .metadata = @embedFile("fixtures/fulu_transition/slots_1/slots.yaml") },
    .{ .name = "over_epoch_boundary", .suite = "sanity/slots", .kind = .slots, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/over_epoch_boundary/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/over_epoch_boundary/post.ssz_snappy"), .metadata = @embedFile("fixtures/fulu_transition/over_epoch_boundary/slots.yaml") },
    .{ .name = "double_empty_epoch", .suite = "sanity/slots", .kind = .slots, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/double_empty_epoch/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/double_empty_epoch/post.ssz_snappy"), .metadata = @embedFile("fixtures/fulu_transition/double_empty_epoch/slots.yaml") },
    .{ .name = "proposer_lookahead_in_state_matches_computed_lookahead", .suite = "epoch_processing/proposer_lookahead", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/proposer_lookahead_in_state_matches_computed_lookahead/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/proposer_lookahead_in_state_matches_computed_lookahead/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/proposer_lookahead_in_state_matches_computed_lookahead/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/proposer_lookahead_in_state_matches_computed_lookahead/post_epoch.ssz_snappy") },
    .{ .name = "proposer_lookahead_does_not_contain_exited_validators", .suite = "epoch_processing/proposer_lookahead", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/proposer_lookahead_does_not_contain_exited_validators/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/proposer_lookahead_does_not_contain_exited_validators/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/proposer_lookahead_does_not_contain_exited_validators/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/proposer_lookahead_does_not_contain_exited_validators/post_epoch.ssz_snappy") },
    .{ .name = "empty_block_transition", .suite = "sanity/blocks", .kind = .block, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/empty_block_transition/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/empty_block_transition/post.ssz_snappy"), .input = @embedFile("fixtures/fulu_transition/empty_block_transition/blocks_0.ssz_snappy"), .metadata = @embedFile("fixtures/fulu_transition/empty_block_transition/meta.yaml") },
    .{ .name = "invalid_incorrect_state_root", .suite = "sanity/blocks", .kind = .block, .expectation = .reject, .pre = @embedFile("fixtures/fulu_transition/invalid_incorrect_state_root/pre.ssz_snappy"), .input = @embedFile("fixtures/fulu_transition/invalid_incorrect_state_root/blocks_0.ssz_snappy"), .metadata = @embedFile("fixtures/fulu_transition/invalid_incorrect_state_root/meta.yaml") },
    .{ .name = "basic_pending_consolidation", .suite = "epoch_processing/pending_consolidations", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/post_epoch.ssz_snappy") },
    .{ .name = "process_pending_deposits_multiple_pending_deposits_below_churn", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/post_epoch.ssz_snappy") },
    .{ .name = "process_pending_deposits_not_finalized", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/post_epoch.ssz_snappy") },
    .{ .name = "consolidation_not_yet_withdrawable_validator", .suite = "epoch_processing/pending_consolidations", .kind = .epoch_processing, .expectation = .post_state, .pre_epoch = @embedFile("fixtures/fulu_transition/consolidation_not_yet_withdrawable_validator/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/consolidation_not_yet_withdrawable_validator/post_epoch.ssz_snappy") },
    .{ .name = "skip_consolidation_when_source_slashed", .suite = "epoch_processing/pending_consolidations", .kind = .epoch_processing, .expectation = .post_state, .pre_epoch = @embedFile("fixtures/fulu_transition/skip_consolidation_when_source_slashed/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/skip_consolidation_when_source_slashed/post_epoch.ssz_snappy") },
    .{ .name = "process_pending_deposits_multiple_pending_deposits_above_churn", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_above_churn/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_above_churn/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_above_churn/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_above_churn/post_epoch.ssz_snappy") },
    .{ .name = "process_pending_deposits_multiple_skipped_deposits_exiting_validators", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_skipped_deposits_exiting_validators/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_skipped_deposits_exiting_validators/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_skipped_deposits_exiting_validators/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_skipped_deposits_exiting_validators/post_epoch.ssz_snappy") },
    .{ .name = "apply_pending_deposit_incorrect_sig_new_deposit", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/apply_pending_deposit_incorrect_sig_new_deposit/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/apply_pending_deposit_incorrect_sig_new_deposit/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/apply_pending_deposit_incorrect_sig_new_deposit/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/apply_pending_deposit_incorrect_sig_new_deposit/post_epoch.ssz_snappy") },
    .{ .name = "apply_pending_deposit_compounding_withdrawal_credentials_max", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/apply_pending_deposit_compounding_withdrawal_credentials_max/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/apply_pending_deposit_compounding_withdrawal_credentials_max/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/apply_pending_deposit_compounding_withdrawal_credentials_max/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/apply_pending_deposit_compounding_withdrawal_credentials_max/post_epoch.ssz_snappy") },
    .{ .name = "process_pending_deposits_mixture_of_skipped_and_above_churn", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/process_pending_deposits_mixture_of_skipped_and_above_churn/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/process_pending_deposits_mixture_of_skipped_and_above_churn/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_mixture_of_skipped_and_above_churn/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_mixture_of_skipped_and_above_churn/post_epoch.ssz_snappy") },
    .{ .name = "all_consolidation_cases_together", .suite = "epoch_processing/pending_consolidations", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/all_consolidation_cases_together/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/all_consolidation_cases_together/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/all_consolidation_cases_together/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/all_consolidation_cases_together/post_epoch.ssz_snappy") },
    .{ .name = "pending_consolidation_with_pending_deposit", .suite = "epoch_processing/pending_consolidations", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/pending_consolidation_with_pending_deposit/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/pending_consolidation_with_pending_deposit/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/pending_consolidation_with_pending_deposit/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/pending_consolidation_with_pending_deposit/post_epoch.ssz_snappy") },
    .{ .name = "effective_balance_hysteresis", .suite = "epoch_processing/effective_balance_updates", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/effective_balance_hysteresis/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/effective_balance_hysteresis/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/effective_balance_hysteresis/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/effective_balance_hysteresis/post_epoch.ssz_snappy") },
    .{ .name = "eth1_vote_reset", .suite = "epoch_processing/eth1_data_reset", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/eth1_vote_reset/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/eth1_vote_reset/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/eth1_vote_reset/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/eth1_vote_reset/post_epoch.ssz_snappy") },
    .{ .name = "historical_summaries_accumulator", .suite = "epoch_processing/historical_summaries_update", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/historical_summaries_accumulator/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/historical_summaries_accumulator/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/historical_summaries_accumulator/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/historical_summaries_accumulator/post_epoch.ssz_snappy") },
    .{ .name = "random_inactivity_scores_empty_participation", .suite = "epoch_processing/inactivity_updates", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/random_inactivity_scores_empty_participation/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/random_inactivity_scores_empty_participation/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/random_inactivity_scores_empty_participation/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/random_inactivity_scores_empty_participation/post_epoch.ssz_snappy") },
    .{ .name = "12_ok_support", .suite = "epoch_processing/justification_and_finalization", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/12_ok_support/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/12_ok_support/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/12_ok_support/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/12_ok_support/post_epoch.ssz_snappy") },
    .{ .name = "slightly_larger_random", .suite = "epoch_processing/participation_flag_updates", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/slightly_larger_random/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/slightly_larger_random/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/slightly_larger_random/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/slightly_larger_random/post_epoch.ssz_snappy") },
    .{ .name = "activation_churn_limit__less_than_activation_limit", .suite = "epoch_processing/registry_updates", .kind = .epoch_processing, .expectation = .post_state, .full_epoch = true, .pre = @embedFile("fixtures/fulu_transition/activation_churn_limit__less_than_activation_limit/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/activation_churn_limit__less_than_activation_limit/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/activation_churn_limit__less_than_activation_limit/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/activation_churn_limit__less_than_activation_limit/post_epoch.ssz_snappy") },
    .{ .name = "genesis_epoch_no_attestations_no_penalties", .suite = "epoch_processing/rewards_and_penalties", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/genesis_epoch_no_attestations_no_penalties/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/genesis_epoch_no_attestations_no_penalties/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/genesis_epoch_no_attestations_no_penalties/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/genesis_epoch_no_attestations_no_penalties/post_epoch.ssz_snappy") },
    .{ .name = "low_penalty", .suite = "epoch_processing/slashings", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/low_penalty/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/low_penalty/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/low_penalty/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/low_penalty/post_epoch.ssz_snappy") },
    .{ .name = "flush_slashings", .suite = "epoch_processing/slashings_reset", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/flush_slashings/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/flush_slashings/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/flush_slashings/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/flush_slashings/post_epoch.ssz_snappy") },
    .{ .name = "updated_randao_mixes", .suite = "epoch_processing/randao_mixes_reset", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/updated_randao_mixes/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/updated_randao_mixes/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/updated_randao_mixes/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/updated_randao_mixes/post_epoch.ssz_snappy") },
    .{ .name = "sync_committees_progress_not_genesis", .suite = "epoch_processing/sync_committee_updates", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/sync_committees_progress_not_genesis/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/sync_committees_progress_not_genesis/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/sync_committees_progress_not_genesis/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/sync_committees_progress_not_genesis/post_epoch.ssz_snappy") },
};

pub fn find(name: []const u8) ?FixtureCase {
    for (selected) |case| if (std.mem.eql(u8, case.name, name)) return case;
    return null;
}

pub fn decode(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    return snappy.decompress(allocator, compressed);
}

pub fn validateCase(case: FixtureCase) !void {
    const has_pre = if (case.kind == .epoch_processing) case.pre_epoch != null else case.pre != null;
    const has_post = if (case.kind == .epoch_processing) case.post_epoch != null else case.post != null;
    if (!has_pre or case.expectation == .post_state and !has_post or
        case.expectation == .reject and case.post != null or
        case.kind == .block and (case.input == null or case.metadata == null) or
        case.kind == .slots and case.metadata == null or
        case.kind == .epoch_processing and (case.pre_epoch == null or case.post_epoch == null))
        return error.InvalidFixture;
}

pub fn decodeState(allocator: std.mem.Allocator, compressed: []const u8) !fulu.BeaconState {
    const bytes = try decode(allocator, compressed);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, fulu.BeaconState, &reader);
}

pub fn decodeBlock(allocator: std.mem.Allocator, compressed: []const u8) !fulu.SignedBeaconBlock {
    const bytes = try decode(allocator, compressed);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, fulu.SignedBeaconBlock, &reader);
}

pub fn parseSlotCount(metadata: []const u8) !fulu.Slot {
    const value = std.mem.trim(u8, metadata, " \t\r\n.");
    return std.fmt.parseInt(fulu.Slot, value, 10) catch error.InvalidMetadata;
}

pub fn parseBlockCount(metadata: []const u8) !usize {
    const key = "blocks_count:";
    const key_index = std.mem.indexOf(u8, metadata, key) orelse return error.InvalidMetadata;
    const start = key_index + key.len;
    var end = start;
    while (end < metadata.len and std.ascii.isDigit(metadata[end]) == false) : (end += 1) {}
    const value_start = end;
    while (end < metadata.len and std.ascii.isDigit(metadata[end])) : (end += 1) {}
    if (value_start == end) return error.InvalidMetadata;
    return std.fmt.parseInt(usize, metadata[value_start..end], 10) catch error.InvalidMetadata;
}

test "selected fixture catalog preserves expected valid and invalid outcomes" {
    try std.testing.expectEqual(@as(usize, 31), selected.len);
    for (selected) |case| {
        try validateCase(case);
        if (case.kind == .block) try std.testing.expect(case.input != null);
    }
}

test "fixture validation rejects missing inputs and malformed compressed state" {
    const invalid = FixtureCase{
        .name = "missing_post",
        .suite = "sanity/slots",
        .kind = .slots,
        .expectation = .post_state,
        .pre = "present",
    };
    try std.testing.expectError(error.InvalidFixture, validateCase(invalid));
    try std.testing.expectError(error.MalformedBlock, decode(std.testing.allocator, "bad"));
}

test "selected slot metadata and block metadata parse explicitly" {
    try std.testing.expectEqual(@as(u64, 1), try parseSlotCount(selected[0].metadata.?));
    try std.testing.expectEqual(@as(u64, 8), try parseSlotCount(selected[1].metadata.?));
    try std.testing.expectEqual(@as(usize, 1), try parseBlockCount(find("empty_block_transition").?.metadata.?));
    try std.testing.expectError(error.InvalidMetadata, parseBlockCount("{}"));
}

test "all selected fixture SSZ payloads decompress and decode" {
    const allocator = std.testing.allocator;
    for (selected) |case| {
        try validateCase(case);
        if (case.pre) |input| {
            const pre = try decodeState(allocator, input);
            ssz.freeDecoded(allocator, fulu.BeaconState, pre);
        }
        if (case.post) |post| {
            const state = try decodeState(allocator, post);
            ssz.freeDecoded(allocator, fulu.BeaconState, state);
        }
        if (case.pre_epoch) |input| {
            const epoch_state = try decodeState(allocator, input);
            ssz.freeDecoded(allocator, fulu.BeaconState, epoch_state);
        }
        if (case.post_epoch) |input| {
            const epoch_state = try decodeState(allocator, input);
            ssz.freeDecoded(allocator, fulu.BeaconState, epoch_state);
        }
        if (case.input) |input| {
            const block = try decodeBlock(allocator, input);
            ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
        }
    }
}

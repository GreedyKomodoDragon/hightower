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
    pre: ?[]const u8,
    post: ?[]const u8 = null,
    input: ?[]const u8 = null,
    pre_epoch: ?[]const u8 = null,
    post_epoch: ?[]const u8 = null,
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
    .{ .name = "basic_pending_consolidation", .suite = "epoch_processing/pending_consolidations", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/basic_pending_consolidation/post_epoch.ssz_snappy") },
    .{ .name = "process_pending_deposits_multiple_pending_deposits_below_churn", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_multiple_pending_deposits_below_churn/post_epoch.ssz_snappy") },
    .{ .name = "process_pending_deposits_not_finalized", .suite = "epoch_processing/pending_deposits", .kind = .epoch_processing, .expectation = .post_state, .pre = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/pre.ssz_snappy"), .post = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/post.ssz_snappy"), .pre_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/pre_epoch.ssz_snappy"), .post_epoch = @embedFile("fixtures/fulu_transition/process_pending_deposits_not_finalized/post_epoch.ssz_snappy") },
};

pub fn find(name: []const u8) ?FixtureCase {
    for (selected) |case| if (std.mem.eql(u8, case.name, name)) return case;
    return null;
}

pub fn decode(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    return snappy.decompress(allocator, compressed);
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
    try std.testing.expectEqual(@as(usize, 10), selected.len);
    for (selected) |case| {
        try std.testing.expect(case.pre != null);
        if (case.expectation == .post_state) try std.testing.expect(case.post != null) else try std.testing.expect(case.post == null);
        if (case.kind == .block) try std.testing.expect(case.input != null);
    }
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
        const pre = try decodeState(allocator, case.pre.?);
        ssz.freeDecoded(allocator, fulu.BeaconState, pre);
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

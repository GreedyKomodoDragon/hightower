const std = @import("std");
const fulu = @import("fulu");
const preset = @import("consensus_preset");

test "Fulu block schema exposes its top-level fields" {
    try std.testing.expect(@hasField(fulu.BeaconBlock, "slot"));
    try std.testing.expect(@hasField(fulu.BeaconBlock, "proposer_index"));
    try std.testing.expect(@hasField(fulu.BeaconBlock, "body"));
    try std.testing.expect(@hasField(fulu.BeaconBlockBody, "execution_payload"));
    try std.testing.expect(@hasField(fulu.BeaconBlockBody, "execution_requests"));
    try std.testing.expect(@hasField(fulu.SignedBeaconBlock, "signature"));
}

test "selected preset configures fixed Fulu state dimensions" {
    const Config = preset.Config;
    try std.testing.expectEqual(@as(usize, @intCast(Config.SLOTS_PER_HISTORICAL_ROOT)), @typeInfo(@FieldType(fulu.BeaconState, "block_roots")).array.len);
    try std.testing.expectEqual(@as(usize, @intCast(Config.EPOCHS_PER_HISTORICAL_VECTOR)), @typeInfo(@FieldType(fulu.BeaconState, "randao_mixes")).array.len);
    try std.testing.expectEqual(@as(usize, @intCast(2 * Config.SLOTS_PER_EPOCH)), @typeInfo(@FieldType(fulu.BeaconState, "proposer_lookahead")).array.len);
    try std.testing.expectEqual(Config.SYNC_COMMITTEE_SIZE, @typeInfo(@FieldType(fulu.SyncCommittee, "pubkeys")).array.len);
}

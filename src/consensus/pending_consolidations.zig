// A consolidation moves stake from an exiting source validator to a target
// validator within BeaconState. The request first waits in a FIFO queue;
// transfer is allowed only when the source's withdrawable epoch has arrived.
//
//   slashed source -> discard request
//   ready source   -> move min(balance, effective balance) to target
//   first unready  -> stop; keep it and all later requests queued
//
// Processing removes the consumed prefix, leaving deferred entries for a later
// epoch. The source validator stays in the registry; this step changes balances.
const std = @import("std");
const fulu = @import("fulu");
const helpers = @import("helpers.zig");
const merkle = @import("merkle");

pub fn processPendingConsolidations(allocator: std.mem.Allocator, state: *fulu.BeaconState) !void {
    const next_epoch = helpers.computeEpochAtSlot(state.slot) + 1;
    const pending = state.pending_consolidations.data;
    var processed: usize = 0;
    for (pending) |entry| {
        if (entry.source_index >= state.validators.data.len or entry.target_index >= state.validators.data.len or entry.source_index == entry.target_index)
            return error.InvalidConsolidationIndex;
        const source = state.validators.data[entry.source_index];
        if (source.slashed) {
            processed += 1;
            continue;
        }
        if (source.withdrawable_epoch > next_epoch) break;
        const amount = @min(state.balances.data[entry.source_index], source.effective_balance);
        @constCast(state.balances.data)[entry.target_index] =
            std.math.add(u64, state.balances.data[entry.target_index], amount) catch return error.BalanceOverflow;
        @constCast(state.balances.data)[entry.source_index] -= amount;
        processed += 1;
    }
    if (processed == 0) return;
    const remaining = try allocator.dupe(fulu.PendingConsolidation, pending[processed..]);
    allocator.free(@constCast(pending));
    state.pending_consolidations.data = remaining;
}

test "basic Fulu pending consolidation matches the pinned epoch result" {
    const fixtures = @import("fixture_runner.zig");
    const allocator = std.testing.allocator;
    const case = fixtures.find("basic_pending_consolidation").?;
    var state = try fixtures.decodeState(allocator, case.pre_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, state);
    const expected = try fixtures.decodeState(allocator, case.post_epoch.?);
    defer @import("ssz").freeDecoded(allocator, fulu.BeaconState, expected);
    try processPendingConsolidations(allocator, &state);
    // post_epoch also includes effective-balance updates and proposer lookahead.
    const actual_balances = try merkle.HashTreeRoot(allocator, state.balances);
    const expected_balances = try merkle.HashTreeRoot(allocator, expected.balances);
    try std.testing.expectEqualSlices(u8, &expected_balances, &actual_balances);
    const actual_pending = try merkle.HashTreeRoot(allocator, state.pending_consolidations);
    const expected_pending = try merkle.HashTreeRoot(allocator, expected.pending_consolidations);
    try std.testing.expectEqualSlices(u8, &expected_pending, &actual_pending);
}

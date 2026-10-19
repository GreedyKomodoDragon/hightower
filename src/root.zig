//! Public Hightower module. `fulu` exposes the SSZ shapes of beacon states and
//! blocks; `consensus` exposes the rules that advance those states through
//! slots, epochs, and signed blocks. Block transitions require an injected
//! execution engine because transaction validity is decided outside beacon
//! consensus. Both exports use the same Fulu types so callers can pass a
//! decoded `fulu.BeaconState` directly to the transition functions.
const std = @import("std");

pub const fulu = @import("fulu");
pub const consensus = @import("consensus/root.zig");

test "Fulu shared types are exported" {
    _ = @sizeOf(fulu.SyncAggregate);
    const run: *const fn (std.mem.Allocator, *fulu.BeaconState, fulu.SignedBeaconBlock, consensus.ExecutionEngine) anyerror!void = consensus.stateTransition;
    _ = run;
}

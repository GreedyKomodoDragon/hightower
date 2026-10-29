//! Public Hightower module. `fulu` exposes the SSZ shapes of beacon states and
//! blocks; `consensus` exposes the rules that advance those states through
//! slots, epochs, and signed blocks. Block transitions require an injected
//! execution engine because transaction validity is decided outside beacon
//! consensus. Both exports use the same Fulu types so callers can pass a
//! decoded `fulu.BeaconState` directly to the transition functions. `api`
//! provides the read-only HTTP layer over a stable consensus store.
const std = @import("std");

pub const fulu = @import("fulu");
pub const preset = @import("consensus_preset");
pub const execution = @import("execution");
pub const consensus = @import("consensus");
pub const api = @import("api");
pub const engine_client = @import("engine_client");
pub const engine_server = @import("engine_server");
pub const storage = @import("storage");

test "Fulu shared types are exported" {
    _ = @sizeOf(fulu.SyncAggregate);
    const run: *const fn (std.mem.Allocator, *fulu.BeaconState, fulu.SignedBeaconBlock, consensus.ExecutionEngine) anyerror!void = consensus.stateTransition;
    _ = run;
}

// Public entry points for Fulu BeaconState transitions. Slot processing records
// roots as beacon time advances; epoch processing updates validator accounting
// at boundaries; stateTransition applies a signed block and checks its claimed
// post-state root. The caller supplies an execution engine to judge the block's
// execution payload, and discards the mutable state if a transition fails.
pub const stateTransition = @import("block.zig").stateTransition;
pub const processSlots = @import("transition.zig").processSlots;
pub const processSlot = @import("transition.zig").processSlot;
pub const processEpoch = @import("epoch.zig").processEpoch;
pub const ExecutionEngine = @import("execution_engine.zig").ExecutionEngine;
pub const NewPayloadRequest = @import("execution_engine.zig").NewPayloadRequest;
pub const PayloadStatus = @import("execution_engine.zig").PayloadStatus;

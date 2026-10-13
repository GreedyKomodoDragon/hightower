// A state transition deterministically turns a pre-state plus slots, epoch
// work, or a signed block into a post-state. The pinned Fulu fixtures check
// resulting SSZ state roots and expected rejection when a block claims the
// wrong post-state root.
// Zig discovers tests through imports, so this root brings the slot, epoch,
// block, and execution-engine checks into one build step.
test {
    _ = @import("helpers.zig");
    _ = @import("domains.zig");
    _ = @import("bls.zig");
    _ = @import("snappy.zig");
    _ = @import("fixture_runner.zig");
    _ = @import("transition.zig");
    _ = @import("lookahead.zig");
    _ = @import("execution_engine.zig");
    _ = @import("block.zig");
    _ = @import("pending_consolidations.zig");
    _ = @import("pending_deposits.zig");
}

// A state transition deterministically turns a pre-state plus slot or epoch
// input into a post-state. The pinned Fulu fixtures provide those inputs and
// expected SSZ state roots. Zig discovers tests through imports, so this root
// imports each consensus module to run their focused checks in one build step.
test {
    _ = @import("helpers.zig");
    _ = @import("domains.zig");
    _ = @import("bls.zig");
    _ = @import("snappy.zig");
    _ = @import("fixture_runner.zig");
    _ = @import("transition.zig");
    _ = @import("epoch.zig");
    _ = @import("lookahead.zig");
    _ = @import("pending_consolidations.zig");
    _ = @import("pending_deposits.zig");
}

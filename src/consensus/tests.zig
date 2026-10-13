// A state transition is the deterministic BeaconState change caused by slots
// and epochs. This root runs the modules' focused tests and pinned Fulu fixtures
// together through the same build step.
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

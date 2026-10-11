const std = @import("std");
const fulu = @import("fulu");

test "Fulu block schema exposes its top-level fields" {
    try std.testing.expect(@hasField(fulu.BeaconBlock, "slot"));
    try std.testing.expect(@hasField(fulu.BeaconBlock, "proposer_index"));
    try std.testing.expect(@hasField(fulu.BeaconBlock, "body"));
    try std.testing.expect(@hasField(fulu.BeaconBlockBody, "execution_payload"));
    try std.testing.expect(@hasField(fulu.BeaconBlockBody, "execution_requests"));
    try std.testing.expect(@hasField(fulu.SignedBeaconBlock, "signature"));
}

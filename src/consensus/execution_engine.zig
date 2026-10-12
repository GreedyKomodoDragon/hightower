const std = @import("std");
const fulu = @import("fulu");

pub const PayloadStatus = enum { valid, invalid, syncing };
pub const NewPayloadRequest = struct {
    payload: *const fulu.ExecutionPayload,
    versioned_hashes: []const fulu.Root,
    parent_beacon_block_root: fulu.Root,
    execution_requests: *const fulu.ExecutionRequests,
};

pub const ExecutionEngine = struct {
    context: *anyopaque,
    verify_and_notify_new_payload: *const fn (*anyopaque, NewPayloadRequest) anyerror!PayloadStatus,

    pub fn verify(self: ExecutionEngine, request: NewPayloadRequest) anyerror!PayloadStatus {
        return self.verify_and_notify_new_payload(self.context, request);
    }
};

pub const TestEngine = struct {
    status: PayloadStatus,
    unavailable: bool = false,

    pub fn interface(self: *TestEngine) ExecutionEngine {
        return .{ .context = self, .verify_and_notify_new_payload = verify };
    }

    fn verify(context: *anyopaque, _: NewPayloadRequest) anyerror!PayloadStatus {
        const self: *TestEngine = @ptrCast(@alignCast(context));
        if (self.unavailable) return error.Unavailable;
        return self.status;
    }
};

test "execution engine boundary preserves status values" {
    var test_engine: TestEngine = .{ .status = .valid };
    const request = NewPayloadRequest{
        .payload = undefined,
        .versioned_hashes = &.{},
        .parent_beacon_block_root = [_]u8{0} ** 32,
        .execution_requests = undefined,
    };
    try std.testing.expectEqual(PayloadStatus.valid, try test_engine.interface().verify(request));
    test_engine.status = .invalid;
    try std.testing.expectEqual(PayloadStatus.invalid, try test_engine.interface().verify(request));
    test_engine.status = .syncing;
    try std.testing.expectEqual(PayloadStatus.syncing, try test_engine.interface().verify(request));
    test_engine.unavailable = true;
    try std.testing.expectError(error.Unavailable, test_engine.interface().verify(request));
}

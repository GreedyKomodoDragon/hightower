// Beacon consensus checks block structure and signatures, while an execution
// engine checks the transaction payload under execution-layer rules. This
// boundary passes the payload, blob versioned hashes, parent beacon root, and
// Fulu execution requests without tying state transition to a network client.
//
//   Beacon block -> NewPayloadRequest -> engine verdict
//                                      valid / invalid / syncing / unavailable
//
// Only valid permits the transition to continue. Syncing means the engine
// cannot verify yet; unavailable is an error. TestEngine supplies deterministic
// responses for fixtures and is not a production accept-all engine.
const std = @import("std");
const fulu = @import("fulu");

pub const PayloadStatus = enum { valid, invalid, syncing };
pub const NewPayloadRequest = struct {
    payload: *const fulu.ExecutionPayload,
    versioned_hashes: []const fulu.Root,
    parent_beacon_block_root: fulu.Root,
    execution_requests: *const fulu.ExecutionRequests,
};

/// Attributes sent to the execution builder after choosing the parent head.
pub const PayloadAttributes = struct {
    timestamp: u64,
    prev_randao: fulu.Bytes32,
    fee_recipient: fulu.ExecutionAddress,
    withdrawals: []const fulu.Withdrawal,
    parent_beacon_block_root: fulu.Root,
};

/// Borrowed builder output; the proposer copies it before returning a block.
pub const BuiltPayload = struct {
    payload: fulu.ExecutionPayload,
    commitments: []const fulu.KZGCommitment,
    requests: fulu.ExecutionRequests,
};

pub const ExecutionEngine = struct {
    context: *anyopaque,
    verify_and_notify_new_payload: *const fn (*anyopaque, NewPayloadRequest) anyerror!PayloadStatus,
    forkchoice_updated: *const fn (*anyopaque, fulu.Root, PayloadAttributes) anyerror!u64 = unsupportedForkchoiceUpdated,
    get_payload: *const fn (*anyopaque, u64) anyerror!BuiltPayload = unsupportedGetPayload,

    pub fn verify(self: ExecutionEngine, request: NewPayloadRequest) anyerror!PayloadStatus {
        return self.verify_and_notify_new_payload(self.context, request);
    }

    /// Start a payload build for the selected head and return its identifier.
    pub fn forkchoiceUpdated(self: ExecutionEngine, head: fulu.Root, attributes: PayloadAttributes) anyerror!u64 {
        return self.forkchoice_updated(self.context, head, attributes);
    }

    /// Retrieve the builder's borrowed payload for a prior build identifier.
    pub fn getPayload(self: ExecutionEngine, id: u64) anyerror!BuiltPayload {
        return self.get_payload(self.context, id);
    }
};

/// Keep existing verifier-only engine implementations source compatible.
fn unsupportedForkchoiceUpdated(_: *anyopaque, _: fulu.Root, _: PayloadAttributes) anyerror!u64 {
    return error.PayloadBuildingUnsupported;
}
/// Report that a verifier-only engine cannot supply a built payload.
fn unsupportedGetPayload(_: *anyopaque, _: u64) anyerror!BuiltPayload {
    return error.PayloadBuildingUnsupported;
}

pub const TestEngine = struct {
    status: PayloadStatus,
    unavailable: bool = false,
    built: ?BuiltPayload = null,
    requested_timestamp: ?u64 = null,
    requested_fee_recipient: ?fulu.ExecutionAddress = null,
    requested_withdrawal_count: ?usize = null,
    head: ?fulu.Root = null,

    /// Expose the deterministic test callbacks through the engine boundary.
    pub fn interface(self: *TestEngine) ExecutionEngine {
        return .{ .context = self, .verify_and_notify_new_payload = verify, .forkchoice_updated = forkchoiceUpdated, .get_payload = getPayload };
    }

    /// Return the configured payload validity result.
    fn verify(context: *anyopaque, _: NewPayloadRequest) anyerror!PayloadStatus {
        const self: *TestEngine = @ptrCast(@alignCast(context));
        if (self.unavailable) return error.Unavailable;
        return self.status;
    }

    /// Record the requested head and attributes for deterministic tests.
    fn forkchoiceUpdated(context: *anyopaque, head: fulu.Root, attributes: PayloadAttributes) anyerror!u64 {
        const self: *TestEngine = @ptrCast(@alignCast(context));
        if (self.unavailable) return error.Unavailable;
        self.head = head;
        self.requested_timestamp = attributes.timestamp;
        self.requested_fee_recipient = attributes.fee_recipient;
        self.requested_withdrawal_count = attributes.withdrawals.len;
        return 1;
    }

    /// Return configured deterministic builder output.
    fn getPayload(context: *anyopaque, id: u64) anyerror!BuiltPayload {
        const self: *TestEngine = @ptrCast(@alignCast(context));
        if (self.unavailable) return error.Unavailable;
        if (id != 1) return error.UnknownPayload;
        return self.built orelse error.NoPayload;
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

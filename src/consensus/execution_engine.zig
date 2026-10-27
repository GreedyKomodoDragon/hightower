// Beacon consensus checks block structure and signatures, while an execution
// engine checks the transaction payload under execution-layer rules. This
// boundary passes the payload, blob versioned hashes, parent beacon root, and
// Fulu execution requests without tying state transition to a network client.
//
//   Beacon block -> NewPayloadRequest -> engine verdict
//                                      valid / invalid / syncing / accepted
//
// Only valid permits the transition to continue. Syncing means the engine
// cannot verify yet; unavailable is an error. TestEngine supplies deterministic
// responses for fixtures and is not a production accept-all engine.
const std = @import("std");
const fulu = @import("fulu");

/// Engine verdicts are protocol results; transport failures remain errors.
pub const PayloadStatus = enum { valid, invalid, syncing, accepted, invalid_block_hash };
/// The last valid ancestor lets fork choice invalidate a rejected branch.
pub const PayloadVerdict = struct {
    status: PayloadStatus,
    latest_valid_hash: ?fulu.Root = null,
};
/// Execution hashes chosen by beacon fork choice, in head, safe, finalized order.
pub const ForkchoiceState = struct {
    head_block_hash: fulu.Root,
    safe_block_hash: fulu.Root,
    finalized_block_hash: fulu.Root,
};
/// A build identifier exists only when the engine accepted payload attributes.
pub const ForkchoiceResult = struct {
    verdict: PayloadVerdict,
    payload_id: ?u64 = null,
};
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
    verify_and_notify_new_payload: *const fn (*anyopaque, NewPayloadRequest) anyerror!PayloadVerdict,
    forkchoice_updated: *const fn (*anyopaque, ForkchoiceState, ?PayloadAttributes) anyerror!ForkchoiceResult = unsupportedForkchoiceUpdated,
    get_payload: *const fn (*anyopaque, u64) anyerror!BuiltPayload = unsupportedGetPayload,

    pub fn verify(self: ExecutionEngine, request: NewPayloadRequest) anyerror!PayloadVerdict {
        return self.verify_and_notify_new_payload(self.context, request);
    }

    /// Start a payload build for the parent execution block hash and return its identifier.
    pub fn forkchoiceUpdated(self: ExecutionEngine, state: ForkchoiceState, attributes: ?PayloadAttributes) anyerror!ForkchoiceResult {
        return self.forkchoice_updated(self.context, state, attributes);
    }

    /// Retrieve the builder's borrowed payload for a prior build identifier.
    pub fn getPayload(self: ExecutionEngine, id: u64) anyerror!BuiltPayload {
        return self.get_payload(self.context, id);
    }
};

/// Keep existing verifier-only engine implementations source compatible.
fn unsupportedForkchoiceUpdated(_: *anyopaque, _: ForkchoiceState, _: ?PayloadAttributes) anyerror!ForkchoiceResult {
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
    safe: ?fulu.Root = null,
    finalized: ?fulu.Root = null,
    latest_valid_hash: ?fulu.Root = null,

    /// Expose the deterministic test callbacks through the engine boundary.
    pub fn interface(self: *TestEngine) ExecutionEngine {
        return .{ .context = self, .verify_and_notify_new_payload = verify, .forkchoice_updated = forkchoiceUpdated, .get_payload = getPayload };
    }

    /// Return the configured payload validity result.
    fn verify(context: *anyopaque, _: NewPayloadRequest) anyerror!PayloadVerdict {
        const self: *TestEngine = @ptrCast(@alignCast(context));
        if (self.unavailable) return error.Unavailable;
        return .{ .status = self.status, .latest_valid_hash = self.latest_valid_hash };
    }

    /// Record the requested head and attributes for deterministic tests.
    fn forkchoiceUpdated(context: *anyopaque, state: ForkchoiceState, attributes: ?PayloadAttributes) anyerror!ForkchoiceResult {
        const self: *TestEngine = @ptrCast(@alignCast(context));
        if (self.unavailable) return error.Unavailable;
        self.head = state.head_block_hash;
        self.safe = state.safe_block_hash;
        self.finalized = state.finalized_block_hash;
        if (attributes) |value| {
            self.requested_timestamp = value.timestamp;
            self.requested_fee_recipient = value.fee_recipient;
            self.requested_withdrawal_count = value.withdrawals.len;
        }
        return .{ .verdict = .{ .status = self.status, .latest_valid_hash = self.latest_valid_hash }, .payload_id = if (self.status == .valid and attributes != null) 1 else null };
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
    try std.testing.expectEqual(PayloadStatus.valid, (try test_engine.interface().verify(request)).status);
    test_engine.status = .invalid;
    try std.testing.expectEqual(PayloadStatus.invalid, (try test_engine.interface().verify(request)).status);
    test_engine.status = .syncing;
    try std.testing.expectEqual(PayloadStatus.syncing, (try test_engine.interface().verify(request)).status);
    test_engine.unavailable = true;
    try std.testing.expectError(error.Unavailable, test_engine.interface().verify(request));
}

// An operation pool holds signed Fulu evidence and votes before a proposer
// includes them. Admission verifies against a state copy; selection replays
// candidates in block order because slashings and exits change later validity.
//
//   admit -> owned, root-sorted entries -> select on proposed state -> block
//                                              accepted block -> remove roots
// Each type is capped at twice its block limit. Attestations also reject
// slashable votes by the same validator while they remain in the pool.
const std = @import("std");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const preset = @import("consensus_preset").Config;
const operations = @import("block_operations.zig");
const bls = @import("bls.zig");
const domains = @import("domains.zig");
const helpers = @import("helpers.zig");
const blst = @import("blst");

/// Pair an owned operation with its SSZ root for sorted storage.
fn Entry(comptime T: type) type {
    return struct { root: fulu.Root, value: T };
}

/// Deep-copy an SSZ value so pool entries and returned blocks own their lists.
pub fn copyValue(allocator: std.mem.Allocator, comptime T: type, value: T) !T {
    const bytes = try ssz.serializeAlloc(allocator, value);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    return ssz.deserialize(allocator, T, &reader);
}

/// Owned and bounded signed operations, sorted by SSZ root for deterministic choice.
pub const Pool = struct {
    allocator: std.mem.Allocator,
    attestations: std.ArrayList(Entry(fulu.Attestation)) = .empty,
    proposer_slashings: std.ArrayList(Entry(fulu.ProposerSlashing)) = .empty,
    attester_slashings: std.ArrayList(Entry(fulu.AttesterSlashing)) = .empty,
    voluntary_exits: std.ArrayList(Entry(fulu.SignedVoluntaryExit)) = .empty,
    bls_changes: std.ArrayList(Entry(fulu.SignedBLSToExecutionChange)) = .empty,

    /// Construct an empty pool using the allocator for owned SSZ values.
    pub fn init(allocator: std.mem.Allocator) Pool {
        return .{ .allocator = allocator };
    }

    /// Release every retained operation and its nested SSZ allocations.
    pub fn deinit(self: *Pool) void {
        inline for (.{ "attestations", "proposer_slashings", "attester_slashings", "voluntary_exits", "bls_changes" }) |name| {
            const list = &@field(self, name);
            for (list.items) |entry| ssz.freeDecoded(self.allocator, @TypeOf(entry.value), entry.value);
            list.deinit(self.allocator);
        }
    }

    /// Verify and own an attestation, merging disjoint participants for the same data.
    pub fn addAttestation(self: *Pool, state: *const fulu.BeaconState, value: fulu.Attestation) !void {
        try validate(self.allocator, state, value, operations.processAttestation);
        self.pruneExpiredAttestations(state.slot);
        try pruneInvalid(self.allocator, fulu.Attestation, &self.attestations, state, 2 * preset.MAX_ATTESTATIONS_ELECTRA, operations.processAttestation);
        const incoming = try operations.getAttestingIndices(self.allocator, state, value);
        defer self.allocator.free(incoming);
        for (self.attestations.items) |entry| {
            const existing = try operations.getAttestingIndices(self.allocator, state, entry.value);
            defer self.allocator.free(existing);
            for (incoming) |index| for (existing) |old| {
                if (index == old and operations.isSlashableAttestationData(value.data, entry.value.data)) return error.ConflictingVote;
            };
        }
        const root = try merkle.HashTreeRoot(self.allocator, value);
        if (contains(fulu.Attestation, self.attestations.items, root)) return error.DuplicateOperation;
        for (self.attestations.items, 0..) |entry, i| {
            if (!std.meta.eql(entry.value.data, value.data)) continue;
            const combined = try combineAttestations(self.allocator, state, entry.value, value) orelse continue;
            errdefer ssz.freeDecoded(self.allocator, fulu.Attestation, combined);
            try validate(self.allocator, state, combined, operations.processAttestation);
            const combined_root = try merkle.HashTreeRoot(self.allocator, combined);
            ssz.freeDecoded(self.allocator, fulu.Attestation, self.attestations.items[i].value);
            self.attestations.items[i] = .{ .root = combined_root, .value = combined };
            std.mem.sort(Entry(fulu.Attestation), self.attestations.items, {}, lessThan(fulu.Attestation));
            return;
        }
        try add(self.allocator, fulu.Attestation, &self.attestations, value, 2 * preset.MAX_ATTESTATIONS_ELECTRA);
    }

    /// Verify and own proposer-slashing evidence against a state copy.
    pub fn addProposerSlashing(self: *Pool, state: *const fulu.BeaconState, value: fulu.ProposerSlashing) !void {
        try validate(self.allocator, state, value, operations.processProposerSlashing);
        try pruneInvalid(self.allocator, fulu.ProposerSlashing, &self.proposer_slashings, state, 2 * preset.MAX_PROPOSER_SLASHINGS, operations.processProposerSlashing);
        try add(self.allocator, fulu.ProposerSlashing, &self.proposer_slashings, value, 2 * preset.MAX_PROPOSER_SLASHINGS);
    }

    /// Verify and own attester-slashing evidence against a state copy.
    pub fn addAttesterSlashing(self: *Pool, state: *const fulu.BeaconState, value: fulu.AttesterSlashing) !void {
        try validate(self.allocator, state, value, operations.processAttesterSlashing);
        try pruneInvalid(self.allocator, fulu.AttesterSlashing, &self.attester_slashings, state, 2 * preset.MAX_ATTESTER_SLASHINGS_ELECTRA, operations.processAttesterSlashing);
        try add(self.allocator, fulu.AttesterSlashing, &self.attester_slashings, value, 2 * preset.MAX_ATTESTER_SLASHINGS_ELECTRA);
    }

    /// Verify and own a voluntary exit against a state copy.
    pub fn addVoluntaryExit(self: *Pool, state: *const fulu.BeaconState, value: fulu.SignedVoluntaryExit) !void {
        try validate(self.allocator, state, value, operations.processVoluntaryExit);
        try pruneInvalid(self.allocator, fulu.SignedVoluntaryExit, &self.voluntary_exits, state, 2 * preset.MAX_VOLUNTARY_EXITS, operations.processVoluntaryExit);
        try add(self.allocator, fulu.SignedVoluntaryExit, &self.voluntary_exits, value, 2 * preset.MAX_VOLUNTARY_EXITS);
    }

    /// Verify and own a withdrawal-credential change against a state copy.
    pub fn addBlsChange(self: *Pool, state: *const fulu.BeaconState, value: fulu.SignedBLSToExecutionChange) !void {
        try validate(self.allocator, state, value, operations.processBLSToExecutionChange);
        try pruneInvalid(self.allocator, fulu.SignedBLSToExecutionChange, &self.bls_changes, state, 2 * preset.MAX_BLS_TO_EXECUTION_CHANGES, operations.processBLSToExecutionChange);
        try add(self.allocator, fulu.SignedBLSToExecutionChange, &self.bls_changes, value, 2 * preset.MAX_BLS_TO_EXECUTION_CHANGES);
    }

    /// Release votes that no future block at this slot can include.
    fn pruneExpiredAttestations(self: *Pool, slot: fulu.Slot) void {
        var i: usize = 0;
        while (i < self.attestations.items.len) {
            const vote_slot = self.attestations.items[i].value.data.slot;
            if (vote_slot > slot or slot - vote_slot > helpers.SLOTS_PER_EPOCH) {
                ssz.freeDecoded(self.allocator, fulu.Attestation, self.attestations.orderedRemove(i).value);
            } else i += 1;
        }
    }

    /// Borrow valid operations in block order; caller allocator holds only list slices.
    pub fn select(self: *const Pool, allocator: std.mem.Allocator, state: *const fulu.BeaconState) !Selection {
        // A caller may use an arena for the proposal. Keep trial states in
        // independent arenas so each candidate's state is released promptly.
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        var working = try copyValue(scratch.allocator(), fulu.BeaconState, state.*);
        const proposer_slashings = try selectList(allocator, fulu.ProposerSlashing, self.proposer_slashings.items, &scratch, &working, preset.MAX_PROPOSER_SLASHINGS, operations.processProposerSlashing);
        errdefer allocator.free(proposer_slashings);
        const attester_slashings = try selectList(allocator, fulu.AttesterSlashing, self.attester_slashings.items, &scratch, &working, preset.MAX_ATTESTER_SLASHINGS_ELECTRA, operations.processAttesterSlashing);
        errdefer allocator.free(attester_slashings);
        const attestations = try selectList(allocator, fulu.Attestation, self.attestations.items, &scratch, &working, preset.MAX_ATTESTATIONS_ELECTRA, operations.processAttestation);
        errdefer allocator.free(attestations);
        const voluntary_exits = try selectList(allocator, fulu.SignedVoluntaryExit, self.voluntary_exits.items, &scratch, &working, preset.MAX_VOLUNTARY_EXITS, operations.processVoluntaryExit);
        errdefer allocator.free(voluntary_exits);
        const bls_changes = try selectList(allocator, fulu.SignedBLSToExecutionChange, self.bls_changes.items, &scratch, &working, preset.MAX_BLS_TO_EXECUTION_CHANGES, operations.processBLSToExecutionChange);
        return .{
            .proposer_slashings = proposer_slashings,
            .attester_slashings = attester_slashings,
            .attestations = attestations,
            .voluntary_exits = voluntary_exits,
            .bls_changes = bls_changes,
        };
    }

    /// Remove only operations actually included in an accepted block.
    pub fn accepted(self: *Pool, body: fulu.BeaconBlockBody) !void {
        try removeIncluded(self.allocator, fulu.ProposerSlashing, &self.proposer_slashings, body.proposer_slashings.data);
        try removeIncluded(self.allocator, fulu.AttesterSlashing, &self.attester_slashings, body.attester_slashings.data);
        try removeIncluded(self.allocator, fulu.Attestation, &self.attestations, body.attestations.data);
        try removeIncluded(self.allocator, fulu.SignedVoluntaryExit, &self.voluntary_exits, body.voluntary_exits.data);
        try removeIncluded(self.allocator, fulu.SignedBLSToExecutionChange, &self.bls_changes, body.bls_to_execution_changes.data);
    }
};

/// List slices are owned by the selection allocator; operation values remain borrowed.
pub const Selection = struct {
    proposer_slashings: []fulu.ProposerSlashing,
    attester_slashings: []fulu.AttesterSlashing,
    attestations: []fulu.Attestation,
    voluntary_exits: []fulu.SignedVoluntaryExit,
    bls_changes: []fulu.SignedBLSToExecutionChange,
};

/// Return the comparator used for deterministic root order.
fn lessThan(comptime T: type) fn (void, Entry(T), Entry(T)) bool {
    return struct {
        /// Compare two operation roots lexicographically.
        fn less(_: void, a: Entry(T), b: Entry(T)) bool {
            return std.mem.order(u8, &a.root, &b.root) == .lt;
        }
    }.less;
}

/// Report whether a root is already retained in a typed list.
fn contains(comptime T: type, entries: []const Entry(T), root: fulu.Root) bool {
    for (entries) |entry| if (std.mem.eql(u8, &entry.root, &root)) return true;
    return false;
}

/// Insert a distinct owned value without exceeding the list's capacity.
fn add(allocator: std.mem.Allocator, comptime T: type, list: *std.ArrayList(Entry(T)), value: T, limit: usize) !void {
    const root = try merkle.HashTreeRoot(allocator, value);
    if (contains(T, list.items, root)) return error.DuplicateOperation;
    if (list.items.len >= limit) return error.PoolFull;
    const owned = try copyValue(allocator, T, value);
    errdefer ssz.freeDecoded(allocator, T, owned);
    try list.append(allocator, .{ .root = root, .value = owned });
    std.mem.sort(Entry(T), list.items, {}, lessThan(T));
}

/// At capacity, discard entries that no longer validate against current state.
fn pruneInvalid(allocator: std.mem.Allocator, comptime T: type, list: *std.ArrayList(Entry(T)), state: *const fulu.BeaconState, limit: usize, process: anytype) !void {
    if (list.items.len < limit) return;
    var i: usize = 0;
    while (i < list.items.len) {
        validate(allocator, state, list.items[i].value, process) catch |err| {
            if (err == error.OutOfMemory) return err;
            ssz.freeDecoded(allocator, T, list.orderedRemove(i).value);
            continue;
        };
        i += 1;
    }
}

/// Run an existing operation processor without changing caller state.
fn validate(allocator: std.mem.Allocator, state: *const fulu.BeaconState, value: anytype, process: anytype) !void {
    var copy = try copyValue(allocator, fulu.BeaconState, state.*);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, copy);
    try process(allocator, &copy, value);
}

/// Replay each candidate on a trial state, retaining valid entries up to limit.
fn selectList(allocator: std.mem.Allocator, comptime T: type, entries: []const Entry(T), scratch: *std.heap.ArenaAllocator, state: *fulu.BeaconState, limit: usize, process: anytype) ![]T {
    var chosen = std.ArrayList(T).empty;
    errdefer chosen.deinit(allocator);
    for (entries) |entry| {
        if (chosen.items.len == limit) break;
        var trial_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        var trial = copyValue(trial_arena.allocator(), fulu.BeaconState, state.*) catch |err| {
            trial_arena.deinit();
            return err;
        };
        if (process(trial_arena.allocator(), &trial, entry.value)) |_| {
            chosen.append(allocator, entry.value) catch |err| {
                trial_arena.deinit();
                return err;
            };
            scratch.deinit();
            scratch.* = trial_arena;
            state.* = trial;
        } else |err| {
            trial_arena.deinit();
            if (err == error.OutOfMemory) return err;
        }
    }
    return chosen.toOwnedSlice(allocator);
}

/// Release entries whose roots appear in an accepted block.
fn removeIncluded(allocator: std.mem.Allocator, comptime T: type, entries: *std.ArrayList(Entry(T)), included: []const T) !void {
    for (included) |value| {
        const root = try merkle.HashTreeRoot(allocator, value);
        for (entries.items, 0..) |entry, i| if (std.mem.eql(u8, &entry.root, &root)) {
            ssz.freeDecoded(allocator, T, entries.orderedRemove(i).value);
            break;
        };
    }
}

/// Merge disjoint committee participants for matching attestation data.
fn combineAttestations(allocator: std.mem.Allocator, state: *const fulu.BeaconState, first: fulu.Attestation, second: fulu.Attestation) !?fulu.Attestation {
    const a = try operations.getAttestingIndices(allocator, state, first);
    defer allocator.free(a);
    const b = try operations.getAttestingIndices(allocator, state, second);
    defer allocator.free(b);
    for (a) |index| for (b) |other| {
        if (index == other) return null;
    };
    var result = first;
    result.committee_bits = first.committee_bits;
    for (&result.committee_bits.data, second.committee_bits.data) |*bit, other| bit.* = bit.* or other;
    var bits = std.ArrayList(bool).empty;
    defer bits.deinit(allocator);
    var a_offset: usize = 0;
    var b_offset: usize = 0;
    for (result.committee_bits.data, 0..) |selected, committee_index| {
        if (!selected) continue;
        const committee = try @import("helpers.zig").getBeaconCommittee(allocator, state, first.data.slot, committee_index);
        defer allocator.free(committee);
        for (0..committee.len) |i| {
            const left = first.committee_bits.data[committee_index] and first.aggregation_bits.data[a_offset + i];
            const right = second.committee_bits.data[committee_index] and second.aggregation_bits.data[b_offset + i];
            try bits.append(allocator, left or right);
        }
        if (first.committee_bits.data[committee_index]) a_offset += committee.len;
        if (second.committee_bits.data[committee_index]) b_offset += committee.len;
    }
    if (bits.items.len > preset.MAX_VALIDATORS_PER_COMMITTEE) return null;
    result.aggregation_bits.data = try bits.toOwnedSlice(allocator);
    errdefer allocator.free(result.aggregation_bits.data);
    result.signature = try bls.aggregateSignatures(first.signature, second.signature);
    return result;
}

test "pool owns admitted attestation, deduplicates, and borrows selection" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const vote = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    var pool = Pool.init(allocator);
    defer pool.deinit();
    try pool.addAttestation(&state, vote);
    try std.testing.expectError(error.DuplicateOperation, pool.addAttestation(&state, vote));
    const original = pool.attestations.items[0].value.aggregation_bits.data[0];
    @constCast(vote.aggregation_bits.data)[0] = !original;
    try std.testing.expectEqual(original, pool.attestations.items[0].value.aggregation_bits.data[0]);
    ssz.freeDecoded(allocator, fulu.Attestation, vote);
    const selected = try pool.select(allocator, &state);
    defer {
        allocator.free(selected.proposer_slashings);
        allocator.free(selected.attester_slashings);
        allocator.free(selected.attestations);
        allocator.free(selected.voluntary_exits);
        allocator.free(selected.bls_changes);
    }
    try std.testing.expectEqual(@as(usize, 1), selected.attestations.len);
    const fixture_block = try fixtures.decodeBlock(allocator, @embedFile("fixtures/fulu_transition/empty_block_transition/blocks_0.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, fixture_block);
    var body = fixture_block.message.body;
    body.attestations.data = selected.attestations;
    try pool.accepted(body);
    try std.testing.expectEqual(@as(usize, 0), pool.attestations.items.len);
}

test "invalid admission leaves pool and input state unchanged" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_invalid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const before = try merkle.HashTreeRoot(allocator, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/attestation_invalid/attestation.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const vote = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, vote);
    var pool = Pool.init(allocator);
    defer pool.deinit();
    try std.testing.expectError(error.InvalidAttestation, pool.addAttestation(&state, vote));
    try std.testing.expectEqual(@as(usize, 0), pool.attestations.items.len);
    try std.testing.expectEqual(before, try merkle.HashTreeRoot(allocator, state));
}

/// Check admission and duplicate rejection with one pinned operation fixture.
fn checkAdmission(comptime T: type, comptime admit: anytype, comptime field: []const u8, pre: []const u8, input: []const u8) !void {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, pre);
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, input);
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const value = try ssz.deserialize(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, value);
    var pool = Pool.init(allocator);
    defer pool.deinit();
    try admit(&pool, &state, value);
    try std.testing.expectEqual(@as(usize, 1), @field(pool, field).items.len);
    try std.testing.expectError(error.DuplicateOperation, admit(&pool, &state, value));
}

test "all remaining signed operation types admit and deduplicate" {
    try checkAdmission(fulu.ProposerSlashing, Pool.addProposerSlashing, "proposer_slashings", @embedFile("fixtures/fulu_block_operations/proposer_slashing_valid/pre.ssz_snappy"), @embedFile("fixtures/fulu_block_operations/proposer_slashing_valid/proposer_slashing.ssz_snappy"));
    try checkAdmission(fulu.AttesterSlashing, Pool.addAttesterSlashing, "attester_slashings", @embedFile("fixtures/fulu_block_operations/attester_slashing_valid/pre.ssz_snappy"), @embedFile("fixtures/fulu_block_operations/attester_slashing_valid/attester_slashing.ssz_snappy"));
    try checkAdmission(fulu.SignedVoluntaryExit, Pool.addVoluntaryExit, "voluntary_exits", @embedFile("fixtures/fulu_block_operations/voluntary_exit_valid/pre.ssz_snappy"), @embedFile("fixtures/fulu_block_operations/voluntary_exit_valid/voluntary_exit.ssz_snappy"));
    try checkAdmission(fulu.SignedBLSToExecutionChange, Pool.addBlsChange, "bls_changes", @embedFile("fixtures/fulu_block_operations/bls_change_valid/pre.ssz_snappy"), @embedFile("fixtures/fulu_block_operations/bls_change_valid/address_change.ssz_snappy"));
}

test "pool bound rejects an extra distinct entry" {
    const allocator = std.testing.allocator;
    var entries = std.ArrayList(Entry(fulu.SignedVoluntaryExit)).empty;
    defer {
        for (entries.items) |entry| ssz.freeDecoded(allocator, fulu.SignedVoluntaryExit, entry.value);
        entries.deinit(allocator);
    }
    const first: fulu.SignedVoluntaryExit = .{ .message = .{ .epoch = 1, .validator_index = 1 }, .signature = [_]u8{1} ** 96 };
    var second = first;
    second.message.validator_index = 2;
    try add(allocator, fulu.SignedVoluntaryExit, &entries, first, 1);
    try std.testing.expectError(error.PoolFull, add(allocator, fulu.SignedVoluntaryExit, &entries, second, 1));
}

test "expired attestations free a full pool for a fresh vote" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const old_vote = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, old_vote);
    const new_slot = @max(state.slot + 1, old_vote.data.slot + helpers.SLOTS_PER_EPOCH + 2);
    try @import("transition.zig").processSlots(allocator, &state, new_slot, @import("epoch.zig").processEpoch);

    var fresh = old_vote;
    fresh.data.slot = new_slot - 1;
    fresh.data.target.epoch = helpers.computeEpochAtSlot(fresh.data.slot);
    fresh.committee_bits.data = [_]bool{false} ** preset.MAX_COMMITTEES_PER_SLOT;
    var validator_index: ?usize = null;
    for (0..preset.MAX_COMMITTEES_PER_SLOT) |committee_index| {
        const committee = try helpers.getBeaconCommittee(allocator, &state, fresh.data.slot, committee_index);
        defer allocator.free(committee);
        if (committee.len == 0) continue;
        fresh.committee_bits.data[committee_index] = true;
        fresh.aggregation_bits.data = try allocator.alloc(bool, committee.len);
        @memset(@constCast(fresh.aggregation_bits.data), false);
        @constCast(fresh.aggregation_bits.data)[0] = true;
        validator_index = @intCast(committee[0]);
        break;
    }
    if (validator_index == null) return error.FixtureNoCommittee;
    defer allocator.free(fresh.aggregation_bits.data);
    var key = blst.SecretKey{};
    const seed = [_]u8{0x71} ** 32;
    key.keygen(&seed, null);
    defer key.deinit();
    @constCast(state.validators.data)[validator_index.?].pubkey = try bls.publicKey(&key);
    const root = try merkle.HashTreeRoot(allocator, fresh.data);
    const domain = domains.getDomain(state, helpers.DOMAIN_BEACON_ATTESTER, fresh.data.target.epoch);
    fresh.signature = bls.sign(&key, domains.computeSigningRoot(root, domain));

    var pool = Pool.init(allocator);
    defer pool.deinit();
    for (0..2 * preset.MAX_ATTESTATIONS_ELECTRA) |i| {
        const stale = try copyValue(allocator, fulu.Attestation, old_vote);
        try pool.attestations.append(allocator, .{ .root = [_]u8{@intCast(i)} ** 32, .value = stale });
    }
    try pool.addAttestation(&state, fresh);
    try std.testing.expectEqual(@as(usize, 1), pool.attestations.items.len);
    try std.testing.expectEqual(fresh.data.slot, pool.attestations.items[0].value.data.slot);
}

test "selection scratch does not consume the caller's small arena" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const vote = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, vote);
    var pool = Pool.init(allocator);
    defer pool.deinit();
    try pool.addAttestation(&state, vote);
    var buffer: [512]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    const selected = try pool.select(fixed.allocator(), &state);
    try std.testing.expectEqual(@as(usize, 1), selected.attestations.len);
}

test "pool aggregates disjoint votes and rejects a conflicting vote" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    const bytes = try fixtures.decode(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/attestation.ssz_snappy"));
    defer allocator.free(bytes);
    var reader: std.Io.Reader = .fixed(bytes);
    const template = try ssz.deserialize(allocator, fulu.Attestation, &reader);
    defer ssz.freeDecoded(allocator, fulu.Attestation, template);
    if (template.aggregation_bits.data.len < 2) return error.FixtureTooSmall;
    var votes: [2]fulu.Attestation = .{ template, template };
    var keys: [2]blst.SecretKey = .{ .{}, .{} };
    defer for (&keys) |*key| key.deinit();
    const root = try merkle.HashTreeRoot(allocator, template.data);
    const domain = domains.getDomain(state, helpers.DOMAIN_BEACON_ATTESTER, template.data.target.epoch);
    for (&votes, &keys, 0..) |*vote, *key, i| {
        const bits = try allocator.dupe(bool, template.aggregation_bits.data);
        @memset(bits, false);
        bits[i] = true;
        vote.aggregation_bits.data = bits;
        const indices = try operations.getAttestingIndices(allocator, &state, vote.*);
        defer allocator.free(indices);
        if (indices.len != 1) return error.InvalidFixtureCommittee;
        const seed = [_]u8{@as(u8, @intCast(0x50 + i))} ** 32;
        key.keygen(&seed, null);
        @constCast(state.validators.data)[indices[0]].pubkey = try bls.publicKey(key);
        vote.signature = bls.sign(key, domains.computeSigningRoot(root, domain));
    }
    defer for (votes) |vote| allocator.free(vote.aggregation_bits.data);
    var pool = Pool.init(allocator);
    defer pool.deinit();
    try pool.addAttestation(&state, votes[0]);
    try pool.addAttestation(&state, votes[1]);
    try std.testing.expectEqual(@as(usize, 1), pool.attestations.items.len);
    const participants = try operations.getAttestingIndices(allocator, &state, pool.attestations.items[0].value);
    defer allocator.free(participants);
    try std.testing.expectEqual(@as(usize, 2), participants.len);
    var conflicting = votes[0];
    conflicting.data.beacon_block_root[0] ^= 1;
    const conflicting_root = try merkle.HashTreeRoot(allocator, conflicting.data);
    conflicting.signature = bls.sign(&keys[0], domains.computeSigningRoot(conflicting_root, domain));
    try std.testing.expectError(error.ConflictingVote, pool.addAttestation(&state, conflicting));
}

/// Dummy processor isolates the shared selection cap from signature validation.
fn acceptForLimitTest(_: std.mem.Allocator, _: *fulu.BeaconState, _: fulu.SignedVoluntaryExit) !void {}

test "selection applies each Fulu operation body limit" {
    const allocator = std.testing.allocator;
    const fixtures = @import("fixture_runner.zig");
    const state = try fixtures.decodeState(allocator, @embedFile("fixtures/fulu_block_operations/attestation_valid/pre.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, state);
    var entries: [33]Entry(fulu.SignedVoluntaryExit) = undefined;
    for (&entries, 0..) |*entry, i| entry.* = .{
        .root = [_]u8{@as(u8, @intCast(i))} ** 32,
        .value = .{ .message = .{ .epoch = 0, .validator_index = i }, .signature = [_]u8{0} ** 96 },
    };
    inline for (.{ preset.MAX_PROPOSER_SLASHINGS, preset.MAX_ATTESTER_SLASHINGS_ELECTRA, preset.MAX_ATTESTATIONS_ELECTRA, preset.MAX_VOLUNTARY_EXITS, preset.MAX_BLS_TO_EXECUTION_CHANGES }) |limit| {
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        var working = try copyValue(scratch.allocator(), fulu.BeaconState, state);
        const chosen = try selectList(allocator, fulu.SignedVoluntaryExit, &entries, &scratch, &working, limit, acceptForLimitTest);
        defer allocator.free(chosen);
        try std.testing.expectEqual(@as(usize, limit), chosen.len);
    }
}

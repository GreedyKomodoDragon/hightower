// Pending transactions are ordered by sender nonce. A gap stays pending; only
// consecutive nonces from current state can be selected. Replacements need a
// 10% bump in every applicable fee cap. Eviction discards the lowest effective
// tip first, then the highest nonce and transaction hash to break ties.
//
// sender nonce n -> n+1 -> gap -> pending later nonce
// The pool owns canonical bytes and blob sidecars. It does not propagate peers.
const std = @import("std");
const execution = @import("execution.zig");
const transition = @import("transition.zig");
const kzg = @import("kzg.zig");

pub const Limits = struct { max_entries: usize = 4096, max_bytes: usize = 64 * 1024 * 1024 };

pub const Entry = struct {
    raw: []u8,
    sidecar: ?[]u8,
    hash: execution.Hash,
    admission: transition.Admission,

    /// Returns the effective priority fee at the current base fee.
    pub fn tip(self: Entry, base_fee: u256) u256 {
        return @min(self.admission.priority_fee, self.admission.max_fee -| base_fee);
    }

    /// Returns the total owned encoded bytes charged against pool bounds.
    pub fn bytes(self: Entry) usize {
        return self.raw.len + if (self.sidecar) |sidecar| sidecar.len else @as(usize, 0);
    }
};

/// In-memory bounded pool of owned, signed transaction bytes.
pub const Pool = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    entries: std.ArrayList(Entry) = .empty,
    byte_count: usize = 0,

    /// Creates an empty pool with explicit count and byte limits.
    pub fn init(allocator: std.mem.Allocator, limits: Limits) Pool {
        return .{ .allocator = allocator, .limits = limits };
    }

    /// Releases every owned transaction and sidecar.
    pub fn deinit(self: *Pool) void {
        for (self.entries.items) |entry| self.freeEntry(entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Admits a signed network transaction and evicts to the configured bounds.
    pub fn admit(self: *Pool, world: *execution.state.State, context: transition.Context, settings: ?*const kzg.Settings, network_raw: []const u8) !execution.Hash {
        if (network_raw.len == 0 or network_raw.len > self.limits.max_bytes) return error.TransactionTooLarge;
        const is_blob = network_raw[0] == 3;
        const raw = if (is_blob) try kzg.canonicalTransaction(self.allocator, settings orelse return error.KzgUnavailable, network_raw) else try self.allocator.dupe(u8, network_raw);
        var owned = true;
        errdefer if (owned) self.allocator.free(raw);
        const sidecar: ?[]u8 = if (is_blob) try self.allocator.dupe(u8, network_raw) else null;
        errdefer if (owned) if (sidecar) |bytes| self.allocator.free(bytes);
        const admission = try transition.validatePending(self.allocator, world, context, raw);
        var hash: execution.Hash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(raw, &hash, .{});
        if (self.findHash(hash) != null) return error.AlreadyKnown;
        const entry: Entry = .{ .raw = raw, .sidecar = sidecar, .hash = hash, .admission = admission };
        if (entry.bytes() > self.limits.max_bytes or self.limits.max_entries == 0) return error.TransactionTooLarge;
        const replacing = self.findNonce(admission.sender, admission.nonce);
        if (replacing) |index| {
            const old = self.entries.items[index];
            if (!replacementAllowed(old.admission, admission)) return error.ReplacementUnderpriced;
        }
        var better_count: usize = 0;
        var better_bytes: usize = 0;
        for (self.entries.items, 0..) |existing, index| {
            if (replacing != null and index == replacing.?) continue;
            if (worse(entry, existing, context.base_fee)) {
                better_count += 1;
                better_bytes += existing.bytes();
            }
        }
        if (better_count >= self.limits.max_entries or better_bytes > self.limits.max_bytes - entry.bytes()) return error.PoolFull;
        if (replacing) |index| {
            const old = self.entries.items[index];
            self.byte_count -= old.bytes();
            self.freeEntry(old);
            self.entries.items[index] = entry;
        } else {
            try self.entries.append(self.allocator, entry);
        }
        owned = false;
        self.byte_count += entry.bytes();
        while (self.entries.items.len > self.limits.max_entries or self.byte_count > self.limits.max_bytes) {
            var worst: usize = 0;
            for (self.entries.items[1..], 1..) |candidate, i| {
                if (worse(candidate, self.entries.items[worst], context.base_fee)) worst = i;
            }
            const removed = self.entries.swapRemove(worst);
            self.byte_count -= removed.bytes();
            const removed_submitted = std.mem.eql(u8, &removed.hash, &hash);
            self.freeEntry(removed);
            if (removed_submitted) return error.PoolFull;
        }
        return hash;
    }

    /// Removes mined or stale sender nonces after canonical state advances.
    pub fn prune(self: *Pool, world: *const execution.state.State) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const entry = self.entries.items[i];
            if (entry.admission.nonce >= world.getNonce(entry.admission.sender)) {
                i += 1;
                continue;
            }
            self.byte_count -= entry.bytes();
            self.freeEntry(self.entries.swapRemove(i));
        }
    }

    /// Selects executable prefixes by tip within a gas limit; returned slices borrow pool bytes.
    pub fn select(self: *const Pool, allocator: std.mem.Allocator, world: *execution.state.State, context: transition.Context, gas_limit: u64) ![][]const u8 {
        var chosen: std.ArrayList([]const u8) = .empty;
        errdefer chosen.deinit(allocator);
        var used = try allocator.alloc(bool, self.entries.items.len);
        defer allocator.free(used);
        @memset(used, false);
        const snap = try world.snapshot();
        defer world.revert(snap) catch {};
        var remaining = gas_limit;
        while (true) {
            var best: ?usize = null;
            for (self.entries.items, 0..) |entry, i| {
                if (used[i] or entry.admission.nonce != world.getNonce(entry.admission.sender) or entry.admission.gas_limit > remaining) continue;
                if (best == null or better(entry, self.entries.items[best.?], context.base_fee)) best = i;
            }
            const index = best orelse break;
            used[index] = true;
            const entry = self.entries.items[index];
            var outcome = transition.applyTransaction(allocator, world, context, entry.raw, remaining, 0) catch continue;
            defer outcome.deinit();
            remaining -= outcome.gas_used;
            try chosen.append(allocator, entry.raw);
        }
        return chosen.toOwnedSlice(allocator);
    }

    /// Finds an admitted transaction by its canonical hash.
    pub fn get(self: *const Pool, hash: execution.Hash) ?*const Entry {
        const index = self.findHash(hash) orelse return null;
        return &self.entries.items[index];
    }

    /// Finds a sender's transaction at one nonce.
    fn findNonce(self: *const Pool, sender: execution.Address, nonce: u64) ?usize {
        for (self.entries.items, 0..) |entry, i| if (entry.admission.nonce == nonce and std.mem.eql(u8, &entry.admission.sender, &sender)) return i;
        return null;
    }

    /// Finds a transaction by canonical hash.
    fn findHash(self: *const Pool, hash: execution.Hash) ?usize {
        for (self.entries.items, 0..) |entry, i| if (std.mem.eql(u8, &entry.hash, &hash)) return i;
        return null;
    }

    /// Releases the storage owned by one entry.
    fn freeEntry(self: *Pool, entry: Entry) void {
        self.allocator.free(entry.raw);
        if (entry.sidecar) |bytes| self.allocator.free(bytes);
    }
};

/// Checks the 10% replacement bump without overflowing 256-bit fee caps.
fn bumped(old: u256, new: u256) bool {
    return new > old and @as(u512, new) * 100 >= @as(u512, old) * 110;
}

/// Requires a bump in gas price, priority cap, and any blob cap present on both entries.
fn replacementAllowed(old: transition.Admission, new: transition.Admission) bool {
    if (!bumped(old.max_fee, new.max_fee) or !bumped(old.priority_fee, new.priority_fee)) return false;
    if (old.blob_fee_cap != null or new.blob_fee_cap != null) {
        if (old.blob_fee_cap == null or new.blob_fee_cap == null) return false;
        if (!bumped(old.blob_fee_cap.?, new.blob_fee_cap.?)) return false;
    }
    return true;
}

/// Orders eviction by low tip, high nonce, then lexicographically high hash.
fn worse(a: Entry, b: Entry, base_fee: u256) bool {
    if (a.tip(base_fee) != b.tip(base_fee)) return a.tip(base_fee) < b.tip(base_fee);
    if (a.admission.nonce != b.admission.nonce) return a.admission.nonce > b.admission.nonce;
    return std.mem.order(u8, &a.hash, &b.hash) == .gt;
}

/// Orders block selection by high tip, then canonical hash.
fn better(a: Entry, b: Entry, base_fee: u256) bool {
    if (a.tip(base_fee) != b.tip(base_fee)) return a.tip(base_fee) > b.tip(base_fee);
    return std.mem.order(u8, &a.hash, &b.hash) == .lt;
}

test "replacement bump is exact at ten percent and includes blob cap" {
    try std.testing.expect(!bumped(100, 109));
    try std.testing.expect(bumped(100, 110));
    const old: transition.Admission = .{ .sender = .{0} ** 20, .nonce = 0, .gas_limit = 21_000, .max_fee = 100, .priority_fee = 10, .blob_fee_cap = 20 };
    var new = old;
    new.max_fee = 110;
    new.priority_fee = 11;
    new.blob_fee_cap = 21;
    try std.testing.expect(!replacementAllowed(old, new));
    new.blob_fee_cap = 22;
    try std.testing.expect(replacementAllowed(old, new));
}

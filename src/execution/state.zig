// Execution state maps addresses to accounts; each account commits to its own
// storage trie and code hash, and the secure state trie commits to all account
// values. Storage keys are 32-byte words and zero values are absent. Mutations
// are journaled while snapshots are open so reverting them restores the prior
// state root. This in-memory model does not persist trie nodes or prune code.
//
// storage slot → secure storage trie ─┐
// code bytes → Keccak code hash ──────┼→ RLP account → secure state trie → root
//                                      └── snapshot journal → revert/commit
// shortcut: account lookups scan arrays and journal records copy account slots; use indexed maps and slot-level undo if profiling shows this in-memory path is costly.
const std = @import("std");
const rlp = @import("rlp");
const trie = @import("trie.zig");

pub const Address = [20]u8;
pub const Hash = [32]u8;

/// Returns the one-hop code target of a valid EIP-7702 designation.
pub fn delegationTarget(code: []const u8) ?Address {
    if (code.len != 23 or !std.mem.eql(u8, code[0..3], &.{ 0xef, 0x01, 0x00 })) return null;
    return code[3..23].*;
}

/// Keccak-256 of the empty byte string, used by accounts with no code.
pub const EMPTY_CODE_HASH: Hash = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

/// Keccak-256 of the RLP empty string, the root of every empty storage trie.
pub const EMPTY_STORAGE_ROOT: Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

/// Consensus account fields committed by the global state trie.
pub const Account = struct {
    nonce: u64,
    balance: u256,
    storage_root: Hash,
    code_hash: Hash,
};

const StorageEntry = struct { slot: u256, value: u256 };
const AccountEntry = struct {
    address: Address,
    nonce: u64 = 0,
    balance: u256 = 0,
    code_hash: Hash = EMPTY_CODE_HASH,
    storage: std.ArrayList(StorageEntry) = .empty,
};
const CodeEntry = struct { hash: Hash, bytes: []u8 };
const Undo = struct { address: Address, previous: ?AccountEntry };
const SnapshotMarker = struct { id: u64, journal_len: usize };

/// Opaque identifier for the top nested snapshot; snapshots must be closed LIFO.
pub const Snapshot = struct { id: u64 };

/// In-memory account, storage, code, and mutation journal.
pub const State = struct {
    allocator: std.mem.Allocator,
    accounts: std.ArrayList(AccountEntry) = .empty,
    codes: std.ArrayList(CodeEntry) = .empty,
    journal: std.ArrayList(Undo) = .empty,
    snapshots: std.ArrayList(SnapshotMarker) = .empty,
    next_snapshot_id: u64 = 1,

    /// Creates an empty state using the supplied allocator for all owned data.
    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    /// Releases accounts, code bytes, and any saved journal entries.
    pub fn deinit(self: *State) void {
        for (self.accounts.items) |*entry| self.deinitAccount(entry);
        self.accounts.deinit(self.allocator);
        for (self.codes.items) |code| self.allocator.free(code.bytes);
        self.codes.deinit(self.allocator);
        self.clearJournal();
        self.journal.deinit(self.allocator);
        self.snapshots.deinit(self.allocator);
        self.* = undefined;
    }

    /// Copies committed account, code, and storage values for a canonical block snapshot.
    pub fn clone(self: *const State, allocator: std.mem.Allocator) !State {
        var copy = State.init(allocator);
        errdefer copy.deinit();
        for (self.accounts.items) |entry| {
            try copy.createAccount(entry.address);
            try copy.setNonce(entry.address, entry.nonce);
            try copy.setBalance(entry.address, entry.balance);
            _ = try copy.setCode(entry.address, self.getCode(entry.address));
            for (entry.storage.items) |slot| try copy.setStorage(entry.address, slot.slot, slot.value);
        }
        return copy;
    }

    /// Creates an explicit empty account; creating an existing account is a no-op.
    pub fn createAccount(self: *State, address: Address) !void {
        if (self.findAccount(address) != null) return;
        _ = try self.appendNewAccount(.{ .address = address });
    }

    /// Removes an account and its storage; absent account deletion is a no-op.
    pub fn deleteAccount(self: *State, address: Address) !void {
        const index = self.findAccount(address) orelse return;
        try self.recordAccount(address);
        var removed = self.accounts.swapRemove(index);
        self.deinitAccount(&removed);
    }

    /// Returns account fields with a freshly computed storage root, or null if absent.
    pub fn getAccount(self: *const State, address: Address) !?Account {
        const entry = self.findAccountConst(address) orelse return null;
        return .{
            .nonce = entry.nonce,
            .balance = entry.balance,
            .storage_root = try self.storageRoot(entry),
            .code_hash = entry.code_hash,
        };
    }

    /// Returns an account nonce, or zero when the account does not exist.
    pub fn getNonce(self: *const State, address: Address) u64 {
        const entry = self.findAccountConst(address) orelse return 0;
        return entry.nonce;
    }

    /// Returns an account balance, or zero when the account does not exist.
    pub fn getBalance(self: *const State, address: Address) u256 {
        const entry = self.findAccountConst(address) orelse return 0;
        return entry.balance;
    }

    /// Sets a nonce and creates an account only for a nonzero value.
    pub fn setNonce(self: *State, address: Address, nonce: u64) !void {
        const entry = try self.writableAccount(address, nonce != 0) orelse return;
        entry.nonce = nonce;
    }

    /// Sets a balance and creates an account only for a nonzero value.
    pub fn setBalance(self: *State, address: Address, balance: u256) !void {
        const entry = try self.writableAccount(address, balance != 0) orelse return;
        entry.balance = balance;
    }

    /// Returns stored code borrowed from this state until deinit, or empty bytes for a missing account.
    pub fn getCode(self: *const State, address: Address) []const u8 {
        const account = self.findAccountConst(address) orelse return &.{};
        for (self.codes.items) |code| {
            if (std.mem.eql(u8, &code.hash, &account.code_hash)) return code.bytes;
        }
        return &.{};
    }

    /// Resolves one EIP-7702 delegation for execution while preserving the account's own code hash.
    pub fn getExecutionCode(self: *const State, address: Address) []const u8 {
        const code = self.getCode(address);
        const target = delegationTarget(code) orelse return code;
        return self.getCode(target);
    }

    /// Stores code by Keccak hash, updates the account, and returns the code hash.
    pub fn setCode(self: *State, address: Address, bytes: []const u8) !Hash {
        const hash = keccak(bytes);
        if (bytes.len != 0) try self.storeCode(hash, bytes);
        const entry = try self.writableAccount(address, bytes.len != 0) orelse return hash;
        entry.code_hash = hash;
        return hash;
    }

    /// Returns a storage word, or zero when its account or slot is absent.
    pub fn getStorage(self: *const State, address: Address, slot: u256) u256 {
        const entry = self.findAccountConst(address) orelse return 0;
        for (entry.storage.items) |stored| if (stored.slot == slot) return stored.value;
        return 0;
    }

    /// Sets a storage word; writing zero deletes the slot and never creates an absent account.
    pub fn setStorage(self: *State, address: Address, slot: u256, value: u256) !void {
        const index = self.findAccount(address);
        if (index) |account_index| {
            const entry = &self.accounts.items[account_index];
            for (entry.storage.items, 0..) |stored, i| {
                if (stored.slot != slot) continue;
                if (value == 0) {
                    try self.recordAccount(address);
                    _ = entry.storage.swapRemove(i);
                } else {
                    try self.recordAccount(address);
                    self.accounts.items[account_index].storage.items[i].value = value;
                }
                return;
            }
            if (value == 0) return;
            try self.recordAccount(address);
            try self.accounts.items[account_index].storage.append(self.allocator, .{ .slot = slot, .value = value });
            return;
        }
        if (value == 0) return;
        var entry = AccountEntry{ .address = address };
        errdefer self.deinitAccount(&entry);
        try entry.storage.append(self.allocator, .{ .slot = slot, .value = value });
        _ = try self.appendNewAccount(entry);
    }

    /// Computes the secure global state trie root from current account values.
    pub fn stateRoot(self: *const State) !Hash {
        var state_trie = trie.Trie.init(self.allocator, true);
        defer state_trie.deinit();
        for (self.accounts.items) |entry| {
            const storage_root = try self.storageRoot(&entry);
            const account_bytes = try encodeAccount(self.allocator, .{
                .nonce = entry.nonce,
                .balance = entry.balance,
                .storage_root = storage_root,
                .code_hash = entry.code_hash,
            });
            defer self.allocator.free(account_bytes);
            try state_trie.put(&entry.address, account_bytes);
        }
        return state_trie.root();
    }

    /// Opens a nested journal snapshot and returns its LIFO handle.
    pub fn snapshot(self: *State) !Snapshot {
        const id = self.next_snapshot_id;
        self.next_snapshot_id = std.math.add(u64, id, 1) catch return error.SnapshotIdOverflow;
        try self.snapshots.append(self.allocator, .{ .id = id, .journal_len = self.journal.items.len });
        return .{ .id = id };
    }

    /// Reverts changes since a snapshot and consumes that top-of-stack handle.
    pub fn revert(self: *State, handle: Snapshot) error{InvalidSnapshot}!void {
        const marker = try self.topSnapshot(handle);
        while (self.journal.items.len > marker.journal_len) {
            const undo = self.journal.pop().?;
            self.applyUndo(undo);
        }
        _ = self.snapshots.pop();
        if (self.snapshots.items.len == 0) self.clearJournal();
    }

    /// Commits a snapshot; undo history remains while a parent snapshot is open.
    pub fn commit(self: *State, handle: Snapshot) error{InvalidSnapshot}!void {
        _ = try self.topSnapshot(handle);
        _ = self.snapshots.pop();
        if (self.snapshots.items.len == 0) self.clearJournal();
    }

    /// Returns the account entry index when the address exists.
    fn findAccount(self: *const State, address: Address) ?usize {
        for (self.accounts.items, 0..) |entry, i| if (std.mem.eql(u8, &entry.address, &address)) return i;
        return null;
    }

    /// Returns an account entry when the address exists.
    fn findAccountConst(self: *const State, address: Address) ?*const AccountEntry {
        const index = self.findAccount(address) orelse return null;
        return &self.accounts.items[index];
    }

    /// Journals the prior entry and appends a new account entry.
    fn appendNewAccount(self: *State, entry: AccountEntry) !*AccountEntry {
        const journal_len = self.journal.items.len;
        try self.recordAccount(entry.address);
        errdefer if (self.journal.items.len > journal_len) self.cancelLastUndo();
        try self.accounts.append(self.allocator, entry);
        return &self.accounts.items[self.accounts.items.len - 1];
    }

    /// Journals an existing account before a write, or creates one when requested.
    fn writableAccount(self: *State, address: Address, create: bool) !?*AccountEntry {
        if (self.findAccount(address)) |index| {
            try self.recordAccount(address);
            return &self.accounts.items[index];
        }
        if (!create) return null;
        return try self.appendNewAccount(.{ .address = address });
    }

    /// Appends an owned copy of the current account to the active journal.
    fn recordAccount(self: *State, address: Address) !void {
        if (self.snapshots.items.len == 0) return;
        var previous: ?AccountEntry = null;
        if (self.findAccount(address)) |index| previous = try self.cloneAccount(self.accounts.items[index]);
        errdefer if (previous) |*entry| self.deinitAccount(entry);
        try self.journal.append(self.allocator, .{ .address = address, .previous = previous });
    }

    /// Deep-copies one account and its storage slots for journal ownership.
    fn cloneAccount(self: *const State, entry: AccountEntry) !AccountEntry {
        var copy = entry;
        copy.storage = .empty;
        errdefer copy.storage.deinit(self.allocator);
        try copy.storage.appendSlice(self.allocator, entry.storage.items);
        return copy;
    }

    /// Restores one journal entry without allocation by reusing retained array capacity.
    fn applyUndo(self: *State, undo: Undo) void {
        if (self.findAccount(undo.address)) |index| {
            var current = self.accounts.swapRemove(index);
            self.deinitAccount(&current);
        }
        if (undo.previous) |previous| self.accounts.appendAssumeCapacity(previous);
    }

    /// Frees an unneeded last journal record after an account append failure.
    fn cancelLastUndo(self: *State) void {
        var undo = self.journal.pop().?;
        if (undo.previous) |*entry| self.deinitAccount(entry);
    }

    /// Frees all journal-owned account snapshots.
    fn clearJournal(self: *State) void {
        while (self.journal.pop()) |undo_const| {
            var undo = undo_const;
            if (undo.previous) |*entry| self.deinitAccount(entry);
        }
    }

    /// Checks that a handle names the current top snapshot.
    fn topSnapshot(self: *State, handle: Snapshot) error{InvalidSnapshot}!SnapshotMarker {
        if (self.snapshots.items.len == 0) return error.InvalidSnapshot;
        const marker = self.snapshots.items[self.snapshots.items.len - 1];
        if (marker.id != handle.id) return error.InvalidSnapshot;
        return marker;
    }

    /// Computes one account's secure storage trie root.
    fn storageRoot(self: *const State, account: *const AccountEntry) !Hash {
        var storage_trie = trie.Trie.init(self.allocator, true);
        defer storage_trie.deinit();
        for (account.storage.items) |stored| {
            var key: [32]u8 = undefined;
            std.mem.writeInt(u256, &key, stored.slot, .big);
            const value = try encodeValue(self.allocator, stored.value);
            defer self.allocator.free(value);
            try storage_trie.put(&key, value);
        }
        return storage_trie.root();
    }

    /// Stores code once by hash; code content is immutable for this State lifetime.
    fn storeCode(self: *State, hash: Hash, bytes: []const u8) !void {
        for (self.codes.items) |entry| if (std.mem.eql(u8, &entry.hash, &hash)) return;
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);
        try self.codes.append(self.allocator, .{ .hash = hash, .bytes = owned });
    }

    /// Frees one account entry and its storage list.
    fn deinitAccount(self: *const State, entry: *AccountEntry) void {
        entry.storage.deinit(self.allocator);
        entry.* = undefined;
    }
};

/// Encodes a storage integer as its canonical RLP string.
fn encodeValue(allocator: std.mem.Allocator, value: u256) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try rlp.rlp(&writer.writer, value);
    return writer.toOwnedSlice();
}

/// Encodes account fields in consensus order: nonce, balance, storage root, code hash.
fn encodeAccount(allocator: std.mem.Allocator, account: Account) ![]u8 {
    var payload_counter_buf: [64]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&payload_counter_buf);
    try rlp.rlp(&counter.writer, account.nonce);
    try rlp.rlp(&counter.writer, account.balance);
    try rlp.rlp(&counter.writer, account.storage_root);
    try rlp.rlp(&counter.writer, account.code_hash);

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try rlp.encoding.encodeListHeader(&writer.writer, @intCast(counter.fullCount()));
    try rlp.rlp(&writer.writer, account.nonce);
    try rlp.rlp(&writer.writer, account.balance);
    try rlp.rlp(&writer.writer, account.storage_root);
    try rlp.rlp(&writer.writer, account.code_hash);
    return writer.toOwnedSlice();
}

/// Computes Ethereum's Keccak-256 digest for code bytes.
fn keccak(bytes: []const u8) Hash {
    var digest: Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(bytes, &digest, .{});
    return digest;
}

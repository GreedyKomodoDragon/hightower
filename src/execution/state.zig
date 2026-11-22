// Execution state indexes accounts and storage by Keccak-hashed trie keys so a
// SNAP checkpoint needs no address or slot preimages. EVM lookups hash their
// original addresses and slots before accessing the same entries. Each account
// commits to its storage trie and code hash; the global state trie commits to
// all accounts. Zero storage values are absent. Snapshot journals restore prior
// roots, and durable checkpoints include code up to 24 KiB. Legacy checkpoints
// with preimages remain readable; new checkpoints store hashed keys.
//
// address / slot → Keccak key → raw trie ─┐
// code bytes → Keccak code hash ──────────┼→ RLP account → state root
//                                         └── snapshot journal → revert/commit
// shortcut: journal records copy account slots; use slot-level undo if profiling shows this in-memory path is costly.
const std = @import("std");
const rlp = @import("rlp");
const trie = @import("trie.zig");

pub const Address = [20]u8;
pub const Hash = [32]u8;
const max_checkpoint_code_size = 24 * 1024;

/// Derives the CREATE address from the creator and its nonce before creation.
pub fn createAddress(creator: Address, nonce: u64) Address {
    var nonce_bytes: [8]u8 = undefined;
    const minimal = rlp.encoding.encodeBigEndian(&nonce_bytes, nonce);
    var encoded: [31]u8 = undefined;
    var len: usize = 22;
    encoded[1] = 0x94;
    @memcpy(encoded[2..22], &creator);
    if (nonce == 0) {
        encoded[len] = 0x80;
        len += 1;
    } else {
        if (nonce >= 128) {
            encoded[len] = 0x80 + @as(u8, @intCast(minimal.len));
            len += 1;
        }
        @memcpy(encoded[len..][0..minimal.len], minimal);
        len += minimal.len;
    }
    encoded[0] = 0xc0 + @as(u8, @intCast(len - 1));
    const digest = keccak(encoded[0..len]);
    return digest[12..32].*;
}

/// Derives the CREATE2 address from a salt and the initcode hash.
pub fn create2Address(creator: Address, salt: u256, initcode: []const u8) Address {
    var bytes: [85]u8 = undefined;
    bytes[0] = 0xff;
    @memcpy(bytes[1..21], &creator);
    std.mem.writeInt(u256, bytes[21..53], salt, .big);
    const code_hash = keccak(initcode);
    @memcpy(bytes[53..85], &code_hash);
    const digest = keccak(&bytes);
    return digest[12..32].*;
}

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

const StorageEntry = struct { key: Hash, value: u256 };
const StorageKey = struct { address: Hash, slot: Hash };
const AccountEntry = struct {
    address: Address = .{0} ** 20,
    key: Hash,
    nonce: u64 = 0,
    balance: u256 = 0,
    code_hash: Hash = EMPTY_CODE_HASH,
    storage: std.ArrayList(StorageEntry) = .empty,
    cached_storage_root: ?Hash = null,
    cached_account_value: ?[]u8 = null,
};
const CodeEntry = struct { hash: Hash, bytes: []u8 };
const AccountFields = struct { nonce: u64, balance: u256, code_hash: Hash };
const Undo = union(enum) {
    fields: struct { address: Address, previous: AccountFields },
    storage: struct { address: Address, slot: u256, previous: ?u256 },
    create: Hash,
    delete: AccountEntry,
};
const SnapshotMarker = struct { id: u64, journal_len: usize };

/// Opaque identifier for the top nested snapshot; snapshots must be closed LIFO.
pub const Snapshot = struct { id: u64 };

/// In-memory account, storage, code, and mutation journal.
pub const State = struct {
    allocator: std.mem.Allocator,
    accounts: std.ArrayList(AccountEntry) = .empty,
    account_index: std.AutoHashMap(Hash, usize),
    codes: std.ArrayList(CodeEntry) = .empty,
    code_index: std.AutoHashMap(Hash, usize),
    storage_index: std.AutoHashMap(StorageKey, usize),
    storage_tries: std.AutoHashMap(Hash, trie.Trie),
    journal: std.ArrayList(Undo) = .empty,
    snapshots: std.ArrayList(SnapshotMarker) = .empty,
    next_snapshot_id: u64 = 1,
    cached_state_root: ?Hash = null,
    state_trie: trie.Trie,
    root_cache_lock: std.atomic.Mutex = .unlocked,

    /// Creates an empty state using the supplied allocator for all owned data.
    pub fn init(allocator: std.mem.Allocator) State {
        return .{
            .allocator = allocator,
            .account_index = .init(allocator),
            .code_index = .init(allocator),
            .storage_index = .init(allocator),
            .storage_tries = .init(allocator),
            .state_trie = trie.Trie.init(allocator, false),
        };
    }

    /// Releases accounts, code bytes, and any saved journal entries.
    pub fn deinit(self: *State) void {
        for (self.accounts.items) |*entry| self.deinitAccount(entry);
        self.accounts.deinit(self.allocator);
        self.account_index.deinit();
        for (self.codes.items) |code| self.allocator.free(code.bytes);
        self.codes.deinit(self.allocator);
        self.code_index.deinit();
        self.storage_index.deinit();
        var storage_iterator = self.storage_tries.iterator();
        while (storage_iterator.next()) |entry| entry.value_ptr.deinit();
        self.storage_tries.deinit();
        self.clearJournal();
        self.journal.deinit(self.allocator);
        self.snapshots.deinit(self.allocator);
        self.state_trie.deinit();
        self.* = undefined;
    }

    /// Copies committed account, code, and storage values for a canonical block snapshot.
    pub fn clone(self: *const State, allocator: std.mem.Allocator) !State {
        var copy = State.init(allocator);
        errdefer copy.deinit();
        for (self.accounts.items) |entry| {
            var cloned = try copy.cloneAccount(entry);
            _ = copy.appendNewAccount(cloned) catch |err| {
                copy.deinitAccount(&cloned);
                return err;
            };
        }
        for (self.codes.items) |code| {
            try copy.storeCode(code.hash, code.bytes);
        }
        return copy;
    }

    /// Encodes every account for a periodic durable checkpoint.
    pub fn checkpointBytes(self: *const State, allocator: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try appendStateInt(&out, allocator, u32, @intCast(self.accounts.items.len));
        for (self.accounts.items) |*entry| try self.writeAccount(&out, allocator, entry);
        return out.toOwnedSlice(allocator);
    }

    /// Encodes account replacements and deletions relative to a parent state.
    pub fn deltaBytes(self: *const State, allocator: std.mem.Allocator, parent: *const State) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendNTimes(allocator, 0, 4);
        var count: u32 = 0;
        for (parent.accounts.items) |entry| if (self.account_index.get(entry.key) == null) {
            try out.append(allocator, 3);
            try out.appendSlice(allocator, &entry.key);
            count = try std.math.add(u32, count, 1);
        };
        for (self.accounts.items) |*entry| {
            const old = if (parent.account_index.get(entry.key)) |i| &parent.accounts.items[i] else null;
            if (old != null and self.sameAccount(parent, entry, old.?)) continue;
            try self.writeAccount(&out, allocator, entry);
            count = try std.math.add(u32, count, 1);
        }
        std.mem.writeInt(u32, out.items[0..4], count, .little);
        return out.toOwnedSlice(allocator);
    }

    /// Applies a checked checkpoint or delta to the current state.
    pub fn applyStateBytes(self: *State, bytes: []const u8) !void {
        var offset: usize = 0;
        const count = try takeStateInt(u32, bytes, &offset);
        if (count > (bytes.len - offset) / 21) return error.InvalidStateData;
        var seen: std.AutoHashMap(Hash, void) = .init(self.allocator);
        defer seen.deinit();
        for (0..count) |_| {
            const tag = (try takeStateBytes(bytes, &offset, 1))[0];
            if (tag > 3) return error.InvalidStateData;
            const has_preimage = tag <= 1;
            const address: Address = if (has_preimage) (try takeStateBytes(bytes, &offset, 20))[0..20].* else .{0} ** 20;
            const key: Hash = if (has_preimage) keccak(&address) else (try takeStateBytes(bytes, &offset, 32))[0..32].*;
            if (seen.contains(key)) return error.InvalidStateData;
            try seen.put(key, {});
            if (tag == 0 or tag == 3) {
                try self.deleteAccountByKey(key);
                continue;
            }
            const nonce = try takeStateInt(u64, bytes, &offset);
            const balance = try takeStateInt(u256, bytes, &offset);
            const code_len = try takeStateInt(u32, bytes, &offset);
            if (code_len > max_checkpoint_code_size) return error.InvalidStateData;
            const code = try takeStateBytes(bytes, &offset, code_len);
            const slots = try takeStateInt(u32, bytes, &offset);
            if (slots > (bytes.len - offset) / 64) return error.InvalidStateData;
            try self.deleteAccountByKey(key);
            if (code.len != 0) try self.storeCode(keccak(code), code);
            var entry = AccountEntry{ .address = address, .key = key, .nonce = nonce, .balance = balance, .code_hash = keccak(code) };
            var owned = true;
            errdefer if (owned) entry.storage.deinit(self.allocator);
            for (0..slots) |_| {
                const slot = if (has_preimage) try takeStateInt(u256, bytes, &offset) else 0;
                const slot_key: Hash = if (has_preimage) slotHash(slot) else (try takeStateBytes(bytes, &offset, 32))[0..32].*;
                const value = try takeStateInt(u256, bytes, &offset);
                if (value == 0) return error.InvalidStateData;
                for (entry.storage.items) |stored| if (std.mem.eql(u8, &stored.key, &slot_key)) return error.InvalidStateData;
                try entry.storage.append(self.allocator, .{ .key = slot_key, .value = value });
            }
            _ = try self.appendNewAccount(entry);
            owned = false;
        }
        if (offset != bytes.len) return error.InvalidStateData;
    }

    /// Compares consensus account values and storage without depending on slot order.
    fn sameAccount(self: *const State, parent: *const State, current: *const AccountEntry, old: *const AccountEntry) bool {
        _ = self;
        if (current.nonce != old.nonce or current.balance != old.balance or current.storage.items.len != old.storage.items.len) return false;
        if (!std.mem.eql(u8, &current.code_hash, &old.code_hash)) return false;
        for (current.storage.items) |slot| {
            const index = parent.storage_index.get(.{ .address = old.key, .slot = slot.key }) orelse return false;
            if (old.storage.items[index].value != slot.value) return false;
        }
        return true;
    }

    /// Writes one full account replacement with code and storage.
    fn writeAccount(self: *const State, out: *std.ArrayList(u8), allocator: std.mem.Allocator, entry: *const AccountEntry) !void {
        try out.append(allocator, 2);
        try out.appendSlice(allocator, &entry.key);
        try appendStateInt(out, allocator, u64, entry.nonce);
        try appendStateInt(out, allocator, u256, entry.balance);
        const code = if (self.code_index.get(entry.code_hash)) |i| self.codes.items[i].bytes else &.{};
        if (code.len > max_checkpoint_code_size) return error.ExecutionCodeTooLarge;
        try appendStateInt(out, allocator, u32, @intCast(code.len));
        try out.appendSlice(allocator, code);
        try appendStateInt(out, allocator, u32, @intCast(entry.storage.items.len));
        for (entry.storage.items) |slot| {
            try out.appendSlice(allocator, &slot.key);
            try appendStateInt(out, allocator, u256, slot.value);
        }
    }

    /// Creates an explicit empty account; creating an existing account is a no-op.
    pub fn createAccount(self: *State, address: Address) !void {
        if (self.findAccount(address) != null) return;
        self.cached_state_root = null;
        _ = try self.appendNewAccount(.{ .address = address, .key = keccak(&address) });
    }

    /// Removes an account and its storage; absent account deletion is a no-op.
    pub fn deleteAccount(self: *State, address: Address) !void {
        try self.deleteAccountByKey(keccak(&address));
    }

    /// Removes an account by its hashed trie key, preserving snapshot undo.
    fn deleteAccountByKey(self: *State, key: Hash) !void {
        const index = self.account_index.get(key) orelse return;
        self.cached_state_root = null;
        self.state_trie.delete(&key);
        self.removeStorageTrie(key);
        try self.recordDeleteByKey(key);
        var removed = self.accounts.swapRemove(index);
        self.removeStorageIndex(&removed);
        _ = self.account_index.remove(key);
        if (index < self.accounts.items.len) {
            const moved = &self.accounts.items[index];
            self.account_index.getPtr(moved.key).?.* = index;
        }
        self.deinitAccount(&removed);
    }

    /// Returns account fields with a freshly computed storage root, or null if absent.
    pub fn getAccount(self: *State, address: Address) !?Account {
        self.lockRootCache();
        defer self.root_cache_lock.unlock();
        const index = self.findAccount(address) orelse return null;
        const entry = &self.accounts.items[index];
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
        if (entry.nonce == nonce) return;
        self.cached_state_root = null;
        self.clearAccountValue(entry);
        entry.nonce = nonce;
    }

    /// Sets a balance and creates an account only for a nonzero value.
    pub fn setBalance(self: *State, address: Address, balance: u256) !void {
        const entry = try self.writableAccount(address, balance != 0) orelse return;
        if (entry.balance == balance) return;
        self.cached_state_root = null;
        self.clearAccountValue(entry);
        entry.balance = balance;
    }

    /// Returns stored code borrowed from this state until deinit, or empty bytes for a missing account.
    pub fn getCode(self: *const State, address: Address) []const u8 {
        const account = self.findAccountConst(address) orelse return &.{};
        const index = self.code_index.get(account.code_hash) orelse return &.{};
        return self.codes.items[index].bytes;
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
        if (std.mem.eql(u8, &entry.code_hash, &hash)) return hash;
        self.cached_state_root = null;
        self.clearAccountValue(entry);
        entry.code_hash = hash;
        return hash;
    }

    /// Returns a storage word, or zero when its account or slot is absent.
    pub fn getStorage(self: *const State, address: Address, slot: u256) u256 {
        const entry = self.findAccountConst(address) orelse return 0;
        const index = self.storage_index.get(.{ .address = entry.key, .slot = slotHash(slot) }) orelse return 0;
        return entry.storage.items[index].value;
    }

    /// Sets a storage word; writing zero deletes the slot and never creates an absent account.
    pub fn setStorage(self: *State, address: Address, slot: u256, value: u256) !void {
        const account_key = keccak(&address);
        const slot_key = slotHash(slot);
        const key = StorageKey{ .address = account_key, .slot = slot_key };
        const index = self.findAccount(address);
        if (index) |account_index| {
            const entry = &self.accounts.items[account_index];
            if (self.storage_index.get(key)) |slot_index| {
                if (value == 0) {
                    const journal_len = self.journal.items.len;
                    try self.recordStorage(address, slot, entry.storage.items[slot_index].value);
                    self.updateStorageTrie(account_key, slot_key, value) catch |err| {
                        if (self.journal.items.len > journal_len) self.cancelLastUndo();
                        return err;
                    };
                    self.cached_state_root = null;
                    entry.cached_storage_root = null;
                    self.clearAccountValue(entry);
                    _ = entry.storage.swapRemove(slot_index);
                    _ = self.storage_index.remove(key);
                    if (slot_index < entry.storage.items.len) {
                        const moved = entry.storage.items[slot_index];
                        self.storage_index.getPtr(.{ .address = account_key, .slot = moved.key }).?.* = slot_index;
                    }
                } else {
                    if (entry.storage.items[slot_index].value == value) return;
                    const journal_len = self.journal.items.len;
                    try self.recordStorage(address, slot, entry.storage.items[slot_index].value);
                    self.updateStorageTrie(account_key, slot_key, value) catch |err| {
                        if (self.journal.items.len > journal_len) self.cancelLastUndo();
                        return err;
                    };
                    self.cached_state_root = null;
                    entry.cached_storage_root = null;
                    self.clearAccountValue(entry);
                    entry.storage.items[slot_index].value = value;
                }
                return;
            }
            if (value == 0) return;
            const journal_len = self.journal.items.len;
            try self.recordStorage(address, slot, null);
            try self.storage_index.ensureUnusedCapacity(1);
            try entry.storage.ensureUnusedCapacity(self.allocator, 1);
            self.updateStorageTrie(account_key, slot_key, value) catch |err| {
                if (self.journal.items.len > journal_len) self.cancelLastUndo();
                return err;
            };
            self.cached_state_root = null;
            entry.cached_storage_root = null;
            self.clearAccountValue(entry);
            entry.storage.appendAssumeCapacity(.{ .key = slot_key, .value = value });
            self.storage_index.putAssumeCapacity(key, entry.storage.items.len - 1);
            return;
        }
        if (value == 0) return;
        self.cached_state_root = null;
        var entry = AccountEntry{ .address = address, .key = account_key };
        errdefer self.deinitAccount(&entry);
        try entry.storage.append(self.allocator, .{ .key = slot_key, .value = value });
        _ = try self.appendNewAccount(entry);
    }

    /// Computes the secure root; simultaneous root reads are serialized, while mutations require exclusive access.
    pub fn stateRoot(self: *State) !Hash {
        self.lockRootCache();
        defer self.root_cache_lock.unlock();
        if (self.cached_state_root) |root_hash| return root_hash;
        for (self.accounts.items) |*entry| {
            if (entry.cached_account_value == null) {
                const storage_root = try self.storageRoot(entry);
                const encoded = try encodeAccount(self.allocator, .{
                    .nonce = entry.nonce,
                    .balance = entry.balance,
                    .storage_root = storage_root,
                    .code_hash = entry.code_hash,
                });
                entry.cached_account_value = encoded;
            }
            try self.state_trie.put(&entry.key, entry.cached_account_value.?);
        }
        const root_hash = try self.state_trie.root();
        self.cached_state_root = root_hash;
        return root_hash;
    }

    /// Serializes derived-root reads so concurrent readers cannot mutate caches together.
    fn lockRootCache(self: *State) void {
        while (!self.root_cache_lock.tryLock()) std.atomic.spinLoopHint();
    }

    /// Sums rebuilt nodes retained in current trie caches for benchmark comparisons.
    pub fn trieNodeBuilds(self: *State) usize {
        self.lockRootCache();
        defer self.root_cache_lock.unlock();
        var builds = self.state_trie.root_node_builds;
        var iterator = self.storage_tries.iterator();
        while (iterator.next()) |entry| builds += entry.value_ptr.root_node_builds;
        return builds;
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
        return self.account_index.get(keccak(&address));
    }

    /// Returns an account entry when the address exists.
    fn findAccountConst(self: *const State, address: Address) ?*const AccountEntry {
        const index = self.findAccount(address) orelse return null;
        return &self.accounts.items[index];
    }

    /// Journals the prior entry and appends a new account entry.
    fn appendNewAccount(self: *State, entry: AccountEntry) !*AccountEntry {
        try self.account_index.ensureUnusedCapacity(1);
        try self.storage_index.ensureUnusedCapacity(@intCast(entry.storage.items.len));
        const journal_len = self.journal.items.len;
        try self.recordCreate(entry.key);
        errdefer if (self.journal.items.len > journal_len) self.cancelLastUndo();
        try self.accounts.append(self.allocator, entry);
        self.cached_state_root = null;
        const index = self.accounts.items.len - 1;
        self.account_index.putAssumeCapacity(entry.key, index);
        for (entry.storage.items, 0..) |stored, slot_index| {
            self.storage_index.putAssumeCapacity(.{ .address = entry.key, .slot = stored.key }, slot_index);
        }
        return &self.accounts.items[index];
    }

    /// Journals an existing account before a write, or creates one when requested.
    fn writableAccount(self: *State, address: Address, create: bool) !?*AccountEntry {
        if (self.findAccount(address)) |index| {
            try self.recordAccount(address);
            return &self.accounts.items[index];
        }
        if (!create) return null;
        return try self.appendNewAccount(.{ .address = address, .key = keccak(&address) });
    }

    /// Record the account fields a later snapshot revert must restore.
    fn recordAccount(self: *State, address: Address) !void {
        if (self.snapshots.items.len == 0) return;
        const index = self.findAccount(address) orelse return;
        const entry = self.accounts.items[index];
        try self.journal.append(self.allocator, .{ .fields = .{
            .address = address,
            .previous = .{ .nonce = entry.nonce, .balance = entry.balance, .code_hash = entry.code_hash },
        } });
    }

    /// Record that an account did not exist before this snapshot.
    fn recordCreate(self: *State, key: Hash) !void {
        if (self.snapshots.items.len == 0) return;
        try self.journal.append(self.allocator, .{ .create = key });
    }

    /// Saves a deleted account selected by its trie key for snapshot undo.
    fn recordDeleteByKey(self: *State, key: Hash) !void {
        if (self.snapshots.items.len == 0) return;
        const index = self.account_index.get(key) orelse return;
        var previous = try self.cloneAccount(self.accounts.items[index]);
        errdefer self.deinitAccount(&previous);
        try self.journal.append(self.allocator, .{ .delete = previous });
    }

    /// Record one storage slot's prior value, or its absence.
    fn recordStorage(self: *State, address: Address, slot: u256, previous: ?u256) !void {
        if (self.snapshots.items.len == 0) return;
        try self.journal.append(self.allocator, .{ .storage = .{ .address = address, .slot = slot, .previous = previous } });
    }

    /// Deep-copies one account and its storage slots for journal ownership.
    fn cloneAccount(self: *const State, entry: AccountEntry) !AccountEntry {
        var copy = entry;
        copy.storage = .empty;
        copy.cached_account_value = null;
        errdefer copy.storage.deinit(self.allocator);
        try copy.storage.appendSlice(self.allocator, entry.storage.items);
        return copy;
    }

    /// Restore one delta without allocation by reusing retained list capacity.
    fn applyUndo(self: *State, undo: Undo) void {
        self.cached_state_root = null;
        switch (undo) {
            .fields => |fields| {
                if (self.findAccount(fields.address)) |index| {
                    const entry = &self.accounts.items[index];
                    entry.nonce = fields.previous.nonce;
                    entry.balance = fields.previous.balance;
                    entry.code_hash = fields.previous.code_hash;
                    self.clearAccountValue(entry);
                }
            },
            .storage => |storage| self.undoStorage(storage.address, storage.slot, storage.previous),
            .create => |key| self.removeAccount(key),
            .delete => |previous| self.restoreAccount(previous),
        }
    }

    /// Restore one storage slot to a prior value or remove it.
    fn undoStorage(self: *State, address: Address, slot: u256, previous: ?u256) void {
        const account_index = self.findAccount(address) orelse return;
        const entry = &self.accounts.items[account_index];
        self.removeStorageTrie(entry.key);
        entry.cached_storage_root = null;
        self.clearAccountValue(entry);
        const key = StorageKey{ .address = keccak(&address), .slot = slotHash(slot) };
        if (previous) |value| {
            if (self.storage_index.get(key)) |slot_index| {
                entry.storage.items[slot_index].value = value;
            } else {
                entry.storage.appendAssumeCapacity(.{ .key = key.slot, .value = value });
                self.storage_index.putAssumeCapacity(key, entry.storage.items.len - 1);
            }
        } else if (self.storage_index.get(key)) |slot_index| {
            _ = entry.storage.swapRemove(slot_index);
            _ = self.storage_index.remove(key);
            if (slot_index < entry.storage.items.len) {
                const moved = entry.storage.items[slot_index];
                self.storage_index.getPtr(.{ .address = key.address, .slot = moved.key }).?.* = slot_index;
            }
        }
    }

    /// Insert one restored account after its deletion.
    fn restoreAccount(self: *State, previous: AccountEntry) void {
        self.cached_state_root = null;
        self.accounts.appendAssumeCapacity(previous);
        const index = self.accounts.items.len - 1;
        self.account_index.putAssumeCapacity(previous.key, index);
        for (previous.storage.items, 0..) |stored, slot_index| {
            self.storage_index.putAssumeCapacity(.{ .address = previous.key, .slot = stored.key }, slot_index);
        }
    }

    /// Remove one account and all of its index entries.
    fn removeAccount(self: *State, key: Hash) void {
        const index = self.account_index.get(key) orelse return;
        self.cached_state_root = null;
        self.state_trie.delete(&key);
        self.removeStorageTrie(key);
        var removed = self.accounts.swapRemove(index);
        self.removeStorageIndex(&removed);
        _ = self.account_index.remove(key);
        if (index < self.accounts.items.len) {
            const moved = &self.accounts.items[index];
            self.account_index.getPtr(moved.key).?.* = index;
        }
        self.deinitAccount(&removed);
    }

    /// Remove every indexed storage slot owned by one account.
    fn removeStorageIndex(self: *State, entry: *const AccountEntry) void {
        for (entry.storage.items) |stored| _ = self.storage_index.remove(.{ .address = entry.key, .slot = stored.key });
    }

    /// Frees an unneeded last journal record after an account append failure.
    fn cancelLastUndo(self: *State) void {
        var undo = self.journal.pop().?;
        self.deinitUndo(&undo);
    }

    /// Frees deletion snapshots and compacts the completed delta log.
    fn clearJournal(self: *State) void {
        while (self.journal.pop()) |undo_const| {
            var undo = undo_const;
            self.deinitUndo(&undo);
        }
    }

    /// Release any storage owned by one delta.
    fn deinitUndo(self: *const State, undo: *Undo) void {
        switch (undo.*) {
            .delete => |*entry| self.deinitAccount(entry),
            else => {},
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
    fn storageRoot(self: *State, account: *AccountEntry) !Hash {
        if (account.cached_storage_root) |root_hash| return root_hash;
        const storage_trie = try self.getStorageTrie(account.key);
        for (account.storage.items) |stored| {
            const value = try encodeValue(self.allocator, stored.value);
            defer self.allocator.free(value);
            try storage_trie.put(&stored.key, value);
        }
        const root_hash = try storage_trie.root();
        account.cached_storage_root = root_hash;
        return root_hash;
    }

    /// Returns an existing per-account trie or creates an empty one.
    fn getStorageTrie(self: *State, key: Hash) !*trie.Trie {
        if (self.storage_tries.getPtr(key)) |storage_trie| return storage_trie;
        try self.storage_tries.ensureUnusedCapacity(1);
        self.storage_tries.putAssumeCapacity(key, trie.Trie.init(self.allocator, false));
        return self.storage_tries.getPtr(key).?;
    }

    /// Updates a materialized account storage trie for one slot mutation.
    fn updateStorageTrie(self: *State, key: Hash, slot_key: Hash, value: u256) !void {
        const storage_trie = self.storage_tries.getPtr(key) orelse return;
        if (value == 0) {
            storage_trie.delete(&slot_key);
            return;
        }
        const encoded = try encodeValue(self.allocator, value);
        defer self.allocator.free(encoded);
        try storage_trie.put(&slot_key, encoded);
    }

    /// Removes and frees one account's cached storage trie before deletion or rollback.
    fn removeStorageTrie(self: *State, key: Hash) void {
        if (self.storage_tries.fetchRemove(key)) |removed| {
            var storage_trie = removed.value;
            storage_trie.deinit();
        }
    }

    /// Stores code once by hash; code content is immutable for this State lifetime.
    fn storeCode(self: *State, hash: Hash, bytes: []const u8) !void {
        if (self.code_index.contains(hash)) return;
        try self.code_index.ensureUnusedCapacity(1);
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);
        try self.codes.append(self.allocator, .{ .hash = hash, .bytes = owned });
        self.code_index.putAssumeCapacity(hash, self.codes.items.len - 1);
    }

    /// Frees one account entry and its storage list.
    fn deinitAccount(self: *const State, entry: *AccountEntry) void {
        entry.storage.deinit(self.allocator);
        if (entry.cached_account_value) |value| self.allocator.free(value);
        // SAFETY: This value is fully initialized before any read.
        entry.* = undefined;
    }

    /// Frees the encoded account value after one consensus field changes.
    fn clearAccountValue(self: *const State, entry: *AccountEntry) void {
        if (entry.cached_account_value) |value| self.allocator.free(value);
        entry.cached_account_value = null;
    }
};

/// Appends a fixed-width state integer in little-endian order.
fn appendStateInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try out.appendSlice(allocator, &encoded);
}

/// Takes a bounded byte slice from durable state data.
fn takeStateBytes(bytes: []const u8, offset: *usize, count: usize) ![]const u8 {
    if (offset.* > bytes.len or count > bytes.len - offset.*) return error.InvalidStateData;
    const field = bytes[offset.*..][0..count];
    offset.* += count;
    return field;
}

/// Reads a fixed-width state integer from durable data.
fn takeStateInt(comptime T: type, bytes: []const u8, offset: *usize) !T {
    const field = try takeStateBytes(bytes, offset, @sizeOf(T));
    return std.mem.readInt(T, field[0..@sizeOf(T)], .little);
}

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
    // SAFETY: This value is fully initialized before any read.
    var digest: Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(bytes, &digest, .{});
    return digest;
}

/// Hashes a 256-bit storage slot as the secure storage trie key.
fn slotHash(slot: u256) Hash {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, slot, .big);
    return keccak(&bytes);
}

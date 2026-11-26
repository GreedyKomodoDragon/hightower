// An execution fork ID checks whether peers share the genesis and applied
// protocol upgrades. Block activations precede timestamp activations; each
// distinct non-genesis activation extends CRC32 with its big-endian uint64.
// The bounded schedule holds at most 32 activations of each kind.
//
// genesis CRC -> passed blocks -> passed timestamps -> next activation
const std = @import("std");

pub const Id = struct { hash: [4]u8, next: u64 };
pub const Schedule = struct {
    genesis: [32]u8,
    genesis_time: u64,
    blocks: [32]u64 = .{0} ** 32,
    block_count: usize = 0,
    times: [32]u64 = .{0} ** 32,
    time_count: usize = 0,

    /// Add a known fork activation, coalescing forks at the same height or time.
    pub fn add(self: *Schedule, timestamp: bool, value: u64) !void {
        if (value == 0 or timestamp and value <= self.genesis_time) return;
        const entries = if (timestamp) &self.times else &self.blocks;
        const count = if (timestamp) &self.time_count else &self.block_count;
        for (entries[0..count.*]) |existing| if (existing == value) return;
        if (count.* == entries.len) return error.TooManyForks;
        entries[count.*] = value;
        count.* += 1;
        std.mem.sort(u64, entries[0..count.*], {}, std.sort.asc(u64));
    }

    /// Compute the current EIP-2124 ID from the canonical head coordinates.
    pub fn at(self: Schedule, block: u64, timestamp: u64) Id {
        var crc = std.hash.Crc32.init();
        crc.update(&self.genesis);
        var next: u64 = 0;
        for (self.blocks[0..self.block_count]) |activation| {
            if (activation > block) {
                next = activation;
                break;
            }
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, activation, .big);
            crc.update(&bytes);
        }
        if (next == 0) for (self.times[0..self.time_count]) |activation| {
            if (activation > timestamp) {
                next = activation;
                break;
            }
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, activation, .big);
            crc.update(&bytes);
        };
        var hash: [4]u8 = undefined;
        std.mem.writeInt(u32, &hash, crc.final(), .big);
        return .{ .hash = hash, .next = next };
    }

    /// Apply EIP-2124's same, subset, and known-superset compatibility cases.
    pub fn compatible(self: Schedule, block: u64, timestamp: u64, remote: Id) bool {
        var crc = std.hash.Crc32.init();
        crc.update(&self.genesis);
        var hashes: [65][4]u8 = undefined;
        var activations: [64]u64 = undefined;
        hashes[0] = hashOf(crc);
        for (self.blocks[0..self.block_count], 0..) |activation, index| {
            activations[index] = activation;
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, activation, .big);
            crc.update(&bytes);
            hashes[index + 1] = hashOf(crc);
        }
        for (self.times[0..self.time_count], 0..) |activation, index| {
            const at_index = self.block_count + index;
            activations[at_index] = activation;
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, activation, .big);
            crc.update(&bytes);
            hashes[at_index + 1] = hashOf(crc);
        }
        const total = self.block_count + self.time_count;
        var local_index: usize = 0;
        while (local_index < total) : (local_index += 1) {
            const head = if (local_index < self.block_count) block else timestamp;
            if (head < activations[local_index]) break;
        }
        if (std.mem.eql(u8, &hashes[local_index], &remote.hash)) {
            const head = if (local_index < self.block_count or self.time_count == 0) block else timestamp;
            // Geth treats values above mainnet genesis time as timestamps in the transition era.
            const timestamp_threshold: u64 = 1_438_269_973;
            return remote.next == 0 or head < remote.next and !(remote.next > timestamp_threshold and timestamp >= remote.next);
        }
        for (hashes[0..local_index], 0..) |hash, index| {
            if (std.mem.eql(u8, &hash, &remote.hash)) return remote.next == activations[index];
        }
        for (hashes[local_index + 1 .. total + 1]) |hash| {
            if (std.mem.eql(u8, &hash, &remote.hash)) return true;
        }
        return false;
    }
};

/// Read one CRC32 state as a network-order fork hash.
fn hashOf(crc: std.hash.Crc32) [4]u8 {
    var hash: [4]u8 = undefined;
    std.mem.writeInt(u32, &hash, crc.final(), .big);
    return hash;
}

test "fork IDs follow block and timestamp activations" {
    var schedule = Schedule{ .genesis = .{1} ** 32, .genesis_time = 100 };
    try schedule.add(false, 0);
    try schedule.add(false, 5);
    try schedule.add(false, 5);
    try schedule.add(true, 120);
    const before = schedule.at(4, 110);
    const middle = schedule.at(5, 110);
    const after = schedule.at(5, 120);
    try std.testing.expectEqual(@as(u64, 5), before.next);
    try std.testing.expectEqual(@as(u64, 120), middle.next);
    try std.testing.expectEqual(@as(u64, 0), after.next);
    try std.testing.expect(!std.mem.eql(u8, &before.hash, &middle.hash));
    try std.testing.expect(!std.mem.eql(u8, &middle.hash, &after.hash));
    try std.testing.expect(schedule.compatible(5, 120, before));
    try std.testing.expect(schedule.compatible(4, 110, after));
    try std.testing.expect(!schedule.compatible(5, 120, .{ .hash = .{0} ** 4, .next = 0 }));
    try std.testing.expect(!schedule.compatible(5, 120, .{ .hash = after.hash, .next = 110 }));
    var divergent = schedule;
    divergent.blocks[0] = 6;
    try std.testing.expect(!schedule.compatible(5, 120, divergent.at(6, 120)));
}

test "EIP-2124 mainnet block fork vectors" {
    var genesis: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&genesis, "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
    var schedule = Schedule{ .genesis = genesis, .genesis_time = 0 };
    for ([_]u64{ 1_150_000, 1_920_000, 2_463_000 }) |activation| try schedule.add(false, activation);
    try std.testing.expectEqualDeep(Id{ .hash = .{ 0xfc, 0x64, 0xec, 0x04 }, .next = 1_150_000 }, schedule.at(0, 0));
    try std.testing.expectEqualDeep(Id{ .hash = .{ 0x97, 0xc2, 0xc3, 0x4c }, .next = 1_920_000 }, schedule.at(1_150_000, 0));
    try std.testing.expectEqualDeep(Id{ .hash = .{ 0x91, 0xd1, 0xf9, 0x48 }, .next = 2_463_000 }, schedule.at(1_920_000, 0));
}

// A signing domain binds a signature to an operation type, fork version, and
// genesis validators root (the chain identity). ForkData and SigningData are
// two-field SSZ containers: hash their padded fields in their declared order.
// These pure helpers never mutate state. getDomain selects the previous version
// strictly before the fork epoch and the current version at or after it.
// Deposits use the genesis version and zero root; BLS-to-execution changes use
// the genesis version and chain root; voluntary exits use the Capella version.
// Those fixed-version callers must pass their network version to computeDomain.
const std = @import("std");
const fulu = @import("fulu");

pub fn computeDomain(domain_type: [4]u8, fork_version: fulu.Version, genesis_validators_root: fulu.Root) [32]u8 {
    var fork_version_chunk = [_]u8{0} ** 32;
    @memcpy(fork_version_chunk[0..4], &fork_version);
    var fork_data_input: [64]u8 = undefined;
    @memcpy(fork_data_input[0..32], &fork_version_chunk);
    @memcpy(fork_data_input[32..64], &genesis_validators_root);
    var fork_data_root: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&fork_data_input, &fork_data_root, .{});

    var domain: [32]u8 = undefined;
    @memcpy(domain[0..4], &domain_type);
    @memcpy(domain[4..32], fork_data_root[0..28]);
    return domain;
}

pub fn computeSigningRoot(object_root: fulu.Root, domain: [32]u8) fulu.Root {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &object_root);
    @memcpy(input[32..64], &domain);
    var root: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &root, .{});
    return root;
}

pub fn getDomain(state: fulu.BeaconState, domain_type: [4]u8, epoch: fulu.Epoch) [32]u8 {
    const version = if (epoch < state.fork.epoch) state.fork.previous_version else state.fork.current_version;
    return computeDomain(domain_type, version, state.genesis_validators_root);
}

fn hex(comptime value: []const u8) [value.len / 2]u8 {
    var bytes: [value.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, value) catch unreachable;
    return bytes;
}

test "pinned minimal fork domains and signing roots" {
    const helpers = @import("helpers.zig");
    const fixtures = @import("fixture_runner.zig");
    var state = try fixtures.decodeState(std.testing.allocator, fixtures.find("slots_1").?.pre.?);
    defer @import("ssz").freeDecoded(std.testing.allocator, fulu.BeaconState, state);
    state.fork = .{ .previous_version = .{ 5, 0, 0, 1 }, .current_version = .{ 6, 0, 0, 1 }, .epoch = 10 };
    state.genesis_validators_root = [_]u8{2} ** 32;
    const object_root = [_]u8{3} ** 32;
    {
        const domain = getDomain(state, helpers.DOMAIN_BEACON_PROPOSER, 9);
        try std.testing.expectEqual(hex("00000000e8332b52eb4b91f0b117253774e7595b44fe992aea805f8c037e25d9"), domain);
        try std.testing.expectEqual(hex("107fd157bcb6fcd41948e868f3ee5c0ec1614b07f826c06068c0cf9659ba107a"), computeSigningRoot(object_root, domain));
    }
    {
        const domain = getDomain(state, helpers.DOMAIN_BEACON_PROPOSER, 10);
        try std.testing.expectEqual(hex("000000004169d190daabab190bdd44462c2593252acd9abbc41bd027c9b432a5"), domain);
        try std.testing.expectEqual(hex("7a2423247e0685b7072e131244afd0b897b5be7ed6fe2bf4b22cddddfb3c3310"), computeSigningRoot(object_root, domain));
    }
    {
        const domain = getDomain(state, helpers.DOMAIN_BEACON_ATTESTER, 11);
        try std.testing.expectEqual(hex("010000004169d190daabab190bdd44462c2593252acd9abbc41bd027c9b432a5"), domain);
        try std.testing.expectEqual(hex("b71a56b7ff8a2bf256db204a21231d389389320cda6d603f8df88a797fd2866a"), computeSigningRoot(object_root, domain));
    }
    {
        const domain = getDomain(state, helpers.DOMAIN_RANDAO, 10);
        try std.testing.expectEqual(hex("020000004169d190daabab190bdd44462c2593252acd9abbc41bd027c9b432a5"), domain);
        try std.testing.expectEqual(hex("4ef61fa5bd8a1164814d2efe634cdc057589fb398ef95540a58650c9b1e6dc91"), computeSigningRoot(object_root, domain));
    }
    {
        const domain = getDomain(state, helpers.DOMAIN_SYNC_COMMITTEE, 10);
        try std.testing.expectEqual(hex("070000004169d190daabab190bdd44462c2593252acd9abbc41bd027c9b432a5"), domain);
        try std.testing.expectEqual(hex("74163a759f2361c72205d23f3d9f33f0f54244fc56d9a86fdf12de48a92575bf"), computeSigningRoot(object_root, domain));
    }
    {
        const domain = computeDomain(helpers.DOMAIN_DEPOSIT, .{ 0, 0, 0, 1 }, [_]u8{0} ** 32);
        try std.testing.expectEqual(hex("0300000018ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053"), domain);
        try std.testing.expectEqual(hex("b34fa307c22575d7f8d8957517f61576e3db0cf076fb7d2cf1efa5c83fddb62b"), computeSigningRoot(object_root, domain));
    }
    {
        const domain = computeDomain(helpers.DOMAIN_BLS_TO_EXECUTION_CHANGE, .{ 0, 0, 0, 1 }, state.genesis_validators_root);
        try std.testing.expectEqual(hex("0a00000075a3f2f4f2163e2c279e9396ef501c3b5eef77e259326d5df14d3bf7"), domain);
        try std.testing.expectEqual(hex("fcdb0b34e87d63d6dae682e66a72ed02d307bae0b04b6d43540ce150d0dd8abc"), computeSigningRoot(object_root, domain));
    }
    {
        const domain = computeDomain(helpers.DOMAIN_VOLUNTARY_EXIT, .{ 3, 0, 0, 1 }, state.genesis_validators_root);
        try std.testing.expectEqual(hex("0400000013f8bd4a0a5509f2c116ab78503e269d76142da0f1548d3da53734c4"), domain);
        try std.testing.expectEqual(hex("47c7f535c0588cb1a5395130e6f1d9d14802c295197f01fc59398ce9c7f0c965"), computeSigningRoot(object_root, domain));
    }
}

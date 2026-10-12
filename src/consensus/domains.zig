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

test "domain and signing root use the SSZ container roots" {
    const domain = computeDomain([_]u8{ 0, 0, 0, 0 }, [_]u8{1} ** 4, [_]u8{2} ** 32);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 4, domain[0..4]);
    const root = computeSigningRoot([_]u8{3} ** 32, domain);
    try std.testing.expect(root[0] != 3 or root[1] != 3);
}

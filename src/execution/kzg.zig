// Blob data travels beside a type-3 transaction, while the block retains only
// its signed payload and versioned hashes. A network wrapper carries either
// one proof per blob or 128 Fulu cell proofs per blob. Verification must finish
// before the payload can enter the pool; a bad sidecar cannot affect state.
//
// network wrapper -> KZG verification -> canonical type-3 payload -> pool
// At most six blobs are accepted per transaction under EIP-7594.
const std = @import("std");
const rlp = @import("rlp");
const ckzg = @import("ckzg");
const execution = @import("execution.zig");
const blob_hash = @import("blob");

pub const Settings = ckzg.Settings;
pub const MAX_BLOBS_PER_TRANSACTION = 6;

/// Loads the pinned v2.1.8 trusted setup from an explicit deployment path.
pub fn loadTrustedSetup(path: [:0]const u8) !Settings {
    return Settings.loadTrustedSetupFile(path, 0);
}

/// Verifies a type-3 network wrapper and returns owned canonical transaction bytes.
pub fn canonicalTransaction(allocator: std.mem.Allocator, settings: *const Settings, raw: []const u8) ![]u8 {
    if (raw.len < 2 or raw[0] != 3) return error.InvalidBlobWrapper;
    var tree = try rlp.decode.decodeAll(allocator, raw[1..]);
    defer tree.deinit(allocator);
    const items = switch (tree) {
        .list => |list| list,
        else => return error.InvalidBlobWrapper,
    };
    if (items.len != 4 and items.len != 5) return error.InvalidBlobWrapper;
    switch (items[0]) {
        .list => {},
        else => return error.InvalidBlobWrapper,
    }
    if (items.len == 5) {
        const version = switch (items[1]) {
            .string => |bytes| bytes,
            else => return error.InvalidBlobWrapper,
        };
        if (version.len != 1 or version[0] != 1) return error.InvalidBlobWrapper;
    }
    const offset: usize = if (items.len == 5) 1 else 0;
    const blobs = switch (items[1 + offset]) {
        .list => |list| list,
        else => return error.InvalidBlobWrapper,
    };
    const commitments = switch (items[2 + offset]) {
        .list => |list| list,
        else => return error.InvalidBlobWrapper,
    };
    const proofs = switch (items[3 + offset]) {
        .list => |list| list,
        else => return error.InvalidBlobWrapper,
    };
    if (blobs.len == 0 or blobs.len > MAX_BLOBS_PER_TRANSACTION or blobs.len != commitments.len or proofs.len != blobs.len * (if (offset == 1) @as(usize, ckzg.CELLS_PER_EXT_BLOB) else 1)) return error.InvalidBlobWrapper;

    var reader: std.Io.Reader = .fixed(raw[1..]);
    const outer = try rlp.decode.readHeader(&reader);
    if (outer.kind != .list) return error.InvalidBlobWrapper;
    const first = try rlp.decode.readHeader(&reader);
    if (first.kind != .list) return error.InvalidBlobWrapper;
    const payload_len = std.math.add(usize, first.header_len, first.payload_len) catch return error.InvalidBlobWrapper;
    if (payload_len > raw.len - 1 - outer.header_len) return error.InvalidBlobWrapper;
    const canonical = try allocator.alloc(u8, payload_len + 1);
    errdefer allocator.free(canonical);
    canonical[0] = 3;
    @memcpy(canonical[1..], raw[1 + outer.header_len ..][0..payload_len]);
    var parsed = try execution.parse(execution.Transaction, allocator, canonical);
    defer parsed.deinit();
    if (parsed.value != .blob or parsed.value.blob.blob_versioned_hashes.len != blobs.len) return error.InvalidBlobWrapper;
    for (blobs, commitments, 0..) |blob_item, commitment_item, i| {
        const blob_bytes = switch (blob_item) {
            .string => |bytes| bytes,
            else => return error.InvalidBlobWrapper,
        };
        const commitment_bytes = switch (commitment_item) {
            .string => |bytes| bytes,
            else => return error.InvalidBlobWrapper,
        };
        if (blob_bytes.len != ckzg.BYTES_PER_BLOB or commitment_bytes.len != 48) return error.InvalidBlobWrapper;
        var blob: ckzg.Blob = .{ .bytes = blob_bytes[0..ckzg.BYTES_PER_BLOB].* };
        var commitment: ckzg.Bytes48 = .{ .bytes = commitment_bytes[0..48].* };
        if (!std.mem.eql(u8, &blob_hash.versionedHash(commitment.bytes), &parsed.value.blob.blob_versioned_hashes[i])) return error.InvalidBlobCommitment;
        const computed = settings.blobToKzgCommitment(&blob) catch return error.InvalidBlobCommitment;
        if (!std.mem.eql(u8, &computed.bytes, &commitment.bytes)) return error.InvalidBlobCommitment;
        if (offset == 0) {
            const proof_bytes = switch (proofs[i]) {
                .string => |bytes| bytes,
                else => return error.InvalidBlobWrapper,
            };
            if (proof_bytes.len != 48) return error.InvalidBlobWrapper;
            var proof: ckzg.Bytes48 = .{ .bytes = proof_bytes[0..48].* };
            if (!(settings.verifyBlobKzgProof(&blob, &commitment, &proof) catch return error.InvalidBlobProof)) return error.InvalidBlobProof;
        } else {
            var cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
            settings.computeCells(&cells, &blob) catch return error.InvalidBlobProof;
            var proof_values: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Bytes48 = undefined;
            var repeated: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Bytes48 = undefined;
            var indices: [ckzg.CELLS_PER_EXT_BLOB]u64 = undefined;
            for (0..ckzg.CELLS_PER_EXT_BLOB) |j| {
                const proof_bytes = switch (proofs[i * ckzg.CELLS_PER_EXT_BLOB + j]) {
                    .string => |bytes| bytes,
                    else => return error.InvalidBlobWrapper,
                };
                if (proof_bytes.len != 48) return error.InvalidBlobWrapper;
                proof_values[j] = .{ .bytes = proof_bytes[0..48].* };
                repeated[j] = commitment;
                indices[j] = @intCast(j);
            }
            if (!(settings.verifyCellKzgProofBatch(&repeated, &indices, &cells, &proof_values) catch return error.InvalidBlobProof)) return error.InvalidBlobProof;
        }
    }
    return canonical;
}

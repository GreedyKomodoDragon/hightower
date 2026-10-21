// Trie vectors model ordered inserts and deletions; each operation changes the
// canonical root, so vector order must be preserved. Secure vectors hash keys
// before branching. These tests cover in-memory roots and inclusion proofs only.
const std = @import("std");
const execution = @import("execution");
const Trie = execution.trie.Trie;
const testing = std.testing;

/// Decodes a vector string as hex when prefixed, or as its literal UTF-8 bytes.
fn vectorBytes(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, text, "0x")) {
        const bytes = try allocator.alloc(u8, (text.len - 2) / 2);
        errdefer allocator.free(bytes);
        return std.fmt.hexToBytes(bytes, text[2..]);
    }
    return allocator.dupe(u8, text);
}

/// Applies one pinned TrieTests file and checks each named final root.
fn checkVectorFile(allocator: std.mem.Allocator, source: []const u8, secure: bool) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, source, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .object);
    var cases = parsed.value.object.iterator();
    while (cases.next()) |item| {
        const operations = item.value_ptr.object.get("in").?.array.items;
        var trie = Trie.init(allocator, secure);
        defer trie.deinit();
        for (operations) |operation| {
            const pair = operation.array.items;
            const key = try vectorBytes(allocator, pair[0].string);
            defer allocator.free(key);
            if (pair[1] == .null) {
                trie.delete(key);
            } else {
                const value = try vectorBytes(allocator, pair[1].string);
                defer allocator.free(value);
                try trie.put(key, value);
            }
        }
        const actual = try trie.root();
        const expected_text = item.value_ptr.object.get("root").?.string;
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, expected_text[2..]);
        try testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "pinned Ethereum trie and secure-trie roots match" {
    try checkVectorFile(testing.allocator, @embedFile("fixtures/trie/trietest.json"), false);
    try checkVectorFile(testing.allocator, @embedFile("fixtures/trie/trietest_secureTrie.json"), true);
}

test "empty trie, single leaf proof, and rejection cases" {
    var empty = Trie.init(testing.allocator, false);
    defer empty.deinit();
    const empty_root = try empty.root();
    try testing.expectEqualSlices(u8, &([_]u8{ 0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21 }), &empty_root);

    var single = Trie.init(testing.allocator, false);
    defer single.deinit();
    try single.put("a", "leaf value");
    const single_root = try single.root();
    try testing.expect(!std.mem.eql(u8, &empty_root, &single_root));
    var single_proof = try single.prove("a");
    defer single_proof.deinit();
    try testing.expect(execution.trie.verifyProof(testing.allocator, single_root, "a", "leaf value", single_proof.nodes, false));
    try testing.expectError(error.KeyNotFound, single.prove("missing"));

    var hashed = Trie.init(testing.allocator, false);
    defer hashed.deinit();
    const long_value = "leaf value longer than thirty two bytes to force a hashed child reference";
    try hashed.put(&.{0x10}, long_value);
    try hashed.put(&.{0x11}, "other");
    const root = try hashed.root();
    var proof = try hashed.prove(&.{0x10});
    defer proof.deinit();
    try testing.expect(execution.trie.verifyProof(testing.allocator, root, &.{0x10}, long_value, proof.nodes, false));
    try testing.expect(!execution.trie.verifyProof(testing.allocator, root, &.{0x10}, "wrong value", proof.nodes, false));
}

test "branching proof resolves inline child nodes" {
    var trie = Trie.init(testing.allocator, false);
    defer trie.deinit();
    try trie.put(&.{0x10}, "small");
    try trie.put(&.{0x20}, "other");
    const root = try trie.root();
    var proof = try trie.prove(&.{0x10});
    defer proof.deinit();
    try testing.expect(execution.trie.verifyProof(testing.allocator, root, &.{0x10}, "small", proof.nodes, false));
    var changed = try trie.prove(&.{0x10});
    defer changed.deinit();
    changed.nodes[0][changed.nodes[0].len - 1] ^= 1;
    try testing.expect(!execution.trie.verifyProof(testing.allocator, root, &.{0x10}, "small", changed.nodes, false));
}

test "ordered transaction roots use RLP indexes and empty values delete" {
    const values = [_][]const u8{ "first", "second" };
    const root = try execution.trie.orderedRoot(testing.allocator, &values);
    var trie = Trie.init(testing.allocator, false);
    defer trie.deinit();
    try trie.put(&.{0x80}, "first");
    try trie.put(&.{1}, "second");
    try testing.expectEqualSlices(u8, &(try trie.root()), &root);
    try trie.put(&.{0x80}, "");
    trie.delete(&.{0x80});
    try testing.expectEqual(@as(usize, 1), trie.entries.items.len);
}

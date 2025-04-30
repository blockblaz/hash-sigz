const std = @import("std");
const sha3 = @import("./sha3.zig");
const ShaTweakHash = sha3.ShaTweakHash;
const ShaTweak = sha3.ShaTweak;
const ssz = @import("ssz");

test "MerkleTree build, path, and verify" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const num_leaves: usize = 1024;
    // Each leaf will consist of `leaf_len` chunks of `hash.hash_size` bytes.
    const leaf_len = 3;

    const parameter = try allocator.alloc(u8, 16);
    defer allocator.free(parameter);
    std.crypto.random.bytes(parameter);

    const hash = ShaTweakHash.init(16, 24);

    // Generate random leaves. Each leaf is a slice of leaf_len chunks.
    var leaves = try allocator.alloc([][]u8, num_leaves);
    defer {
        for (leaves) |leaf_chunks| {
            for (leaf_chunks) |chunk| {
                allocator.free(chunk);
            }
            allocator.free(leaf_chunks);
        }
        allocator.free(leaves);
    }

    // Fill every leaf with `leaf_len` random chunks.
    for (0..num_leaves) |i| {
        leaves[i] = try allocator.alloc([]u8, leaf_len);
        for (0..leaf_len) |j| {
            leaves[i][j] = try allocator.alloc(u8, hash.hash_size);
            std.crypto.random.bytes(leaves[i][j]);
        }
    }

    // Hash the leaves with the level 0 tweak.
    var leaf_hashes = try allocator.alloc([]u8, num_leaves);
    defer {
        for (leaf_hashes) |h| allocator.free(h);
        allocator.free(leaf_hashes);
    }
    for (leaves, 0..) |leaf_chunks, i| {
        leaf_hashes[i] = try allocator.alloc(u8, hash.hash_size);
        const tweak = hash.tree_tweak(0, @as(u32, @intCast(i)));
        hash.hash(parameter, tweak, leaf_chunks, leaf_hashes[i]);
    }

    const tree = try ssz.merkleizeWithTweak(ShaTweakHash, hash, allocator, parameter, leaf_hashes);
    defer {
        for (tree) |node| {
            allocator.free(node);
        }
        allocator.free(tree);
    }

    const root = ssz.treeRoot(tree);

    for (0..num_leaves) |idx| {
        const path = try ssz.buildPath(allocator, tree, idx);
        defer {
            for (path) |node| {
                allocator.free(node);
            }
            allocator.free(path);
        }

        const leaf_tweak = hash.tree_tweak(0, @as(u32, @intCast(idx)));
        const leaf_hash_expected = try allocator.alloc(u8, hash.hash_size);
        defer allocator.free(leaf_hash_expected);
        hash.hash(parameter, leaf_tweak, leaves[idx], leaf_hash_expected);

        const leaf_hash_to_verify = try allocator.dupe(u8, leaf_hash_expected);
        defer allocator.free(leaf_hash_to_verify);

        const ok = ssz.verifyPath(ShaTweakHash, parameter, hash, idx, root, leaf_hash_to_verify, path);
        try testing.expect(ok);
    }
}

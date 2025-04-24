const std = @import("std");
const sha3 = @import("./sha3.zig");
const ShaTweakHash = sha3.ShaTweakHash;
const ShaTweak = sha3.ShaTweak;

pub fn MerkleTree(comptime TweakHash: type) type {
    return struct {
        height: usize,
        nodes: [][]u8,
        hash: TweakHash,

        pub fn build(allocator: std.mem.Allocator, parameter: []u8, hash: TweakHash, leaf_hashes: []const []u8) !@This() {
            const num_leaves = leaf_hashes.len;
            std.debug.assert(num_leaves > 0);
            std.debug.assert(std.math.isPowerOfTwo(num_leaves));
            const height = std.math.log2_int(usize, num_leaves);
            // std.debug.assert(num_leaves == (1 << height));

            const node_count = (2 * num_leaves) - 1;
            var nodes = try allocator.alloc([]u8, node_count);

            for (leaf_hashes, 0..) |leaf_hash, i| {
                const leaf_pos = node_count - num_leaves + i;
                nodes[leaf_pos] = try allocator.dupe(u8, leaf_hash);
            }

            var level: u8 = 1;
            var level_size: usize = num_leaves / 2;
            var level_offset: usize = node_count - num_leaves - level_size;

            while (level_size > 0) {
                for (0..level_size) |i| {
                    const left_child = nodes[level_offset + level_size + i * 2];
                    const right_child = nodes[level_offset + level_size + i * 2 + 1];

                    var combined = [_][]u8{ left_child, right_child };

                    nodes[level_offset + i] = try allocator.alloc(u8, hash.hash_size);
                    const tweak = hash.tree_tweak(level, @as(u32, @intCast(i)));
                    hash.hash(parameter, tweak, &combined, nodes[level_offset + i]);
                }

                level += 1;
                level_size /= 2;
                level_offset -= level_size;
            }

            return @This(){
                .height = height,
                .nodes = nodes,
                .hash = hash,
            };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.nodes) |node| {
                allocator.free(node);
            }
            allocator.free(self.nodes);
        }

        pub fn root(self: *const @This()) []const u8 {
            return self.nodes[0];
        }

        pub fn path(self: *const @This(), allocator: std.mem.Allocator, leaf_index: usize) !MerklePath(TweakHash) {
            // std.debug.assert(leaf_index < (1 << self.height));

            var siblings = try allocator.alloc([]u8, self.height);

            var current_index = leaf_index;
            const num_leaves = @as(u32, 1) << @intCast(self.height);
            const total_nodes = (2 * num_leaves) - 1;
            var node_index = total_nodes - num_leaves + current_index;
            for (0..self.height) |level| {
                const is_left = current_index % 2 == 0;
                const sibling_offset: isize = if (is_left) 1 else -1;

                const sibling_node_index: usize = @intCast(@as(isize, @intCast(node_index)) + sibling_offset);
                siblings[level] = try allocator.dupe(u8, self.nodes[sibling_node_index]);

                current_index /= 2;
                node_index = (node_index - 1) / 2;
            }

            return MerklePath(TweakHash){
                .siblings = siblings,
                .leaf_index = leaf_index,
                .height = self.height,
                .hash = self.hash,
            };
        }
    };
}

pub fn MerklePath(comptime TweakHash: type) type {
    return struct {
        siblings: [][]u8,
        leaf_index: usize,
        height: usize,
        hash: TweakHash,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.siblings) |sibling| {
                allocator.free(sibling);
            }
            allocator.free(self.siblings);
        }

        pub fn verify(self: *const @This(), allocator: std.mem.Allocator, parameter: []u8, root: []const u8, leaf_hash: []const u8) !bool {
            var current = try allocator.dupe(u8, leaf_hash);
            defer allocator.free(current);

            var current_index = self.leaf_index;

            for (0..self.height) |level| {
                const is_left = current_index % 2 == 0;
                const sibling = self.siblings[level];

                const combined = if (is_left)
                    [_][]const u8{ current, sibling }
                else
                    [_][]const u8{ sibling, current };

                const tweak = self.hash.tree_tweak(@as(u8, @intCast(level + 1)), @as(u32, @intCast(current_index / 2)));

                const parent = try allocator.alloc(u8, self.hash.hash_size);
                self.hash.hash(parameter, tweak, &combined, parent);

                allocator.free(current);
                current = parent;

                current_index /= 2;
            }

            const result = std.mem.eql(u8, current, root);
            return result;
        }
    };
}

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
    for (leaves, 0..) |leaf_chunks, i| { // leaf_chunks is [][]u8
        leaf_hashes[i] = try allocator.alloc(u8, hash.hash_size);
        const tweak = hash.tree_tweak(0, @as(u32, @intCast(i)));
        // Pass leaf_chunks directly as it's already [][]u8
        hash.hash(parameter, tweak, leaf_chunks, leaf_hashes[i]);
    }

    // Build the Merkle Tree
    var tree = try MerkleTree(ShaTweakHash).build(allocator, parameter, hash, leaf_hashes);
    defer tree.deinit(allocator);

    const root = tree.root();

    // For every leaf, compute its authentication path and verify it
    // against the original leaf data (which is a slice of chunks).
    for (0..num_leaves) |idx| {
        var path = try tree.path(allocator, idx);
        defer path.deinit(allocator);
        const leaf_tweak = hash.tree_tweak(0, @as(u32, @intCast(idx)));
        const leaf_hash_expected = try allocator.alloc(u8, hash.hash_size);
        defer allocator.free(leaf_hash_expected);
        hash.hash(parameter, leaf_tweak, leaves[idx], leaf_hash_expected);

        const ok = try path.verify(allocator, parameter, root, leaf_hash_expected);
        try testing.expect(ok);
    }
}

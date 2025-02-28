const std = @import("std");
const ShaTweakHash = @import("sha3.zig").ShaTweakHash;

pub const MerkleTree = struct {
    height: usize,
    nodes: [][]u8,
    hash: *const ShaTweakHash,
    
    pub fn build(
        allocator: std.mem.Allocator,
        hash: *const ShaTweakHash,
        leaf_hashes: []const []const u8
    ) !MerkleTree {
        const num_leaves = leaf_hashes.len;
        std.debug.assert(num_leaves > 0);
        
        const height = std.math.log2_int(usize, num_leaves);
        std.debug.assert(num_leaves == (1 << height));
        
        const node_count = (2 * num_leaves) - 1;
        var nodes = try allocator.alloc([]u8, node_count);
        
        for (0..num_leaves) |i| {
            const leaf_pos = node_count - num_leaves + i;
            const tweak = hash.treeTweak(0, @as(u32, i));
            defer allocator.free(tweak);
            
            nodes[leaf_pos] = hash.hash(tweak, leaf_hashes[i]);
        }
        
        var level: u8 = 1;
        var level_size: usize = num_leaves / 2;
        var level_offset: usize = node_count - num_leaves - level_size;
        
        while (level_size > 0) {
            for (0..level_size) |i| {
                const left_child = nodes[level_offset + level_size + i * 2];
                const right_child = nodes[level_offset + level_size + i * 2 + 1];
                
                var combined = try allocator.alloc(u8, left_child.len + right_child.len);
                std.mem.copy(u8, combined, left_child);
                std.mem.copy(u8, combined[left_child.len..], right_child);
                
                const tweak = hash.treeTweak(level, @as(u32, i));
                defer allocator.free(tweak);
                
                nodes[level_offset + i] = hash.hash(tweak, combined);
                allocator.free(combined);
            }
            
            level += 1;
            level_size /= 2;
            level_offset -= level_size;
        }
        
        return MerkleTree{
            .height = height,
            .nodes = nodes,
            .hash = hash,
        };
    }
    
    pub fn deinit(self: *MerkleTree, allocator: std.mem.Allocator) void {
        for (self.nodes) |node| {
            allocator.free(node);
        }
        allocator.free(self.nodes);
    }
    
    pub fn root(self: *const MerkleTree) []const u8 {
        return self.nodes[0];
    }
    
    pub fn path(
        self: *const MerkleTree,
        allocator: std.mem.Allocator,
        leaf_index: usize
    ) !MerklePath {
        std.debug.assert(leaf_index < (1 << self.height));
        
        var siblings = try allocator.alloc([]u8, self.height);
        
        var current_index = leaf_index;
        const num_leaves = 1 << self.height;
        const total_nodes = (2 * num_leaves) - 1;
        var node_index = total_nodes - num_leaves + current_index;
        
        for (0..self.height) |level| {
            const is_left = current_index % 2 == 0;
            const sibling_offset = if (is_left) 1 else -1;
            
            siblings[level] = try allocator.dupe(u8, self.nodes[node_index + sibling_offset]);
            
            current_index /= 2;
            node_index = (node_index - 1) / 2;
        }
        
        return MerklePath{
            .siblings = siblings,
            .leaf_index = leaf_index,
            .height = self.height,
            .hash = self.hash,
        };
    }
};

pub const MerklePath = struct {
    siblings: [][]u8,
    leaf_index: usize,
    height: usize,
    hash: *const ShaTweakHash,
    
    pub fn deinit(self: *MerklePath, allocator: std.mem.Allocator) void {
        for (self.siblings) |sibling| {
            allocator.free(sibling);
        }
        allocator.free(self.siblings);
    }
    
    pub fn verify(
        self: *const MerklePath,
        allocator: std.mem.Allocator,
        root: []const u8,
        leaf: []const u8
    ) !bool {
        const leaf_tweak = self.hash.treeTweak(0, @as(u32, self.leaf_index));
        defer allocator.free(leaf_tweak);
        var current = self.hash.hash(leaf_tweak, leaf);
        defer allocator.free(current);
        
        var current_index = self.leaf_index;
        
        for (0..self.height) |level| {
            const is_left = current_index % 2 == 0;
            const sibling = self.siblings[level];
            
            var combined = try allocator.alloc(u8, current.len + sibling.len);
            defer allocator.free(combined);
            
            if (is_left) {
                std.mem.copy(u8, combined, current);
                std.mem.copy(u8, combined[current.len..], sibling);
            } else {
                std.mem.copy(u8, combined, sibling);
                std.mem.copy(u8, combined[sibling.len..], current);
            }
            
            const tweak = self.hash.treeTweak(@as(u8, level + 1), @as(u32, current_index / 2));
            defer allocator.free(tweak);
            
            const parent = self.hash.hash(tweak, combined);
            allocator.free(current);
            current = parent;
            
            current_index /= 2;
        }
        
        return std.mem.eql(u8, current, root);
    }
};
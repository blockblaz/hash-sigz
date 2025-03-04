const std = @import("std");

pub fn MerkleTree(comptime TweakHash: type) type {
    return struct {
        height: usize,
        nodes: [][]u8,
        hash: TweakHash,
        
        pub fn build(
            allocator: std.mem.Allocator,
            hash: TweakHash,
            leaf_hashes: []const []const u8
        ) !@This() {
            const num_leaves = leaf_hashes.len;
            std.debug.assert(num_leaves > 0);
            
            const height = std.math.log2_int(usize, num_leaves);
            std.debug.assert(num_leaves == (1 << height));
            
            const node_count = (2 * num_leaves) - 1;
            var nodes = try allocator.alloc([]u8, node_count);
            
            for (0..num_leaves) |i| {
                const leaf_pos = node_count - num_leaves + i;
                const tweak = try hash.treeTweak(0, @as(u32, @intCast(i)));
                defer allocator.free(tweak);
                
                nodes[leaf_pos] = try hash.hash(tweak, &[_][]const u8{leaf_hashes[i]});
            }
            
            var level: u8 = 1;
            var level_size: usize = num_leaves / 2;
            var level_offset: usize = node_count - num_leaves - level_size;
            
            while (level_size > 0) {
                for (0..level_size) |i| {
                    const left_child = nodes[level_offset + level_size + i * 2];
                    const right_child = nodes[level_offset + level_size + i * 2 + 1];
                    
                    const combined = [_][]const u8{ left_child, right_child };
                    
                    const tweak = try hash.treeTweak(level, @as(u32, @intCast(i)));
                    defer allocator.free(tweak);
                    
                    nodes[level_offset + i] = try hash.hash(tweak, &combined);
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
        
        pub fn path(
            self: *const @This(),
            allocator: std.mem.Allocator,
            leaf_index: usize
        ) !MerklePath(TweakHash) {
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
        hash: *const TweakHash,
        
        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.siblings) |sibling| {
                allocator.free(sibling);
            }
            allocator.free(self.siblings);
        }
        
        pub fn verify(
            self: *const @This(),
            allocator: std.mem.Allocator,
            root: []const u8,
            leaf: []const u8
        ) !bool {
            const leaf_tweak = try self.hash.treeTweak(0, @as(u32, @intCast(self.leaf_index)));
            defer allocator.free(leaf_tweak);
            var current = try self.hash.hash(leaf_tweak, &[_][]const u8{leaf});
            defer allocator.free(current);
            
            var current_index = self.leaf_index;
            
            for (0..self.height) |level| {
                const is_left = current_index % 2 == 0;
                const sibling = self.siblings[level];
                
                const combined = if (is_left)
                    [_][]const u8{ current, sibling }
                else
                    [_][]const u8{ sibling, current };
                
                const tweak = try self.hash.treeTweak(@as(u8, @intCast(level + 1)), @as(u32, @intCast(current_index / 2)));
                defer allocator.free(tweak);
                
                const parent = try self.hash.hash(tweak, &combined);
                allocator.free(current);
                current = parent;
                
                current_index /= 2;
            }
            
            return std.mem.eql(u8, current, root);
        }
    };
}

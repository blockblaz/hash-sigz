const std = @import("std");
const ShaTweakHash = @import("tweak/sha3.zig").ShaTweakHash;

pub fn chain(
    allocator: std.mem.Allocator,
    hash: *const ShaTweakHash,
    epoch: u32,
    chain_index: u16,
    start_pos: u16,
    steps: usize,
    start_value: []const u8
) ![]u8 {
    var current = try allocator.dupe(u8, start_value);
    
    for (0..steps) |j| {
        const pos = @as(u16, @intCast(start_pos)) + @as(u16, @intCast(j)) + 1;
        const tweak = hash.chainTweak(epoch, chain_index, pos);
        defer allocator.free(tweak);
        
        const next = hash.hash(tweak, &[_][]const u8{current});
        allocator.free(current);
        current = next;
    }
    
    return current;
}

test "chain associativity" {
    var allocator = std.testing.allocator;
    var hash = try ShaTweakHash.init(allocator, 16, 32); 
    defer hash.deinit();
    
    const epoch = 9;
    const chain_index = 20;
    var random = std.crypto.random;
    
    const start_value = random.bytes(hash.output_size);
    
    const total_steps = 16;
    
    const end_direct = try chain(
        allocator, &hash, epoch, chain_index, 0, total_steps, start_value
    );
    defer allocator.free(end_direct);
    
    for (0..total_steps + 1) |split| {
        const steps_a = split;
        const steps_b = total_steps - split;
        
        const intermediate = try chain(
            allocator, &hash, epoch, chain_index, 0, steps_a, start_value
        );
        
        const end_indirect = try chain(
            allocator, &hash, epoch, chain_index, steps_a, steps_b, intermediate
        );
        
        try std.testing.expectEqualSlices(u8, end_direct, end_indirect);
        
        allocator.free(intermediate);
        allocator.free(end_indirect);
    }
}
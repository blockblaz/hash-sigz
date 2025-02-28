const std = @import("std");
const bench = @import("bench.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    
    // Poseidon-TargetSum-L20-W2-11
    // Look into Poseidon Security + Perf Constraints
    const configs = [_]bench.BenchConfig{
        .{ .name = "SHA-Winternitz-L18-W1", .lifetime_log2 = 18, .chunk_size = 1,},
    };
    
    std.debug.print("Running XMSS benchmarks.\n", .{});
    for (configs) |config| {
        try bench.runBenchmark(allocator, config);
    }
}
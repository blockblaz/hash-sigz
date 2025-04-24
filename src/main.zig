const std = @import("std");
const bench = @import("bench.zig");

pub fn main() !void {
    // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // const allocator = arena.allocator();
    // defer arena.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Poseidon-TargetSum-L20-W2-11
    // Look into Poseidon Security + Perf Constraints
    const configs = [_]bench.BenchConfig{
        .{
            .name = "SHA-Winternitz-L18-W1",
            .lifetime_log2 = 18,
            .chunk_size = 1,
            .num_checksum_chunks = 8,
        },
    };

    std.debug.print("Running XMSS benchmarks.\n", .{});
    for (configs) |config| {
        try bench.runBenchmark(allocator, config);
    }
}

test "all tests" {
    _ = @import("utils.zig");
    _ = @import("hash_chain.zig");
    _ = @import("tweak/sha3.zig");
    _ = @import("prf/sha3.zig");
    _ = @import("message_hash/sha3.zig");
    _ = @import("encoding/winternitz.zig");
    _ = @import("tweak/tree.zig");
}

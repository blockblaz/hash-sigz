const std = @import("std");
const time = std.time;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const ShaPRF = @import("prf/sha3.zig").ShaPRF;
const ShaWinternitzXMSS = @import("../src/lib.zig").ShaWinternitzXMSS;
const ShaTargetSumXMSS = @import("../src/lib.zig").ShaTargetSumXMSS;
const XMSS = @import("../src/xmss.zig").XMSS;

pub const BenchConfig = struct {
    name: []const u8,
    lifetime_log2: u8,
    chunk_size: u8,
    num_checksum_chunks: u8,
    parameter_size: u8,
    randomness_size: u8,
    message_hash_len: u8,
    hash_size: u8,
    encoding_type: enum { Winternitz, TargetSum },
    target_sum: ?usize,
};

// Use ZBench?
pub fn runBenchmark(
    allocator: Allocator,
    config: BenchConfig,
    xmss: anytype,
) !void {
    var random = std.crypto.random;

    // KeyGen
    const key_gen_start = time.nanoTimestamp();
    var key_pair = try xmss.generateKeyPair();
    const key_gen_time = time.nanoTimestamp() - key_gen_start;
    defer key_pair.public_key.deinit(allocator);
    defer key_pair.secret_key.deinit(allocator);

    var message: [32]u8 = undefined;
    random.bytes(&message);

    const lifetime = @as(u32, 1) << @intCast(config.lifetime_log2);
    const epoch: u32 = random.uintLessThan(u32, lifetime);

    // Sign
    const sign_start = time.nanoTimestamp();
    const sign_iterations = 1000;
    for (0..sign_iterations) |_| {
        var signature = try xmss.sign(&key_pair.secret_key, epoch, &message);
        defer signature.deinit(allocator);
    }
    const sign_time = @divTrunc((time.nanoTimestamp() - sign_start), sign_iterations);

    // Verify
    const verify_start = time.nanoTimestamp();
    const verify_iterations = 1000;
    // Re-sign once to get a signature for verification loop (signing is benchmarked above)
    var signature_for_verify = try xmss.sign(&key_pair.secret_key, epoch, &message);
    defer signature_for_verify.deinit(allocator);

    for (0..verify_iterations) |_| {
        const is_valid = try xmss.verify(&key_pair.public_key, epoch, &message, &signature_for_verify);
        std.debug.assert(is_valid);
    }
    const verify_time = @divTrunc((time.nanoTimestamp() - verify_start), verify_iterations);

    std.debug.print("{s}: keyGen={d}ms sign={d}µs verify={d}µs\n", .{
        config.name,
        @divTrunc(key_gen_time, 1000000),
        @divTrunc(sign_time, 1000),
        @divTrunc(verify_time, 1000),
    });
}

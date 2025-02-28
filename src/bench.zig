const std = @import("std");
const time = std.time;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const ShaPRF = @import("prf/sha3.zig").ShaPRF;
const xmss_signature = @import("../src/xmss.zig").XMSS;

pub const BenchConfig = struct {
    name: []const u8,
    lifetime_log2: u8,
    chunk_size: u8,
    // encoding_type: enum { Winternitz, TargetSum },
    // target_sum_offset_percent: ?u8, 
};

// Use ZBench?
pub fn runBenchmark(allocator: Allocator, config: BenchConfig) !void {
    var signature_scheme = try xmss_signature.init(allocator, config.lifetime_log2, config.chunk_size);

    var random = std.crypto.random;

    // KeyGen
    const key_gen_start = time.nanoTimestamp();
    const key_pair = try signature_scheme.generateKeyPair();
    const key_gen_time = time.nanoTimestamp() - key_gen_start;
    defer key_pair.deinit();

    var message: [32]u8 = undefined;
    random.bytes(&message);

    const epoch: u32 = random.uintLessThan(u32, 1 << config.lifetime_log2);

    // Sign
    const sign_start = time.nanoTimestamp();
    const sign_iterations = 1000;
    for (0..sign_iterations) |_| {
        const signature = try signature_scheme.sign(&key_pair.secret_key, epoch, &message, &random);
        defer signature.deinit();
    }
    const sign_time = (time.nanoTimestamp() - sign_start) / sign_iterations;

    // Verify
    const verify_start = time.nanoTimestamp();
    const verify_iterations = 1000; 
    const signature = try signature_scheme.sign(&key_pair.secret_key, epoch, &message, &random);
    defer signature.deinit();
    
    for (0..verify_iterations) |_| {
        const is_valid = signature_scheme.verify(&key_pair.public_key, epoch, &message, &signature);
        std.debug.assert(is_valid);
    }
    const verify_time = (time.nanoTimestamp() - verify_start) / verify_iterations;

    std.debug.print(
        "{s}: keyGen={d}ms sign={d}µs verify={d}µs\n", 
        .{
            config.name,
            @divTrunc(key_gen_time, 1000000),
            @divTrunc(sign_time, 1000),
            @divTrunc(verify_time, 1000),
        }
    );
}
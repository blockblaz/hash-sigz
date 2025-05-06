const std = @import("std");
const bench = @import("bench.zig");
const ShaTweakHash = @import("tweak/sha3.zig").ShaTweakHash;
const ShaWinternitzXMSS = @import("lib.zig").ShaWinternitzXMSS;
const ShaTargetSumXMSS = @import("lib.zig").ShaTargetSumXMSS;
const TargetSumEncoding = @import("encoding/target_sum.zig").TargetSumEncoding;
const WinternitzEncoding = @import("encoding/winternitz.zig").WinternitzEncoding;
const ShaMessageHash = @import("message_hash/sha3.zig").ShaMessageHash;
const ShaPRF = @import("prf/sha3.zig").ShaPRF;
pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // const allocator = arena.allocator();
    // defer arena.deinit();

    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // const allocator = gpa.allocator();
    // defer _ = gpa.deinit();

    // Poseidon-TargetSum-L20-W2-11
    // Look into Poseidon Security + Perf Constraints
    const configs = [_]bench.BenchConfig{
        .{
            .name = "SHA-Winternitz-L18-W1",
            .lifetime_log2 = 18,
            .chunk_size = 1,
            .num_checksum_chunks = 8,
            .parameter_size = 18,
            .randomness_size = 20,
            .message_hash_len = 18,
            .hash_size = 18,
            .encoding_type = .Winternitz,
            .target_sum = null,
        },
        .{
            .name = "SHA-TargetSumNoOffset-L18-W1",
            .lifetime_log2 = 18,
            .chunk_size = 1,
            .num_checksum_chunks = 8,
            .parameter_size = 18,
            .randomness_size = 32,
            .message_hash_len = 18,
            .hash_size = 18,
            .encoding_type = .TargetSum,
            .target_sum = 70,
        },
    };

    std.debug.print("Running XMSS benchmarks.\n", .{});
    for (configs) |config| {
        if (config.encoding_type == .Winternitz) {
            const tweak_hash = ShaTweakHash.init(config.parameter_size, config.hash_size);
            const prf = ShaPRF.init(config.hash_size);
            const message_hash = ShaMessageHash.init(config.parameter_size, config.randomness_size, config.chunk_size, config.message_hash_len);
            const encoding = WinternitzEncoding(ShaMessageHash).init(message_hash, config.num_checksum_chunks);
            const xmss = ShaWinternitzXMSS.init(allocator, config.lifetime_log2, tweak_hash, message_hash, prf, encoding);
            try bench.runBenchmark(allocator, config, xmss);
        } else if (config.encoding_type == .TargetSum) {
            const tweak_hash = ShaTweakHash.init(config.parameter_size, config.hash_size);
            const prf = ShaPRF.init(config.hash_size);
            const message_hash = ShaMessageHash.init(config.parameter_size, config.randomness_size, config.chunk_size, config.message_hash_len);
            const encoding = TargetSumEncoding(ShaMessageHash).init(message_hash, config.target_sum.?);
            const xmss = ShaTargetSumXMSS.init(allocator, config.lifetime_log2, tweak_hash, message_hash, prf, encoding);
            try bench.runBenchmark(allocator, config, xmss);
        }
    }
}

test "all tests" {
    _ = @import("utils.zig");
    _ = @import("hash_chain.zig");
    _ = @import("tweak/sha3.zig");
    _ = @import("prf/sha3.zig");
    _ = @import("message_hash/sha3.zig");
    _ = @import("encoding/winternitz.zig");
    _ = @import("encoding/target_sum.zig");
}

test "ShaWinternitzXMSS sign/verify small" {
    const allocator = std.testing.allocator;

    const lifetime_log2: u8 = 4;

    const hash = ShaTweakHash.init(26, 26);
    const prf = ShaPRF.init(26);
    const message_hash = ShaMessageHash.init(26, 20, 1, 26);
    const encoding = WinternitzEncoding(ShaMessageHash).init(message_hash, 8);
    var xmss = ShaWinternitzXMSS.init(allocator, lifetime_log2, hash, message_hash, prf, encoding);

    var key_pair = try xmss.generateKeyPair();
    defer key_pair.public_key.deinit(allocator);
    defer key_pair.secret_key.deinit(allocator);

    var message: [32]u8 = undefined;
    std.crypto.random.bytes(&message);

    // should be < lifetime
    const epoch = 12;
    var signature = try xmss.sign(&key_pair.secret_key, @intCast(epoch), &message);
    defer signature.deinit(allocator);

    const valid = try xmss.verify(&key_pair.public_key, @intCast(epoch), &message, &signature);
    try std.testing.expect(valid);
}

const std = @import("std");
const ShaMessageHash = @import("../message_hash/sha3.zig").ShaMessageHash;

pub fn TargetSumEncoding(comptime MessageHash: type) type {
    return struct {
        const Self = @This();

        hash: MessageHash,
        target_sum: usize,
        num_chunks: usize,
        max_tries: usize,

        pub fn init(hash: MessageHash, target_sum: usize) Self {
            std.debug.assert(hash.chunk_size > 0 and hash.chunk_size <= 8 and 8 % hash.chunk_size == 0);
            return Self{
                .hash = hash,
                .target_sum = target_sum,
                .num_chunks = hash.message_hash_len * 8 / hash.chunk_size,
                // this should be estimated via more
                // extensive experiments with concrete hash functions.
                .max_tries = 100000,
            };
        }

        pub fn generateRandomness(self: *Self, out: []u8) void {
            self.hash.generateRandomness(out);
        }

        pub fn encode(
            self: Self,
            allocator: std.mem.Allocator,
            parameter: []u8,
            message: []const u8,
            randomness: []u8,
            epoch: u32,
        ) ![]u8 {
            const chunks = try self.hash.apply(allocator, parameter, epoch, randomness, message);

            var current_sum: usize = 0;
            for (chunks) |chunk| {
                current_sum += chunk;
            }

            if (current_sum == self.target_sum) {
                return chunks;
            } else {
                allocator.free(chunks);
                return error.TargetSumMismatch;
            }
        }
    };
}

test "TargetSumEncoding encode with ShaMessageHash" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const parameter_size = 18;
    const randomness_size = 23;
    const chunk_size = 1;
    const message_hash_len = 18;
    const message_len = 32;

    var parameter: [parameter_size]u8 = undefined;
    std.crypto.random.bytes(&parameter);


    var message: [message_len]u8 = undefined;
    std.crypto.random.bytes(&message);

    const max_tries = 100000;
    const target_sum = 72;

    var result: ?[]u8 = null;

    for (0..max_tries) |_| {
        const hash = ShaMessageHash.init(parameter_size, randomness_size, chunk_size, message_hash_len);
        const encoding = TargetSumEncoding(ShaMessageHash).init(hash, target_sum);

        var randomness: [randomness_size]u8 = undefined;
        std.crypto.random.bytes(&randomness);

        const encoded_chunks = encoding.encode(
            allocator,
            &parameter,
            &message,
            &randomness,
            24,
        ) catch |e| {
            if (e == error.TargetSumMismatch) {
                continue;
            } else {
                return e;
            }
        };

        result = encoded_chunks;
        break;
    }

    if (result) |chunks| {
        defer allocator.free(chunks);
        var sum: usize = 0;
        for (chunks) |chunk| {
            sum += chunk;
        }
        try std.testing.expectEqual(sum, target_sum);
    } else {
        std.debug.print("Target sum {} not found after {} tries.\n", .{ target_sum, max_tries });
        return error.TestTargetSumNotFound;
    }
}
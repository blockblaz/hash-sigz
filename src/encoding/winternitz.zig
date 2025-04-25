const std = @import("std");
const ShaMessageHash = @import("../message_hash/sha3.zig").ShaMessageHash;
const bytesToChunks = @import("../utils.zig").bytesToChunks;

pub fn WinternitzEncoding(comptime MessageHash: type) type {
    return struct {
        const Self = @This();

        message_hash: MessageHash,
        num_chunks: usize,
        num_checksum_chunks: usize,
        max_tries: usize,

        pub fn init(message_hash: MessageHash, num_checksum_chunks: usize) Self {
            return Self{
                .message_hash = message_hash,
                .num_chunks = message_hash.message_hash_len * 8 / message_hash.chunk_size + num_checksum_chunks,
                .num_checksum_chunks = num_checksum_chunks,
                .max_tries = 1,
            };
        }

        pub fn encode(self: Self, allocator: std.mem.Allocator, parameter: []u8, message: []const u8, randomness: []const u8, epoch: u32) ![]u8 {
            const msg_chunks = try self.message_hash.apply(allocator, parameter, epoch, randomness, message);
            defer allocator.free(msg_chunks);

            const base = @as(u64, 1) << @intCast(self.message_hash.chunk_size);
            var checksum: u64 = 0;

            for (msg_chunks) |chunk| {
                checksum += (base - 1) - chunk;
            }

            var checksum_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &checksum_bytes, checksum, .little);

            const checksum_chunks = try bytesToChunks(allocator, &checksum_bytes, self.message_hash.chunk_size);
            defer allocator.free(checksum_chunks);

            var result = try allocator.alloc(u8, msg_chunks.len + self.num_checksum_chunks);
            @memcpy(result[0..msg_chunks.len], msg_chunks);
            @memcpy(result[msg_chunks.len..], checksum_chunks[0..self.num_checksum_chunks]);

            return result;
        }
    };
}

test "WinternitzEncoding encode with ShaMessageHash" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const parameter_size = 32;
    const randomness_size = 32;
    const chunk_size = 4;
    const num_checksum_chunks = 3;
    const message_hash_len = 18;
    var sha_hash = ShaMessageHash.init(parameter_size, randomness_size, chunk_size, message_hash_len);

    const encoding = WinternitzEncoding(ShaMessageHash).init(sha_hash, num_checksum_chunks);

    const message = "test_message";
    var randomness: [randomness_size]u8 = undefined;
    sha_hash.generateRandomness(&randomness);
    const epoch: u32 = 12345;

    const parameter = try allocator.alloc(u8, parameter_size);
    std.crypto.random.bytes(parameter);
    defer allocator.free(parameter);
    const result = try encoding.encode(allocator, parameter, message, &randomness, epoch);
    defer allocator.free(result);

    const expected_msg_chunks_len = @divTrunc(message_hash_len * 8 + chunk_size - 1, chunk_size);
    const expected_total_len = expected_msg_chunks_len + num_checksum_chunks;

    // Verify the total length of the encoded result
    try testing.expectEqual(expected_total_len, result.len);
}

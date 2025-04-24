const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;
const random = std.crypto.random;
const bytesToChunks = @import("../utils.zig").bytesToChunks;

const TWEAK_SEPERATOR_MESSAGE = [1]u8{0x02};

pub const ShaMessageHash = struct {
    const Self = @This();

    parameter_size: usize,
    randomness_size: usize,
    chunk_size: usize,
    // parameter: []u8,

    pub fn init(parameter_size: usize, randomness_size: usize, chunk_size: usize) !Self {
        // const parameter = try allocator.alloc(u8, parameter_size);
        // std.crypto.random.bytes(parameter);

        return Self{
            .parameter_size = parameter_size,
            .randomness_size = randomness_size,
            .chunk_size = chunk_size,
            // .parameter = parameter,
        };
    }


    pub fn generateRandomness(_: Self, out: []u8) void {
        std.crypto.random.bytes(out);
    }

    pub fn apply(self: *const Self, allocator: std.mem.Allocator, parameter: []u8, epoch: u32, randomness: []const u8, message: []const u8) ![]u8 {
        var hasher = Sha3.init(.{});

        hasher.update(randomness);

        hasher.update(parameter);

        var epoch_bytes: [4]u8 = undefined;
        // Ref Impl has this in Little Endian?
        std.mem.writeInt(u32, &epoch_bytes, epoch, .little);
        hasher.update(&epoch_bytes);

        hasher.update(&TWEAK_SEPERATOR_MESSAGE);

        hasher.update(message);

        var digest: [Sha3.digest_length]u8 = undefined;
        hasher.final(&digest);

        return try bytesToChunks(allocator, &digest, self.chunk_size);
    }
};

test "ShaMessageHash apply" {
    const allocator = std.testing.allocator;

    const chunk_size = 2;
    const parameter_size = 32;

    var message_hash = try ShaMessageHash.init(parameter_size, 32, chunk_size);

    var randomness: [32]u8 = undefined;
    message_hash.generateRandomness(&randomness);

    const parameter = try allocator.alloc(u8, parameter_size);
    std.crypto.random.bytes(parameter);
    defer allocator.free(parameter);

    const result = try message_hash.apply(allocator, parameter, 1, &randomness, "test");
    defer allocator.free(result);

    try std.testing.expect(result.len == parameter_size * 8 / chunk_size);
}

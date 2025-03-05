const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;
const random = std.crypto.random;
const bytesToChunks = @import("../utils.zig").bytesToChunks;

const TWEAK_SEPERATOR_MESSAGE = 0x02;

pub const ShaMessageHash = struct {
    const Self = @This();

    parameter_size: usize,
    randomness_size: usize,
    chunk_size: usize,
    parameter: []u8,

    pub fn init(allocator: std.mem.Allocator, parameter_size: usize, randomness_size: usize, chunk_size: usize) !Self {
        const parameter = try allocator.alloc(u8, parameter_size);
        std.crypto.random.bytes(parameter);

        return Self{
            .parameter_size = parameter_size,
            .randomness_size = randomness_size,
            .chunk_size = chunk_size,
            .parameter = parameter,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.parameter);
    }

    pub fn generateRandomness(self: *const Self) []u8 {
        const randomness = std.crypto.random.bytes(self.randomness_size);
        return randomness;
    }

    pub fn apply(self: *const Self, allocator: std.mem.Allocator, epoch: u32, randomness: []const u8, message: []const u8) ![]u8 {
        var hasher = Sha3.init(.{});

        hasher.update(randomness);

        hasher.update(self.parameter);

        var epoch_bytes: [4]u8 = undefined;
        // Ref Impl has this in Little Endian?
        std.mem.writeInt(u32, &epoch_bytes, epoch, .big);
        hasher.update(&epoch_bytes);

        hasher.update(TWEAK_SEPERATOR_MESSAGE);

        hasher.update(message);

        var digest: [Sha3.digest_length]u8 = undefined;
        hasher.final(&digest);

        return try bytesToChunks(allocator, &digest, self.chunk_size);
    }
};

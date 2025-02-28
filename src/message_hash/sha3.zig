const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;
const random = std.crypto.random;
const bytesToChunks = @import("../utils.zig").bytesToChunks;

pub const ShaMessageHash = struct {
    const Self = @This();

    parameter_size: usize,
    randomness_size: usize,
    num_chunks: usize,
    chunk_size: usize,
    parameter: []u8,
    
    pub fn init(
        parameter_size: usize, 
        randomness_size: usize,
        num_chunks: usize,
        chunk_size: usize
    ) Self {
        const param = std.crypto.random.bytes(parameter_size);
        
        return Self{
            .parameter_size = parameter_size,
            .randomness_size = randomness_size,
            .num_chunks = num_chunks,
            .chunk_size = chunk_size,
            .parameter = param,
        };
    }
    
    pub fn generateRandomness(self: *const Self) []u8 {
        const randomness = std.crypto.random.bytes(self.randomness_size);
        return randomness;
    }
    
    pub fn apply(
        self: *const Self,
        allocator: std.mem.Allocator,
        epoch: u32,
        randomness: []const u8,
        message: []const u8
    ) ![]u8 {
        var hasher = Sha3.init(.{});
        
        hasher.update(randomness);
        
        hasher.update(self.parameter);
        

        var epoch_bytes: [4]u8 = undefined;
        // Ref Impl has this in Little Endian? 
        std.mem.writeIntBig(u32, &epoch_bytes, epoch);
        hasher.update(&epoch_bytes);

        // TWEAK_SEPERATOR_MESSAGE
        hasher.update(0x02);
        
        hasher.update(message);
        
        var digest: [Sha3.digest_length]u8 = undefined;
        hasher.final(&digest);
        
        return try bytesToChunks(allocator, &digest, self.chunk_size);
    }
};
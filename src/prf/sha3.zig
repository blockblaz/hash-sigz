const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;

pub const ShaPRF = struct {
    const Self = @This();

    key_size: usize,
    output_size: usize,
    key: []u8,
    
    const PRF_DOMAIN_SEPERATOR = [16]u8{
        0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 
        0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00
    };
    
    pub fn init(allocator: std.mem.Allocator, key_size: usize, output_size: usize) Self {
        const key = try allocator.alloc(u8, key_size);
        var random = std.crypto.random;
        random.bytes(key);
        
        return ShaPRF{
            .key_size = key_size,
            .output_size = output_size,
            .key = key,
        };
    }
    
    pub fn deinit(self: *ShaPRF, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
    }
    
    pub fn apply(self: *const ShaPRF, epoch: u32, chain_index: u64) ![]u8 {
        var hasher = Sha3.init(.{});

        hasher.update(&PRF_DOMAIN_SEPERATOR);

        hasher.update(self.key);

        var epoch_bytes: [4]u8 = undefined;
        std.mem.writeIntBig(u32, &epoch_bytes, epoch);
        hasher.update(&epoch_bytes);

        var index_bytes: [8]u8 = undefined;
        std.mem.writeIntBig(u64, &index_bytes, chain_index);
        hasher.update(&index_bytes);

        var result: [self.output_size]u8 = undefined;
        hasher.final(&result);
        
        return result;
    }
};
const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;

pub const ShaPRF = struct {
    const Self = @This();

    const KEY_SIZE = 32;
    output_size: usize,
    key: [KEY_SIZE]u8,
    
    const PRF_DOMAIN_SEPERATOR = [16]u8{
        0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 
        0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00
    };
    
    pub fn init(output_size: usize) Self {
        // SHA PRF: Output length must be less than 256 bit
        std.debug.assert(output_size < 64);

        var key: [KEY_SIZE]u8 = undefined;
        std.crypto.random.bytes(&key);
        
        return ShaPRF{
            .output_size = output_size,
            .key = key,
        };
    }
    
    pub fn apply(self: *const ShaPRF, epoch: u32, chain_index: u64) []u8 {
        var hasher = Sha3.init(.{});

        hasher.update(&PRF_DOMAIN_SEPERATOR);

        hasher.update(&self.key);

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

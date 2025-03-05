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

        return Self {
            .output_size = output_size,
            .key = key,
        };
    }

    pub fn apply(self: Self, epoch: u32, chain_index: u64) []u8 {
        var hasher = Sha3.init(.{});

        hasher.update(&PRF_DOMAIN_SEPERATOR);

        hasher.update(&self.key);

        var epoch_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &epoch_bytes, epoch, .big);
        hasher.update(&epoch_bytes);

        var index_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &index_bytes, chain_index, .big);
        hasher.update(&index_bytes);

        var result: [32]u8 = undefined;
        hasher.final(&result);

        return result[0..self.output_size];
    }
};

test "ShaPRF apply truncation" {
    const testing = std.testing;
    // const allocator = testing.allocator;

    const ShaPRF26 = ShaPRF(26);
    const ShaPRF32 = ShaPRF(32);

    var prf26 = ShaPRF26.init();
    var prf32 = ShaPRF32.init();

    // Copy same key to both PRFs
    @memcpy(&prf32.key, &prf26.key);

    const epoch = 123;
    const chain_index = 456;

    const result26 = prf26.apply(epoch, chain_index);
    const result32 = prf32.apply(epoch, chain_index);

    // Check that first 26 bytes match
    try testing.expectEqualSlices(u8, result26[0..26], result32[0..26]);
}

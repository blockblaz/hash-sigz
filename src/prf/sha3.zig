const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;

pub const ShaPRF = struct {
    const Self = @This();

    output_size: usize,

    pub const KEY_SIZE = 32;
    const PRF_DOMAIN_SEPERATOR = [16]u8{ 0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00 };

    pub fn init(output_size: usize) Self {
        // SHA PRF: Output length must be less than 256 bit
        std.debug.assert(output_size < 64);

        var key: [KEY_SIZE]u8 = undefined;
        std.crypto.random.bytes(&key);

        return Self{
            .output_size = output_size,
        };
    }

    pub fn generateKey(_: Self, out: []u8) void {
        std.crypto.random.bytes(out);
    }

    pub fn apply(self: Self, key: []u8, epoch: u32, chain_index: u64, out: []u8) void {
        var hasher = Sha3.init(.{});

        hasher.update(&PRF_DOMAIN_SEPERATOR);

        hasher.update(key);

        var epoch_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &epoch_bytes, epoch, .big);
        hasher.update(&epoch_bytes);

        var index_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &index_bytes, chain_index, .big);
        hasher.update(&index_bytes);

        var result: [32]u8 = undefined;
        hasher.final(&result);

        @memcpy(out, result[0..self.output_size]);
    }
};

test "ShaPRF deterministic for same inputs" {
    const prf = ShaPRF.init(16);

    const epoch = 42;
    const chain_index = 123;

    var key: [ShaPRF.KEY_SIZE]u8 = undefined;
    prf.generateKey(&key);

    var result1: [16]u8 = undefined;
    prf.apply(&key, epoch, chain_index, &result1);

    var result2: [16]u8 = undefined;
    prf.apply(&key, epoch, chain_index, &result2);

    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "ShaPRF different outputs for different epochs" {
    const prf = ShaPRF.init(16);

    const chain_index = 123;

    var key: [ShaPRF.KEY_SIZE]u8 = undefined;
    prf.generateKey(&key);

    var result1: [16]u8 = undefined;
    prf.apply(&key, 1, chain_index, &result1);

    var result2: [16]u8 = undefined;
    prf.apply(&key, 2, chain_index, &result2);

    try std.testing.expect(!std.mem.eql(u8, &result1, &result2));
}

test "ShaPRF different outputs for different chain indices" {
    const prf = ShaPRF.init(16);

    const epoch = 42;

    var key: [ShaPRF.KEY_SIZE]u8 = undefined;
    prf.generateKey(&key);

    var result1: [16]u8 = undefined;
    prf.apply(&key, epoch, 1, &result1);

    var result2: [16]u8 = undefined;
    prf.apply(&key, epoch, 2, &result2);

    try std.testing.expect(!std.mem.eql(u8, &result1, &result2));
}

test "ShaPRF different instances produce different outputs" {
    const prf1 = ShaPRF.init(16);
    const prf2 = ShaPRF.init(16);

    const epoch = 42;
    const chain_index = 123;

    var key1: [ShaPRF.KEY_SIZE]u8 = undefined;
    prf1.generateKey(&key1);

    var key2: [ShaPRF.KEY_SIZE]u8 = undefined;
    prf2.generateKey(&key2);

    var result1: [16]u8 = undefined;
    prf1.apply(&key1, epoch, chain_index, &result1);

    var result2: [16]u8 = undefined;
    prf2.apply(&key2, epoch, chain_index, &result2);

    try std.testing.expect(!std.mem.eql(u8, &result1, &result2));
}

const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;

pub const ShaTweak = union(enum) {
    tree: struct {
        level: u8,
        pos_in_level: u32,
    },
    chain: struct {
        epoch: u32,
        chain_index: u16,
        pos_in_chain: u16,
    },

    // FIXME: https://github.com/b-wagn/hash-sig/issues/11
    pub fn to_bytes(self: ShaTweak) []const u8 {
        switch (self) {
            .tree => |t| {
                var bytes: [6]u8 = undefined;
                std.mem.writeInt(u8, bytes[0..1], t.level, .big);
                std.mem.writeInt(u32, bytes[1..5], t.pos_in_level, .big);
                bytes[5] = 0x00;
                return &bytes;
            },
            .chain => |c| {
                var bytes: [9]u8 = undefined;
                std.mem.writeInt(u32, bytes[0..4], c.epoch, .big);
                std.mem.writeInt(u16, bytes[4..6], c.chain_index, .big);
                std.mem.writeInt(u16, bytes[6..8], c.pos_in_chain, .big);
                bytes[8] = 0x01;
                return &bytes;
            },
        }
    }
};

pub const ShaTweakHash = struct {
    const Self = @This();

    parameter_size: usize,
    hash_size: usize,

    // const Parameter = [PARAMETER_LENGTH]u8;
    // const Domain = [HASH_LEN]u8;

    pub fn init(parameter_size: usize, hash_size: usize) Self {
        return .{
            .parameter_size = parameter_size,
            .hash_size = hash_size,
        };
    }

    pub fn hash(self: Self, parameter: []u8, tweak: ShaTweak, msg: []const []const u8, out: []u8) void {
        var hasher = Sha3.init(.{});

        hasher.update(parameter);

        const tweak_bytes = tweak.to_bytes();
        hasher.update(tweak_bytes);

        for (msg) |m| {
            hasher.update(m);
        }

        var result: [32]u8 = undefined;
        hasher.final(&result);

        @memcpy(out, result[0..self.hash_size]);
    }

    pub fn tree_tweak(_: Self, level: u8, pos_in_level: u32) ShaTweak {
        return .{ .tree = .{ .level = level, .pos_in_level = pos_in_level } };
    }

    pub fn chain_tweak(_: Self, epoch: u32, chain_index: u16, pos_in_chain: u16) ShaTweak {
        return .{ .chain = .{ .epoch = epoch, .chain_index = chain_index, .pos_in_chain = pos_in_chain } };
    }
};

test "ShaTweak128 tree hash" {
    const hash = ShaTweakHash.init(16, 16);
    var parameter: [16]u8 = undefined;
    std.crypto.random.bytes(&parameter);

    const tweak = hash.tree_tweak(1, 2);
    var out: [16]u8 = undefined;
    hash.hash(&parameter, tweak, &[_][]const u8{"test"}, &out);
}

test "ShaTweak128 chain hash" {
    const hash = ShaTweakHash.init(16, 16);
    var parameter: [16]u8 = undefined;
    std.crypto.random.bytes(&parameter);

    const tweak = hash.chain_tweak(100, 1, 1);
    var out: [16]u8 = undefined;
    hash.hash(&parameter, tweak, &[_][]const u8{"test"}, &out);
}
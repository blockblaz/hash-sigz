const std = @import("std");
const Sha3 = std.crypto.hash.sha3.Sha3_256;
const TweakableHash = @import("tweakable.zig").TweakableHash;

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
    message: struct {
        epoch: u32,
    },

    // FIXME: https://github.com/b-wagn/hash-sig/issues/11
    pub fn to_bytes(self: ShaTweak) []const u8 {
        comptime switch (self) {
            .tree => |t| {
                var bytes = [6]u8;
                std.mem.writeIntBig(u8, bytes[0..1], t.level);
                std.mem.writeIntBig(u32, bytes[1..5], t.pos_in_level);
                bytes[5] = 0x00;
                return bytes;
            },
            .chain => |c| {
                var bytes = [9]u8;
                std.mem.writeIntBig(u32, bytes[0..4], c.epoch);
                std.mem.writeIntBig(u16, bytes[4..6], c.chain_index);
                std.mem.writeIntBig(u16, bytes[6..8], c.pos_in_chain);
                bytes[8] = 0x01;
                return bytes;
            },
            .message => |m| {
                var bytes = [5]u8;
                // ref impl has this in little endian??
                std.mem.writeIntBig(u32, bytes[0..4], m.epoch);
                bytes[4] = 0x02;
                return bytes;
            },
        };
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

    fn hash(parameter: []u8, tweak: ShaTweak, msg: []const []u8) []u8 {
        var hasher = Sha3.init(.{});

        hasher.update(&parameter);

        const tweak_bytes = tweak.to_bytes();
        hasher.update(&tweak_bytes);

        for (msg) |m| {
            hasher.update(&m);
        }

        var result: [Self.HASH_LEN]u8 = undefined;
        hasher.final(&result);

        return result;
    }

    fn rand_parameter(rand: *std.rand.Random) []u8 {
        var parameter: []u8 = undefined;
        rand.bytes(&parameter);
        return parameter;
    }

    fn rand_domain(rand: *std.rand.Random) []u8 {
        var domain: []u8 = undefined;
        rand.bytes(&domain);
        return domain;
    }

    fn tree_tweak(level: u8, pos_in_level: u32) ShaTweak {
        return .{ .tree = .{ .level = level, .pos_in_level = pos_in_level } };
    }

    fn chain_tweak(epoch: u32, chain_index: u16, pos_in_chain: u16) ShaTweak {
        return .{ .chain = .{ .epoch = epoch, .chain_index = chain_index, .pos_in_chain = pos_in_chain } };
    }
};

pub const ShaTweak128 = ShaTweakHash(16, 16);
pub const ShaTweak192 = ShaTweakHash(24, 24);
pub const ShaTweak256 = ShaTweakHash(32, 32);

// TODO:// Tests

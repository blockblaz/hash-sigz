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

    // FIXME: https://github.com/b-wagn/hash-sig/issues/11
    pub fn to_bytes(self: ShaTweak) []const u8 {
        switch (self) {
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
        }
    }
};

pub fn ShaTweakHash(comptime PARAMETER_LENGTH: usize, comptime HASH_LEN: usize) type {
    const Parameter = [PARAMETER_LENGTH]u8;
    const Domain = [HASH_LEN]u8;

    return struct {
        pub fn init() TweakableHash(Parameter, Domain, ShaTweak) {
            return .{
                .hash_fn = hash,
                .rand_param_fn = rand_parameter,
                .rand_domain_fn = rand_domain,
                .tree_tweak_fn = tree_tweak,
                .chain_tweak_fn = chain_tweak,
            };
        }

        fn hash(param: Parameter, tweak: ShaTweak, msg: []const Domain) Domain {
            var hasher = Sha3.init(.{});

            hasher.update(&param);

            const tweak_bytes = tweak.to_bytes();
            hasher.update(&tweak_bytes);

            for (msg) |m| {
                hasher.update(&m);
            }

            var result: [HASH_LEN]u8 = undefined;
            hasher.final(&result);

            return result;
        }

        fn rand_parameter(rand: *std.rand.Random) Parameter {
            var param: Parameter = undefined;
            rand.bytes(&param);
            return param;
        }

        fn rand_domain(rand: *std.rand.Random) Domain {
            var domain: Domain = undefined;
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
}

pub const ShaTweak128 = ShaTweakHash(16, 16);
pub const ShaTweak192 = ShaTweakHash(24, 24);
pub const ShaTweak256 = ShaTweakHash(32, 32);

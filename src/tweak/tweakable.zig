const std = @import("std");

pub fn TweakableHash(
    comptime Parameter: type,
    comptime Domain: type,
    comptime Tweak: type,
) type {
    return struct {
        const Self = @This();
        
        hash_fn: *const fn (param: Parameter, tweak: Tweak, msg: []const Domain) Domain,
        rand_param_fn: *const fn (rand: *std.rand.Random) Parameter,
        rand_domain_fn: *const fn (rand: *std.rand.Random) Domain,
        tree_tweak_fn: *const fn (level: u8, pos_in_level: u32) Tweak,
        chain_tweak_fn: *const fn (epoch: u32, chain_index: u16, pos_in_chain: u16) Tweak,
        
        pub fn hash(self: Self, param: Parameter, tweak: Tweak, msg: []const Domain) Domain {
            return self.hash_fn(param, tweak, msg);
        }
        
        pub fn rand_parameter(self: Self, rand: *std.rand.Random) Parameter {
            return self.rand_param_fn(rand);
        }
        
        pub fn rand_domain(self: Self, rand: *std.rand.Random) Domain {
            return self.rand_domain_fn(rand);
        }
        
        pub fn tree_tweak(self: Self, level: u8, pos_in_level: u32) Tweak {
            return self.tree_tweak_fn(level, pos_in_level);
        }
        
        pub fn chain_tweak(self: Self, epoch: u32, chain_index: u16, pos_in_chain: u16) Tweak {
            return self.chain_tweak_fn(epoch, chain_index, pos_in_chain);
        }
    };
}
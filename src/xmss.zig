const std = @import("std");
const Allocator = std.mem.Allocator;
const ShaTweak128 = @import("tweak/sha3.zig").ShaTweak128;
const ShaTweakHash = @import("tweak/sha3.zig").ShaTweakHash;
const ShaPRF = @import("prf/sha3.zig").ShaPRF;
const ShaMessageHash = @import("message_hash/sha3.zig").ShaMessageHash;
// const MessageHash = @import("message_hash/message_hash.zig").MessageHash;
const WinternitzEncoding = @import("encoding/winternitz.zig").WinternitzEncoding;
const MerkleTree = @import("tweak/tree.zig").MerkleTree;
const MerklePath = @import("tweak/tree.zig").MerklePath;
const chain = @import("hash_chain.zig").chain;
// const TweakableHash = @import("tweak/tweakable.zig").TweakableHash;
// const PRF = @import("prf/prf.zig").PRF;
// const IncomparableEncoding = @import("encoding/encoding.zig").IncomparableEncoding;

pub fn XMSS(
    comptime TweakHash: type,
    comptime PRF: type,
    comptime MessageHash: type,
    comptime IncomparableEncoding: type,
) type {
    return struct {
        const Self = @This();

        pub const Signature = struct {
            path: MerklePath(TweakHash),
            randomness: []u8,
            chain_values: [][]u8,

            pub fn deinit(self: *@This(), allocator: Allocator) void {
                self.path.deinit(allocator);
                allocator.free(self.randomness);
                for (self.chain_values) |val| {
                    allocator.free(val);
                }
                allocator.free(self.chain_values);
            }
        };

        pub const PublicKey = struct {
            // Domain
            root: []u8,
            // Parameter
            hash_parameter: []u8,

            pub fn deinit(self: *@This(), allocator: Allocator) void {
                allocator.free(self.root);
                allocator.free(self.hash_parameter);
            }
        };

        pub const SecretKey = struct {
            // Key
            prf_key: []u8,
            // Merkle Tree of All 2^LOG_LIFETIME Hashes
            tree: MerkleTree(TweakHash),
            // Parameter
            parameter: []u8,

            pub fn deinit(self: *@This(), allocator: Allocator) void {
                allocator.free(self.prf_key);
                self.tree.deinit(allocator);
                allocator.free(self.parameter);
            }
        };

        allocator: Allocator,
        lifetime_log2: u8,
        chunk_size: u8,
        hash: TweakHash,
        prf: PRF,
        encoding: IncomparableEncoding,
        message_hash: anyerror!MessageHash,
        parameter: []u8,

        pub fn init(
            allocator: Allocator,
            lifetime_log2: u8,
            chunk_size: u8,
            randomness_size: u8,
        ) !Self {
            const PARAMETER_SIZE = 18;

            const output_size: u8 = if (chunk_size == 1 or chunk_size == 2)
                25
            else if (chunk_size == 4)
                26
            else if (chunk_size == 8)
                28
            else
                return error.UnsupportedChunkSize;

            const hash = TweakHash.init(PARAMETER_SIZE, output_size);
            const prf = PRF.init(output_size);
            const parameter = hash.rand_parameter(PARAMETER_SIZE);

            const num_message_chunks = @as(u16, 256) / chunk_size;
            const base = @as(u8, 1) << @intCast(chunk_size);
            const max_checksum = num_message_chunks * (base - 1);
            const num_checksum_chunks = 1 + @divFloor(std.math.log2_int(usize, max_checksum), chunk_size);

            const message_hash = try MessageHash.init(allocator, PARAMETER_SIZE, randomness_size, chunk_size);
            const encoding = IncomparableEncoding.init(message_hash, num_checksum_chunks);

            return @This(){
                .allocator = allocator,
                .lifetime_log2 = lifetime_log2,
                .chunk_size = chunk_size,
                .hash = hash,
                .prf = prf,
                .encoding = encoding,
                .message_hash = message_hash,
                .parameter = parameter,
            };
        }

        pub fn deinit(self: *Self) void {
            self.hash.deinit(self.allocator);
            self.prf.deinit(self.allocator);
            self.encoding.deinit(self.allocator);
            self.message_hash.deinit(self.allocator);
        }

        pub fn generateKeyPair(self: *Self) !struct { public_key: PublicKey, secret_key: SecretKey } {
            const lifetime = @as(usize, 1) << @intCast(self.lifetime_log2);
            const num_chains = self.encoding.num_checksum_chunks;

            const prf_key = try self.allocator.dupe(u8, &self.prf.key);

            var public_keys = try self.allocator.alloc([]u8, lifetime);
            const chain_length = @as(usize, 1) << @intCast(self.chunk_size);

            for (0..lifetime) |epoch| {
                var chain_ends = try self.allocator.alloc([]u8, num_chains);

                for (0..num_chains) |chain_index| {
                    const start = self.prf.apply(@as(u32, @intCast(epoch)), @as(u64, @intCast(chain_index)));

                    const end = try chain(self.allocator, &self.hash, self.parameter, @as(u32, @intCast(epoch)), @as(u16, @intCast(chain_index)), 0, chain_length - 1, start);

                    self.allocator.free(start);
                    chain_ends[chain_index] = end;
                }

                const tweak = self.hash.tree_tweak(0, @as(u32, @intCast(epoch)));
                public_keys[epoch] = self.hash.hash(self.parameter, tweak, chain_ends);
                self.allocator.free(tweak);

                for (chain_ends) |end| {
                    self.allocator.free(end);
                }
                self.allocator.free(chain_ends);
            }

            var tree = try MerkleTree(TweakHash).build(self.allocator, self.parameter, self.hash, public_keys);

            const key_pair = .{
                .public_key = PublicKey {
                    .root = try self.allocator.dupe(u8, tree.root()),
                    .hash_parameter = try self.allocator.dupe(u8, self.parameter),
                },
                .secret_key = SecretKey {
                    .prf_key = prf_key,
                    .tree = tree,
                    .parameter = try self.allocator.dupe(u8, self.parameter),
                },
            };

            for (public_keys) |pk| {
                self.allocator.free(pk);
            }
            self.allocator.free(public_keys);

            return key_pair;
        }

        pub fn sign(
            self: *Self,
            secret_key: *const SecretKey,
            epoch: u32,
            message: []const u8,
        ) !Signature {
            const path = try secret_key.tree.path(self.allocator, @as(usize, epoch));

            const randomness = try self.message_hash.generateRandomness(self.allocator);
            const chunks = try self.encoding.encode(self.allocator, message, randomness, epoch);

            const num_chains = chunks.len;
            var chain_values = try self.allocator.alloc([]u8, num_chains);

            for (0..num_chains) |i| {
                const start = try self.prf.apply(self.allocator, epoch, @as(u64, @intCast(i)));

                const steps = chunks[i];
                chain_values[i] = try chain(self.allocator, &self.hash, epoch, @as(u16, @intCast(i)), 0, steps, start);

                self.allocator.free(start);
            }

            self.allocator.free(chunks);

            return Signature{
                .path = path,
                .randomness = randomness,
                .chain_values = chain_values,
            };
        }

        pub fn verify(self: *Self, public_key: *const PublicKey, epoch: u32, message: []const u8, signature: *const Signature) !bool {
            const chunks = try self.encoding.encode(self.allocator, message, signature.randomness, epoch);
            defer self.allocator.free(chunks);

            const num_chains = chunks.len;
            const chain_length = @as(usize, 1) << self.chunk_size;
            var chain_ends = try self.allocator.alloc([]u8, num_chains);
            defer {
                for (chain_ends) |end| {
                    self.allocator.free(end);
                }
                self.allocator.free(chain_ends);
            }

            for (0..num_chains) |i| {
                const steps_left = chain_length - 1 - chunks[i];
                chain_ends[i] = try chain(self.allocator, &self.hash, epoch, @as(u16, @intCast(i)), chunks[i], steps_left, signature.chain_values[i]);
            }

            const tweak = try self.hash.treeTweak(0, epoch);
            defer self.allocator.free(tweak);

            const computed_pk = try self.hash.hash(tweak, chain_ends);
            defer self.allocator.free(computed_pk);

            return try signature.path.verify(self.allocator, public_key.root, computed_pk);
        }
    };
}

pub const ShaWinternitzXMSS = XMSS(ShaTweakHash, ShaPRF, ShaMessageHash, WinternitzEncoding(ShaMessageHash));
// pub const ShaTargetSumXMSS = XMSS(ShaTweakHash, ShaPRF, ShaMessageHash, TargetSumEncoding);
// pub const PoseidonWinternitzXMSS = XMSS(PoseidonTweakHash, PoseidonPRF, PoseidonMessageHash, WinternitzEncoding);
// pub const PoseidonTargetSumXMSS = XMSS(PoseidonTweakHash, PoseidonPRF, PoseidonMessageHash, TargetSumEncoding);

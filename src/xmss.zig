const std = @import("std");
const Allocator = std.mem.Allocator;
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
        message_hash: MessageHash,

        pub fn init(
            allocator: Allocator,
            lifetime_log2: u8,
            chunk_size: u8,
            randomness_size: u8,
            num_checksum_chunks: u8,
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
            // const parameter = try allocator.alloc(u8, PARAMETER_SIZE);
            // std.crypto.random.bytes(parameter);

            const message_hash = try MessageHash.init(PARAMETER_SIZE, randomness_size, chunk_size);
            const encoding = IncomparableEncoding.init(message_hash, num_checksum_chunks);

            return @This(){
                .allocator = allocator,
                .lifetime_log2 = lifetime_log2,
                .chunk_size = chunk_size,
                .hash = hash,
                .prf = prf,
                .encoding = encoding,
                .message_hash = message_hash,
            };
        }

        pub fn generateKeyPair(self: *Self) !struct { public_key: PublicKey, secret_key: SecretKey } {
            const lifetime = @as(u32, 1) << @intCast(self.lifetime_log2);
            const num_message_chunks = self.message_hash.parameter_size * 8 / self.chunk_size;
            const num_chains = num_message_chunks + self.encoding.num_checksum_chunks;

            const prf_key = try self.allocator.alloc(u8, 32);
            self.prf.generateKey(prf_key);
            const parameter = try self.allocator.alloc(u8, self.hash.parameter_size);
            std.crypto.random.bytes(parameter);

            var public_key_hashes = try self.allocator.alloc([]u8, lifetime);
            const chain_length = @as(u16, 1) << @intCast(self.chunk_size);

            for (0..lifetime) |epoch| {
                var chain_ends = try self.allocator.alloc([]u8, num_chains);
                for (0..num_chains) |chain_index| {
                    const start = try self.allocator.alloc(u8, self.prf.output_size);
                    self.prf.apply(prf_key, @intCast(epoch), @intCast(chain_index), start);
                    const steps: u16 = chain_length - 1;
                    chain(self.hash, parameter, @intCast(epoch), @intCast(chain_index), 0, steps, start);
                    chain_ends[chain_index] = start;
                }
                const tweak = self.hash.tree_tweak(0, @intCast(epoch));
                const leaf = try self.allocator.alloc(u8, self.hash.hash_size);
                self.hash.hash(parameter, tweak, chain_ends, leaf);
                public_key_hashes[epoch] = leaf;
                for (chain_ends) |end| self.allocator.free(end);
                self.allocator.free(chain_ends);
            }

            var tree = try MerkleTree(TweakHash).build(
                self.allocator,
                parameter,
                self.hash,
                public_key_hashes,
            );

            const key_pair = .{
                .public_key = PublicKey{
                    .root = try self.allocator.dupe(u8, tree.root()),
                    .hash_parameter = try self.allocator.dupe(u8, parameter),
                },
                .secret_key = SecretKey{
                    .prf_key = prf_key,
                    .tree = tree,
                    .parameter = parameter,
                },
            };

            for (public_key_hashes) |pk| {
                self.allocator.free(pk);
            }
            self.allocator.free(public_key_hashes);

            return key_pair;
        }

        pub fn sign(
            self: *Self,
            secret_key: *const SecretKey,
            epoch: u32,
            message: []const u8,
        ) !Signature {
            const path = try secret_key.tree.path(self.allocator, @as(usize, epoch));

            const randomness = try self.allocator.alloc(u8, self.message_hash.randomness_size);
            self.message_hash.generateRandomness(randomness);
            const chunks = try self.encoding.encode(self.allocator, secret_key.parameter, message, randomness, epoch);

            const num_message_chunks = self.message_hash.parameter_size * 8 / self.chunk_size;
            const num_chains = num_message_chunks + self.encoding.num_checksum_chunks;

            var chain_values = try self.allocator.alloc([]u8, num_chains);
            for (0..num_chains) |i| {
                const start = try self.allocator.alloc(u8, self.prf.output_size);
                self.prf.apply(secret_key.prf_key, epoch, @as(u64, @intCast(i)), start);
                const steps: u16 = @as(u16, @intCast(chunks[i]));
                chain(self.hash, secret_key.parameter, epoch, @as(u16, @intCast(i)), 0, steps, start);
                chain_values[i] = start;
            }

            self.allocator.free(chunks);

            return Signature{
                .path = path,
                .randomness = randomness,
                .chain_values = chain_values,
            };
        }

        pub fn verify(self: *Self, public_key: *const PublicKey, epoch: u32, message: []const u8, signature: *const Signature) !bool {
            const chunks = try self.encoding.encode(self.allocator, public_key.hash_parameter, message, signature.randomness, epoch);
            defer self.allocator.free(chunks);

            const num_message_chunks = self.message_hash.parameter_size * 8 / self.chunk_size;
            const num_chains = num_message_chunks + self.encoding.num_checksum_chunks;
            const chain_length = @as(usize, 1) << @intCast(self.chunk_size);
            var chain_ends = try self.allocator.alloc([]u8, num_chains);
            defer {
                for (chain_ends) |end_slice| self.allocator.free(end_slice);
                self.allocator.free(chain_ends);
            }

            for (0..num_chains) |i| {
                const end = try self.allocator.dupe(u8, signature.chain_values[i]);

                const steps_left: u16 = @intCast(chain_length - 1 - chunks[i]);
                chain(self.hash, public_key.hash_parameter, epoch, @as(u16, @intCast(i)), @as(u16, chunks[i]), steps_left, end);
                chain_ends[i] = end;
            }

            const leaf_tweak = self.hash.tree_tweak(0, epoch);
            const leaf_hash_recomputed = try self.allocator.alloc(u8, self.hash.hash_size);
            defer self.allocator.free(leaf_hash_recomputed);
            self.hash.hash(public_key.hash_parameter, leaf_tweak, chain_ends, leaf_hash_recomputed);

            const is_valid = try signature.path.verify(self.allocator, public_key.hash_parameter, public_key.root, leaf_hash_recomputed);

            return is_valid;
        }
    };
}

pub const ShaWinternitzXMSS = XMSS(ShaTweakHash, ShaPRF, ShaMessageHash, WinternitzEncoding(ShaMessageHash));
// pub const ShaTargetSumXMSS = XMSS(ShaTweakHash, ShaPRF, ShaMessageHash, TargetSumEncoding);
// pub const PoseidonWinternitzXMSS = XMSS(PoseidonTweakHash, PoseidonPRF, PoseidonMessageHash, WinternitzEncoding);
// pub const PoseidonTargetSumXMSS = XMSS(PoseidonTweakHash, PoseidonPRF, PoseidonMessageHash, TargetSumEncoding);

test "ShaWinternitzXMSS sign/verify small" {
    const allocator = std.testing.allocator;

    const lifetime_log2: u8 = 4;
    const chunk_size: u8 = 1;

    var xmss = try ShaWinternitzXMSS.init(allocator, lifetime_log2, chunk_size, 26, 8);

    var key_pair = try xmss.generateKeyPair();
    defer key_pair.public_key.deinit(allocator);
    defer key_pair.secret_key.deinit(allocator);

    var message: [32]u8 = undefined;
    std.crypto.random.bytes(&message);

    // should be < lifetime
    const epoch = 12;
    var signature = try xmss.sign(&key_pair.secret_key, @intCast(epoch), &message);
    defer signature.deinit(allocator);

    const valid = try xmss.verify(&key_pair.public_key, @intCast(epoch), &message, &signature);
    try std.testing.expect(valid);
}

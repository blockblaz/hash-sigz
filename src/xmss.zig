const std = @import("std");
const Allocator = std.mem.Allocator;
const ShaTweak128 = @import("tweak/sha3.zig").ShaTweak128;
const ShaTweakHash = @import("tweak/sha3.zig").ShaTweakHash;
const ShaPRF = @import("prf/sha3.zig").ShaPRF;
const ShaMessageHash = @import("message_hash/sha3.zig").ShaMessageHash;
const WinternitzEncoding = @import("encoding/winternitz.zig").WinternitzEncoding;
const MerkleTree = @import("tweak/tree.zig").MerkleTree;
const MerklePath = @import("tweak/tree.zig").MerklePath;
const chain = @import("hash_chain.zig").chain;
const TweakableHash = @import("tweak/tweakable.zig").TweakableHash;
const PRF = @import("prf/prf.zig").PRF;

pub const XMSS = struct {
    pub const Signature = struct {
        path: MerklePath,
        randomness: []u8,
        chain_values: [][]u8,
    };

    pub const XMSSPublicKey = struct {
        // Domain
        root: []u8,
        // Parameter
        hash_parameter: []u8,
    };

    pub const XMSSSecretKey = struct {
        // Key
        prf_key: []u8,
        // Merkle Tree of All 2^LOG_LIFETIME Hashes
        tree: MerkleTree,
        // Parameter
        parameter: []u8,
    };

    allocator: Allocator,
    lifetime_log2: u8,
    chunk_size: u8,
    hash: TweakableHash,
    prf: PRF,
    encoding: WinternitzEncoding,

    pub fn init(
        allocator: Allocator,
        lifetime_log2: u8,
        chunk_size: u8,
    ) !XMSS {
        const parameter_size = 18;
        const output_size: u8 = if (chunk_size == 1 or chunk_size == 2) 25 else if (chunk_size == 4) 26 else if (chunk_size == 8) 28 else return error.UnsupportedChunkSize;

        const hash = ShaTweakHash.init(parameter_size, output_size);
        const prf = try ShaPRF.init(allocator, 32, output_size);

        const num_message_chunks = @as(u16, 256) / chunk_size;
        const base = @as(u8, 1) << @intCast(chunk_size);
        const max_checksum = num_message_chunks * (base - 1);
        const num_checksum_chunks = 1 + @divFloor(std.math.log2_int(usize, max_checksum), chunk_size);

        const encoding = try WinternitzEncoding.init(allocator, parameter_size, 20, chunk_size, num_message_chunks, num_checksum_chunks);

        return XMSS{
            .allocator = allocator,
            .lifetime_log2 = lifetime_log2,
            .chunk_size = chunk_size,
            .hash = hash,
            .prf = prf,
            .encoding = encoding,
        };
    }

    pub fn deinit(self: *XMSS) void {
        self.hash.deinit(self.allocator);
        self.prf.deinit(self.allocator);
        self.encoding.deinit(self.allocator);
    }

    pub fn generateKeyPair(self: *XMSS) !struct { XMSSPublicKey, XMSSSecretKey } {
        const lifetime = @as(usize, 1) << self.lifetime_log2;
        const num_chains = self.encoding.num_checksum_chunks + self.encoding.message_hash.num_chunks;

        const prf_key = try self.allocator.dupe(u8, self.prf.key);

        var public_keys = try self.allocator.alloc([]u8, lifetime);
        const chain_length = @as(usize, 1) << self.chunk_size;

        for (0..lifetime) |epoch| {
            var chain_ends = try self.allocator.alloc([]u8, num_chains);

            for (0..num_chains) |chain_index| {
                const start = try self.prf.apply(self.allocator, @as(u32, @intCast(epoch)), @as(u64, @intCast(chain_index)));

                const end = try chain(self.allocator, &self.hash, @as(u32, @intCast(epoch)), @as(u16, @intCast(chain_index)), 0, chain_length - 1, start);

                self.allocator.free(start);
                chain_ends[chain_index] = end;
            }

            const tweak = self.hash.treeTweak(0, @as(u32, @intCast(epoch)));
            public_keys[epoch] = try self.hash.hash(tweak, chain_ends);
            self.allocator.free(tweak);

            for (chain_ends) |end| {
                self.allocator.free(end);
            }
            self.allocator.free(chain_ends);
        }

        var tree = try MerkleTree.build(self.allocator, &self.hash, public_keys);

        const key_pair = struct { XMSSPublicKey, XMSSSecretKey }{
            .public_key = .{
                .root = try self.allocator.dupe(u8, tree.root()),
                .hash_parameter = try self.allocator.dupe(u8, self.hash.parameter),
            },
            .secret_key = .{
                .prf_key = prf_key,
                .merkle_tree = tree,
                .hash_parameter = try self.allocator.dupe(u8, self.hash.parameter),
            },
        };

        for (public_keys) |pk| {
            self.allocator.free(pk);
        }
        self.allocator.free(public_keys);

        return key_pair;
    }

    pub fn sign(
        self: *XMSS,
        secret_key: XMSSSecretKey,
        epoch: u32,
        message: []const u8,
    ) !Signature {
        const path = try secret_key.merkle_tree.path(self.allocator, @as(usize, epoch));

        const randomness = try self.encoding.message_hash.generateRandomness(self.allocator);
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

    pub fn verify(self: *XMSS, public_key: *const XMSSPublicKey, epoch: u32, message: []const u8, signature: *const Signature) !bool {
        const chunks = self.encoding.encode(self.allocator, message, signature.randomness, epoch) catch return false;
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

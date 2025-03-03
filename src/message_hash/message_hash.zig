const std = @import("std");
const ShaMessageHash = @import("sha3.zig").ShaMessageHash;

pub const MessageHash = union(enum) {
    sha: ShaMessageHash,
    // poseidon: PoseidonMessageHash,
};
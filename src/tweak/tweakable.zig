const std = @import("std");
const ShaTweakHash = @import("sha3.zig").ShaTweakHash;

pub const TweakableHash = union(enum) {
    sha: ShaTweakHash,
    // poseidon: PoseidonTweakHash,
};
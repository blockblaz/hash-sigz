const std = @import("std");
const ShaPRF = @import("sha3.zig").ShaPRF;

pub const PRF = union(enum) {
    sha: ShaPRF,
    // poseidon: PoseidonPRF,
};
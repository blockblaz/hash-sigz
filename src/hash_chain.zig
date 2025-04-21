const std = @import("std");
const ShaTweakHash = @import("tweak/sha3.zig").ShaTweakHash;

pub fn chain(
    hash: anytype,
    parameter: []u8,
    epoch: u32,
    chain_index: u16,
    start_pos: u16,
    steps: u16,
    msg: []u8
) void {
    for (0..steps) |j| {
        const pos = @as(u16, @intCast(start_pos)) + @as(u16, @intCast(j)) + 1;
        const tweak = hash.chain_tweak(epoch, chain_index, pos);

        hash.hash(parameter, tweak, &[_][]u8{msg}, msg);
    }
}

test "chain associativity" {
    var hash = ShaTweakHash.init(16, 32);

    const epoch = 9;
    const chain_index = 20;
    var random = std.crypto.random;

    var start_value: [32]u8 = undefined;
    random.bytes(&start_value);

    var parameter: [16]u8 = undefined;
    random.bytes(&parameter);

    const total_steps = 16;

    var start_value_copy: [32]u8 = start_value;
    chain(&hash, &parameter, epoch, chain_index, 0, total_steps, &start_value_copy);

    for (0..total_steps + 1) |split| {
        const steps_a: u16 = @intCast(split);
        const steps_b: u16 = total_steps - steps_a;

        var intermediate_value: [32]u8 = start_value;
        chain(&hash, &parameter, epoch, chain_index, 0, steps_a, &intermediate_value);

        var end_indirect: [32]u8 = intermediate_value;
        chain(&hash, &parameter, epoch, chain_index, steps_a, steps_b, &end_indirect);

        try std.testing.expectEqualSlices(u8, &start_value_copy, &end_indirect);
    }
}

const std = @import("std");
const WinternitzEncoding = @import("winternitz.zig").WinternitzEncoding;

pub const IncomparableEncoding = union(enum) {
    winternitz: WinternitzEncoding,
    // targetSum: TargetSumEncoding,
};
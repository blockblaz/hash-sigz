const XMSS = @import("xmss.zig").XMSS;
const ShaTweakHash = @import("tweak/sha3.zig").ShaTweakHash;
const ShaPRF = @import("prf/sha3.zig").ShaPRF;
const ShaMessageHash = @import("message_hash/sha3.zig").ShaMessageHash;
const WinternitzEncoding = @import("encoding/winternitz.zig").WinternitzEncoding;
const TargetSumEncoding = @import("encoding/target_sum.zig").TargetSumEncoding;

pub const ShaWinternitzXMSS = XMSS(ShaTweakHash, ShaPRF, ShaMessageHash, WinternitzEncoding(ShaMessageHash));
pub const ShaTargetSumXMSS = XMSS(ShaTweakHash, ShaPRF, ShaMessageHash, TargetSumEncoding(ShaMessageHash));
// pub const PoseidonWinternitzXMSS = XMSS(PoseidonTweakHash, PoseidonPRF, PoseidonMessageHash, WinternitzEncoding);
// pub const PoseidonTargetSumXMSS = XMSS(PoseidonTweakHash, PoseidonPRF, PoseidonMessageHash, TargetSumEncoding);

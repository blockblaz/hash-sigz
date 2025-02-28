const std = @import("std");
const ShaMessageHash = @import("../message_hash/sha3.zig").ShaMessageHash;
const bytesToChunks = @import("../utils.zig").bytesToChunks;

pub const WinternitzEncoding = struct {
    message_hash: ShaMessageHash,
    num_checksum_chunks: usize,
    
    pub fn init(
        allocator: std.mem.Allocator,
        parameter_size: usize,
        randomness_size: usize,
        chunk_size: usize,
        num_message_chunks: usize,  
        num_checksum_chunks: usize
    ) !WinternitzEncoding {
        const msg_hash = try ShaMessageHash.init(
            allocator,
            parameter_size,
            randomness_size,
            num_message_chunks,
            chunk_size
        );
        
        return WinternitzEncoding{
            .message_hash = msg_hash,
            .num_checksum_chunks = num_checksum_chunks,
        };
    }
    
    pub fn deinit(self: *WinternitzEncoding, allocator: std.mem.Allocator) void {
        self.message_hash.deinit(allocator);
    }
    
    pub fn encode(
        self: *const WinternitzEncoding,
        allocator: std.mem.Allocator,
        message: []const u8,
        randomness: []const u8,
        epoch: u32
    ) ![]u8 {
        const msg_chunks = try self.message_hash.apply(
            allocator, 
            epoch, 
            randomness, 
            message
        );
        defer allocator.free(msg_chunks);
        
        const base = 1 << self.message_hash.chunk_size;
        var checksum: u64 = 0;
        
        for (msg_chunks) |chunk| {
            checksum += (base - 1) - chunk;
        }
        
        var checksum_bytes: [8]u8 = undefined;
        std.mem.writeIntLittle(u64, &checksum_bytes, checksum);
        
        const checksum_chunks = try bytesToChunks(
            allocator,
            &checksum_bytes,
            self.message_hash.chunk_size,
            self.num_checksum_chunks
        );
        defer allocator.free(checksum_chunks);
        
        var result = try allocator.alloc(u8, msg_chunks.len + checksum_chunks.len);
        std.mem.copy(u8, result[0..msg_chunks.len], msg_chunks);
        std.mem.copy(u8, result[msg_chunks.len..], checksum_chunks);
        
        return result;
    }
};
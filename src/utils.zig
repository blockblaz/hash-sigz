const std = @import("std");

fn bytesToChunks(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    chunk_size: usize
) ![]u8 {
    std.debug.assert(chunk_size == 1 or chunk_size == 2 or chunk_size == 4 or chunk_size == 8);

    if(chunk_size == 8) return bytes;
    
    const chunks_per_byte = 8 / chunk_size;
    const num_chunks = bytes.len * chunks_per_byte;
    var chunks = try allocator.alloc(u8, num_chunks);
    
    var chunk_idx: usize = 0;
    for (bytes) |byte| {
        for (0..chunks_per_byte) |i| {
            if (chunk_idx >= num_chunks) break;
            
            const shift: u8 = @intCast(i * chunk_size);
            const mask: u8 = @intCast((1 << chunk_size) - 1);
            chunks[chunk_idx] = (byte >> shift) & mask;
            
            chunk_idx += 1;
        }
        if (chunk_idx >= num_chunks) break;
    }
    
    return chunks;
}
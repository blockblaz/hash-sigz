const std = @import("std");

fn bytesToChunks(
    allocator: std.mem.Allocator,
    bytes: []u8,
    comptime chunk_size: usize,
) ![]u8 {
    std.debug.assert(chunk_size == 1 or chunk_size == 2 or chunk_size == 4 or chunk_size == 8);

    if(chunk_size == 8) return bytes;
    
    const chunks_per_byte = 8 / chunk_size;
    const num_chunks = bytes.len * chunks_per_byte;
    var chunks = try allocator.alloc(u8, num_chunks);
    var chunk_idx: usize = 0;

    const mask: u8 = @intCast((1 << chunk_size) - 1);
    const shift: u8 = @intCast(chunk_size);

    for (bytes) |*byte| {
        for (0..chunks_per_byte) |_| {
            // if (chunk_idx >= num_chunks) break;
            chunks[chunk_idx] = (byte.*) & mask;
            byte.* >>= shift;
            chunk_idx += 1;
        }
    }
    
    return chunks;
}

test "bytesToChunks" {
    const allocator = std.testing.allocator;

    // w = 1
    var input = [_]u8{0b10101010};
    const chunks = try bytesToChunks(allocator, &input, 1);
    defer allocator.free(chunks);
    try std.testing.expectEqualSlices(u8, &[_]u8{0,1,0,1,0,1,0,1}, chunks);

    // w = 2
    var input2 = [_]u8{0b11100100};
    const chunks2 = try bytesToChunks(allocator, &input2, 2);
    defer allocator.free(chunks2);
    try std.testing.expectEqualSlices(u8, &[_]u8{0,1,2,3}, chunks2);

    // w = 4
    var input4 = [_]u8{0b11110000};
    const chunks4 = try bytesToChunks(allocator, &input4, 4);
    defer allocator.free(chunks4);
    try std.testing.expectEqualSlices(u8, &[_]u8{0,15}, chunks4);

    // w = 8
    var input8 = [_]u8{0b11111111};
    const chunks8 = try bytesToChunks(allocator, &input8, 8);
    try std.testing.expectEqualSlices(u8, &[_]u8{255}, chunks8);
}

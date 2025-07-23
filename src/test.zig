const std = @import("std");
const hashsig = @import("hash-sigzz");

pub fn main() !void {
    std.debug.print("Run 'zig build test' for actual tests\n", .{});
}

test "basic sign and verify" {
    std.debug.print("\n--- Testing basic sign and verify ---\n", .{});

    // Generate a keypair
    std.debug.print("Generating keypair...\n", .{});
    var keypair = hashsig.generateKeyPair(0, 1000) catch |err| {
        std.debug.print("Failed to generate keypair: {}\n", .{err});
        return err;
    };
    defer keypair.deinit();
    std.debug.print("Keypair generated successfully\n", .{});

    // Create message "gm, ethereum" padded to 32 bytes
    var message = [_]u8{0} ** 32;
    const msg_text = "gm, ethereum";
    @memcpy(message[0..msg_text.len], msg_text);

    const epoch: u32 = 42;

    // Sign the message
    std.debug.print("Signing message \"{s}\" at epoch {}...\n", .{ msg_text, epoch });
    var signature = hashsig.sign(keypair.secret_key, epoch, &message) catch |err| {
        std.debug.print("Failed to sign: {}\n", .{err});
        return err;
    };
    defer signature.deinit();
    std.debug.print("Message signed successfully\n", .{});

    // Verify the signature
    std.debug.print("Verifying signature...\n", .{});
    const is_valid = hashsig.verify(keypair.public_key, epoch, &message, signature.ptr);
    
    try std.testing.expect(is_valid);
    std.debug.print("Signature verification successful!\n", .{});

    // Test with wrong epoch (should fail)
    std.debug.print("Testing with wrong epoch (should fail)...\n", .{});
    const wrong_epoch_valid = hashsig.verify(keypair.public_key, epoch + 1, &message, signature.ptr);
    try std.testing.expect(!wrong_epoch_valid);
    std.debug.print("Correctly rejected signature with wrong epoch\n", .{});

    // Test with wrong message (should fail)
    std.debug.print("Testing with wrong message (should fail)...\n", .{});
    var wrong_message = message;
    wrong_message[0] = 0xFF;
    const wrong_msg_valid = hashsig.verify(keypair.public_key, epoch, &wrong_message, signature.ptr);
    try std.testing.expect(!wrong_msg_valid);
    std.debug.print("Correctly rejected signature with wrong message\n", .{});
}

test "error cases" {
    std.debug.print("\n--- Testing error cases ---\n", .{});

    // Test invalid epoch range
    std.debug.print("Testing invalid epoch range...\n", .{});
    const lifetime: u64 = 262144; // 2^18 for Poseidon lifetime 18
    std.debug.print("Lifetime: {}\n", .{lifetime});

    const result = hashsig.generateKeyPair(0, @intCast(lifetime + 1));
    try std.testing.expectError(error.InvalidEpoch, result);
    std.debug.print("Correctly failed with invalid epoch range\n", .{});
}
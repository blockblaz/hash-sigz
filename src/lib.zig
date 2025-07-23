const std = @import("std");

// NOTE: this uses the old poseidon instance not the newer poseidon_top_level instantiation. will need to be updated later
// TODO: needs signature to bytes and back to signature so that we can access the signature and send it over the network instead of using opaque pointers
// https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding
// https://doc.rust-lang.org/nomicon/unwinding.html
// TODO: all possible panics need to be handled at the ffi level / use c-unwind?
// TODO: make sure there are no memory leaks at the ffi boundary
// TODO: client integration for signing and verification
// TODO: test the signing and verification with a BeamBlock in the zeam client

// Error types matching Rust enum
pub const HashSigError = enum(u32) {
    success = 0,
    null_pointer = 1,
    invalid_message_length = 2,
    invalid_epoch = 3,
    signing_failed = 4,
    allocation_failed = 5,
};

// Opaque pointer types
pub const PublicKey = *anyopaque;
pub const SecretKey = *anyopaque;
pub const Signature = *anyopaque;

// External FFI functions from Rust
extern "C" fn hashsig_gen_keypair(
    activation_epoch: usize,
    num_active_epochs: usize,
    pk_out: *PublicKey,
    sk_out: *SecretKey,
) HashSigError;

extern "C" fn hashsig_sign(
    sk: SecretKey,
    epoch: u32,
    message: [*c]const u8,
    message_len: usize,
    sig_out: *Signature,
) HashSigError;

extern "C" fn hashsig_verify(
    pk: PublicKey,
    epoch: u32,
    message: [*c]const u8,
    message_len: usize,
    sig: Signature,
) bool;

extern "C" fn hashsig_free_publickey(pk: PublicKey) void;
extern "C" fn hashsig_free_secretkey(sk: SecretKey) void;
extern "C" fn hashsig_free_signature(sig: Signature) void;
// extern "C" fn hashsig_get_lifetime() u64;

// Zig wrapper types for memory management
pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    pub fn deinit(self: *KeyPair) void {
        hashsig_free_publickey(self.public_key);
        hashsig_free_secretkey(self.secret_key);
    }
};

pub const HashSignature = struct {
    ptr: Signature,

    pub fn deinit(self: *HashSignature) void {
        hashsig_free_signature(self.ptr);
    }
};

// High-level Zig API
pub fn generateKeyPair(activation_epoch: usize, num_active_epochs: usize) !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .secret_key = undefined,
    };

    const result = hashsig_gen_keypair(
        activation_epoch,
        num_active_epochs,
        &keypair.public_key,
        &keypair.secret_key,
    );

    return switch (result) {
        .success => keypair,
        .null_pointer => error.NullPointer,
        .invalid_epoch => error.InvalidEpoch,
        .allocation_failed => error.AllocationFailed,
        else => error.UnknownError,
    };
}

pub fn sign(secret_key: SecretKey, epoch: u32, message: *const [32]u8) !HashSignature {
    var signature = HashSignature{
        .ptr = undefined,
    };

    const result = hashsig_sign(
        secret_key,
        epoch,
        message.ptr,
        32,
        &signature.ptr,
    );

    return switch (result) {
        .success => signature,
        .null_pointer => error.NullPointer,
        .invalid_message_length => error.InvalidMessageLength,
        .signing_failed => error.SigningFailed,
        .allocation_failed => error.AllocationFailed,
        else => error.UnknownError,
    };
}

pub fn verify(public_key: PublicKey, epoch: u32, message: *const [32]u8, signature: Signature) bool {
    return hashsig_verify(
        public_key,
        epoch,
        message.ptr,
        32,
        signature,
    );
}

// pub fn getLifetime() u64 {
//     return hashsig_get_lifetime();
// }

// Usage
// pub fn example() !void {
//     // Generate a keypair
//     var keypair = try generateKeyPair(0, 1000);
//     defer keypair.deinit();

//     // Create a message to sign
//     const message = [_]u8{0x01} ** 32;

//     // Sign the message
//     var signature = try sign(keypair.secret_key, 42, &message);
//     defer signature.deinit();

//     // Verify the signature
//     const is_valid = verify(keypair.public_key, 42, &message, signature.ptr);
    
//     std.debug.print("Signature valid: {}\n", .{is_valid});
// }
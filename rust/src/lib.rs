use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W4;
use hashsig::signature::SignatureScheme;
use std::ffi::c_void;
use std::slice;

type Scheme = SIGWinternitzLifetime18W4;
type PublicKey = <Scheme as SignatureScheme>::PublicKey;
type SecretKey = <Scheme as SignatureScheme>::SecretKey;
type Signature = <Scheme as SignatureScheme>::Signature;

// TODO:// Make sure Box pointer casts and implementation do not cause memory issues.

/// Error codes for hash signature operations
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum HashSigError {
    /// Operation completed successfully
    Success = 0,
    /// A null pointer was passed where a valid pointer was expected
    NullPointer = 1,
    /// Message length is not 32 bytes
    InvalidMessageLength = 2,
    /// Epoch is outside valid range for the key
    InvalidEpoch = 3,
    /// Signature generation failed
    SigningFailed = 4,
    /// Memory allocation failed
    AllocationFailed = 5,
}

// Opaque pointer types for FFI
pub type PublicKeyPtr = *mut c_void;
pub type SecretKeyPtr = *mut c_void;
pub type SignaturePtr = *mut c_void;

/// Generate a new hash signature keypair
/// 
/// # Arguments
/// * `activation_epoch` - First epoch this key can sign for
/// * `num_active_epochs` - Number of epochs this key can sign for
/// * `pk_out` - Output pointer for public key
/// * `sk_out` - Output pointer for secret key
/// 
/// # Returns
/// * `HashSigError::Success` on success, error code otherwise
#[no_mangle]
pub extern "C" fn hashsig_gen_keypair(
    activation_epoch: usize,
    num_active_epochs: usize,
    pk_out: *mut PublicKeyPtr,
    sk_out: *mut SecretKeyPtr,
) -> HashSigError {
    if pk_out.is_null() || sk_out.is_null() {
        return HashSigError::NullPointer;
    }

    // Validate epoch range
    if activation_epoch + num_active_epochs > Scheme::LIFETIME as usize {
        return HashSigError::InvalidEpoch;
    }

    // Use the same RNG as in main.rs
    let mut rng = rand::rng();
    let (pk, sk) = Scheme::gen(&mut rng, activation_epoch, num_active_epochs);

    // Transfer ownership to raw pointers
    let pk_ptr = Box::into_raw(Box::new(pk)) as *mut c_void;
    let sk_ptr = Box::into_raw(Box::new(sk)) as *mut c_void;

    unsafe {
        *pk_out = pk_ptr;
        *sk_out = sk_ptr;
    }

    HashSigError::Success
}

#[no_mangle]
pub extern "C" fn hashsig_sign(
    sk: SecretKeyPtr,
    epoch: u32,
    message: *const u8,
    message_len: usize,
    sig_out: *mut SignaturePtr,
) -> HashSigError {
    if sk.is_null() || message.is_null() || sig_out.is_null() {
        return HashSigError::NullPointer;
    }

    if message_len != 32 {
        return HashSigError::InvalidMessageLength;
    }

    // Cast back to secret key reference
    let sk_ref = unsafe { &*(sk as *const SecretKey) };

    // Copy message to fixed array
    let msg_slice = unsafe { slice::from_raw_parts(message, 32) };
    let mut msg_array = [0u8; 32];
    msg_array.copy_from_slice(msg_slice);

    // Use thread RNG for signing
    let mut rng = rand::rng();
    
    match Scheme::sign(&mut rng, sk_ref, epoch, &msg_array) {
        Ok(sig) => {
            let sig_ptr = Box::into_raw(Box::new(sig)) as *mut c_void;
            unsafe {
                *sig_out = sig_ptr;
            }
            HashSigError::Success
        }
        Err(_) => HashSigError::SigningFailed,
    }
}

#[no_mangle]
pub extern "C" fn hashsig_verify(
    pk: PublicKeyPtr,
    epoch: u32,
    message: *const u8,
    message_len: usize,
    sig: SignaturePtr,
) -> bool {
    if pk.is_null() || message.is_null() || sig.is_null() {
        return false;
    }

    if message_len != 32 {
        return false;
    }

    // Cast back to references
    let pk_ref = unsafe { &*(pk as *const PublicKey) };
    let sig_ref = unsafe { &*(sig as *const Signature) };

    // Copy message to fixed array
    let msg_slice = unsafe { slice::from_raw_parts(message, 32) };
    let mut msg_array = [0u8; 32];
    msg_array.copy_from_slice(msg_slice);

    Scheme::verify(pk_ref, epoch, &msg_array, sig_ref)
}

// Type-specific free functions to prevent mixing up types

#[no_mangle]
pub extern "C" fn hashsig_free_publickey(pk: PublicKeyPtr) {
    if !pk.is_null() {
        unsafe {
            // Reconstruct Box to properly drop and deallocate
            let _ = Box::from_raw(pk as *mut PublicKey);
        }
    }
}

#[no_mangle]
pub extern "C" fn hashsig_free_secretkey(sk: SecretKeyPtr) {
    if !sk.is_null() {
        unsafe {
            // Reconstruct Box to properly drop and deallocate
            let _ = Box::from_raw(sk as *mut SecretKey);
        }
    }
}

#[no_mangle]
pub extern "C" fn hashsig_free_signature(sig: SignaturePtr) {
    if !sig.is_null() {
        unsafe {
            // Reconstruct Box to properly drop and deallocate
            let _ = Box::from_raw(sig as *mut Signature);
        }
    }
}

// Helper function to get the lifetime constant
#[no_mangle]
pub extern "C" fn hashsig_get_lifetime() -> u64 {
    Scheme::LIFETIME
}
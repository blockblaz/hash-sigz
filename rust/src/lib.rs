use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W4;
use hashsig::signature::SignatureScheme;
use serde::{Serialize, Deserialize};
// use bincode::{config,encode_to_vec, decode_from_slice};  
use bincode::config;
use bincode::serde::{encode_to_vec, decode_from_slice};

use std::ffi::c_void;
use std::slice;
use paste::paste;

type Scheme = SIGWinternitzLifetime18W4;
type PublicKey = <Scheme as SignatureScheme>::PublicKey;
type SecretKey = <Scheme as SignatureScheme>::SecretKey;
type Signature = <Scheme as SignatureScheme>::Signature;

// TODO:// Make sure Box pointer casts and implementation do not cause memory issues.
#[repr(C)]
pub struct Buf {
    data: *const u8,
    len:  usize,
}

#[no_mangle] 
pub extern "C" fn hashsig_free_buf(buf: Buf) {
    if !buf.data.is_null() {
        unsafe { drop(Box::from_raw(slice::from_raw_parts_mut(buf.data as *mut u8, buf.len))) }
    }
}

// builder methods in bincode::config aren’t yet const fn
#[inline]
fn binconfig() -> bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::NoLimit,
> {
    use bincode::config as cfg;
    cfg::standard()
        .with_fixed_int_encoding()
        .with_little_endian()
}
macro_rules! make_ser_funcs {
    ($name:ident, $t:ty) => {
        paste! {
            #[no_mangle]
            pub extern "C" fn [<$name _serialize>](obj: *const $t) -> Buf {
                use core::ptr;

                if obj.is_null() {
                    return Buf { data: ptr::null(), len: 0 };
                }

                // SAFETY: pointer checked for null above
                let cfg   = binconfig();
                let bytes = bincode::serde::encode_to_vec(unsafe { &*obj }, cfg)
                    .expect("serialization failed");

                let len = bytes.len();
                let ptr = Box::into_raw(bytes.into_boxed_slice()) as *const u8;
                Buf { data: ptr, len }
            }

            #[no_mangle]
            pub extern "C" fn [<$name _deserialize>](buf: Buf,
                                                     out: *mut *mut core::ffi::c_void)
                                                     -> bool {
                if buf.data.is_null() || out.is_null() {
                    return false;
                }

                let slice = unsafe { core::slice::from_raw_parts(buf.data, buf.len) };
                let cfg   = binconfig();

                match bincode::serde::decode_from_slice::<$t, _>(slice, cfg) {
                    Ok((obj, _)) => {
                        unsafe { *out = Box::into_raw(Box::new(obj)) as *mut _; }
                        true
                    }
                    Err(_) => false,
                }
            }
        }
    };
}

make_ser_funcs!(hashsig_pk,  PublicKey);
make_ser_funcs!(hashsig_sk,  SecretKey);
make_ser_funcs!(hashsig_sig, Signature);

// const BINCODE_CONFIG: config::Configuration<config::LittleEndian, config::Fixint, config::NoLimit> =
//     config::standard()
//         .with_fixed_int_encoding()
//         .with_little_endian();

//         macro_rules! make_ser_funcs {
//             ($name:ident, $t:ty) => {
//                 paste! {
//                     #[no_mangle]
//                     pub extern "C" fn [<$name _serialize>](obj: *const $t) -> Buf {
//                         if obj.is_null() {
//                             return Buf {
//                                 data: ptr::null(),
//                                 len: 0,
//                             };
//                         }
//                         let bytes = encode_to_vec(unsafe { &*obj }, BINCODE_CONFIG)
//                             .expect("serialize");
//                         let len = bytes.len();
//                         let ptr = Box::into_raw(bytes.into_boxed_slice()) as *const u8;
//                         Buf { data: ptr, len }
//                     }
        
//                     #[no_mangle]
//                     pub extern "C" fn [<$name _deserialize>](buf: Buf, out: *mut *mut c_void) -> bool {
//                         if buf.data.is_null() || out.is_null() {
//                             return false;
//                         }
//                         let slice = unsafe { slice::from_raw_parts(buf.data, buf.len) };
//                         match decode_from_slice::<$t>(slice, BINCODE_CONFIG) {
//                             Ok((obj, _)) => {
//                                 unsafe {
//                                     *out = Box::into_raw(Box::new(obj)) as *mut c_void;
//                                 }
//                                 true
//                             }
//                             Err(_) => false,
//                         }
//                     }
//                 }
//             };
//         }
        

// make_ser_funcs!(hashsig_pk, PublicKey);
// make_ser_funcs!(hashsig_sk, SecretKey);
// make_ser_funcs!(hashsig_sig, Signature);


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
    let (pk, sk) = Scheme::key_gen(&mut rng, activation_epoch, num_active_epochs);

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


#[cfg(test)]
mod ffi_roundtrip_tests {
    use super::*;
    use std::ptr;
    use bincode::serde::encode_to_vec;

    fn cfg() -> impl bincode::config::Config {
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian()
    }

    /// Helper to turn a Buf back into Vec<u8> for comparison
    unsafe fn buf_to_vec(buf: Buf) -> Vec<u8> {
        let slice = std::slice::from_raw_parts(buf.data, buf.len);
        let v = slice.to_vec();
        hashsig_free_buf(buf);
        v
    }

    #[test]
    fn public_key_roundtrip() {
        unsafe {
            let mut pk_ptr: PublicKeyPtr = ptr::null_mut();
            let mut sk_ptr: SecretKeyPtr = ptr::null_mut();
            assert_eq!(
                hashsig_gen_keypair(0, 1, &mut pk_ptr, &mut sk_ptr),
                HashSigError::Success
            );
            let buf = hashsig_pk_serialize(pk_ptr as *const PublicKey);
            assert!(!buf.data.is_null() && buf.len > 0);

            let mut pk2_ptr: *mut std::ffi::c_void = ptr::null_mut();
            assert!(hashsig_pk_deserialize(buf, &mut pk2_ptr));
            let orig = encode_to_vec(&*(pk_ptr as *const PublicKey), cfg()).unwrap();
            let copy = encode_to_vec(&*(pk2_ptr as *const PublicKey), cfg()).unwrap();
            assert_eq!(orig, copy);


            hashsig_free_publickey(pk_ptr);
            hashsig_free_publickey(pk2_ptr);
            hashsig_free_secretkey(sk_ptr);
        }
    }

    #[test]
    fn secret_key_roundtrip() {
        unsafe {
            let mut pk_ptr: PublicKeyPtr = ptr::null_mut();
            let mut sk_ptr: SecretKeyPtr = ptr::null_mut();
            assert_eq!(
                hashsig_gen_keypair(5, 3, &mut pk_ptr, &mut sk_ptr),
                HashSigError::Success
            );

            let buf = hashsig_sk_serialize(sk_ptr as *const SecretKey);
            assert!(!buf.data.is_null());

            let mut sk2_ptr: *mut std::ffi::c_void = ptr::null_mut();
            assert!(hashsig_sk_deserialize(buf, &mut sk2_ptr));

            let orig = encode_to_vec(&*(sk_ptr as *const SecretKey), cfg()).unwrap();
            let copy = encode_to_vec(&*(sk2_ptr as *const SecretKey), cfg()).unwrap();
            assert_eq!(orig, copy);

            hashsig_free_publickey(pk_ptr);
            hashsig_free_secretkey(sk_ptr);
            hashsig_free_secretkey(sk2_ptr);
        }
    }

    #[test]
    fn signature_roundtrip_and_verify() {
        unsafe {
            // ---- keypair & sign ----
            let mut pk_ptr: PublicKeyPtr = ptr::null_mut();
            let mut sk_ptr: SecretKeyPtr = ptr::null_mut();
            assert_eq!(
                hashsig_gen_keypair(0, 1, &mut pk_ptr, &mut sk_ptr),
                HashSigError::Success
            );

            let msg = [42u8; 32];
            let mut sig_ptr: SignaturePtr = ptr::null_mut();
            assert_eq!(
                hashsig_sign(
                    sk_ptr,
                    0,
                    msg.as_ptr(),
                    msg.len(),
                    &mut sig_ptr
                ),
                HashSigError::Success
            );

            // ---- serialize + deserialize signature ----
            let buf = hashsig_sig_serialize(sig_ptr as *const Signature);
            assert!(!buf.data.is_null());

            let mut sig2_ptr: *mut std::ffi::c_void = ptr::null_mut();
            assert!(hashsig_sig_deserialize(buf, &mut sig2_ptr));

            // ---- verify with original PK & message ----
            assert!(hashsig_verify(
                pk_ptr,
                0,
                msg.as_ptr(),
                msg.len(),
                sig2_ptr
            ));

            // ---- clean up ----
            hashsig_free_publickey(pk_ptr);
            hashsig_free_secretkey(sk_ptr);
            hashsig_free_signature(sig_ptr);
            hashsig_free_signature(sig2_ptr);
        }
    }
}

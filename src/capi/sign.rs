//! libsodium's Ed25519, in the `crypto_sign_ed25519_*` shape: a secret key is
//! the 32-byte seed followed by the 32-byte verification key it derives.

use core::ffi::c_int;

use crate::ed25519::{PublicKey, SecretKey, Signature, verify};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_bytes() -> usize {
    64
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_seedbytes() -> usize {
    32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_publickeybytes() -> usize {
    32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_secretkeybytes() -> usize {
    64
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_seed_keypair(
    pk: *mut u8,
    sk: *mut u8,
    seed: *const u8,
) -> c_int {
    unsafe {
        let seed: [u8; 32] = super::read_array(seed);
        let secret = SecretKey::from_bytes(seed);
        let public = secret.public();
        super::write_bytes(pk, public.as_bytes());
        super::write_bytes(sk, &seed);
        super::write_bytes(sk.add(32), public.as_bytes());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_keypair(pk: *mut u8, sk: *mut u8) -> c_int {
    unsafe {
        let mut seed = [0u8; 32];
        super::mem::randombytes_buf(seed.as_mut_ptr() as *mut core::ffi::c_void, 32);
        let res = crypto_sign_ed25519_seed_keypair(pk, sk, seed.as_ptr());
        crate::ed25519::wipe(&mut seed);
        res
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_sk_to_seed(seed: *mut u8, sk: *const u8) -> c_int {
    unsafe {
        super::write_bytes(seed, &super::read_array::<32>(sk));
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_sk_to_pk(pk: *mut u8, sk: *const u8) -> c_int {
    unsafe {
        super::write_bytes(pk, &super::read_array::<32>(sk.add(32)));
        0
    }
}

/// Sign with the seed half of `sk`.
///
/// libsodium takes the verification key used in the challenge from the second
/// half of `sk` rather than deriving it; the two agree for every key the node
/// can produce, since its keys always come from
/// `crypto_sign_ed25519_seed_keypair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_detached(
    sig: *mut u8,
    siglen_p: *mut u64,
    m: *const u8,
    mlen: u64,
    sk: *const u8,
) -> c_int {
    unsafe {
        let seed: [u8; 32] = super::read_array(sk);
        let signature = SecretKey::from_bytes(seed).sign(super::as_slice(m, mlen as usize));
        super::write_bytes(sig, signature.as_bytes());
        if !siglen_p.is_null() {
            siglen_p.write_unaligned(64);
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_sign_ed25519_verify_detached(
    sig: *const u8,
    m: *const u8,
    mlen: u64,
    pk: *const u8,
) -> c_int {
    unsafe {
        let public = PublicKey::from_bytes(super::read_array(pk));
        let signature = Signature::from_bytes(super::read_array(sig));
        if verify(&public, super::as_slice(m, mlen as usize), &signature) {
            0
        } else {
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 test vector 2, which is also libsodium's.
    #[test]
    fn rfc8032_vector() {
        let seed = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 64];
        let mut sig = [0u8; 64];
        let msg = [0x72u8];
        unsafe {
            assert_eq!(
                crypto_sign_ed25519_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()),
                0
            );
            let mut siglen = 0u64;
            assert_eq!(
                crypto_sign_ed25519_detached(
                    sig.as_mut_ptr(),
                    &mut siglen,
                    msg.as_ptr(),
                    1,
                    sk.as_ptr()
                ),
                0
            );
            assert_eq!(siglen, 64);
            assert_eq!(
                crypto_sign_ed25519_verify_detached(sig.as_ptr(), msg.as_ptr(), 1, pk.as_ptr()),
                0
            );
            // a different message does not verify
            assert_eq!(
                crypto_sign_ed25519_verify_detached(sig.as_ptr(), b"\x73".as_ptr(), 1, pk.as_ptr()),
                -1
            );

            let mut seed_back = [0u8; 32];
            crypto_sign_ed25519_sk_to_seed(seed_back.as_mut_ptr(), sk.as_ptr());
            assert_eq!(seed_back, seed);
            let mut pk_back = [0u8; 32];
            crypto_sign_ed25519_sk_to_pk(pk_back.as_mut_ptr(), sk.as_ptr());
            assert_eq!(pk_back, pk);
        }
        assert_eq!(
            hex(&pk),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        assert_eq!(
            hex(&sig),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

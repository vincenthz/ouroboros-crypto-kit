//! libsodium's SHA-2 and Blake2b, one-shot and incremental.
//!
//! The incremental state lives in the buffer the caller allocated, which is
//! `crypto_hash_sha256_state` (128 bytes), `crypto_hash_sha512_state` (256) or
//! `crypto_generichash_blake2b_state` (384). Those buffers have no alignment
//! guarantee, so the contexts are moved in and out of them with unaligned
//! reads and writes.

use core::ffi::c_int;

use cryptoxide::hashing::blake2b::ContextDyn as Blake2bDyn;

use crate::hash::{Sha256Context, Sha512Context, sha256, sha512};

/// The Blake2b context together with the output length it was initialized for:
/// libsodium's `_final` takes the length again, and mismatching it is an error
/// rather than something to silently accept.
struct Blake2bState {
    ctx: Blake2bDyn,
    outlen: usize,
}

const BLAKE2B_MAX: usize = 64;

const _: () = assert!(core::mem::size_of::<Sha256Context>() <= 128);
const _: () = assert!(core::mem::size_of::<Sha512Context>() <= 256);
const _: () = assert!(core::mem::size_of::<Blake2bState>() <= 384);

/* ---------------------------------------------------------------- */
/* SHA-256                                                          */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha256_bytes() -> usize {
    32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha256(out: *mut u8, input: *const u8, inlen: u64) -> c_int {
    unsafe {
        let digest = sha256(super::as_slice(input, inlen as usize));
        super::write_bytes(out, &digest);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha256_init(state: *mut u8) -> c_int {
    unsafe {
        (state as *mut Sha256Context).write_unaligned(Sha256Context::new());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha256_update(
    state: *mut u8,
    input: *const u8,
    inlen: u64,
) -> c_int {
    unsafe {
        let mut ctx = (state as *const Sha256Context).read_unaligned();
        ctx.update_mut(super::as_slice(input, inlen as usize));
        (state as *mut Sha256Context).write_unaligned(ctx);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha256_final(state: *mut u8, out: *mut u8) -> c_int {
    unsafe {
        let ctx = (state as *const Sha256Context).read_unaligned();
        super::write_bytes(out, &ctx.finalize());
        0
    }
}

/* ---------------------------------------------------------------- */
/* SHA-512                                                          */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha512_bytes() -> usize {
    64
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha512(out: *mut u8, input: *const u8, inlen: u64) -> c_int {
    unsafe {
        let digest = sha512(super::as_slice(input, inlen as usize));
        super::write_bytes(out, &digest);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha512_init(state: *mut u8) -> c_int {
    unsafe {
        (state as *mut Sha512Context).write_unaligned(Sha512Context::new());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha512_update(
    state: *mut u8,
    input: *const u8,
    inlen: u64,
) -> c_int {
    unsafe {
        let mut ctx = (state as *const Sha512Context).read_unaligned();
        ctx.update_mut(super::as_slice(input, inlen as usize));
        (state as *mut Sha512Context).write_unaligned(ctx);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_sha512_final(state: *mut u8, out: *mut u8) -> c_int {
    unsafe {
        let ctx = (state as *const Sha512Context).read_unaligned();
        super::write_bytes(out, &ctx.finalize());
        0
    }
}

/* ---------------------------------------------------------------- */
/* Blake2b                                                          */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_generichash_blake2b_bytes() -> usize {
    32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_generichash_blake2b_statebytes() -> usize {
    384
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_generichash_blake2b(
    out: *mut u8,
    outlen: usize,
    input: *const u8,
    inlen: u64,
    key: *const u8,
    keylen: usize,
) -> c_int {
    unsafe {
        if outlen == 0 || outlen > BLAKE2B_MAX || keylen > BLAKE2B_MAX {
            return -1;
        }
        let mut ctx = Blake2bDyn::new_keyed(outlen, super::as_slice(key, keylen));
        ctx.update_mut(super::as_slice(input, inlen as usize));
        let mut digest = [0u8; BLAKE2B_MAX];
        ctx.finalize_at(&mut digest[..outlen]);
        super::write_bytes(out, &digest[..outlen]);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_generichash_blake2b_init(
    state: *mut u8,
    key: *const u8,
    keylen: usize,
    outlen: usize,
) -> c_int {
    unsafe {
        if outlen == 0 || outlen > BLAKE2B_MAX || keylen > BLAKE2B_MAX {
            return -1;
        }
        let ctx = Blake2bDyn::new_keyed(outlen, super::as_slice(key, keylen));
        (state as *mut Blake2bState).write_unaligned(Blake2bState { ctx, outlen });
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_generichash_blake2b_update(
    state: *mut u8,
    input: *const u8,
    inlen: u64,
) -> c_int {
    unsafe {
        let mut st = (state as *const Blake2bState).read_unaligned();
        st.ctx.update_mut(super::as_slice(input, inlen as usize));
        (state as *mut Blake2bState).write_unaligned(st);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_generichash_blake2b_final(
    state: *mut u8,
    out: *mut u8,
    outlen: usize,
) -> c_int {
    unsafe {
        let st = (state as *const Blake2bState).read_unaligned();
        if outlen != st.outlen {
            return -1;
        }
        let mut digest = [0u8; BLAKE2B_MAX];
        st.ctx.finalize_at(&mut digest[..outlen]);
        super::write_bytes(out, &digest[..outlen]);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_incremental_matches_one_shot() {
        let mut state = [0u8; 128];
        let mut out = [0u8; 32];
        unsafe {
            assert_eq!(crypto_hash_sha256_init(state.as_mut_ptr()), 0);
            assert_eq!(
                crypto_hash_sha256_update(state.as_mut_ptr(), b"hello ".as_ptr(), 6),
                0
            );
            assert_eq!(
                crypto_hash_sha256_update(state.as_mut_ptr(), b"world".as_ptr(), 5),
                0
            );
            assert_eq!(
                crypto_hash_sha256_final(state.as_mut_ptr(), out.as_mut_ptr()),
                0
            );
        }
        assert_eq!(out, sha256(b"hello world"));
    }

    #[test]
    fn sha512_incremental_matches_one_shot() {
        let mut state = [0u8; 256];
        let mut out = [0u8; 64];
        unsafe {
            crypto_hash_sha512_init(state.as_mut_ptr());
            crypto_hash_sha512_update(state.as_mut_ptr(), b"abc".as_ptr(), 3);
            crypto_hash_sha512_final(state.as_mut_ptr(), out.as_mut_ptr());
        }
        assert_eq!(out, sha512(b"abc"));
    }

    #[test]
    fn blake2b_matches_the_fixed_width_versions() {
        let mut out = [0u8; 32];
        unsafe {
            assert_eq!(
                crypto_generichash_blake2b(
                    out.as_mut_ptr(),
                    32,
                    b"abc".as_ptr(),
                    3,
                    core::ptr::null(),
                    0
                ),
                0
            );
        }
        assert_eq!(out, crate::hash::blake2b_256(b"abc"));

        let mut out224 = [0u8; 28];
        unsafe {
            crypto_generichash_blake2b(
                out224.as_mut_ptr(),
                28,
                b"abc".as_ptr(),
                3,
                core::ptr::null(),
                0,
            );
        }
        assert_eq!(out224, crate::hash::blake2b_224(b"abc"));
    }

    #[test]
    fn blake2b_incremental_matches_one_shot() {
        // deliberately misaligned by one byte, as the caller's buffer may be
        let mut backing = [0u8; 400];
        let state = unsafe { backing.as_mut_ptr().add(1) };
        let mut out = [0u8; 32];
        unsafe {
            assert_eq!(
                crypto_generichash_blake2b_init(state, core::ptr::null(), 0, 32),
                0
            );
            assert_eq!(
                crypto_generichash_blake2b_update(state, b"ab".as_ptr(), 2),
                0
            );
            assert_eq!(
                crypto_generichash_blake2b_update(state, b"c".as_ptr(), 1),
                0
            );
            assert_eq!(
                crypto_generichash_blake2b_final(state, out.as_mut_ptr(), 32),
                0
            );
            // a mismatched output length is refused rather than mistrusted
            crypto_generichash_blake2b_init(state, core::ptr::null(), 0, 32);
            assert_eq!(
                crypto_generichash_blake2b_final(state, out.as_mut_ptr(), 28),
                -1
            );
        }
        assert_eq!(out, crate::hash::blake2b_256(b"abc"));
    }

    #[test]
    fn blake2b_rejects_impossible_lengths() {
        let mut out = [0u8; 64];
        unsafe {
            assert_eq!(
                crypto_generichash_blake2b(
                    out.as_mut_ptr(),
                    0,
                    b"".as_ptr(),
                    0,
                    core::ptr::null(),
                    0
                ),
                -1
            );
            assert_eq!(
                crypto_generichash_blake2b(
                    out.as_mut_ptr(),
                    65,
                    b"".as_ptr(),
                    0,
                    core::ptr::null(),
                    0
                ),
                -1
            );
        }
    }
}

//! The C ABI of this crate: drop-in replacements for the parts of libsodium
//! (including the input-output-hk VRF extension), libsecp256k1 and blst that a
//! Cardano node links against.
//!
//! The point of this module is that `cardano-crypto-class` and
//! `cardano-crypto-praos` can be built and linked without a single line of C
//! cryptography: the symbols their `foreign import`s name are exported from
//! here, with the same signatures and the same acceptance rules, and the work
//! is done by the Rust in the rest of the crate.
//!
//! The headers that go with these definitions are in `capi/include`; they are
//! the documentation for each function, and they fix the sizes of the opaque
//! structs the Haskell side allocates:
//!
//! | struct | size | holds |
//! |---|---|---|
//! | `crypto_hash_sha256_state` | 128 | [`cryptoxide`] SHA-256 context |
//! | `crypto_hash_sha512_state` | 256 | [`cryptoxide`] SHA-512 context |
//! | `crypto_generichash_blake2b_state` | 384 | Blake2b context + output length |
//! | `blst_p1` / `blst_p2` | 144 / 288 | [`eccoxide`] projective point |
//! | `blst_p1_affine` / `blst_p2_affine` | 96 / 192 | canonical big-endian coordinates |
//! | `blst_fp12` | 576 | [`MlResult`](crate::plutus::bls12_381::MlResult) |
//! | `blst_scalar` / `blst_fr` | 32 / 32 | little-endian / canonical scalar |
//! | `secp256k1_pubkey` / `_xonly_pubkey` | 64 | affine `x \|\| y`, big-endian |
//! | `secp256k1_ecdsa_signature` | 64 | `r \|\| s`, big-endian |
//! | `secp256k1_keypair` | 96 | `sk \|\| x \|\| y`, big-endian |
//!
//! Nothing outside this module ever looks inside those structs, so the choice of
//! representation is ours; what has to agree with the C libraries is the
//! behaviour of the functions, and that is what the rest of the crate provides.
//!
//! # Conventions
//!
//! * a function that libsodium gives an `int` returns `0` for success and `-1`
//!   for failure; libsecp256k1's return `1` for success and `0` for failure;
//!   blst's return a `BLST_ERROR`;
//! * pointers are trusted to be non-null and to point at as many bytes as the
//!   corresponding C prototype promises, which is what the callers do;
//! * a `(pointer, length)` pair with length zero may have a null pointer.

// The C prototypes in `capi/include` document these functions; repeating each
// one as a doc comment here would only let the two drift apart.
#![allow(missing_docs)]
#![allow(clippy::missing_safety_doc)]

mod blst;
mod hash;
mod mac;
mod mem;
mod secp;
mod sign;
mod vrf;

use core::slice;

/// A `&[u8]` over a C `(pointer, length)` pair, tolerating the null pointer C
/// code passes for an empty slice.
pub(crate) unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    unsafe {
        if len == 0 || ptr.is_null() {
            &[]
        } else {
            slice::from_raw_parts(ptr, len)
        }
    }
}

/// The `N` bytes at `ptr`.
pub(crate) unsafe fn read_array<const N: usize>(ptr: *const u8) -> [u8; N] {
    unsafe {
        let mut out = [0u8; N];
        core::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N);
        out
    }
}

/// Write `src` to the buffer at `dst`, which the caller promises is at least
/// `src.len()` bytes long.
pub(crate) unsafe fn write_bytes(dst: *mut u8, src: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    }
}

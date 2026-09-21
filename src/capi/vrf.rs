//! The VRF functions of the input-output-hk libsodium fork: `draft-03`, which
//! every Shelley-era block uses, and the batch-compatible `draft-13`.
//!
//! A signing key is the 32-byte seed followed by the 32-byte verification key,
//! which is the fork's layout and `cardano-crypto-praos`'s serialisation. The
//! generic `crypto_vrf_*` entry points are the draft-03 ones, as in the fork;
//! key derivation is the same for both drafts, which is why
//! `Cardano.Crypto.VRF.PraosBatchCompat` can use them for its own keys.

use core::ffi::c_int;

use crate::vrf::{OUTPUT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SEED_SIZE, praos, praos_batch};

/* ---------------------------------------------------------------- */
/* draft-03                                                         */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_bytes() -> usize {
    praos::PROOF_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_outputbytes() -> usize {
    OUTPUT_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_seedbytes() -> usize {
    SEED_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_publickeybytes() -> usize {
    PUBLIC_KEY_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_secretkeybytes() -> usize {
    SECRET_KEY_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_keypair_from_seed(
    pk: *mut u8,
    sk: *mut u8,
    seed: *const u8,
) -> c_int {
    unsafe {
        let secret = praos::SecretKey::from_seed(&super::read_array(seed));
        super::write_bytes(sk, secret.as_bytes());
        super::write_bytes(pk, secret.public().as_bytes());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_sk_to_pk(pk: *mut u8, skpk: *const u8) {
    unsafe {
        super::write_bytes(pk, &super::read_array::<32>(skpk.add(32)));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_sk_to_seed(seed: *mut u8, skpk: *const u8) {
    unsafe {
        super::write_bytes(seed, &super::read_array::<32>(skpk));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_prove(
    proof: *mut u8,
    skpk: *const u8,
    m: *const u8,
    mlen: u64,
) -> c_int {
    unsafe {
        let secret = praos::SecretKey::from_bytes(&super::read_array(skpk));
        let p = secret.prove(super::as_slice(m, mlen as usize));
        super::write_bytes(proof, p.as_bytes());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_verify(
    output: *mut u8,
    pk: *const u8,
    proof: *const u8,
    m: *const u8,
    mlen: u64,
) -> c_int {
    unsafe {
        let public = praos::PublicKey::from_bytes(super::read_array(pk));
        let p = praos::Proof::from_bytes(super::read_array(proof));
        match praos::verify(&public, &p, super::as_slice(m, mlen as usize)) {
            Ok(out) => {
                super::write_bytes(output, out.as_bytes());
                0
            }
            Err(_) => -1,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft03_proof_to_hash(
    hash: *mut u8,
    proof: *const u8,
) -> c_int {
    unsafe {
        let p = praos::Proof::from_bytes(super::read_array(proof));
        match p.to_hash() {
            Ok(out) => {
                super::write_bytes(hash, out.as_bytes());
                0
            }
            Err(_) => -1,
        }
    }
}

/* ---------------------------------------------------------------- */
/* draft-13, batch-compatible                                       */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_bytes_batchcompat() -> usize {
    praos_batch::PROOF_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_outputbytes() -> usize {
    OUTPUT_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_seedbytes() -> usize {
    SEED_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_publickeybytes() -> usize {
    PUBLIC_KEY_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_secretkeybytes() -> usize {
    SECRET_KEY_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_keypair_from_seed_batchcompat(
    pk: *mut u8,
    sk: *mut u8,
    seed: *const u8,
) -> c_int {
    unsafe {
        let secret = praos_batch::SecretKey::from_seed(&super::read_array(seed));
        super::write_bytes(sk, secret.as_bytes());
        super::write_bytes(pk, secret.public().as_bytes());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_prove_batchcompat(
    proof: *mut u8,
    skpk: *const u8,
    m: *const u8,
    mlen: u64,
) -> c_int {
    unsafe {
        let secret = praos_batch::SecretKey::from_bytes(&super::read_array(skpk));
        let p = secret.prove(super::as_slice(m, mlen as usize));
        super::write_bytes(proof, p.as_bytes());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_verify_batchcompat(
    output: *mut u8,
    pk: *const u8,
    proof: *const u8,
    m: *const u8,
    mlen: u64,
) -> c_int {
    unsafe {
        let public = praos_batch::PublicKey::from_bytes(super::read_array(pk));
        let p = praos_batch::Proof::from_bytes(super::read_array(proof));
        match praos_batch::verify(&public, &p, super::as_slice(m, mlen as usize)) {
            Ok(out) => {
                super::write_bytes(output, out.as_bytes());
                0
            }
            Err(_) => -1,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_ietfdraft13_proof_to_hash_batchcompat(
    hash: *mut u8,
    proof: *const u8,
) -> c_int {
    unsafe {
        let p = praos_batch::Proof::from_bytes(super::read_array(proof));
        match p.to_hash() {
            Ok(out) => {
                super::write_bytes(hash, out.as_bytes());
                0
            }
            Err(_) => -1,
        }
    }
}

/* ---------------------------------------------------------------- */
/* The generic entry points                                         */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_bytes() -> usize {
    praos::PROOF_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_outputbytes() -> usize {
    OUTPUT_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_seedbytes() -> usize {
    SEED_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_publickeybytes() -> usize {
    PUBLIC_KEY_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_secretkeybytes() -> usize {
    SECRET_KEY_SIZE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_keypair(pk: *mut u8, sk: *mut u8) -> c_int {
    unsafe {
        let mut seed = [0u8; SEED_SIZE];
        super::mem::randombytes_buf(seed.as_mut_ptr() as *mut core::ffi::c_void, seed.len());
        let res = crypto_vrf_ietfdraft03_keypair_from_seed(pk, sk, seed.as_ptr());
        crate::ed25519::wipe(&mut seed);
        res
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_seed_keypair(
    pk: *mut u8,
    sk: *mut u8,
    seed: *const u8,
) -> c_int {
    unsafe { crypto_vrf_ietfdraft03_keypair_from_seed(pk, sk, seed) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_sk_to_pk(pk: *mut u8, skpk: *const u8) -> c_int {
    unsafe {
        crypto_vrf_ietfdraft03_sk_to_pk(pk, skpk);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_sk_to_seed(seed: *mut u8, skpk: *const u8) -> c_int {
    unsafe {
        crypto_vrf_ietfdraft03_sk_to_seed(seed, skpk);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_prove(
    proof: *mut u8,
    skpk: *const u8,
    m: *const u8,
    mlen: u64,
) -> c_int {
    unsafe { crypto_vrf_ietfdraft03_prove(proof, skpk, m, mlen) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_verify(
    output: *mut u8,
    pk: *const u8,
    proof: *const u8,
    m: *const u8,
    mlen: u64,
) -> c_int {
    unsafe { crypto_vrf_ietfdraft03_verify(output, pk, proof, m, mlen) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_vrf_proof_to_hash(hash: *mut u8, proof: *const u8) -> c_int {
    unsafe { crypto_vrf_ietfdraft03_proof_to_hash(hash, proof) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft03_round_trip_through_the_c_abi() {
        let seed = [7u8; 32];
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 64];
        let mut proof = [0u8; 80];
        let mut output = [0u8; 64];
        let mut output2 = [0u8; 64];
        let msg = b"a message";
        unsafe {
            assert_eq!(
                crypto_vrf_ietfdraft03_keypair_from_seed(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr(),
                    seed.as_ptr()
                ),
                0
            );
            assert_eq!(
                crypto_vrf_ietfdraft03_prove(proof.as_mut_ptr(), sk.as_ptr(), msg.as_ptr(), 9),
                0
            );
            assert_eq!(
                crypto_vrf_ietfdraft03_verify(
                    output.as_mut_ptr(),
                    pk.as_ptr(),
                    proof.as_ptr(),
                    msg.as_ptr(),
                    9
                ),
                0
            );
            assert_eq!(
                crypto_vrf_ietfdraft03_proof_to_hash(output2.as_mut_ptr(), proof.as_ptr()),
                0
            );
            assert_eq!(output, output2);

            // a tampered proof is rejected
            proof[0] ^= 1;
            assert_eq!(
                crypto_vrf_ietfdraft03_verify(
                    output.as_mut_ptr(),
                    pk.as_ptr(),
                    proof.as_ptr(),
                    msg.as_ptr(),
                    9
                ),
                -1
            );
        }
        unsafe {
            assert_eq!(crypto_vrf_ietfdraft03_bytes(), 80);
            assert_eq!(crypto_vrf_ietfdraft13_bytes_batchcompat(), 128);
        }
    }

    #[test]
    fn draft13_round_trip_through_the_c_abi() {
        let seed = [9u8; 32];
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 64];
        let mut proof = [0u8; 128];
        let mut output = [0u8; 64];
        let msg = b"another";
        unsafe {
            // the generic key derivation is the one draft-13 uses
            assert_eq!(
                crypto_vrf_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()),
                0
            );
            assert_eq!(
                crypto_vrf_ietfdraft13_prove_batchcompat(
                    proof.as_mut_ptr(),
                    sk.as_ptr(),
                    msg.as_ptr(),
                    7
                ),
                0
            );
            assert_eq!(
                crypto_vrf_ietfdraft13_verify_batchcompat(
                    output.as_mut_ptr(),
                    pk.as_ptr(),
                    proof.as_ptr(),
                    msg.as_ptr(),
                    7
                ),
                0
            );
            let mut output2 = [0u8; 64];
            assert_eq!(
                crypto_vrf_ietfdraft13_proof_to_hash_batchcompat(
                    output2.as_mut_ptr(),
                    proof.as_ptr()
                ),
                0
            );
            assert_eq!(output, output2);
        }
    }
}

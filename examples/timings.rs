//! Rough timings of the operations a node performs per block or per script.
//!
//! ```text
//! cargo run --release --example timings
//! ```
//!
//! This is a sanity check, not a benchmark: single-threaded, wall clock, no
//! statistics. It exists so that a change that makes something 100x slower is
//! noticed.

use std::time::Instant;

use ouroboros_crypto_kit::plutus::bls12_381::{miller_loop, Scalar as BlsScalar, G1, G2};
use ouroboros_crypto_kit::plutus::secp256k1;
use ouroboros_crypto_kit::vrf::{praos, praos_batch};
use ouroboros_crypto_kit::{ed25519, hash, kes};

fn time<T>(label: &str, iterations: u32, mut f: impl FnMut() -> T) {
    // warm up any lazily built table
    let _ = f();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = f();
    }
    let elapsed = start.elapsed();
    let per = elapsed / iterations;
    println!("{label:<44} {:>10.3?}", per);
}

fn main() {
    println!("--- hashing (1 KiB) ---");
    let data = vec![0xa5u8; 1024];
    time("blake2b-256", 20_000, || hash::blake2b_256(&data));
    time("sha2-256", 20_000, || hash::sha256(&data));
    time("keccak-256", 20_000, || hash::keccak_256(&data));

    println!("\n--- ed25519 ---");
    let sk = ed25519::SecretKey::from_bytes([7u8; 32]);
    let pk = sk.public();
    let sig = sk.sign(&data);
    time("sign", 2_000, || sk.sign(&data));
    time("verify", 2_000, || ed25519::verify(&pk, &data, &sig));

    println!("\n--- VRF (draft-03, what the chain uses today) ---");
    let vrf_sk = praos::SecretKey::from_seed(&[3u8; 32]);
    let vrf_pk = vrf_sk.public();
    let proof = vrf_sk.prove(&data[..32]);
    time("prove", 1_000, || vrf_sk.prove(&data[..32]));
    time("verify", 1_000, || {
        praos::verify(&vrf_pk, &proof, &data[..32])
    });

    println!("\n--- VRF (draft-13, batch compatible) ---");
    let sk13 = praos_batch::SecretKey::from_seed(&[3u8; 32]);
    let pk13 = sk13.public();
    let proof13 = sk13.prove(&data[..32]);
    time("prove", 1_000, || sk13.prove(&data[..32]));
    time("verify", 1_000, || {
        praos_batch::verify(&pk13, &proof13, &data[..32])
    });

    println!("\n--- KES (Sum6, as in a block header) ---");
    let kes_sk = kes::SumKes::from_seed(6, &mut [11u8; 32]).unwrap();
    let kes_pk = kes_sk.public();
    let kes_sig = kes_sk.sign(&data[..32]);
    time("keygen (depth 6)", 200, || {
        kes::SumKes::from_seed(6, &mut [11u8; 32]).unwrap()
    });
    time("sign", 2_000, || kes_sk.sign(&data[..32]));
    time("verify", 2_000, || kes_sig.verify(0, &kes_pk, &data[..32]));

    println!("\n--- secp256k1 (Plutus builtins) ---");
    let ecdsa_sk = secp256k1::SecretKey::from_bytes(&[9u8; 32]).unwrap();
    let ecdsa_pk = ecdsa_sk.public_compressed();
    let digest = hash::sha256(&data);
    let ecdsa_sig = ecdsa_sk.sign_ecdsa(&digest);
    time("ecdsa verify", 1_000, || {
        secp256k1::verify_ecdsa(&ecdsa_pk, &digest, &ecdsa_sig)
    });

    println!("\n--- BLS12-381 (Plutus builtins) ---");
    let g1 = G1::generator();
    let g2 = G2::generator();
    let k = BlsScalar::from_u64(0x1234_5678_9abc_def0);
    let g1c = g1.compress();
    let g2c = g2.compress();
    time("G1 add", 200_000, || g1.add(&g1));
    time("G1 scalarMul", 2_000, || g1.scalar_mul(&k));
    time("G2 scalarMul", 500, || g2.scalar_mul(&k));
    time("G1 compress", 100_000, || g1.compress());
    time("G1 uncompress (incl. subgroup check)", 200, || {
        G1::uncompress(&g1c)
    });
    time("G2 uncompress (incl. subgroup check)", 100, || {
        G2::uncompress(&g2c)
    });
    time("G1 hashToGroup", 200, || {
        G1::hash_to_group(&data[..32], b"dst")
    });
    time("G2 hashToGroup", 50, || {
        G2::hash_to_group(&data[..32], b"dst")
    });
    let ml = miller_loop(&g1, &g2);
    time("millerLoop", 200, || miller_loop(&g1, &g2));
    time("finalVerify", 100, || ml.final_verify(&ml));
}

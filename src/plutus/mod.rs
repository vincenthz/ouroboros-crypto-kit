//! The cryptographic primitives Plutus exposes as builtins.
//!
//! * [`secp256k1`] — `verifyEcdsaSecp256k1Signature` and
//!   `verifySchnorrSecp256k1Signature` (CIP-49).
//! * [`bls12_381`] — the G1, G2 and pairing operations of CIP-0381.
//!
//! The hash builtins (`sha2_256`, `sha3_256`, `keccak_256`, `blake2b_224`,
//! `blake2b_256`, `ripemd_160`) are plain hash functions and live in
//! [`crate::hash`]; `verifyEd25519Signature` is [`crate::ed25519::verify`].

pub mod bls12_381;
pub mod secp256k1;

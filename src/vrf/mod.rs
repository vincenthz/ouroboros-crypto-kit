//! The two VRF flavours used by Ouroboros Praos.
//!
//! * [`praos`] is `ECVRF-ED25519-SHA512-Elligator2` as specified in
//!   `draft-irtf-cfrg-vrf-03`, and is what has secured every block since
//!   Shelley. 80-byte proofs.
//! * [`praos_batch`] is the batch-compatible variant built on
//!   `draft-irtf-cfrg-vrf-13`: the proof carries the two announcements instead
//!   of the challenge, so verification is an equality check rather than a
//!   recomputation, which is what makes batching possible. 128-byte proofs.
//!
//! Both follow the C code in `cardano-crypto-praos/cbits` rather than the
//! drafts themselves; the places where the two disagree are called out in the
//! implementations.

pub mod praos;
pub mod praos_batch;

/// Errors returned when a VRF proof cannot be verified.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VrfError {
    /// The verification key is not canonically encoded, has small order, or is
    /// not a curve point.
    InvalidKey,
    /// The proof is not well formed: gamma is not a canonically encoded curve
    /// point, or the response scalar is not canonical.
    InvalidProof,
    /// The proof is well formed but does not verify against the key and input.
    VerificationFailed,
    /// A key, proof or output was given with the wrong length.
    InvalidLength,
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            VrfError::InvalidKey => "invalid VRF verification key",
            VrfError::InvalidProof => "malformed VRF proof",
            VrfError::VerificationFailed => "VRF proof verification failed",
            VrfError::InvalidLength => "invalid length",
        };
        f.write_str(s)
    }
}

/// Size of a VRF seed.
pub const SEED_SIZE: usize = 32;
/// Size of a VRF verification key.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Size of a VRF signing key as the node serialises it: seed followed by the
/// verification key.
pub const SECRET_KEY_SIZE: usize = 64;
/// Size of a VRF output.
pub const OUTPUT_SIZE: usize = 64;

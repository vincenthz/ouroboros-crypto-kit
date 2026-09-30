//! Cardano cryptography, using pure Rust by default with optional native
//! backends for the Plutus curves.
//!
//! This crate is a drop-in replacement for the cryptography a Cardano node
//! needs. The default build has no C dependency; the `blst` and `secp256k1`
//! features select their upstream native implementations:
//!
//! * [`hash`] — the hash functions used by the chain and by Plutus.
//! * [`ed25519`] — Ed25519 signing and verification, with the exact
//!   acceptance criteria of the node (see [`ed25519::verify`]).
//! * [`byron`] — the extended Ed25519 keys of `cardano-crypto` that sign
//!   everything in the Byron era, with crypton's verification rules.
//! * [`vrf`] — the two VRF flavours of Praos:
//!   [`vrf::praos`] (`draft-03`, used since Shelley) and
//!   [`vrf::praos_batch`] (`draft-13` batch-compatible).
//! * [`kes`] — the key evolving signatures used by block producers
//!   (`SumKES` and `CompactSumKES` over Ed25519 / Blake2b-256).
//! * [`plutus`] — the primitives exposed as Plutus builtins: BLS12-381
//!   (G1, G2, pairing) and Secp256k1 (ECDSA, Schnorr/BIP340).
//!
//! # Bit-for-bit compatibility
//!
//! Every algorithm here is written against the implementation the node actually
//! runs, not against the corresponding IETF draft, and is checked against
//! published test vectors:
//!
//! | this crate | reference implementation | vectors |
//! |---|---|---|
//! | [`vrf::praos`] | `cardano-crypto-praos/cbits/vrf03` + its vendored `ed25519_ref10` | 7 from `cardano-base`, 31 from libsodium |
//! | [`vrf::praos_batch`] | `cardano-crypto-praos/cbits/vrf13_batchcompat` | 7 from `cardano-base` |
//! | [`kes`] | `cardano-crypto-class` `Cardano.Crypto.KES.{Sum,CompactSum}` | the 14 Haskell-generated `.bin` files |
//! | [`byron`] | `cardano-crypto` `cbits/encrypted_sign.c` + ed25519-donna, crypton `Ed25519.verify` | 51 + 9 `cardano-crypto` goldens |
//! | [`ed25519`] | libsodium `crypto_sign_verify_detached` | RFC 8032 |
//! | [`plutus::bls12_381`] | `blst` as used by `plutus-core` (CIP-0381) | 10 from RFC 9380, 78 from `ethereum/bls12-381-tests` |
//! | [`plutus::secp256k1`] | `libsecp256k1` as used by `plutus-core` (CIP-0049) | 19 BIP-340, 252 Wycheproof |
//!
//! Where the reference implementation deviates from the standard it follows —
//! and it does, in several places — the deviation is reproduced here and
//! documented at the place where it happens. The three that matter most:
//!
//! * VRF draft-03 clears the sign bit before Elligator2, so Cardano's VRF is
//!   incompatible with any implementation that follows the draft;
//! * VRF draft-13 hashes with RFC 9380 `encode_to_curve` and puts the
//!   verification key in the challenge, which the `vrf_dalek` crate does not;
//! * Ed25519 verification rejects small-order and non-canonically encoded keys,
//!   which a bare `cryptoxide::ed25519::verify` does not.
//!

#![deny(missing_docs)]
// Unsafe is confined to the exported C ABI and the optional `blst` FFI backend.
#![cfg_attr(not(any(feature = "capi", feature = "blst")), forbid(unsafe_code))]

pub mod edwards25519;
pub mod hash;

pub mod ed25519;

#[cfg(feature = "byron")]
pub mod byron;

#[cfg(feature = "kes")]
pub mod kes;

#[cfg(feature = "vrf")]
pub mod vrf;

#[cfg(feature = "plutus")]
pub mod plutus;

#[cfg(feature = "capi")]
pub mod capi;

#[cfg(test)]
mod testutil;

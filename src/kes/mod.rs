//! Key Evolving Signatures, as `cardano-base` defines them.
//!
//! Two constructions are provided, both being the binary "sum" composition of
//! Malkin-Micciancio-Miner ([eprint 2001/034]) applied recursively over Ed25519
//! with Blake2b-256 as the hash:
//!
//! * [`SumKes`] — `Cardano.Crypto.KES.Sum`. A signature carries, for every
//!   level of the Merkle tree, both children's verification keys:
//!   `64 + 64 * depth` bytes. This is the one Cardano uses (`Sum6KES`, so
//!   448-byte signatures in block headers).
//! * [`CompactSumKes`] — `Cardano.Crypto.KES.CompactSum`. A signature carries
//!   only the sibling's verification key per level and reconstructs the rest,
//!   halving the size: `64 + 32 * (depth + 1)` bytes.
//!
//! A key of depth `d` can sign `2^d` periods, and evolving it destroys the
//! ability to sign earlier ones: [`SumKes::update`] overwrites the seed of the
//! subtree it leaves behind.
//!
//! # Serialisation
//!
//! Keys serialise exactly as `rawSerialiseSignKeyKES` does, so a `kes.skey`
//! produced by `cardano-cli` can be loaded directly. Note that the period is
//! *not* part of that encoding — the node tracks it from the operational
//! certificate — so [`SumKes::from_bytes`] takes it explicitly.
//!
//! ```
//! use ouroboros_crypto_kit::kes::SumKes;
//!
//! let mut sk = SumKes::from_seed(6, &mut [0u8; 32]).unwrap();
//! let vk = sk.public();
//! let sig = sk.sign(b"block header");
//! assert!(sig.verify(0, &vk, b"block header").is_ok());
//!
//! sk.update().unwrap();
//! assert_eq!(sk.period(), 1);
//! let sig1 = sk.sign(b"next header");
//! assert!(sig1.verify(1, &vk, b"next header").is_ok());
//! // the period-1 signature is not a valid period-0 signature
//! assert!(sig1.verify(0, &vk, b"next header").is_err());
//! ```
//!
//! [eprint 2001/034]: https://eprint.iacr.org/2001/034

use crate::ed25519;

/// The deepest tree `cardano-base` instantiates (`Sum7KES`).
pub const MAX_DEPTH: u8 = 7;

/// Size of a KES verification key (a Blake2b-256 digest, or an Ed25519 key at
/// depth 0).
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of the seed a KES key is generated from.
pub const SEED_SIZE: usize = 32;

/// Errors produced by the KES operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KesError {
    /// The depth is larger than [`MAX_DEPTH`].
    InvalidDepth(u8),
    /// A key or signature had the wrong length.
    InvalidSize {
        /// What was expected.
        expected: usize,
        /// What was given.
        got: usize,
    },
    /// The key has reached its last period and cannot evolve further.
    Expired,
    /// The Merkle path in the signature does not hash to the verification key.
    HashMismatch,
    /// The Ed25519 signature at the leaf is invalid.
    InvalidSignature,
}

impl core::fmt::Display for KesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KesError::InvalidDepth(d) => write!(f, "unsupported KES depth {d}"),
            KesError::InvalidSize { expected, got } => {
                write!(f, "invalid KES size: expected {expected} bytes, got {got}")
            }
            KesError::Expired => f.write_str("KES key cannot be updated further"),
            KesError::HashMismatch => f.write_str("KES verification key mismatch"),
            KesError::InvalidSignature => f.write_str("invalid Ed25519 signature in KES signature"),
        }
    }
}

/// Number of periods a key of this depth can sign.
pub const fn total_periods(depth: u8) -> u32 {
    1u32 << depth
}

/// Size of the raw serialisation of a signing key of this depth.
pub const fn secret_key_size(depth: u8) -> usize {
    // the Ed25519 seed, then per level: the seed of the right subtree and both
    // children's verification keys
    32 + (depth as usize) * (32 + 2 * PUBLIC_KEY_SIZE)
}

/// Size of a [`SumKes`] signature of this depth.
pub const fn signature_size(depth: u8) -> usize {
    64 + (depth as usize) * 2 * PUBLIC_KEY_SIZE
}

/// Size of a [`CompactSumKes`] signature of this depth.
pub const fn compact_signature_size(depth: u8) -> usize {
    64 + (depth as usize + 1) * PUBLIC_KEY_SIZE
}

/// A KES verification key: the Blake2b-256 digest of the two children's keys
/// (or, at depth 0, an Ed25519 verification key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Build a verification key from its 32 bytes.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }

    /// Read a verification key from a slice of exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KesError> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(KesError::InvalidSize {
                expected: PUBLIC_KEY_SIZE,
                got: bytes.len(),
            });
        }
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        out.copy_from_slice(bytes);
        Ok(PublicKey(out))
    }

    /// The 32 bytes of this key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// `hashPairOfVKeys`: Blake2b-256 of the concatenation of two keys.
fn hash_pair(left: &PublicKey, right: &PublicKey) -> PublicKey {
    let mut ctx = crate::hash::Blake2bContext::<256>::new();
    ctx.update_mut(&left.0);
    ctx.update_mut(&right.0);
    PublicKey(ctx.finalize())
}

/// `expandSeed`: split a seed into the two subtree seeds, as
/// `Blake2b-256(0x01 || seed)` and `Blake2b-256(0x02 || seed)`.
fn expand_seed(seed: &[u8; SEED_SIZE]) -> ([u8; SEED_SIZE], [u8; SEED_SIZE]) {
    let mut left = crate::hash::Blake2bContext::<256>::new();
    left.update_mut(&[1]);
    left.update_mut(seed);
    let mut right = crate::hash::Blake2bContext::<256>::new();
    right.update_mut(&[2]);
    right.update_mut(seed);
    (left.finalize(), right.finalize())
}

fn check_depth(depth: u8) -> Result<(), KesError> {
    if depth > MAX_DEPTH {
        Err(KesError::InvalidDepth(depth))
    } else {
        Ok(())
    }
}

/// The Ed25519 verification key of a seed, i.e. the depth-0 KES key.
fn leaf_public(seed: &[u8; 32]) -> PublicKey {
    PublicKey(*ed25519::SecretKey::from_bytes(*seed).public().as_bytes())
}

/// Generate a signing key of `depth` into `sk`, consuming (and wiping) `seed`.
///
/// Returns the verification key. `sk` must be [`secret_key_size`] long.
fn keygen(depth: u8, sk: &mut [u8], seed: &mut [u8; SEED_SIZE]) -> PublicKey {
    debug_assert_eq!(sk.len(), secret_key_size(depth));
    if depth == 0 {
        sk.copy_from_slice(&seed[..]);
        let vk = leaf_public(seed);
        ed25519::wipe(&mut seed[..]);
        return vk;
    }

    let (mut r0, mut r1) = expand_seed(seed);
    ed25519::wipe(&mut seed[..]);

    let child = secret_key_size(depth - 1);
    let (child_sk, rest) = sk.split_at_mut(child);

    // The right subtree's seed is kept so that the key can evolve into it
    // later; the subtree itself is generated now only to learn its verification
    // key, and immediately dropped.
    rest[..32].copy_from_slice(&r1);

    let vk0 = keygen(depth - 1, child_sk, &mut r0);
    let mut scratch = vec![0u8; child];
    let vk1 = keygen(depth - 1, &mut scratch, &mut r1);
    ed25519::wipe(&mut scratch);

    rest[32..64].copy_from_slice(&vk0.0);
    rest[64..96].copy_from_slice(&vk1.0);
    hash_pair(&vk0, &vk1)
}

/// Evolve `sk` from `period` to `period + 1`.
fn update(depth: u8, sk: &mut [u8], period: u32) -> Result<(), KesError> {
    debug_assert_eq!(sk.len(), secret_key_size(depth));
    if period + 1 == total_periods(depth) {
        return Err(KesError::Expired);
    }
    let half = total_periods(depth) / 2;
    let child = secret_key_size(depth - 1);
    let (child_sk, rest) = sk.split_at_mut(child);

    if period + 1 < half {
        update(depth - 1, child_sk, period)
    } else if period + 1 == half {
        // cross over into the right subtree: regenerate it from the stored
        // seed, which is destroyed in the process — this is what makes the
        // scheme forward secure
        let mut seed = [0u8; SEED_SIZE];
        seed.copy_from_slice(&rest[..32]);
        ed25519::wipe(&mut rest[..32]);
        let _ = keygen(depth - 1, child_sk, &mut seed);
        Ok(())
    } else {
        update(depth - 1, child_sk, period - half)
    }
}

/// Ed25519-sign with the leaf key of `sk`.
fn leaf_sign(sk: &[u8], message: &[u8]) -> [u8; 64] {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk[..32]);
    let key = ed25519::SecretKey::from_bytes(seed);
    ed25519::wipe(&mut seed);
    *key.sign(message).as_bytes()
}

/// The verification key of a serialised signing key.
fn derive_public(depth: u8, sk: &[u8]) -> PublicKey {
    if depth == 0 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&sk[..32]);
        let vk = leaf_public(&seed);
        ed25519::wipe(&mut seed);
        vk
    } else {
        let child = secret_key_size(depth - 1);
        let vk0 = PublicKey::from_slice(&sk[child + 32..child + 64]).expect("32 bytes");
        let vk1 = PublicKey::from_slice(&sk[child + 64..child + 96]).expect("32 bytes");
        hash_pair(&vk0, &vk1)
    }
}

/// A `SumKES` signing key of a runtime-chosen depth.
///
/// The period is tracked alongside the key material for convenience, but is not
/// part of [`SumKes::as_bytes`], matching `rawSerialiseSignKeyKES`.
pub struct SumKes {
    depth: u8,
    period: u32,
    bytes: Vec<u8>,
}

impl Drop for SumKes {
    fn drop(&mut self) {
        ed25519::wipe(&mut self.bytes);
    }
}

/// Deliberately opaque: a signing key must not end up in a log.
impl core::fmt::Debug for SumKes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SumKes(depth {}, period {})", self.depth, self.period)
    }
}

impl SumKes {
    /// Generate a key of `depth` from `seed`, wiping the seed.
    pub fn from_seed(depth: u8, seed: &mut [u8; SEED_SIZE]) -> Result<Self, KesError> {
        check_depth(depth)?;
        let mut bytes = vec![0u8; secret_key_size(depth)];
        let _ = keygen(depth, &mut bytes, seed);
        Ok(SumKes {
            depth,
            period: 0,
            bytes,
        })
    }

    /// Load a key from its raw serialisation, at a known period.
    pub fn from_bytes(depth: u8, period: u32, bytes: &[u8]) -> Result<Self, KesError> {
        check_depth(depth)?;
        let expected = secret_key_size(depth);
        if bytes.len() != expected {
            return Err(KesError::InvalidSize {
                expected,
                got: bytes.len(),
            });
        }
        Ok(SumKes {
            depth,
            period,
            bytes: bytes.to_vec(),
        })
    }

    /// The raw serialisation of this key (`rawSerialiseSignKeyKES`).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The depth of this key.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The period this key can currently sign.
    pub fn period(&self) -> u32 {
        self.period
    }

    /// The verification key of the whole tree (`deriveVerKeyKES`).
    pub fn public(&self) -> PublicKey {
        derive_public(self.depth, &self.bytes)
    }

    /// Evolve to the next period, destroying the ability to sign the current
    /// one.
    pub fn update(&mut self) -> Result<(), KesError> {
        update(self.depth, &mut self.bytes, self.period)?;
        self.period += 1;
        Ok(())
    }

    /// Sign `message` for the current period.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut bytes = Vec::with_capacity(signature_size(self.depth));
        sum_sign(self.depth, &self.bytes, message, &mut bytes);
        Signature {
            depth: self.depth,
            bytes,
        }
    }
}

fn sum_sign(depth: u8, sk: &[u8], message: &[u8], out: &mut Vec<u8>) {
    if depth == 0 {
        out.extend_from_slice(&leaf_sign(sk, message));
        return;
    }
    let child = secret_key_size(depth - 1);
    sum_sign(depth - 1, &sk[..child], message, out);
    // both children's verification keys, in tree order
    out.extend_from_slice(&sk[child + 32..child + 96]);
}

/// A `SumKES` signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    depth: u8,
    bytes: Vec<u8>,
}

impl Signature {
    /// Read a signature of `depth` from its raw serialisation.
    pub fn from_bytes(depth: u8, bytes: &[u8]) -> Result<Self, KesError> {
        check_depth(depth)?;
        let expected = signature_size(depth);
        if bytes.len() != expected {
            return Err(KesError::InvalidSize {
                expected,
                got: bytes.len(),
            });
        }
        Ok(Signature {
            depth,
            bytes: bytes.to_vec(),
        })
    }

    /// The raw serialisation of this signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The depth of the tree this signature comes from.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Verify this signature for `period` under `public_key`.
    ///
    /// Like `verifyKES`, no bound is placed on `period`: a period beyond the
    /// tree's capacity walks to the right-most leaf rather than being rejected,
    /// which is the behaviour the node relies on the consensus layer to
    /// prevent.
    pub fn verify(
        &self,
        period: u32,
        public_key: &PublicKey,
        message: &[u8],
    ) -> Result<(), KesError> {
        sum_verify(self.depth, &self.bytes, period, public_key, message)
    }
}

fn sum_verify(
    depth: u8,
    sig: &[u8],
    period: u32,
    vk: &PublicKey,
    message: &[u8],
) -> Result<(), KesError> {
    if depth == 0 {
        let signature = ed25519::Signature::from_slice(&sig[..64]).expect("64 bytes");
        let key = ed25519::PublicKey::from_bytes(vk.0);
        return if ed25519::verify(&key, message, &signature) {
            Ok(())
        } else {
            Err(KesError::InvalidSignature)
        };
    }

    let child = signature_size(depth - 1);
    let vk0 = PublicKey::from_slice(&sig[child..child + 32]).expect("32 bytes");
    let vk1 = PublicKey::from_slice(&sig[child + 32..child + 64]).expect("32 bytes");
    if &hash_pair(&vk0, &vk1) != vk {
        return Err(KesError::HashMismatch);
    }

    let half = total_periods(depth) / 2;
    if period < half {
        sum_verify(depth - 1, &sig[..child], period, &vk0, message)
    } else {
        sum_verify(depth - 1, &sig[..child], period - half, &vk1, message)
    }
}

/// A `CompactSumKES` signing key of a runtime-chosen depth.
///
/// The key material is laid out exactly like [`SumKes`]'s — only the signatures
/// differ.
pub struct CompactSumKes {
    depth: u8,
    period: u32,
    bytes: Vec<u8>,
}

impl Drop for CompactSumKes {
    fn drop(&mut self) {
        ed25519::wipe(&mut self.bytes);
    }
}

/// Deliberately opaque: a signing key must not end up in a log.
impl core::fmt::Debug for CompactSumKes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CompactSumKes(depth {}, period {})",
            self.depth, self.period
        )
    }
}

impl CompactSumKes {
    /// Generate a key of `depth` from `seed`, wiping the seed.
    pub fn from_seed(depth: u8, seed: &mut [u8; SEED_SIZE]) -> Result<Self, KesError> {
        check_depth(depth)?;
        let mut bytes = vec![0u8; secret_key_size(depth)];
        let _ = keygen(depth, &mut bytes, seed);
        Ok(CompactSumKes {
            depth,
            period: 0,
            bytes,
        })
    }

    /// Load a key from its raw serialisation, at a known period.
    pub fn from_bytes(depth: u8, period: u32, bytes: &[u8]) -> Result<Self, KesError> {
        check_depth(depth)?;
        let expected = secret_key_size(depth);
        if bytes.len() != expected {
            return Err(KesError::InvalidSize {
                expected,
                got: bytes.len(),
            });
        }
        Ok(CompactSumKes {
            depth,
            period,
            bytes: bytes.to_vec(),
        })
    }

    /// The raw serialisation of this key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The depth of this key.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The period this key can currently sign.
    pub fn period(&self) -> u32 {
        self.period
    }

    /// The verification key of the whole tree.
    pub fn public(&self) -> PublicKey {
        derive_public(self.depth, &self.bytes)
    }

    /// Evolve to the next period.
    pub fn update(&mut self) -> Result<(), KesError> {
        update(self.depth, &mut self.bytes, self.period)?;
        self.period += 1;
        Ok(())
    }

    /// Sign `message` for the current period.
    pub fn sign(&self, message: &[u8]) -> CompactSignature {
        let mut bytes = Vec::with_capacity(compact_signature_size(self.depth));
        compact_sign(self.depth, &self.bytes, self.period, message, &mut bytes);
        CompactSignature {
            depth: self.depth,
            bytes,
        }
    }
}

fn compact_sign(depth: u8, sk: &[u8], period: u32, message: &[u8], out: &mut Vec<u8>) {
    if depth == 0 {
        out.extend_from_slice(&leaf_sign(sk, message));
        // the leaf carries its own verification key, so the path can be
        // recomputed from the signature alone
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&sk[..32]);
        out.extend_from_slice(&leaf_public(&seed).0);
        ed25519::wipe(&mut seed);
        return;
    }
    let child = secret_key_size(depth - 1);
    let half = total_periods(depth) / 2;
    // only the sibling's verification key is included
    let (sub_period, sibling) = if period < half {
        (period, &sk[child + 64..child + 96])
    } else {
        (period - half, &sk[child + 32..child + 64])
    };
    let sibling = sibling.to_vec();
    compact_sign(depth - 1, &sk[..child], sub_period, message, out);
    out.extend_from_slice(&sibling);
}

/// A `CompactSumKES` signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompactSignature {
    depth: u8,
    bytes: Vec<u8>,
}

impl CompactSignature {
    /// Read a signature of `depth` from its raw serialisation.
    pub fn from_bytes(depth: u8, bytes: &[u8]) -> Result<Self, KesError> {
        check_depth(depth)?;
        let expected = compact_signature_size(depth);
        if bytes.len() != expected {
            return Err(KesError::InvalidSize {
                expected,
                got: bytes.len(),
            });
        }
        Ok(CompactSignature {
            depth,
            bytes: bytes.to_vec(),
        })
    }

    /// The raw serialisation of this signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The depth of the tree this signature comes from.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Recompute the verification key this signature implies for `period`,
    /// verifying the Ed25519 signature at the leaf along the way.
    pub fn recompute(&self, period: u32, message: &[u8]) -> Result<PublicKey, KesError> {
        compact_recompute(self.depth, &self.bytes, period, message)
    }

    /// Verify this signature for `period` under `public_key`.
    pub fn verify(
        &self,
        period: u32,
        public_key: &PublicKey,
        message: &[u8],
    ) -> Result<(), KesError> {
        if &self.recompute(period, message)? == public_key {
            Ok(())
        } else {
            Err(KesError::HashMismatch)
        }
    }
}

fn compact_recompute(
    depth: u8,
    sig: &[u8],
    period: u32,
    message: &[u8],
) -> Result<PublicKey, KesError> {
    if depth == 0 {
        let signature = ed25519::Signature::from_slice(&sig[..64]).expect("64 bytes");
        let vk = PublicKey::from_slice(&sig[64..96]).expect("32 bytes");
        let key = ed25519::PublicKey::from_bytes(vk.0);
        return if ed25519::verify(&key, message, &signature) {
            Ok(vk)
        } else {
            Err(KesError::InvalidSignature)
        };
    }

    let child = compact_signature_size(depth - 1);
    let sibling = PublicKey::from_slice(&sig[child..child + 32]).expect("32 bytes");
    let half = total_periods(depth) / 2;
    if period < half {
        let vk = compact_recompute(depth - 1, &sig[..child], period, message)?;
        Ok(hash_pair(&vk, &sibling))
    } else {
        let vk = compact_recompute(depth - 1, &sig[..child], period - half, message)?;
        Ok(hash_pair(&sibling, &vk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_cardano_base() {
        // Sum6KES: 608-byte keys, 448-byte signatures; CompactSum6KES: 288-byte
        // signatures. These are the numbers a Shelley block header carries.
        assert_eq!(secret_key_size(6), 608);
        assert_eq!(signature_size(6), 448);
        assert_eq!(compact_signature_size(6), 288);
        assert_eq!(secret_key_size(0), 32);
        assert_eq!(signature_size(0), 64);
        assert_eq!(compact_signature_size(0), 96);
    }

    #[test]
    fn sum_signs_every_period() {
        for depth in 0..=4u8 {
            let mut sk = SumKes::from_seed(depth, &mut [depth; 32]).unwrap();
            let vk = sk.public();
            for period in 0..total_periods(depth) {
                assert_eq!(sk.period(), period);
                let sig = sk.sign(b"message");
                assert_eq!(sig.as_bytes().len(), signature_size(depth));
                sig.verify(period, &vk, b"message")
                    .unwrap_or_else(|e| panic!("depth {depth} period {period}: {e}"));

                // a signature only verifies for its own period ...
                if period + 1 < total_periods(depth) {
                    assert!(sig.verify(period + 1, &vk, b"message").is_err());
                }
                // ... and only for its own message
                assert!(sig.verify(period, &vk, b"other").is_err());

                if period + 1 == total_periods(depth) {
                    assert_eq!(sk.update().unwrap_err(), KesError::Expired);
                } else {
                    sk.update().unwrap();
                }
            }
        }
    }

    #[test]
    fn compact_signs_every_period() {
        for depth in 0..=4u8 {
            let mut sk = CompactSumKes::from_seed(depth, &mut [depth; 32]).unwrap();
            let vk = sk.public();
            for period in 0..total_periods(depth) {
                let sig = sk.sign(b"message");
                assert_eq!(sig.as_bytes().len(), compact_signature_size(depth));
                sig.verify(period, &vk, b"message")
                    .unwrap_or_else(|e| panic!("depth {depth} period {period}: {e}"));
                if period + 1 < total_periods(depth) {
                    assert!(sig.verify(period + 1, &vk, b"message").is_err());
                }
                assert!(sig.verify(period, &vk, b"other").is_err());
                if period + 1 < total_periods(depth) {
                    sk.update().unwrap();
                }
            }
        }
    }

    #[test]
    fn public_key_is_stable_across_updates() {
        let mut sk = SumKes::from_seed(5, &mut [7u8; 32]).unwrap();
        let vk = sk.public();
        for _ in 0..31 {
            sk.update().unwrap();
            assert_eq!(sk.public(), vk);
        }
    }

    #[test]
    fn serialisation_roundtrip() {
        let mut sk = SumKes::from_seed(3, &mut [9u8; 32]).unwrap();
        sk.update().unwrap();
        sk.update().unwrap();
        let restored = SumKes::from_bytes(3, sk.period(), sk.as_bytes()).unwrap();
        assert_eq!(restored.public(), sk.public());
        assert_eq!(restored.sign(b"m"), sk.sign(b"m"));

        let sig = sk.sign(b"m");
        let parsed = Signature::from_bytes(3, sig.as_bytes()).unwrap();
        assert_eq!(parsed, sig);
        assert!(Signature::from_bytes(3, &sig.as_bytes()[1..]).is_err());
    }

    #[test]
    fn rejects_bad_depth_and_size() {
        assert_eq!(
            SumKes::from_seed(8, &mut [0u8; 32]).unwrap_err(),
            KesError::InvalidDepth(8)
        );
        assert_eq!(
            SumKes::from_bytes(6, 0, &[0u8; 10]).unwrap_err(),
            KesError::InvalidSize {
                expected: 608,
                got: 10
            }
        );
    }
}

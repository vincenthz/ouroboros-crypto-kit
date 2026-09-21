//! Ed25519 signatures, with the acceptance criteria of the Cardano node.
//!
//! Signing and verification themselves come from [`cryptoxide`]; what this
//! module adds is the exact set of checks libsodium's
//! `crypto_sign_verify_detached` performs, which is what
//! `cardano-crypto-class`'s `Ed25519DSIGN` calls, and therefore what decides
//! whether a witness on the chain is valid:
//!
//! 1. if the top nibble of `s` is set, `s` must be canonical (reduced mod l);
//! 2. `R` (the first half of the signature) must not have small order;
//! 3. the verification key must be canonically encoded and must not have small
//!    order;
//! 4. `R` is compared to `[s]B - [k]A` byte for byte (no cofactored
//!    comparison).
//!
//! Checks 2 and 3 are the difference between this module and a plain
//! `cryptoxide::ed25519::verify`, and they are not cosmetic: without them a
//! transaction that the node rejects would be accepted here.
//!
//! Extended (64-byte) secret keys are also supported, since Byron-era keys and
//! BIP32-Ed25519 derivations produce keys of that shape.

use crate::edwards25519 as ed;

/// Size of an Ed25519 seed (what Cardano calls a signing key).
pub const SEED_SIZE: usize = 32;
/// Size of an Ed25519 verification key.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Size of an Ed25519 signature.
pub const SIGNATURE_SIZE: usize = 64;
/// Size of an extended (already hashed and clamped) secret key.
pub const EXTENDED_SECRET_KEY_SIZE: usize = 64;

/// An Ed25519 secret key: the 32-byte seed.
#[derive(Clone)]
pub struct SecretKey([u8; SEED_SIZE]);

/// An Ed25519 extended secret key: a clamped scalar followed by the nonce
/// prefix, i.e. the 64 bytes an ordinary secret key expands to.
#[derive(Clone)]
pub struct ExtendedSecretKey([u8; EXTENDED_SECRET_KEY_SIZE]);

/// An Ed25519 verification key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Drop for ExtendedSecretKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Overwrite a buffer, in a way the optimiser is not allowed to remove.
pub(crate) fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // a volatile write would be better, but that needs unsafe; a read of
        // the value through a black-box-ish path is enough to keep it.
        *b = 0;
    }
    core::hint::black_box(buf);
}

impl SecretKey {
    /// Build a secret key from a 32-byte seed.
    pub fn from_bytes(seed: [u8; SEED_SIZE]) -> Self {
        SecretKey(seed)
    }

    /// The seed of this secret key.
    pub fn as_bytes(&self) -> &[u8; SEED_SIZE] {
        &self.0
    }

    /// Derive the matching verification key.
    pub fn public(&self) -> PublicKey {
        let (_, public) = cryptoxide::ed25519::keypair(&self.0);
        PublicKey(public)
    }

    /// Expand this key into its extended form: SHA-512 of the seed, clamped.
    pub fn extended(&self) -> ExtendedSecretKey {
        let h = crate::hash::sha512(&self.0);
        let mut out = [0u8; EXTENDED_SECRET_KEY_SIZE];
        out.copy_from_slice(&h);
        out[0] &= 248;
        out[31] &= 127;
        out[31] |= 64;
        ExtendedSecretKey(out)
    }

    /// Sign `message`.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let (keypair, _) = cryptoxide::ed25519::keypair(&self.0);
        Signature(cryptoxide::ed25519::signature(message, &keypair))
    }
}

impl ExtendedSecretKey {
    /// Build an extended secret key from its 64 bytes.
    ///
    /// No structural check is performed: it is up to the caller to provide a
    /// properly clamped scalar (Cardano's Byron and BIP32-Ed25519 keys are).
    pub fn from_bytes(bytes: [u8; EXTENDED_SECRET_KEY_SIZE]) -> Self {
        ExtendedSecretKey(bytes)
    }

    /// The 64 bytes of this key.
    pub fn as_bytes(&self) -> &[u8; EXTENDED_SECRET_KEY_SIZE] {
        &self.0
    }

    /// Derive the matching verification key.
    pub fn public(&self) -> PublicKey {
        PublicKey(cryptoxide::ed25519::extended_to_public(&self.0))
    }

    /// Sign `message`.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(cryptoxide::ed25519::signature_extended(message, &self.0))
    }
}

impl PublicKey {
    /// Build a verification key from its 32 bytes.
    ///
    /// The encoding is not validated here; [`verify`] performs the same
    /// validation as the node.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }

    /// Read a verification key from a slice of exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        if bytes.len() != PUBLIC_KEY_SIZE {
            return None;
        }
        out.copy_from_slice(bytes);
        Some(PublicKey(out))
    }

    /// The 32 bytes of this key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Verify `signature` over `message`, with the node's acceptance criteria.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        verify(self, message, signature)
    }
}

impl Signature {
    /// Build a signature from its 64 bytes.
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Signature(bytes)
    }

    /// Read a signature from a slice of exactly 64 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return None;
        }
        let mut out = [0u8; SIGNATURE_SIZE];
        out.copy_from_slice(bytes);
        Some(Signature(out))
    }

    /// The 64 bytes of this signature.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

/// Verify an Ed25519 signature exactly like libsodium's
/// `crypto_sign_verify_detached`, which is what the node uses.
///
/// In particular a signature whose `R` has small order, or a verification key
/// that is non-canonically encoded or of small order, is rejected even when the
/// underlying equation holds.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let pk = &public_key.0;
    let sig = &signature.0;

    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);

    // 1. s must be canonical when it could possibly not be
    if (s[31] & 240) != 0 && !ed::scalar_is_canonical(&s) {
        return false;
    }
    // 2. R must not have small order
    if ed::point_has_small_order(&r) {
        return false;
    }
    // 3. the key must be canonical and not of small order
    if !ed::point_is_canonical(pk) || ed::point_has_small_order(pk) {
        return false;
    }

    // 4. the equation itself
    cryptoxide::ed25519::verify(message, pk, sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{hex, hex_array};

    // RFC 8032 section 7.1 test vectors
    const RFC8032: &[(&str, &str, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    #[test]
    fn rfc8032_vectors() {
        for (seed, pk, msg, sig) in RFC8032 {
            let sk = SecretKey::from_bytes(hex_array::<32>(seed));
            let public = sk.public();
            assert_eq!(public.as_bytes()[..], hex(pk)[..], "public key mismatch");

            let message = hex(msg);
            let signature = sk.sign(&message);
            assert_eq!(signature.as_bytes()[..], hex(sig)[..], "signature mismatch");
            assert!(verify(&public, &message, &signature));

            // the extended form signs identically
            let ext = sk.extended();
            assert_eq!(ext.public(), public);
            assert_eq!(ext.sign(&message), signature);
        }
    }

    #[test]
    fn rejects_tampered_signature() {
        let sk = SecretKey::from_bytes([3u8; 32]);
        let pk = sk.public();
        let sig = sk.sign(b"message");
        assert!(verify(&pk, b"message", &sig));
        assert!(!verify(&pk, b"messagf", &sig));

        let mut bad = *sig.as_bytes();
        bad[0] ^= 1;
        assert!(!verify(&pk, b"message", &Signature::from_bytes(bad)));
    }

    #[test]
    fn rejects_small_order_key() {
        // the identity is a valid encoding but a small-order point
        let pk = PublicKey::from_bytes(hex_array::<32>(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ));
        let sig = Signature::from_bytes([0u8; 64]);
        assert!(!verify(&pk, b"message", &sig));
    }

    #[test]
    fn rejects_non_canonical_key() {
        // p + 1 encodes the identity non-canonically
        let pk = PublicKey::from_bytes(hex_array::<32>(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ));
        let sig = Signature::from_bytes([0u8; 64]);
        assert!(!verify(&pk, b"message", &sig));
    }

    #[test]
    fn rejects_non_canonical_scalar() {
        let sk = SecretKey::from_bytes([9u8; 32]);
        let pk = sk.public();
        let mut sig = *sk.sign(b"message").as_bytes();
        // l itself: non-canonical, and the top nibble is set so the check
        // applies
        sig[32..].copy_from_slice(&hex(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ));
        assert!(!verify(&pk, b"message", &Signature::from_bytes(sig)));
    }
}

//! The two Secp256k1 verification builtins of Plutus (CIP-49).
//!
//! `plutus-core` verifies through `cardano-crypto-class`, which calls
//! libsecp256k1 (v0.3.2 in cardano-node 11.1.3). Each builtin is three steps,
//! and so is this module:
//!
//! 1. decode the verification key (`rawDeserialiseVerKeyDSIGN`): a length check,
//!    then `secp256k1_ec_pubkey_parse` (ECDSA) or `secp256k1_xonly_pubkey_parse`
//!    (Schnorr) — [`EcdsaPublicKey::from_slice`], [`SchnorrPublicKey::from_slice`];
//! 2. decode the signature (`rawDeserialiseSigDSIGN`): a length check, then
//!    `secp256k1_ecdsa_signature_parse_compact` for ECDSA, nothing more for
//!    Schnorr — [`EcdsaSignature::from_slice`], [`SchnorrSignature::from_slice`];
//! 3. verify (`verifyDSIGN`): `secp256k1_ecdsa_verify` or
//!    `secp256k1_schnorrsig_verify`, whose 0 or 1 is the builtin's `False` or
//!    `True` — [`ecdsa_verify`], [`schnorr_verify`].
//!
//! A failure in step 1 or 2 (or, for ECDSA, a message that is not 32 bytes) is a
//! builtin *error*; everything step 3 rejects is `False`. The split is
//! libsecp256k1's, so it is reproduced exactly:
//!
//! * the compact ECDSA parse accepts any `r` and `s` below the group order `n`,
//!   **zero included**; `secp256k1_ecdsa_verify` then answers 0 for a high `s`
//!   (above `(n-1)/2`, the malleability rule) and for `r = 0` or `s = 0`, and
//!   accepts `x(R) == r + n` as well as `x(R) == r` when `r + n < p`;
//! * the Schnorr signature is not parsed at all: `secp256k1_schnorrsig_verify`
//!   answers 0 for `r >= p` and for `s >= n`, as for any other bad signature.
//!
//! [`verify_ecdsa`] and [`verify_schnorr`] compose the three steps in
//! `plutus-core`'s order (key, then signature, then for ECDSA the message
//! length) and return `Err` for a decoding failure, `Ok(false)` and `Ok(true)`
//! for the verdict.

use crate::hash::{Sha256Context, sha256};
use eccoxide::curve::field::Sign;

use eccoxide::curve::sec2::p256k1::{FieldElement, Point, PointAffine, Scalar};

/// Size of a compressed public key, as the ECDSA builtin requires.
pub const ECDSA_PUBLIC_KEY_SIZE: usize = 33;
/// Size of an x-only public key, as the Schnorr builtin requires.
pub const SCHNORR_PUBLIC_KEY_SIZE: usize = 32;
/// Size of a signature, in both schemes.
pub const SIGNATURE_SIZE: usize = 64;
/// Size of the message the ECDSA builtin accepts (it must already be a hash).
pub const ECDSA_MESSAGE_SIZE: usize = 32;

/// Why a Secp256k1 verification could not be performed: one of its inputs does
/// not decode. A signature that decodes but does not verify is not an error,
/// it is `Ok(false)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Secp256k1Error {
    /// The public key has the wrong length, or does not encode a curve point.
    InvalidPublicKey,
    /// The signature has the wrong length, or (ECDSA only) `r` or `s` is not
    /// below the group order.
    InvalidSignature,
    /// The message has the wrong length (ECDSA requires exactly 32 bytes).
    InvalidMessage,
}

impl core::fmt::Display for Secp256k1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Secp256k1Error::InvalidPublicKey => "invalid secp256k1 public key",
            Secp256k1Error::InvalidSignature => "invalid secp256k1 signature",
            Secp256k1Error::InvalidMessage => "invalid secp256k1 message",
        };
        f.write_str(s)
    }
}

/// n, the order of the group, as a field element — needed for the `x(R) == r+n`
/// case of ECDSA verification (`secp256k1_ecdsa_const_order_as_fe`).
#[cfg(any(test, not(feature = "secp256k1")))]
const ORDER_AS_FE_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// p - n, used to decide whether `r + n` can still be a valid x coordinate
/// (`secp256k1_ecdsa_const_p_minus_order`).
#[cfg(any(test, not(feature = "secp256k1")))]
const P_MINUS_ORDER_BYTES: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// `(n-1)/2`: an `s` strictly greater than this is "high" and rejected.
const HALF_ORDER_BYTES: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// `secp256k1_scalar_is_high` on the big-endian encoding of a scalar.
pub(crate) fn scalar_is_high(bytes: &[u8; 32]) -> bool {
    // big-endian comparison against (n-1)/2
    bytes[..] > HALF_ORDER_BYTES[..]
}

/// Reduce a 32-byte big-endian integer modulo n (`secp256k1_scalar_set_b32`).
pub(crate) fn scalar_from_bytes_mod_order(bytes: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    wide[32..].copy_from_slice(bytes);
    Scalar::init_from_wide_bytes_be(wide)
}

/// Split 64 bytes into its two 32-byte halves.
fn halves(bytes: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&bytes[..32]);
    b.copy_from_slice(&bytes[32..]);
    (a, b)
}

/* ---------------------------------------------------------------- */
/* ECDSA                                                            */
/* ---------------------------------------------------------------- */

/// A verification key of `verifyEcdsaSecp256k1Signature`: a 33-byte compressed
/// SEC1 point, decoded as `secp256k1_ec_pubkey_parse` decodes it.
#[derive(Clone)]
pub struct EcdsaPublicKey {
    bytes: [u8; ECDSA_PUBLIC_KEY_SIZE],
    #[cfg_attr(feature = "secp256k1", allow(dead_code))]
    point: PointAffine,
}

impl core::fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EcdsaPublicKey").field(&self.bytes).finish()
    }
}

impl EcdsaPublicKey {
    /// `rawDeserialiseVerKeyDSIGN @EcdsaSecp256k1DSIGN`: exactly 33 bytes, then
    /// `secp256k1_ec_pubkey_parse`, which for 33 bytes is
    /// `secp256k1_eckey_pubkey_parse`: a `0x02` (even `y`) or `0x03` (odd `y`)
    /// tag, an `x` below `p`, and `x³ + 7` a square. (The subgroup check that
    /// follows is trivial: the cofactor is 1.) The uncompressed and hybrid
    /// 65-byte forms the C function also takes are excluded by the length.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; ECDSA_PUBLIC_KEY_SIZE] = bytes.try_into().ok()?;
        let sign = match bytes[0] {
            0x02 => Sign::Positive, // even y
            0x03 => Sign::Negative, // odd y
            _ => return None,
        };
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..]);
        let x = FieldElement::from_bytes_be(&x_bytes)?;
        let point = PointAffine::decompress(&x, sign).into_option()?;
        Some(EcdsaPublicKey { bytes, point })
    }

    /// The 33 bytes the key was decoded from.
    pub fn as_bytes(&self) -> &[u8; ECDSA_PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

/// A signature of `verifyEcdsaSecp256k1Signature`: `r || s`, 32 bytes each,
/// big-endian, decoded as `secp256k1_ecdsa_signature_parse_compact` decodes it.
#[derive(Clone)]
pub struct EcdsaSignature {
    bytes: [u8; SIGNATURE_SIZE],
    #[cfg_attr(feature = "secp256k1", allow(dead_code))]
    r: Scalar,
    #[cfg_attr(feature = "secp256k1", allow(dead_code))]
    s: Scalar,
}

impl core::fmt::Debug for EcdsaSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EcdsaSignature").field(&self.bytes).finish()
    }
}

impl EcdsaSignature {
    /// `rawDeserialiseSigDSIGN @EcdsaSecp256k1DSIGN`: exactly 64 bytes, then
    /// `secp256k1_ecdsa_signature_parse_compact`, which fails only when `r` or
    /// `s` overflows the group order. Zero is accepted for both (verification
    /// then answers `false`), and so is a high `s`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; SIGNATURE_SIZE] = bytes.try_into().ok()?;
        let (r_bytes, s_bytes) = halves(&bytes);
        let r = Scalar::from_bytes_be(&r_bytes);
        let s = Scalar::from_bytes_be(&s_bytes);
        // ret &= !overflow, for r then s: either one overflowing fails the parse
        match (r, s) {
            (Some(r), Some(s)) => Some(EcdsaSignature { bytes, r, s }),
            _ => None,
        }
    }

    /// The 64 bytes the signature was decoded from.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.bytes
    }
}

/// `secp256k1_ecdsa_verify`, which is `verifyDSIGN @EcdsaSecp256k1DSIGN`:
///
/// ```c
/// return (!secp256k1_scalar_is_high(&s) &&
///         secp256k1_pubkey_load(ctx, &q, pubkey) &&
///         secp256k1_ecdsa_sig_verify(&r, &s, &q, &m));
/// ```
///
/// with `m` the message reduced modulo `n`. `secp256k1_ecdsa_sig_verify` answers
/// 0 for `r = 0` or `s = 0` and for `R` at infinity, then accepts `x(R) == r`,
/// or `x(R) == r + n` when `r + n < p`.
pub fn ecdsa_verify(
    public_key: &EcdsaPublicKey,
    message: &[u8; ECDSA_MESSAGE_SIZE],
    signature: &EcdsaSignature,
) -> bool {
    let (_, s_bytes) = halves(&signature.bytes);
    if scalar_is_high(&s_bytes) {
        return false;
    }

    #[cfg(feature = "secp256k1")]
    {
        let Ok(q) = libsecp256k1::PublicKey::from_slice(&public_key.bytes) else {
            return false;
        };
        let Ok(sig) = libsecp256k1::ecdsa::Signature::from_compact(&signature.bytes) else {
            return false;
        };
        let msg = libsecp256k1::Message::from_digest(*message);
        libsecp256k1::ecdsa::verify(&sig, msg, &q).is_ok()
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        let m = scalar_from_bytes_mod_order(message);
        ecdsa_sig_verify(&signature.r, &signature.s, &public_key.point, &m)
    }
}

/// `secp256k1_ecdsa_sig_verify` (`src/ecdsa_impl.h`), the non-exhaustive build.
#[cfg(not(feature = "secp256k1"))]
fn ecdsa_sig_verify(sigr: &Scalar, sigs: &Scalar, pubkey: &PointAffine, message: &Scalar) -> bool {
    if sigr.is_zero() || sigs.is_zero() {
        return false;
    }

    let sn = sigs.inverse();
    let u1 = &sn * message;
    let u2 = &sn * sigr;
    // pr = u2*Q + u1*G
    let pr = &Point::mul_base(&u1) + &(&Point::from_affine(pubkey) * &u2);
    let Some(pr) = pr.to_affine() else {
        // secp256k1_gej_is_infinity(&pr)
        return false;
    };
    let (x, _) = pr.to_coordinate();

    // xr = r as a field element; r < n < p, so it is always in range
    let r_bytes = sigr.to_bytes_be();
    let Some(xr) = FieldElement::from_bytes_be(&r_bytes) else {
        return false;
    };
    if &xr == x {
        return true;
    }
    if r_bytes[..] >= P_MINUS_ORDER_BYTES[..] {
        // xr + n >= p, so the second case cannot happen
        return false;
    }
    let Some(order_as_fe) = FieldElement::from_bytes_be(&ORDER_AS_FE_BYTES) else {
        return false;
    };
    &(&xr + &order_as_fe) == x
}

/// `verifyEcdsaSecp256k1Signature`, in `plutus-core`'s order: the key
/// ([`EcdsaPublicKey::from_slice`], else [`Secp256k1Error::InvalidPublicKey`]),
/// then the signature ([`EcdsaSignature::from_slice`], else
/// [`Secp256k1Error::InvalidSignature`]), then the message length (exactly 32
/// bytes, else [`Secp256k1Error::InvalidMessage`]); then `Ok` of
/// [`ecdsa_verify`]'s verdict.
///
/// * `public_key` — 33 bytes, compressed SEC1;
/// * `message` — exactly 32 bytes, already hashed;
/// * `signature` — 64 bytes, `r || s` big-endian.
pub fn verify_ecdsa(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Secp256k1Error> {
    let q = EcdsaPublicKey::from_slice(public_key).ok_or(Secp256k1Error::InvalidPublicKey)?;
    let sig = EcdsaSignature::from_slice(signature).ok_or(Secp256k1Error::InvalidSignature)?;
    let msg: &[u8; ECDSA_MESSAGE_SIZE] = message
        .try_into()
        .map_err(|_| Secp256k1Error::InvalidMessage)?;
    Ok(ecdsa_verify(&q, msg, &sig))
}

/* ---------------------------------------------------------------- */
/* Schnorr (BIP-340)                                                */
/* ---------------------------------------------------------------- */

/// BIP-340's `hash_tag(m) = SHA256(SHA256(tag) || SHA256(tag) || m)`.
pub(crate) fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256(tag);
    let mut ctx = Sha256Context::new();
    ctx.update_mut(&tag_hash);
    ctx.update_mut(&tag_hash);
    for p in parts {
        ctx.update_mut(p);
    }
    ctx.finalize()
}

/// BIP-340 `lift_x`, as `secp256k1_xonly_pubkey_parse` does it: `x` below `p`
/// (`secp256k1_fe_set_b32_limit`) and `x³ + 7` a square
/// (`secp256k1_ge_set_xo_var` with even `y`); the subgroup check is trivial.
pub(crate) fn lift_x(x_bytes: &[u8; 32]) -> Result<PointAffine, Secp256k1Error> {
    let x = FieldElement::from_bytes_be(x_bytes).ok_or(Secp256k1Error::InvalidPublicKey)?;
    PointAffine::decompress(&x, Sign::Positive)
        .into_option()
        .ok_or(Secp256k1Error::InvalidPublicKey)
}

/// A verification key of `verifySchnorrSecp256k1Signature`: a 32-byte x-only
/// key, decoded as `secp256k1_xonly_pubkey_parse` decodes it.
#[derive(Clone)]
pub struct SchnorrPublicKey {
    bytes: [u8; SCHNORR_PUBLIC_KEY_SIZE],
    #[cfg_attr(feature = "secp256k1", allow(dead_code))]
    point: PointAffine,
}

impl core::fmt::Debug for SchnorrPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SchnorrPublicKey")
            .field(&self.bytes)
            .finish()
    }
}

impl SchnorrPublicKey {
    /// `rawDeserialiseVerKeyDSIGN @SchnorrSecp256k1DSIGN`: exactly 32 bytes
    /// (`guardFixedSized`), then `secp256k1_xonly_pubkey_parse`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; SCHNORR_PUBLIC_KEY_SIZE] = bytes.try_into().ok()?;
        let point = lift_x(&bytes).ok()?;
        Some(SchnorrPublicKey { bytes, point })
    }

    /// The 32 bytes the key was decoded from (`x`, big-endian, below `p`).
    pub fn as_bytes(&self) -> &[u8; SCHNORR_PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

/// A signature of `verifySchnorrSecp256k1Signature`: 64 bytes, `r || s`.
/// Nothing but the length is checked when it is decoded; an `r` or `s` out of
/// range makes [`schnorr_verify`] answer `false`.
#[derive(Clone, Debug)]
pub struct SchnorrSignature([u8; SIGNATURE_SIZE]);

impl SchnorrSignature {
    /// `rawDeserialiseSigDSIGN @SchnorrSecp256k1DSIGN`: a `PinnedSizedBytes 64`,
    /// so exactly 64 bytes and nothing else.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(SchnorrSignature)
    }

    /// The 64 bytes of the signature.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

/// `secp256k1_schnorrsig_verify`, which is `verifyDSIGN @SchnorrSecp256k1DSIGN`
/// (`src/modules/schnorrsig/main_impl.h`), in its order: `r` must be below `p`
/// and `s` below `n` (else 0); `e = hash_challenge(r || x(P) || m) mod n`;
/// `R = s*G - e*P` must not be infinity, must have an even `y`, and its `x` must
/// equal `r`.
pub fn schnorr_verify(
    public_key: &SchnorrPublicKey,
    message: &[u8],
    signature: &SchnorrSignature,
) -> bool {
    let (r_bytes, s_bytes) = halves(&signature.0);
    // if (!secp256k1_fe_set_b32_limit(&rx, &sig64[0])) return 0;
    let Some(rx) = FieldElement::from_bytes_be(&r_bytes) else {
        return false;
    };
    // secp256k1_scalar_set_b32(&s, &sig64[32], &overflow); if (overflow) return 0;
    let Some(s) = Scalar::from_bytes_be(&s_bytes) else {
        return false;
    };

    #[cfg(feature = "secp256k1")]
    {
        let _ = (rx, s);
        let Ok(p) = libsecp256k1::XOnlyPublicKey::from_byte_array(public_key.bytes) else {
            return false;
        };
        let sig = libsecp256k1::schnorr::Signature::from_byte_array(signature.0);
        libsecp256k1::schnorr::verify(&sig, message, &p).is_ok()
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        // pk.x serialised is the key's own bytes: it parsed, so it is below p
        let e_bytes = tagged_hash(
            b"BIP0340/challenge",
            &[&r_bytes, &public_key.bytes, message],
        );
        let e = scalar_from_bytes_mod_order(&e_bytes);

        // rj = s*G + (-e)*P
        let rj = &Point::mul_base(&s) - &(&Point::from_affine(&public_key.point) * &e);
        let Some(r) = rj.to_affine() else {
            // secp256k1_ge_is_infinity(&r)
            return false;
        };
        let (x, y) = r.to_coordinate();
        y.sign() == Sign::Positive && x == &rx
    }
}

/// `verifySchnorrSecp256k1Signature`, in `plutus-core`'s order: the key
/// ([`SchnorrPublicKey::from_slice`], else
/// [`Secp256k1Error::InvalidPublicKey`]), then the signature length (else
/// [`Secp256k1Error::InvalidSignature`]); then `Ok` of [`schnorr_verify`]'s
/// verdict. Never [`Secp256k1Error::InvalidMessage`]: the message has any length.
///
/// * `public_key` — 32 bytes, x-only;
/// * `message` — any length;
/// * `signature` — 64 bytes, `r || s`.
pub fn verify_schnorr(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Secp256k1Error> {
    let p = SchnorrPublicKey::from_slice(public_key).ok_or(Secp256k1Error::InvalidPublicKey)?;
    let sig = SchnorrSignature::from_slice(signature).ok_or(Secp256k1Error::InvalidSignature)?;
    Ok(schnorr_verify(&p, message, &sig))
}

/// A secp256k1 secret key, provided so that the verification paths can be
/// exercised (Plutus itself only ever verifies).
pub struct SecretKey(Scalar);

impl SecretKey {
    /// Read a secret key from 32 big-endian bytes; fails when it is zero or not
    /// below the group order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let s = Scalar::from_bytes_be(bytes)?;
        if s.is_zero() {
            None
        } else {
            Some(SecretKey(s))
        }
    }

    /// The compressed (33-byte) public key.
    pub fn public_compressed(&self) -> [u8; ECDSA_PUBLIC_KEY_SIZE] {
        let p = Point::mul_base(&self.0)
            .to_affine()
            .expect("non-zero scalar");
        let (x, sign) = p.compress();
        let mut out = [0u8; ECDSA_PUBLIC_KEY_SIZE];
        out[0] = if sign == Sign::Positive { 0x02 } else { 0x03 };
        out[1..].copy_from_slice(&x.to_bytes_be());
        out
    }

    /// The x-only (32-byte) public key used by BIP-340.
    pub fn public_x_only(&self) -> [u8; SCHNORR_PUBLIC_KEY_SIZE] {
        let p = Point::mul_base(&self.0)
            .to_affine()
            .expect("non-zero scalar");
        let (x, _) = p.compress();
        x.to_bytes_be()
    }

    /// Deterministic ECDSA (RFC 6979 is not implemented; the nonce is derived
    /// from SHA-256 of the key and message, which is enough for tests), with the
    /// low-`s` normalisation `libsecp256k1` applies.
    pub fn sign_ecdsa(&self, message: &[u8; 32]) -> [u8; SIGNATURE_SIZE] {
        let mut counter = 0u8;
        loop {
            let k_bytes = tagged_hash(
                b"ouroboros-crypto-kit/ecdsa-nonce",
                &[&self.0.to_bytes_be(), message, &[counter]],
            );
            counter = counter.wrapping_add(1);
            let k = match Scalar::from_bytes_be(&k_bytes) {
                Some(k) if !k.is_zero() => k,
                _ => continue,
            };
            let big_r = match Point::mul_base(&k).to_affine() {
                Some(p) => p,
                None => continue,
            };
            let (x, _) = big_r.to_coordinate();
            let r = scalar_from_bytes_mod_order(&x.to_bytes_be());
            if r.is_zero() {
                continue;
            }
            let m = scalar_from_bytes_mod_order(message);
            let s = &k.inverse() * &(&m + &(&r * &self.0));
            if s.is_zero() {
                continue;
            }
            // normalise to the lower half
            let s_bytes = s.to_bytes_be();
            let s = if scalar_is_high(&s_bytes) { -&s } else { s };

            let mut out = [0u8; SIGNATURE_SIZE];
            out[..32].copy_from_slice(&r.to_bytes_be());
            out[32..].copy_from_slice(&s.to_bytes_be());
            return out;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::hex;

    /// p, the field modulus, big-endian.
    const P_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
    /// n, the group order, big-endian.
    const N_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    fn sig_of(r: &str, s: &str) -> Vec<u8> {
        let mut v = hex(r);
        v.extend(hex(s));
        assert_eq!(v.len(), 64);
        v
    }

    fn be32(x: u8) -> String {
        format!("{:064x}", x)
    }

    /// The three constants above are the group order and two values derived
    /// from it. Nothing in a signature reaches `ORDER_AS_FE_BYTES` — the
    /// `x(R) == r + n` branch needs an `r` below `p - n`, about one value in
    /// 2¹²⁷ — so it is checked here against the other two instead.
    #[test]
    fn order_constants_agree() {
        // n is exactly one past the largest scalar: n - 1 is one, n is not.
        let mut n_minus_1 = ORDER_AS_FE_BYTES;
        n_minus_1[31] -= 1;
        assert!(
            Scalar::from_bytes_be(&n_minus_1).is_some(),
            "n - 1 is a scalar"
        );
        assert!(
            Scalar::from_bytes_be(&ORDER_AS_FE_BYTES).is_none(),
            "n is not"
        );
        assert_eq!(&ORDER_AS_FE_BYTES[..], &hex(N_HEX)[..]);

        // n + (p - n) == p == 0 in the field.
        let n = FieldElement::from_bytes_be(&ORDER_AS_FE_BYTES).expect("n < p");
        let p_minus_n = FieldElement::from_bytes_be(&P_MINUS_ORDER_BYTES).expect("p - n < p");
        assert!((&n + &p_minus_n).is_zero());

        // 2 * (n-1)/2 + 1 == n == 0 in the scalar field.
        let half = Scalar::from_bytes_be(&HALF_ORDER_BYTES).expect("(n-1)/2 < n");
        assert!((&(&half + &half) + &Scalar::one()).is_zero());
    }

    #[test]
    fn ecdsa_roundtrip() {
        let sk = SecretKey::from_bytes(&[1u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = crate::hash::sha256(b"a message");
        let sig = sk.sign_ecdsa(&msg);
        assert_eq!(verify_ecdsa(&pk, &msg, &sig), Ok(true));

        // a different message does not verify: False, not an error
        let other = crate::hash::sha256(b"another message");
        assert_eq!(verify_ecdsa(&pk, &other, &sig), Ok(false));

        // the step-by-step API agrees
        let q = EcdsaPublicKey::from_slice(&pk).expect("key");
        let s = EcdsaSignature::from_slice(&sig).expect("sig");
        assert!(ecdsa_verify(&q, &msg, &s));
        assert!(!ecdsa_verify(&q, &other, &s));
        assert_eq!(q.as_bytes(), &pk);
        assert_eq!(&s.as_bytes()[..], &sig[..]);
    }

    /// `secp256k1_ecdsa_verify` answers 0 for a high `s`; the signature itself
    /// parses (`parse_compact` only checks `s < n`), so the builtin is `False`.
    #[test]
    fn ecdsa_high_s_is_false() {
        let sk = SecretKey::from_bytes(&[2u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = crate::hash::sha256(b"malleability");
        let sig = sk.sign_ecdsa(&msg);
        assert_eq!(verify_ecdsa(&pk, &msg, &sig), Ok(true));

        // negate s: still a mathematically valid ECDSA signature, but high
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let s_neg = -&Scalar::from_bytes_be(&s).unwrap();
        let mut malleable = sig;
        malleable[32..].copy_from_slice(&s_neg.to_bytes_be());
        assert!(EcdsaSignature::from_slice(&malleable).is_some());
        assert_eq!(verify_ecdsa(&pk, &msg, &malleable), Ok(false));

        // s = (n-1)/2 is the largest low s, (n-1)/2 + 1 the smallest high one
        let mut half = sig;
        half[32..].copy_from_slice(&HALF_ORDER_BYTES);
        assert!(EcdsaSignature::from_slice(&half).is_some());
        assert_eq!(verify_ecdsa(&pk, &msg, &half), Ok(false));
        let mut half_plus_1 = half;
        half_plus_1[63] += 1;
        assert!(EcdsaSignature::from_slice(&half_plus_1).is_some());
        assert_eq!(verify_ecdsa(&pk, &msg, &half_plus_1), Ok(false));
    }

    /// `parse_compact` accepts `r = 0` and `s = 0`; `secp256k1_ecdsa_sig_verify`
    /// answers 0 for them, so the builtin is `False`.
    #[test]
    fn ecdsa_zero_r_or_s_is_false() {
        let sk = SecretKey::from_bytes(&[3u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = [0u8; 32];
        for sig in [
            sig_of(&be32(0), &be32(1)),
            sig_of(&be32(1), &be32(0)),
            sig_of(&be32(0), &be32(0)),
        ] {
            assert!(EcdsaSignature::from_slice(&sig).is_some());
            assert_eq!(verify_ecdsa(&pk, &msg, &sig), Ok(false), "{sig:02x?}");
        }
        // the generator as the key, as in the cn exactness review
        let g = hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert_eq!(
            verify_ecdsa(&g, &msg, &sig_of(&be32(0), &be32(1))),
            Ok(false)
        );
        assert_eq!(
            verify_ecdsa(&g, &msg, &sig_of(&be32(1), &be32(0))),
            Ok(false)
        );
    }

    /// `parse_compact` fails when `r` or `s` is not below `n`: an error.
    #[test]
    fn ecdsa_r_or_s_not_below_order_is_invalid_signature() {
        let sk = SecretKey::from_bytes(&[4u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = crate::hash::sha256(b"range");
        let ff = "ff".repeat(32);
        let mut n_minus_1 = hex(N_HEX);
        n_minus_1[31] -= 1;
        let mut n_plus_1 = hex(N_HEX);
        n_plus_1[31] += 1;
        let n_minus_1 = crate::testutil::to_hex(&n_minus_1);
        let n_plus_1 = crate::testutil::to_hex(&n_plus_1);
        for sig in [
            sig_of(N_HEX, &be32(1)),
            sig_of(&be32(1), N_HEX),
            sig_of(&n_plus_1, &be32(1)),
            sig_of(&be32(1), &n_plus_1),
            sig_of(&ff, &be32(1)),
            sig_of(&be32(1), &ff),
            sig_of(N_HEX, N_HEX),
            sig_of(P_HEX, &be32(1)),
        ] {
            assert!(EcdsaSignature::from_slice(&sig).is_none());
            assert_eq!(
                verify_ecdsa(&pk, &msg, &sig),
                Err(Secp256k1Error::InvalidSignature),
                "{sig:02x?}"
            );
        }
        // n - 1 parses; as s it is high, as r it is just a wrong r
        for sig in [sig_of(&n_minus_1, &be32(1)), sig_of(&be32(1), &n_minus_1)] {
            assert!(EcdsaSignature::from_slice(&sig).is_some());
            assert_eq!(verify_ecdsa(&pk, &msg, &sig), Ok(false));
        }
    }

    /// `plutus-core` decodes the key, then the signature, then the message.
    #[test]
    fn ecdsa_check_order() {
        let sk = SecretKey::from_bytes(&[5u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = crate::hash::sha256(b"order");
        let sig = sk.sign_ecdsa(&msg);
        let bad_sig = sig_of(N_HEX, N_HEX);

        assert_eq!(
            verify_ecdsa(&[0], &[0], &[0]),
            Err(Secp256k1Error::InvalidPublicKey)
        );
        assert_eq!(
            verify_ecdsa(&[0x05; 33], &msg[..31], &bad_sig),
            Err(Secp256k1Error::InvalidPublicKey)
        );
        assert_eq!(
            verify_ecdsa(&pk, &msg[..31], &bad_sig),
            Err(Secp256k1Error::InvalidSignature)
        );
        assert_eq!(
            verify_ecdsa(&pk, &msg[..31], &sig[..63]),
            Err(Secp256k1Error::InvalidSignature)
        );
        assert_eq!(
            verify_ecdsa(&pk, &msg[..31], &sig),
            Err(Secp256k1Error::InvalidMessage)
        );
        let mut long = msg.to_vec();
        long.push(0);
        assert_eq!(
            verify_ecdsa(&pk, &long, &sig),
            Err(Secp256k1Error::InvalidMessage)
        );
        // a zero signature parses, so a bad message length is what is reported
        assert_eq!(
            verify_ecdsa(&pk, b"", &[0u8; 64]),
            Err(Secp256k1Error::InvalidMessage)
        );
    }

    #[test]
    fn ecdsa_rejects_malformed_keys() {
        let sk = SecretKey::from_bytes(&[6u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = crate::hash::sha256(b"x");
        let sig = sk.sign_ecdsa(&msg);

        let mut long = pk.to_vec();
        long.push(0);
        // an uncompressed key, a bad tag, x = p, x not on the curve
        let mut uncompressed = [0u8; 33];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pk[1..]);
        let mut x_is_p = hex("02");
        x_is_p.extend(hex(P_HEX));
        // x = 5: 5³ + 7 = 132 is not a square mod p
        let mut off_curve = hex("02");
        off_curve.extend(hex(&be32(5)));
        for key in [
            &pk[..32],
            &long[..],
            &uncompressed[..],
            &x_is_p[..],
            &off_curve[..],
            &[][..],
        ] {
            assert!(EcdsaPublicKey::from_slice(key).is_none(), "{key:02x?}");
            assert_eq!(
                verify_ecdsa(key, &msg, &sig),
                Err(Secp256k1Error::InvalidPublicKey)
            );
        }
        // both parities of a valid x are keys; only the right one verifies
        let mut flipped = pk;
        flipped[0] ^= 1;
        assert!(EcdsaPublicKey::from_slice(&flipped).is_some());
        assert_eq!(verify_ecdsa(&flipped, &msg, &sig), Ok(false));
    }

    /// plutus-conformance 1.70.0.0
    /// `verifyEcdsaSecp256k1Signature/test-vector-03`: "low r, high s", expected
    /// `(con bool False)`.
    #[test]
    fn conformance_ecdsa_vector_03() {
        let pk = hex("032e433589dce61863199171f4d1e3fa946a5832621fcd29559940a0950f96fb6f");
        let msg = crate::hash::sha256(b"");
        let sig = hex(
            "603e6e7bf67152188204f76f6274d38c477bdbc3954cdaa44e4ef49691a517de\
             d5eaad30c2e69e3e9b124bcc48fa0e4d0aa0dfdb4ca9d537ea1dcd46c94b8f56",
        );
        assert_eq!(verify_ecdsa(&pk, &msg, &sig), Ok(false));

        // with s negated it is the low-s signature, which verifies: the False
        // above is the malleability rule alone
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let s_neg = -&Scalar::from_bytes_be(&s).unwrap();
        let mut low = sig.clone();
        low[32..].copy_from_slice(&s_neg.to_bytes_be());
        assert_eq!(verify_ecdsa(&pk, &msg, &low), Ok(true));

        // vector 01: the same key and message, another (low-s) signature
        let sig01 = hex(
            "4941155e2303988a1be97a021fbaf9fe6064d05ea694bc5e89328f297154e5c6\
             3a2f3e7b5f509294a4c2e22feb697a16b792fabfebe9d0f38403b1c929836b5a",
        );
        assert_eq!(verify_ecdsa(&pk, &msg, &sig01), Ok(true));
    }

    /// plutus-conformance 1.70.0.0 `verifySchnorrSecp256k1Signature/test-vector-12`
    /// (`r` equal to p) and `-13` (`s` equal to n), both BIP-340 vectors, both
    /// expected `(con bool False)`.
    #[test]
    fn conformance_schnorr_vectors_12_13() {
        let pk = hex("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659");
        let msg = hex("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89");
        let v12 = hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f\
             69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        );
        let v13 = hex(
            "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769\
             fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        );
        assert_eq!(verify_schnorr(&pk, &msg, &v12), Ok(false));
        assert_eq!(verify_schnorr(&pk, &msg, &v13), Ok(false));
    }

    /// `secp256k1_schnorrsig_verify` answers 0 for `r >= p` and `s >= n`: the
    /// builtin is `False`, never an error.
    #[test]
    fn schnorr_r_or_s_out_of_range_is_false() {
        let pk = hex("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659");
        let msg = hex("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89");
        let good_r = "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769";
        let good_s = "69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b";
        let ff = "ff".repeat(32);
        let mut p_plus_1 = hex(P_HEX);
        p_plus_1[31] += 1;
        let p_plus_1 = crate::testutil::to_hex(&p_plus_1);
        let mut n_plus_1 = hex(N_HEX);
        n_plus_1[31] += 1;
        let n_plus_1 = crate::testutil::to_hex(&n_plus_1);
        for sig in [
            sig_of(P_HEX, good_s),
            sig_of(&p_plus_1, good_s),
            sig_of(&ff, good_s),
            sig_of(good_r, N_HEX),
            sig_of(good_r, &n_plus_1),
            sig_of(good_r, &ff),
            sig_of(P_HEX, N_HEX),
        ] {
            assert!(SchnorrSignature::from_slice(&sig).is_some());
            assert_eq!(verify_schnorr(&pk, &msg, &sig), Ok(false), "{sig:02x?}");
        }
        // and for a zero signature, or zero halves
        for sig in [
            sig_of(&be32(0), &be32(0)),
            sig_of(&be32(0), good_s),
            sig_of(good_r, &be32(0)),
        ] {
            assert_eq!(verify_schnorr(&pk, &msg, &sig), Ok(false));
        }
    }

    /// `plutus-core` decodes the key (length, then `xonly_pubkey_parse`), then the
    /// signature (length only).
    #[test]
    fn schnorr_check_order() {
        let pk = hex("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659");
        // x = 0 is not on the curve (7 is not a square mod p)
        let off_curve = [0u8; 32];
        let x_is_p = hex(P_HEX);
        for key in [
            &off_curve[..],
            &x_is_p[..],
            &pk[..31],
            &[][..],
            &[0u8; 33][..],
        ] {
            assert!(SchnorrPublicKey::from_slice(key).is_none());
            assert_eq!(
                verify_schnorr(key, b"", &[0u8; 63]),
                Err(Secp256k1Error::InvalidPublicKey)
            );
            assert_eq!(
                verify_schnorr(key, b"", &[0u8; 64]),
                Err(Secp256k1Error::InvalidPublicKey)
            );
        }
        for sig in [&[0u8; 63][..], &[0u8; 65][..], &[][..]] {
            assert!(SchnorrSignature::from_slice(sig).is_none());
            assert_eq!(
                verify_schnorr(&pk, b"", sig),
                Err(Secp256k1Error::InvalidSignature)
            );
        }
    }

    #[test]
    fn schnorr_bip340_vector_0() {
        // BIP-340 test vector index 0; the whole CSV is exercised in
        // tests/secp256k1_vectors.rs
        let pk = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        let msg = hex("0000000000000000000000000000000000000000000000000000000000000000");
        let sig = hex(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215\
             25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        );
        assert_eq!(verify_schnorr(&pk, &msg, &sig), Ok(true));
        let p = SchnorrPublicKey::from_slice(&pk).expect("key");
        let s = SchnorrSignature::from_slice(&sig).expect("sig");
        assert!(schnorr_verify(&p, &msg, &s));
        assert_eq!(&p.as_bytes()[..], &pk[..]);
        assert_eq!(&s.as_bytes()[..], &sig[..]);

        // flipping a bit of the message breaks it: False
        let mut msg2 = msg.clone();
        msg2[0] ^= 1;
        assert_eq!(verify_schnorr(&pk, &msg2, &sig), Ok(false));
    }

    #[test]
    fn schnorr_accepts_any_message_length() {
        // unlike ECDSA, the Schnorr builtin takes a message of any size
        let sk = SecretKey::from_bytes(&[5u8; 32]).expect("valid key");
        let pk = sk.public_x_only();
        let sig = [0u8; 64];
        assert_eq!(verify_schnorr(&pk, b"", &sig), Ok(false));
        assert_eq!(verify_schnorr(&pk, &[7u8; 1000], &sig), Ok(false));
        assert_eq!(
            verify_schnorr(&pk[..31], b"", &sig),
            Err(Secp256k1Error::InvalidPublicKey)
        );
    }
}

//! The two Secp256k1 verification builtins of Plutus (CIP-49).
//!
//! Both follow `libsecp256k1`, which is what `plutus-core` calls, including the
//! parts where it is stricter than the bare algorithm:
//!
//! * [`verify_ecdsa`] rejects a signature whose `s` is in the upper half of the
//!   scalar field (`secp256k1_ecdsa_verify` does, to prevent malleability), and
//!   accepts `x(R) == r + n` as well as `x(R) == r` when `r + n < p`, which is
//!   what `secp256k1_ecdsa_sig_verify` does;
//! * [`verify_schnorr`] is BIP-340 with its x-only keys, even-y convention and
//!   tagged challenge hash.
//!
//! The builtins are total: a malformed key, signature or message length is a
//! verification failure, reported here as an [`Secp256k1Error`].

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

/// Why a Secp256k1 verification could not be performed or did not hold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Secp256k1Error {
    /// The public key has the wrong length, or does not encode a curve point.
    InvalidPublicKey,
    /// The signature has the wrong length, or its scalars are out of range.
    InvalidSignature,
    /// The message has the wrong length (ECDSA requires exactly 32 bytes).
    InvalidMessage,
    /// The signature is well formed but does not verify.
    VerificationFailed,
}

impl core::fmt::Display for Secp256k1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Secp256k1Error::InvalidPublicKey => "invalid secp256k1 public key",
            Secp256k1Error::InvalidSignature => "invalid secp256k1 signature",
            Secp256k1Error::InvalidMessage => "invalid secp256k1 message",
            Secp256k1Error::VerificationFailed => "secp256k1 signature verification failed",
        };
        f.write_str(s)
    }
}

/// n, the order of the group, as a field element — needed for the `x(R) == r+n`
/// case of ECDSA verification.
#[cfg(any(test, not(feature = "secp256k1")))]
const ORDER_AS_FE_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// p - n, used to decide whether `r + n` can still be a valid x coordinate.
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

pub(crate) fn scalar_is_high(bytes: &[u8; 32]) -> bool {
    // big-endian comparison against (n-1)/2
    bytes[..] > HALF_ORDER_BYTES[..]
}

/// Parse a 33-byte compressed public key (`secp256k1_ec_pubkey_parse`, limited
/// to the compressed form Plutus requires).
fn parse_compressed_key(pk: &[u8]) -> Result<PointAffine, Secp256k1Error> {
    if pk.len() != ECDSA_PUBLIC_KEY_SIZE {
        return Err(Secp256k1Error::InvalidPublicKey);
    }
    let sign = match pk[0] {
        0x02 => Sign::Positive, // even y
        0x03 => Sign::Negative, // odd y
        _ => return Err(Secp256k1Error::InvalidPublicKey),
    };
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&pk[1..]);
    let x = FieldElement::from_bytes_be(&x_bytes).ok_or(Secp256k1Error::InvalidPublicKey)?;
    PointAffine::decompress(&x, sign)
        .into_option()
        .ok_or(Secp256k1Error::InvalidPublicKey)
}

/// Reduce a 32-byte big-endian integer modulo n (`secp256k1_scalar_set_b32`).
pub(crate) fn scalar_from_bytes_mod_order(bytes: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    wide[32..].copy_from_slice(bytes);
    Scalar::init_from_wide_bytes_be(wide)
}

/// `verifyEcdsaSecp256k1Signature`.
///
/// * `public_key` — 33 bytes, compressed SEC1;
/// * `message` — exactly 32 bytes, already hashed;
/// * `signature` — 64 bytes, `r || s` big-endian, with `s` in the lower half.
pub fn verify_ecdsa(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Secp256k1Error> {
    if message.len() != ECDSA_MESSAGE_SIZE {
        return Err(Secp256k1Error::InvalidMessage);
    }
    if signature.len() != SIGNATURE_SIZE {
        return Err(Secp256k1Error::InvalidSignature);
    }
    let q = parse_compressed_key(public_key)?;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // `secp256k1_ecdsa_signature_parse_compact` rejects r or s >= n ...
    let r = Scalar::from_bytes_be(&r_bytes).ok_or(Secp256k1Error::InvalidSignature)?;
    let s = Scalar::from_bytes_be(&s_bytes).ok_or(Secp256k1Error::InvalidSignature)?;
    // ... `secp256k1_ecdsa_verify` rejects a high s ...
    if scalar_is_high(&s_bytes) {
        return Err(Secp256k1Error::InvalidSignature);
    }
    // ... and `secp256k1_ecdsa_sig_verify` rejects zeroes
    if r.is_zero() || s.is_zero() {
        return Err(Secp256k1Error::InvalidSignature);
    }

    #[cfg(feature = "secp256k1")]
    {
        let _ = q;
        let q = libsecp256k1::PublicKey::from_slice(public_key)
            .map_err(|_| Secp256k1Error::InvalidPublicKey)?;
        let sig = libsecp256k1::ecdsa::Signature::from_compact(signature)
            .map_err(|_| Secp256k1Error::InvalidSignature)?;
        let msg =
            libsecp256k1::Message::from_digest(message.try_into().expect("message length checked"));
        libsecp256k1::ecdsa::verify(&sig, msg, &q).map_err(|_| Secp256k1Error::VerificationFailed)
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        let mut m_bytes = [0u8; 32];
        m_bytes.copy_from_slice(message);
        let m = scalar_from_bytes_mod_order(&m_bytes);

        let sinv = s.inverse();
        let u1 = &sinv * &m;
        let u2 = &sinv * &r;

        // R = u1*G + u2*Q
        let point = &Point::mul_base(&u1) + &(&Point::from_affine(&q) * &u2);
        let affine = point
            .to_affine()
            .ok_or(Secp256k1Error::VerificationFailed)?;
        let (x, _) = affine.to_coordinate();

        // x(R) == r, or x(R) == r + n when that is still below p
        let r_as_fe =
            FieldElement::from_bytes_be(&r_bytes).ok_or(Secp256k1Error::InvalidSignature)?;
        if &r_as_fe == x {
            return Ok(());
        }
        if r_bytes[..] < P_MINUS_ORDER_BYTES[..] {
            let order_as_fe = FieldElement::from_bytes_be(&ORDER_AS_FE_BYTES).expect("n < p");
            if &(&r_as_fe + &order_as_fe) == x {
                return Ok(());
            }
        }
        Err(Secp256k1Error::VerificationFailed)
    }
}

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

/// BIP-340 `lift_x`: the point with x coordinate `x` and even y.
pub(crate) fn lift_x(x_bytes: &[u8; 32]) -> Result<PointAffine, Secp256k1Error> {
    let x = FieldElement::from_bytes_be(x_bytes).ok_or(Secp256k1Error::InvalidPublicKey)?;
    PointAffine::decompress(&x, Sign::Positive)
        .into_option()
        .ok_or(Secp256k1Error::InvalidPublicKey)
}

/// `verifySchnorrSecp256k1Signature`: BIP-340 verification.
///
/// * `public_key` — 32 bytes, x-only;
/// * `message` — any length;
/// * `signature` — 64 bytes, `r || s`.
pub fn verify_schnorr(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Secp256k1Error> {
    if public_key.len() != SCHNORR_PUBLIC_KEY_SIZE {
        return Err(Secp256k1Error::InvalidPublicKey);
    }
    if signature.len() != SIGNATURE_SIZE {
        return Err(Secp256k1Error::InvalidSignature);
    }

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public_key);
    let p = lift_x(&pk_bytes)?;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // r must be a field element and s a scalar, both canonical
    let r_as_fe = FieldElement::from_bytes_be(&r_bytes).ok_or(Secp256k1Error::InvalidSignature)?;
    let s = Scalar::from_bytes_be(&s_bytes).ok_or(Secp256k1Error::InvalidSignature)?;

    #[cfg(feature = "secp256k1")]
    {
        let _ = (p, r_as_fe, s);
        let p = libsecp256k1::XOnlyPublicKey::from_byte_array(pk_bytes)
            .map_err(|_| Secp256k1Error::InvalidPublicKey)?;
        let sig = libsecp256k1::schnorr::Signature::from_byte_array(
            signature.try_into().expect("signature length checked"),
        );
        libsecp256k1::schnorr::verify(&sig, message, &p)
            .map_err(|_| Secp256k1Error::VerificationFailed)
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        let e_bytes = tagged_hash(b"BIP0340/challenge", &[&r_bytes, &pk_bytes, message]);
        let e = scalar_from_bytes_mod_order(&e_bytes);

        // R = s*G - e*P
        let point = &Point::mul_base(&s) - &(&Point::from_affine(&p) * &e);
        let affine = point
            .to_affine()
            .ok_or(Secp256k1Error::VerificationFailed)?;
        let (x, y) = affine.to_coordinate();

        if y.sign() != Sign::Positive || x != &r_as_fe {
            return Err(Secp256k1Error::VerificationFailed);
        }
        Ok(())
    }
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
        assert!(verify_ecdsa(&pk, &msg, &sig).is_ok());

        // a different message does not verify
        let other = crate::hash::sha256(b"another message");
        assert_eq!(
            verify_ecdsa(&pk, &other, &sig).unwrap_err(),
            Secp256k1Error::VerificationFailed
        );
    }

    #[test]
    fn ecdsa_rejects_high_s() {
        let sk = SecretKey::from_bytes(&[2u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = crate::hash::sha256(b"malleability");
        let sig = sk.sign_ecdsa(&msg);
        assert!(verify_ecdsa(&pk, &msg, &sig).is_ok());

        // negate s: still a mathematically valid ECDSA signature, but high
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let s_neg = -&Scalar::from_bytes_be(&s).unwrap();
        let mut malleable = sig;
        malleable[32..].copy_from_slice(&s_neg.to_bytes_be());
        assert_eq!(
            verify_ecdsa(&pk, &msg, &malleable).unwrap_err(),
            Secp256k1Error::InvalidSignature
        );
    }

    #[test]
    fn ecdsa_rejects_malformed_inputs() {
        let sk = SecretKey::from_bytes(&[3u8; 32]).expect("valid key");
        let pk = sk.public_compressed();
        let msg = crate::hash::sha256(b"x");
        let sig = sk.sign_ecdsa(&msg);

        assert_eq!(
            verify_ecdsa(&pk[..32], &msg, &sig).unwrap_err(),
            Secp256k1Error::InvalidPublicKey
        );
        assert_eq!(
            verify_ecdsa(&pk, &msg[..31], &sig).unwrap_err(),
            Secp256k1Error::InvalidMessage
        );
        assert_eq!(
            verify_ecdsa(&pk, &msg, &sig[..63]).unwrap_err(),
            Secp256k1Error::InvalidSignature
        );

        // an uncompressed key is not accepted by the builtin
        let mut uncompressed = [0u8; 33];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pk[1..]);
        assert_eq!(
            verify_ecdsa(&uncompressed, &msg, &sig).unwrap_err(),
            Secp256k1Error::InvalidPublicKey
        );

        // r = 0 is rejected
        let mut zero_r = sig;
        zero_r[..32].fill(0);
        assert_eq!(
            verify_ecdsa(&pk, &msg, &zero_r).unwrap_err(),
            Secp256k1Error::InvalidSignature
        );
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
        assert!(verify_schnorr(&pk, &msg, &sig).is_ok());

        // flipping a bit of the message breaks it
        let mut msg2 = msg.clone();
        msg2[0] ^= 1;
        assert!(verify_schnorr(&pk, &msg2, &sig).is_err());
    }

    #[test]
    fn schnorr_accepts_any_message_length() {
        // unlike ECDSA, the Schnorr builtin takes a message of any size
        let sk = SecretKey::from_bytes(&[5u8; 32]).expect("valid key");
        let pk = sk.public_x_only();
        // a signature we cannot produce here (signing needs the even-y
        // adjustment), so just check that the length is not what is rejected
        let sig = [0u8; 64];
        assert_eq!(
            verify_schnorr(&pk, b"", &sig).unwrap_err(),
            Secp256k1Error::VerificationFailed
        );
        assert_eq!(
            verify_schnorr(&pk, &[7u8; 1000], &sig).unwrap_err(),
            Secp256k1Error::VerificationFailed
        );
        assert_eq!(
            verify_schnorr(&pk[..31], b"", &sig).unwrap_err(),
            Secp256k1Error::InvalidPublicKey
        );
    }
}

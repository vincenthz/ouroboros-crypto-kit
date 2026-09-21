//! BLS12-381, as Plutus exposes it (CIP-0381).
//!
//! The builtins map onto this module as follows:
//!
//! | Plutus builtin | here |
//! |---|---|
//! | `bls12_381_G1_add` / `_neg` / `_scalarMul` / `_equal` | [`G1::add`], [`G1::neg`], [`G1::scalar_mul`], `PartialEq` |
//! | `bls12_381_G1_hashToGroup` | [`G1::hash_to_group`] |
//! | `bls12_381_G1_compress` / `_uncompress` | [`G1::compress`], [`G1::uncompress`] |
//! | `bls12_381_G2_*` | the same on [`G2`] |
//! | `bls12_381_millerLoop` | [`miller_loop`] |
//! | `bls12_381_mulMlResult` | [`MlResult::mul`] |
//! | `bls12_381_finalVerify` | [`MlResult::final_verify`] |
//!
//! The group arithmetic, the hash-to-curve suites and the (de)serialisation are
//! [`eccoxide`]'s; what this module adds is the Plutus surface — the error
//! taxonomy `blst` reports, the domain separation tag limit, and the scalar
//! reduction Plutus's unbounded `Integer` argument needs.
//!
//! Group elements include the point at infinity, and the (de)serialisation is
//! the ZCash format `blst` implements: 48 bytes for G1, 96 for G2, with three
//! flag bits in the first byte (compressed, infinity, and the sign of `y`) and
//! `Fp2` coordinates written imaginary part first. `uncompress` performs every
//! check `blst_p1_uncompress` does, including subgroup membership, because
//! Plutus treats all of them as failures.
//!
//! ```
//! use ouroboros_crypto_kit::plutus::bls12_381::{miller_loop, G1, G2, Scalar};
//!
//! let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
//! let p = G1::hash_to_group(b"message", dst).unwrap();
//! assert_eq!(G1::uncompress(&p.compress()).unwrap(), p);
//!
//! // e(a*P, Q) == e(P, a*Q)
//! let a = Scalar::from_u64(42);
//! let q = G2::generator();
//! assert!(miller_loop(&p.scalar_mul(&a), &q).final_verify(&miller_loop(&p, &q.scalar_mul(&a))));
//! ```

#[path = "pairing.rs"]
mod pairing;

use core::convert::TryInto;
use eccoxide::curve::bls12_381::{Fp, Scalar as EccScalar, g1, g2};

pub use pairing::MlResult;

/// Size of a compressed G1 element.
pub const G1_COMPRESSED_SIZE: usize = g1::Point::COMPRESSED_SIZE;
/// Size of a compressed G2 element.
pub const G2_COMPRESSED_SIZE: usize = g2::Point::COMPRESSED_SIZE;
/// Size of an uncompressed G1 element (`blst_p1_serialize`).
pub const G1_UNCOMPRESSED_SIZE: usize = g1::Point::UNCOMPRESSED_SIZE;
/// Size of an uncompressed G2 element (`blst_p2_serialize`).
pub const G2_UNCOMPRESSED_SIZE: usize = g2::Point::UNCOMPRESSED_SIZE;

/// The longest domain separation tag `hashToGroup` accepts.
///
/// RFC 9380 hashes a longer tag down rather than refusing it but `blst` — and therefore Plutus — caps it here.
pub const MAX_DST_SIZE: usize = 255;

/// Why a BLS12-381 operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlsError {
    /// The input has the wrong length.
    InvalidLength {
        /// What was expected.
        expected: usize,
        /// What was given.
        got: usize,
    },
    /// The encoding is malformed: wrong flag bits, a non-canonical coordinate,
    /// or a non-zero payload on an infinity encoding (`BLST_BAD_ENCODING`).
    BadEncoding,
    /// The coordinates do not satisfy the curve equation
    /// (`BLST_POINT_NOT_ON_CURVE`).
    NotOnCurve,
    /// The point is on the curve but outside the prime-order subgroup
    /// (`BLST_POINT_NOT_IN_GROUP`).
    NotInGroup,
    /// The domain separation tag is longer than [`MAX_DST_SIZE`].
    DstTooLong(usize),
}

impl core::fmt::Display for BlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlsError::InvalidLength { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            BlsError::BadEncoding => f.write_str("malformed BLS12-381 point encoding"),
            BlsError::NotOnCurve => f.write_str("BLS12-381 point is not on the curve"),
            BlsError::NotInGroup => f.write_str("BLS12-381 point is not in the subgroup"),
            BlsError::DstTooLong(n) => {
                write!(f, "domain separation tag is {n} bytes, at most 255 allowed")
            }
        }
    }
}

/// An element of the scalar field, i.e. an integer modulo `r`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Scalar(EccScalar);

impl Scalar {
    /// The scalar `n`.
    pub fn from_u64(n: u64) -> Self {
        Scalar(EccScalar::from_u64(n))
    }

    /// Reduce a big-endian integer of any length modulo `r`.
    ///
    /// This is what Plutus's `scalarMul` does with its `Integer` argument.
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        // Horner over 16-byte chunks: acc = acc * 2^128 + chunk. Chunks are
        // small enough to be reduced directly by the wide constructor.
        let mut acc = EccScalar::zero();
        let shift = pow2_scalar(128);
        for chunk in bytes.chunks(16) {
            let mut wide = [0u8; 64];
            wide[64 - chunk.len()..].copy_from_slice(chunk);
            let value = EccScalar::init_from_wide_bytes_be(wide);
            let scale = if chunk.len() == 16 {
                shift.clone()
            } else {
                pow2_scalar(8 * chunk.len())
            };
            acc = &(&acc * &scale) + &value;
        }
        Scalar(acc)
    }

    /// Reduce a signed integer, given as a big-endian magnitude and a sign,
    /// modulo `r`.
    pub fn from_be_bytes_signed_mod_order(magnitude: &[u8], negative: bool) -> Self {
        let s = Self::from_be_bytes_mod_order(magnitude);
        if negative { Scalar(-&s.0) } else { s }
    }

    /// The canonical big-endian encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes_be()
    }

    /// Whether this is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

/// `2^bits` as a scalar, for `bits <= 128`.
fn pow2_scalar(bits: usize) -> EccScalar {
    assert!(bits <= 128);
    let mut wide = [0u8; 64];
    wide[63 - bits / 8] = 1 << (bits % 8);
    EccScalar::init_from_wide_bytes_be(wide)
}

/// An element of G1.
#[derive(Clone, Debug)]
pub struct G1(g1::Point);

/// An element of G2.
#[derive(Clone, Debug)]
pub struct G2(g2::Point);

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G1 {}

impl PartialEq for G2 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G2 {}

fn check_dst(dst: &[u8]) -> Result<(), BlsError> {
    if dst.len() > MAX_DST_SIZE {
        Err(BlsError::DstTooLong(dst.len()))
    } else {
        Ok(())
    }
}

fn check_length(bytes: &[u8], expected: usize) -> Result<(), BlsError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(BlsError::InvalidLength {
            expected,
            got: bytes.len(),
        })
    }
}

/// Bit 7 of the leading byte: only the x-coordinate is present.
const COMPRESSION_FLAG: u8 = 0b1000_0000;
/// Bit 6 of the leading byte: the encoded point is the identity.
const INFINITY_FLAG: u8 = 0b0100_0000;
/// Bit 5 of the leading byte: the dropped `y` is the larger of the two roots.
const SORT_FLAG: u8 = 0b0010_0000;
const FLAGS_MASK: u8 = COMPRESSION_FLAG | INFINITY_FLAG | SORT_FLAG;

/// Whether 48 big-endian bytes are the canonical representative of an `Fp`
/// element, i.e. below `p`.
fn fp_is_canonical(bytes: &[u8]) -> bool {
    let bytes: &[u8; 48] = bytes.try_into().expect("a coordinate component");
    Fp::from_bytes_be(bytes).is_some()
}

/// Everything about an encoding that is wrong in the bytes themselves rather
/// than in the point they stand for: the flag bits, the payload of an infinity
/// encoding, and the canonicity of each coordinate component.
///
/// underlying decoders answer `None` for all of those *and* for a
/// well-formed encoding of a point that misses the curve, but `blst` — and so
/// Plutus — tells the two apart as `BLST_BAD_ENCODING` and
/// `BLST_POINT_NOT_ON_CURVE`. Ruling out the byte-level failures here leaves
/// [`BlsError::NotOnCurve`] as the only reason left for the decoder to refuse.
///
/// The checks mirror `read_compressed_flags` / `read_uncompressed_flags` and
/// the canonicity half of underlying coordinate readers; `bytes` is a full
/// encoding of the expected length, a whole number of 48-byte components with
/// the flags in the top bits of the first.
fn check_encoding(bytes: &[u8], compressed: bool) -> Result<(), BlsError> {
    let flags = bytes[0] & FLAGS_MASK;

    if (flags & COMPRESSION_FLAG != 0) != compressed {
        return Err(BlsError::BadEncoding);
    }
    // an uncompressed encoding carries `y` itself, so there is no root to sort
    if !compressed && flags & SORT_FLAG != 0 {
        return Err(BlsError::BadEncoding);
    }
    if flags & INFINITY_FLAG != 0 {
        // the identity has a single encoding per flavour: its flags and nothing
        // else, the sort bit included
        let payload = bytes[1..]
            .iter()
            .fold(bytes[0] & !(COMPRESSION_FLAG | INFINITY_FLAG), |acc, b| {
                acc | b
            });
        return if payload == 0 {
            Ok(())
        } else {
            Err(BlsError::BadEncoding)
        };
    }

    // every component has to be the canonical representative of its class; the
    // flags share the leading byte with the first one
    let mut leading = [0u8; 48];
    leading.copy_from_slice(&bytes[..48]);
    leading[0] &= !FLAGS_MASK;
    if !fp_is_canonical(&leading) || !bytes[48..].chunks(48).all(fp_is_canonical) {
        return Err(BlsError::BadEncoding);
    }
    Ok(())
}

impl G1 {
    /// The point at infinity, the identity of the group.
    pub fn zero() -> Self {
        G1(g1::Point::INFINITY)
    }

    /// The standard generator.
    pub fn generator() -> Self {
        G1(g1::Point::GENERATOR)
    }

    /// Whether this is the point at infinity.
    pub fn is_zero(&self) -> bool {
        self.0.to_affine().is_none()
    }

    /// `bls12_381_G1_add`.
    pub fn add(&self, other: &Self) -> Self {
        G1(&self.0 + &other.0)
    }

    /// `bls12_381_G1_neg`.
    pub fn neg(&self) -> Self {
        G1(-&self.0)
    }

    /// `bls12_381_G1_scalarMul`: the scalar is taken modulo `r`.
    pub fn scalar_mul(&self, k: &Scalar) -> Self {
        G1(&self.0 * &k.0)
    }

    /// `bls12_381_G1_hashToGroup`: RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_`
    /// with the given domain separation tag.
    pub fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self, BlsError> {
        check_dst(dst)?;
        Ok(G1(g1::Point::hash_to_curve(msg, dst)))
    }

    /// `bls12_381_G1_compress`: the 48-byte ZCash encoding.
    pub fn compress(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }

    /// `bls12_381_G1_uncompress`: parse the 48-byte ZCash encoding, checking the
    /// flags, the canonicity of `x`, the curve equation and subgroup membership.
    pub fn uncompress(bytes: &[u8]) -> Result<Self, BlsError> {
        let point = Self::uncompress_point(bytes)?;
        if !g1_in_subgroup(&point) {
            return Err(BlsError::NotInGroup);
        }
        Ok(G1(point))
    }

    /// The parsing half of [`G1::uncompress`], without the subgroup check.
    ///
    /// `blst_p1_uncompress` stops here and leaves the subgroup check to
    /// `blst_p1_in_g1`, so the C API needs the two separately.
    pub(crate) fn uncompress_point(bytes: &[u8]) -> Result<g1::Point, BlsError> {
        check_length(bytes, G1_COMPRESSED_SIZE)?;
        check_encoding(bytes, true)?;
        g1::Point::from_compressed_oncurve_only(bytes.try_into().expect("length checked"))
            .ok_or(BlsError::NotOnCurve)
    }

    /// The uncompressed 96-byte encoding (`blst_p1_serialize`), for
    /// interoperability and testing; Plutus only uses the compressed form.
    pub fn serialize(&self) -> [u8; G1_UNCOMPRESSED_SIZE] {
        self.0.to_uncompressed()
    }

    /// Parse the uncompressed 96-byte encoding.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, BlsError> {
        let point = Self::deserialize_point(bytes)?;
        if !g1_in_subgroup(&point) {
            return Err(BlsError::NotInGroup);
        }
        Ok(G1(point))
    }

    /// The parsing half of [`G1::deserialize`], without the subgroup check.
    pub(crate) fn deserialize_point(bytes: &[u8]) -> Result<g1::Point, BlsError> {
        check_length(bytes, G1_UNCOMPRESSED_SIZE)?;
        check_encoding(bytes, false)?;
        g1::Point::from_uncompressed_oncurve_only(bytes.try_into().expect("length checked"))
            .ok_or(BlsError::NotOnCurve)
    }

    /// Wrap n point.
    ///
    /// Unlike [`G1::uncompress`] this does not check subgroup membership: the C
    /// API has to be able to hold a point that is on the curve but outside the
    /// subgroup, because `blst` reports that as a separate step.
    #[allow(unused)]
    pub(crate) fn from_point(point: g1::Point) -> Self {
        G1(point)
    }

    /// The underlying point.
    #[allow(unused)]
    pub(crate) fn as_point(&self) -> &g1::Point {
        &self.0
    }

    /// Whether this element is in the prime-order subgroup (`blst_p1_in_g1`).
    #[allow(unused)]
    pub(crate) fn in_subgroup(&self) -> bool {
        g1_in_subgroup(&self.0)
    }
}

/// Whether a curve point is in the prime-order subgroup of G1.
pub(crate) fn g1_in_subgroup(point: &g1::Point) -> bool {
    point.is_in_subgroup().into()
}

/// Whether a curve point is in the prime-order subgroup of G2.
pub(crate) fn g2_in_subgroup(point: &g2::Point) -> bool {
    point.is_in_subgroup().into()
}

impl G2 {
    /// The point at infinity, the identity of the group.
    pub fn zero() -> Self {
        G2(g2::Point::INFINITY)
    }

    /// The standard generator.
    pub fn generator() -> Self {
        G2(g2::Point::GENERATOR)
    }

    /// Whether this is the point at infinity.
    pub fn is_zero(&self) -> bool {
        self.0.to_affine().is_none()
    }

    /// `bls12_381_G2_add`.
    pub fn add(&self, other: &Self) -> Self {
        G2(&self.0 + &other.0)
    }

    /// `bls12_381_G2_neg`.
    pub fn neg(&self) -> Self {
        G2(-&self.0)
    }

    /// `bls12_381_G2_scalarMul`: the scalar is taken modulo `r`.
    pub fn scalar_mul(&self, k: &Scalar) -> Self {
        G2(&self.0 * &k.0)
    }

    /// `bls12_381_G2_hashToGroup`: RFC 9380 `BLS12381G2_XMD:SHA-256_SSWU_RO_`
    /// with the given domain separation tag.
    pub fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self, BlsError> {
        check_dst(dst)?;
        Ok(G2(g2::Point::hash_to_curve(msg, dst)))
    }

    /// `bls12_381_G2_compress`: the 96-byte ZCash encoding, imaginary part
    /// first.
    pub fn compress(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }

    /// `bls12_381_G2_uncompress`.
    pub fn uncompress(bytes: &[u8]) -> Result<Self, BlsError> {
        let point = Self::uncompress_point(bytes)?;
        if !g2_in_subgroup(&point) {
            return Err(BlsError::NotInGroup);
        }
        Ok(G2(point))
    }

    /// The parsing half of [`G2::uncompress`], without the subgroup check.
    pub(crate) fn uncompress_point(bytes: &[u8]) -> Result<g2::Point, BlsError> {
        check_length(bytes, G2_COMPRESSED_SIZE)?;
        check_encoding(bytes, true)?;
        g2::Point::from_compressed_oncurve_only(bytes.try_into().expect("length checked"))
            .ok_or(BlsError::NotOnCurve)
    }

    /// The uncompressed 192-byte encoding (`blst_p2_serialize`).
    pub fn serialize(&self) -> [u8; G2_UNCOMPRESSED_SIZE] {
        self.0.to_uncompressed()
    }

    /// Parse the uncompressed 192-byte encoding.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, BlsError> {
        let point = Self::deserialize_point(bytes)?;
        if !g2_in_subgroup(&point) {
            return Err(BlsError::NotInGroup);
        }
        Ok(G2(point))
    }

    /// The parsing half of [`G2::deserialize`], without the subgroup check.
    pub(crate) fn deserialize_point(bytes: &[u8]) -> Result<g2::Point, BlsError> {
        check_length(bytes, G2_UNCOMPRESSED_SIZE)?;
        check_encoding(bytes, false)?;
        g2::Point::from_uncompressed_oncurve_only(bytes.try_into().expect("length checked"))
            .ok_or(BlsError::NotOnCurve)
    }

    /// Wrap a point, without checking subgroup membership; see
    /// [`G1::from_point`].
    #[allow(unused)]
    pub(crate) fn from_point(point: g2::Point) -> Self {
        G2(point)
    }

    /// The underlying point.
    #[allow(unused)]
    pub(crate) fn as_point(&self) -> &g2::Point {
        &self.0
    }

    /// Whether this element is in the prime-order subgroup (`blst_p2_in_g2`).
    #[allow(unused)]
    pub(crate) fn in_subgroup(&self) -> bool {
        g2_in_subgroup(&self.0)
    }
}

/// `bls12_381_millerLoop`.
pub fn miller_loop(p: &G1, q: &G2) -> MlResult {
    pairing::miller_loop(&p.0, &q.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eccoxide::params::bls12_381::ORDER_BYTES;

    fn g1_of(k: u64) -> G1 {
        G1::generator().scalar_mul(&Scalar::from_u64(k))
    }
    fn g2_of(k: u64) -> G2 {
        G2::generator().scalar_mul(&Scalar::from_u64(k))
    }

    #[test]
    fn group_laws() {
        let p = g1_of(3);
        let q = g1_of(5);
        assert_eq!(p.add(&q), g1_of(8));
        assert_eq!(p.add(&p), g1_of(6));
        assert_eq!(p.add(&p.neg()), G1::zero());
        assert_eq!(p.add(&G1::zero()), p);
        assert!(G1::zero().is_zero());
        assert!(!p.is_zero());

        let p = g2_of(3);
        let q = g2_of(5);
        assert_eq!(p.add(&q), g2_of(8));
        assert_eq!(p.add(&p.neg()), G2::zero());
        assert_eq!(p.add(&G2::zero()), p);
    }

    #[test]
    fn compression_round_trips() {
        for k in [0u64, 1, 2, 7, 1000, u64::MAX] {
            let p = g1_of(k);
            assert_eq!(G1::uncompress(&p.compress()).unwrap(), p);
            assert_eq!(G1::deserialize(&p.serialize()).unwrap(), p);

            let q = g2_of(k);
            assert_eq!(G2::uncompress(&q.compress()).unwrap(), q);
            assert_eq!(G2::deserialize(&q.serialize()).unwrap(), q);
        }
    }

    #[test]
    fn infinity_encodings() {
        let bytes = G1::zero().compress();
        assert_eq!(bytes[0], 0xc0);
        assert!(bytes[1..].iter().all(|b| *b == 0));
        assert!(G1::uncompress(&bytes).unwrap().is_zero());

        // a non-zero payload on an infinity encoding is rejected
        let mut bad = bytes;
        bad[47] = 1;
        assert_eq!(G1::uncompress(&bad).unwrap_err(), BlsError::BadEncoding);
        // as is the sign bit being set
        let mut bad = bytes;
        bad[0] |= 0x20;
        assert_eq!(G1::uncompress(&bad).unwrap_err(), BlsError::BadEncoding);

        let bytes = G2::zero().compress();
        assert_eq!(bytes[0], 0xc0);
        assert!(G2::uncompress(&bytes).unwrap().is_zero());

        // the uncompressed flavour has no compression bit and no sign bit
        let bytes = G1::zero().serialize();
        assert_eq!(bytes[0], 0x40);
        assert!(G1::deserialize(&bytes).unwrap().is_zero());
        let mut bad = bytes;
        bad[0] |= 0x20;
        assert_eq!(G1::deserialize(&bad).unwrap_err(), BlsError::BadEncoding);
    }

    #[test]
    fn uncompress_rejects_bad_input() {
        let p = g1_of(9);
        let good = p.compress();

        assert_eq!(
            G1::uncompress(&good[..47]).unwrap_err(),
            BlsError::InvalidLength {
                expected: 48,
                got: 47
            }
        );
        // the compression flag must be set
        let mut bad = good;
        bad[0] &= 0x7f;
        assert_eq!(G1::uncompress(&bad).unwrap_err(), BlsError::BadEncoding);
        // x must be canonical: p itself is not
        let mut bad = [0u8; 48];
        bad.copy_from_slice(&eccoxide::params::bls12_381::P_BYTES);
        bad[0] |= 0x80;
        assert_eq!(G1::uncompress(&bad).unwrap_err(), BlsError::BadEncoding);
        // x = 1 has no matching y: 1 + 4 = 5 is not a square mod p
        let mut bad = [0u8; 48];
        bad[47] = 1;
        bad[0] |= 0x80;
        assert_eq!(G1::uncompress(&bad).unwrap_err(), BlsError::NotOnCurve);
    }

    #[test]
    fn deserialize_rejects_bad_input() {
        let good = g1_of(9).serialize();

        assert_eq!(
            G1::deserialize(&good[..95]).unwrap_err(),
            BlsError::InvalidLength {
                expected: 96,
                got: 95
            }
        );
        // the compression flag must be clear
        let mut bad = good;
        bad[0] |= 0x80;
        assert_eq!(G1::deserialize(&bad).unwrap_err(), BlsError::BadEncoding);
        // y is a coordinate of its own, and must be canonical too
        let mut bad = good;
        bad[48..].copy_from_slice(&eccoxide::params::bls12_381::P_BYTES);
        assert_eq!(G1::deserialize(&bad).unwrap_err(), BlsError::BadEncoding);
        // a canonical (x, y) off the curve is a different failure
        let mut bad = good;
        bad[95] ^= 1;
        assert_eq!(G1::deserialize(&bad).unwrap_err(), BlsError::NotOnCurve);
    }

    #[test]
    fn compression_records_the_sign_of_y() {
        // flipping the sign bit gives -P
        let p = g1_of(11);
        let mut flipped = p.compress();
        flipped[0] ^= 0x20;
        assert_eq!(G1::uncompress(&flipped).unwrap(), p.neg());

        let q = g2_of(11);
        let mut flipped = q.compress();
        flipped[0] ^= 0x20;
        assert_eq!(G2::uncompress(&flipped).unwrap(), q.neg());
    }

    #[test]
    fn scalar_reduction() {
        // r reduces to zero, r+1 to one
        let r = ORDER_BYTES;
        assert!(Scalar::from_be_bytes_mod_order(&r).is_zero());
        let mut r_plus_1 = r;
        r_plus_1[31] += 1;
        assert_eq!(
            Scalar::from_be_bytes_mod_order(&r_plus_1),
            Scalar::from_u64(1)
        );
        // a scalar wider than 32 bytes is folded, not truncated
        let mut wide = [0u8; 48];
        wide[47] = 5;
        assert_eq!(Scalar::from_be_bytes_mod_order(&wide), Scalar::from_u64(5));
        // and 2^256 is not congruent to zero
        let mut two_256 = [0u8; 33];
        two_256[0] = 1;
        assert!(!Scalar::from_be_bytes_mod_order(&two_256).is_zero());

        let p = g1_of(1);
        assert_eq!(
            p.scalar_mul(&Scalar::from_be_bytes_mod_order(&r)),
            G1::zero()
        );
        assert_eq!(
            p.scalar_mul(&Scalar::from_be_bytes_signed_mod_order(&[3], true)),
            g1_of(3).neg()
        );
    }

    #[test]
    fn hash_to_group_lands_in_the_subgroup() {
        for msg in [&b""[..], b"abc", b"a longer message to hash"] {
            let p = G1::hash_to_group(msg, b"dst").unwrap();
            assert!(p.in_subgroup(), "G1 hash is not in the subgroup");
            let q = G2::hash_to_group(msg, b"dst").unwrap();
            assert!(q.in_subgroup(), "G2 hash is not in the subgroup");
        }
        assert!(
            G1::hash_to_group(b"a", b"dst").unwrap() != G1::hash_to_group(b"b", b"dst").unwrap()
        );
        assert!(
            G1::hash_to_group(b"m", b"one").unwrap() != G1::hash_to_group(b"m", b"two").unwrap()
        );
    }

    #[test]
    fn hash_to_group_rejects_a_long_dst() {
        let dst = [0u8; 256];
        assert_eq!(
            G1::hash_to_group(b"m", &dst).unwrap_err(),
            BlsError::DstTooLong(256)
        );
        assert_eq!(
            G2::hash_to_group(b"m", &dst).unwrap_err(),
            BlsError::DstTooLong(256)
        );
        assert!(G1::hash_to_group(b"m", &dst[..255]).is_ok());
    }

    #[test]
    fn pairing_check_through_the_plutus_api() {
        // e(a*P, b*Q) == e(ab*P, Q)
        let a = Scalar::from_u64(3);
        let b = Scalar::from_u64(5);
        let p = G1::generator();
        let q = G2::generator();
        let lhs = miller_loop(&p.scalar_mul(&a), &q.scalar_mul(&b));
        let rhs = miller_loop(&p.scalar_mul(&Scalar::from_u64(15)), &q);
        assert!(lhs.final_verify(&rhs));

        // the standard signature check: e(H, pk) == e(sig, G2)
        let sk = Scalar::from_u64(1234);
        let h = G1::hash_to_group(b"message", b"dst").unwrap();
        let sig = h.scalar_mul(&sk);
        let pk = G2::generator().scalar_mul(&sk);
        assert!(miller_loop(&h, &pk).final_verify(&miller_loop(&sig, &G2::generator())));

        let other = G1::hash_to_group(b"other", b"dst").unwrap();
        assert!(!miller_loop(&other, &pk).final_verify(&miller_loop(&sig, &G2::generator())));
    }
}

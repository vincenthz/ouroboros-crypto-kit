//! Native `blst` backend for the backend-independent CIP-0381 API.

use blst::{
    BLST_ERROR, blst_fp12, blst_fp12_finalverify, blst_fp12_is_equal, blst_fp12_mul,
    blst_hash_to_g1, blst_hash_to_g2, blst_miller_loop, blst_p1, blst_p1_add_or_double,
    blst_p1_affine, blst_p1_affine_in_g1, blst_p1_cneg, blst_p1_compress, blst_p1_deserialize,
    blst_p1_from_affine, blst_p1_generator, blst_p1_is_equal, blst_p1_is_inf, blst_p1_mult,
    blst_p1_serialize, blst_p1_to_affine, blst_p1_uncompress, blst_p2, blst_p2_add_or_double,
    blst_p2_affine, blst_p2_affine_in_g2, blst_p2_cneg, blst_p2_compress, blst_p2_deserialize,
    blst_p2_from_affine, blst_p2_generator, blst_p2_is_equal, blst_p2_is_inf, blst_p2_mult,
    blst_p2_serialize, blst_p2_to_affine, blst_p2_uncompress, blst_scalar,
    blst_scalar_from_bendian,
};
use eccoxide::curve::bls12_381::Scalar as EccScalar;

/// Size of a compressed G1 element.
pub const G1_COMPRESSED_SIZE: usize = 48;
/// Size of a compressed G2 element.
pub const G2_COMPRESSED_SIZE: usize = 96;
/// Size of an uncompressed G1 element.
pub const G1_UNCOMPRESSED_SIZE: usize = 96;
/// Size of an uncompressed G2 element.
pub const G2_UNCOMPRESSED_SIZE: usize = 192;
/// The longest domain separation tag accepted by the Plutus builtin.
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
    /// The encoding is malformed.
    BadEncoding,
    /// The coordinates are not on the curve.
    NotOnCurve,
    /// The point is not in the prime-order subgroup.
    NotInGroup,
    /// The domain separation tag is too long.
    DstTooLong(usize),
}

impl core::fmt::Display for BlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            Self::BadEncoding => f.write_str("malformed BLS12-381 point encoding"),
            Self::NotOnCurve => f.write_str("BLS12-381 point is not on the curve"),
            Self::NotInGroup => f.write_str("BLS12-381 point is not in the subgroup"),
            Self::DstTooLong(n) => {
                write!(f, "domain separation tag is {n} bytes, at most 255 allowed")
            }
        }
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

fn check_dst(dst: &[u8]) -> Result<(), BlsError> {
    if dst.len() <= MAX_DST_SIZE {
        Ok(())
    } else {
        Err(BlsError::DstTooLong(dst.len()))
    }
}

fn map_blst_error(error: BLST_ERROR) -> Result<(), BlsError> {
    match error {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        BLST_ERROR::BLST_BAD_ENCODING => Err(BlsError::BadEncoding),
        BLST_ERROR::BLST_POINT_NOT_ON_CURVE => Err(BlsError::NotOnCurve),
        BLST_ERROR::BLST_POINT_NOT_IN_GROUP => Err(BlsError::NotInGroup),
        _ => Err(BlsError::BadEncoding),
    }
}

/// An integer modulo the BLS12-381 scalar-field order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Scalar(EccScalar);

impl Scalar {
    /// Construct a scalar from a `u64`.
    pub fn from_u64(n: u64) -> Self {
        Self(EccScalar::from_u64(n))
    }

    /// Reduce an arbitrary-length big-endian integer modulo the field order.
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut acc = EccScalar::zero();
        for byte in bytes {
            let mut wide = [0u8; 64];
            wide[62] = 1;
            let radix = EccScalar::init_from_wide_bytes_be(wide);
            wide = [0u8; 64];
            wide[63] = *byte;
            acc = &(&acc * &radix) + &EccScalar::init_from_wide_bytes_be(wide);
        }
        Self(acc)
    }

    /// Reduce a signed big-endian magnitude modulo the field order.
    pub fn from_be_bytes_signed_mod_order(magnitude: &[u8], negative: bool) -> Self {
        let value = Self::from_be_bytes_mod_order(magnitude);
        if negative { Self(-&value.0) } else { value }
    }

    /// Return the canonical big-endian encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes_be()
    }

    /// Whether the scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn as_blst(&self) -> blst_scalar {
        let mut out = blst_scalar::default();
        unsafe { blst_scalar_from_bendian(&mut out, self.to_bytes().as_ptr()) };
        out
    }
}

/// An element of BLS12-381 G1.
#[derive(Clone, Debug)]
pub struct G1(blst_p1);

/// An element of BLS12-381 G2.
#[derive(Clone, Debug)]
pub struct G2(blst_p2);

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_p1_is_equal(&self.0, &other.0) }
    }
}
impl Eq for G1 {}
impl PartialEq for G2 {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_p2_is_equal(&self.0, &other.0) }
    }
}
impl Eq for G2 {}

impl G1 {
    /// The identity element.
    pub fn zero() -> Self {
        Self::generator().scalar_mul(&Scalar::from_u64(0))
    }

    /// The standard generator.
    pub fn generator() -> Self {
        Self(unsafe { *blst_p1_generator() })
    }

    /// Whether this is the identity.
    pub fn is_zero(&self) -> bool {
        unsafe { blst_p1_is_inf(&self.0) }
    }

    /// Add two points.
    pub fn add(&self, other: &Self) -> Self {
        let mut out = blst_p1::default();
        unsafe { blst_p1_add_or_double(&mut out, &self.0, &other.0) };
        Self(out)
    }

    /// Negate this point.
    pub fn neg(&self) -> Self {
        let mut out = self.clone();
        unsafe { blst_p1_cneg(&mut out.0, true) };
        out
    }

    /// Multiply by a scalar reduced modulo the group order.
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        let scalar = scalar.as_blst();
        let mut out = blst_p1::default();
        unsafe { blst_p1_mult(&mut out, &self.0, scalar.b.as_ptr(), 256) };
        Self(out)
    }

    /// Hash a message to G1 using the Plutus/RFC 9380 suite.
    pub fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self, BlsError> {
        check_dst(dst)?;
        let mut out = blst_p1::default();
        unsafe {
            blst_hash_to_g1(
                &mut out,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            )
        };
        Ok(Self(out))
    }

    /// Return the 48-byte compressed encoding.
    pub fn compress(&self) -> [u8; G1_COMPRESSED_SIZE] {
        let mut out = [0u8; G1_COMPRESSED_SIZE];
        unsafe { blst_p1_compress(out.as_mut_ptr(), &self.0) };
        out
    }

    /// Parse a compressed point and require subgroup membership.
    pub fn uncompress(bytes: &[u8]) -> Result<Self, BlsError> {
        check_length(bytes, G1_COMPRESSED_SIZE)?;
        let mut affine = blst_p1_affine::default();
        map_blst_error(unsafe { blst_p1_uncompress(&mut affine, bytes.as_ptr()) })?;
        if !unsafe { blst_p1_affine_in_g1(&affine) } {
            return Err(BlsError::NotInGroup);
        }
        let mut out = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut out, &affine) };
        Ok(Self(out))
    }

    /// Return the 96-byte uncompressed encoding.
    pub fn serialize(&self) -> [u8; G1_UNCOMPRESSED_SIZE] {
        let mut out = [0u8; G1_UNCOMPRESSED_SIZE];
        unsafe { blst_p1_serialize(out.as_mut_ptr(), &self.0) };
        out
    }

    /// Parse an uncompressed point and require subgroup membership.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, BlsError> {
        check_length(bytes, G1_UNCOMPRESSED_SIZE)?;
        let mut affine = blst_p1_affine::default();
        map_blst_error(unsafe { blst_p1_deserialize(&mut affine, bytes.as_ptr()) })?;
        if !unsafe { blst_p1_affine_in_g1(&affine) } {
            return Err(BlsError::NotInGroup);
        }
        let mut out = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut out, &affine) };
        Ok(Self(out))
    }
}

impl G2 {
    /// The identity element.
    pub fn zero() -> Self {
        Self::generator().scalar_mul(&Scalar::from_u64(0))
    }

    /// The standard generator.
    pub fn generator() -> Self {
        Self(unsafe { *blst_p2_generator() })
    }

    /// Whether this is the identity.
    pub fn is_zero(&self) -> bool {
        unsafe { blst_p2_is_inf(&self.0) }
    }

    /// Add two points.
    pub fn add(&self, other: &Self) -> Self {
        let mut out = blst_p2::default();
        unsafe { blst_p2_add_or_double(&mut out, &self.0, &other.0) };
        Self(out)
    }

    /// Negate this point.
    pub fn neg(&self) -> Self {
        let mut out = self.clone();
        unsafe { blst_p2_cneg(&mut out.0, true) };
        out
    }

    /// Multiply by a scalar reduced modulo the group order.
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        let scalar = scalar.as_blst();
        let mut out = blst_p2::default();
        unsafe { blst_p2_mult(&mut out, &self.0, scalar.b.as_ptr(), 256) };
        Self(out)
    }

    /// Hash a message to G2 using the Plutus/RFC 9380 suite.
    pub fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self, BlsError> {
        check_dst(dst)?;
        let mut out = blst_p2::default();
        unsafe {
            blst_hash_to_g2(
                &mut out,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            )
        };
        Ok(Self(out))
    }

    /// Return the 96-byte compressed encoding.
    pub fn compress(&self) -> [u8; G2_COMPRESSED_SIZE] {
        let mut out = [0u8; G2_COMPRESSED_SIZE];
        unsafe { blst_p2_compress(out.as_mut_ptr(), &self.0) };
        out
    }

    /// Parse a compressed point and require subgroup membership.
    pub fn uncompress(bytes: &[u8]) -> Result<Self, BlsError> {
        check_length(bytes, G2_COMPRESSED_SIZE)?;
        let mut affine = blst_p2_affine::default();
        map_blst_error(unsafe { blst_p2_uncompress(&mut affine, bytes.as_ptr()) })?;
        if !unsafe { blst_p2_affine_in_g2(&affine) } {
            return Err(BlsError::NotInGroup);
        }
        let mut out = blst_p2::default();
        unsafe { blst_p2_from_affine(&mut out, &affine) };
        Ok(Self(out))
    }

    /// Return the 192-byte uncompressed encoding.
    pub fn serialize(&self) -> [u8; G2_UNCOMPRESSED_SIZE] {
        let mut out = [0u8; G2_UNCOMPRESSED_SIZE];
        unsafe { blst_p2_serialize(out.as_mut_ptr(), &self.0) };
        out
    }

    /// Parse an uncompressed point and require subgroup membership.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, BlsError> {
        check_length(bytes, G2_UNCOMPRESSED_SIZE)?;
        let mut affine = blst_p2_affine::default();
        map_blst_error(unsafe { blst_p2_deserialize(&mut affine, bytes.as_ptr()) })?;
        if !unsafe { blst_p2_affine_in_g2(&affine) } {
            return Err(BlsError::NotInGroup);
        }
        let mut out = blst_p2::default();
        unsafe { blst_p2_from_affine(&mut out, &affine) };
        Ok(Self(out))
    }
}

/// A Miller-loop result, before final exponentiation.
#[derive(Clone, Debug)]
pub struct MlResult(blst_fp12);

impl PartialEq for MlResult {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_fp12_is_equal(&self.0, &other.0) }
    }
}
impl Eq for MlResult {}

impl MlResult {
    /// Multiply two Miller-loop results.
    pub fn mul(&self, other: &Self) -> Self {
        let mut out = core::mem::MaybeUninit::<blst_fp12>::uninit();
        unsafe {
            blst_fp12_mul(out.as_mut_ptr(), &self.0, &other.0);
            Self(out.assume_init())
        }
    }

    /// Compare two results after final exponentiation.
    pub fn final_verify(&self, other: &Self) -> bool {
        unsafe { blst_fp12_finalverify(&self.0, &other.0) }
    }
}

/// Run the optimal Ate Miller loop.
pub fn miller_loop(p: &G1, q: &G2) -> MlResult {
    let mut p_affine = blst_p1_affine::default();
    let mut q_affine = blst_p2_affine::default();
    let mut out = core::mem::MaybeUninit::<blst_fp12>::uninit();
    unsafe {
        blst_p1_to_affine(&mut p_affine, &p.0);
        blst_p2_to_affine(&mut q_affine, &q.0);
        blst_miller_loop(out.as_mut_ptr(), &q_affine, &p_affine);
        MlResult(out.assume_init())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plutus::bls12_381::parity_rust_backend as rust;

    #[test]
    fn native_and_rust_backends_are_byte_exact() {
        let magnitudes: [&[u8]; 6] = [&[], &[0], &[1], &[0xff; 32], &[0x5a; 48], &[0xa5; 97]];

        for magnitude in magnitudes {
            for negative in [false, true] {
                let native = Scalar::from_be_bytes_signed_mod_order(magnitude, negative);
                let pure = rust::Scalar::from_be_bytes_signed_mod_order(magnitude, negative);
                assert_eq!(native.to_bytes(), pure.to_bytes());

                let n1 = G1::generator().scalar_mul(&native);
                let r1 = rust::G1::generator().scalar_mul(&pure);
                assert_eq!(n1.compress(), r1.compress());
                assert_eq!(n1.serialize(), r1.serialize());

                let n2 = G2::generator().scalar_mul(&native);
                let r2 = rust::G2::generator().scalar_mul(&pure);
                assert_eq!(n2.compress(), r2.compress());
                assert_eq!(n2.serialize(), r2.serialize());
            }
        }

        for (message, dst) in [
            (&b""[..], &b"dst"[..]),
            (&b"abc"[..], &b"BLS12381 parity"[..]),
            (&b"a longer message with a zero\0byte"[..], &[0x42; 255][..]),
        ] {
            assert_eq!(
                G1::hash_to_group(message, dst).unwrap().compress(),
                rust::G1::hash_to_group(message, dst).unwrap().compress(),
            );
            assert_eq!(
                G2::hash_to_group(message, dst).unwrap().compress(),
                rust::G2::hash_to_group(message, dst).unwrap().compress(),
            );
        }
    }

    #[test]
    fn native_and_rust_backends_report_the_same_failures() {
        fn native_g1(bytes: &[u8]) -> String {
            format!("{:?}", G1::uncompress(bytes).unwrap_err())
        }
        fn pure_g1(bytes: &[u8]) -> String {
            format!("{:?}", rust::G1::uncompress(bytes).unwrap_err())
        }

        let mut bad_infinity = G1::zero().compress();
        bad_infinity[47] = 1;
        let mut missing_compression = G1::generator().compress();
        missing_compression[0] &= 0x7f;
        let mut off_curve = [0u8; 48];
        off_curve[0] = 0x80;
        off_curve[47] = 1;

        for bytes in [
            &bad_infinity[..],
            &missing_compression[..],
            &off_curve[..],
            &[0u8; 47][..],
        ] {
            assert_eq!(native_g1(bytes), pure_g1(bytes));
        }

        let dst = [0u8; 256];
        assert_eq!(
            format!("{:?}", G2::hash_to_group(b"m", &dst).unwrap_err()),
            format!("{:?}", rust::G2::hash_to_group(b"m", &dst).unwrap_err()),
        );
    }

    #[test]
    fn native_and_rust_pairing_decisions_match() {
        for (a, b) in [(0, 0), (1, 1), (3, 5), (42, 43)] {
            let native_lhs = miller_loop(
                &G1::generator().scalar_mul(&Scalar::from_u64(a)),
                &G2::generator(),
            );
            let native_rhs = miller_loop(
                &G1::generator(),
                &G2::generator().scalar_mul(&Scalar::from_u64(b)),
            );
            let pure_lhs = rust::miller_loop(
                &rust::G1::generator().scalar_mul(&rust::Scalar::from_u64(a)),
                &rust::G2::generator(),
            );
            let pure_rhs = rust::miller_loop(
                &rust::G1::generator(),
                &rust::G2::generator().scalar_mul(&rust::Scalar::from_u64(b)),
            );
            assert_eq!(
                native_lhs.final_verify(&native_rhs),
                pure_lhs.final_verify(&pure_rhs)
            );
        }
    }
}

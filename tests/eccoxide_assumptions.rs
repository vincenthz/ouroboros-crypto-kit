//! Properties of `eccoxide` that this crate relies on.
//!
//! The point addition used throughout — for cofactor clearing, subgroup checks,
//! double-and-add over arbitrary-size scalars, and ECDSA's `u1*G + u2*Q` — is
//! `eccoxide`'s `+` operator on projective points. For `a = 0` curves that is
//! the Renes-Costello-Batina complete formula, so it is also correct when the
//! two points are equal, when one is the point at infinity, and when they are
//! each other's negation. Nothing in the API promises that, so it is pinned
//! here: if a future version swapped in an incomplete formula, several functions
//! in this crate would silently produce wrong results, and this test is what
//! would catch it.

use eccoxide::curve::group::CurveGroup;

#[test]
fn point_addition_is_complete() {
    use eccoxide::curve::bls12_381::{g1, g2, Scalar};

    let p = g1::Point::mul_base(&Scalar::from_u64(7));
    assert_eq!(&p + &p, p.double(), "g1: P+P != 2P");
    assert_eq!(&g1::Point::INFINITY + &p, p, "g1: O+P != P");
    assert_eq!(&p + &g1::Point::INFINITY, p, "g1: P+O != P");
    assert_eq!(&p + &(-&p), g1::Point::INFINITY, "g1: P+(-P) != O");
    assert!(
        (&p + &(-&p)).to_affine().is_none(),
        "g1: P-P does not report as infinity"
    );

    let q = g2::Point::mul_base(&Scalar::from_u64(9));
    assert_eq!(&q + &q, q.double(), "g2: Q+Q != 2Q");
    assert_eq!(&g2::Point::INFINITY + &q, q, "g2: O+Q != Q");
    assert_eq!(&q + &(-&q), g2::Point::INFINITY, "g2: Q+(-Q) != O");

    use eccoxide::curve::sec2::p256k1;
    let r = p256k1::Point::mul_base(&p256k1::Scalar::from_u64(5));
    assert_eq!(&r + &r, r.double(), "p256k1: R+R != 2R");
    assert_eq!(&p256k1::Point::INFINITY + &r, r, "p256k1: O+R != R");
    assert_eq!(&r + &(-&r), p256k1::Point::INFINITY, "p256k1: R+(-R) != O");
}

/// Edwards25519 addition is complete by construction (`a = -1` twisted
/// Edwards), which the VRF relies on when it adds `s*B` to `-c*Y`.
#[test]
fn edwards_addition_is_complete() {
    use eccoxide::curve::curve25519::{Point, Scalar};

    let p = Point::mul_base(&Scalar::from_u64(7));
    assert!(&p + &p == p.double(), "P+P != 2P");
    assert!(&Point::IDENTITY + &p == p, "O+P != P");
    assert!(&p + &(-&p) == Point::IDENTITY, "P+(-P) != O");
}

/// The wide scalar constructors reduce rather than truncate, which is what makes
/// `sc25519_reduce` and Plutus's `scalarMul` faithful.
#[test]
fn wide_scalar_constructors_reduce() {
    use eccoxide::curve::curve25519::Scalar;

    // l, little-endian, in a 64-byte buffer must reduce to zero
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ]);
    assert!(Scalar::init_from_wide_bytes_le(wide).is_zero());
}

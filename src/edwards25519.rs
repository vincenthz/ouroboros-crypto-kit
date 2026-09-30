//! Low-level edwards25519 primitives, byte-for-byte compatible with `ref10`.
//!
//! Everything here mirrors a specific function of the `ed25519_ref10` code that
//! `cardano-crypto-praos` vendors from libsodium (the names are given in the
//! documentation of each item), because the encodings and the acceptance
//! criteria of that code are consensus-relevant:
//!
//! * point decoding ignores the top bit of the y coordinate and reduces it mod
//!   p, so *non-canonical* encodings decode successfully, callers that must
//!   reject them do so explicitly with [`point_is_canonical`];
//! * the two Elligator2 variants differ in how they pick the sign of the
//!   resulting point: [`elligator2_from_uniform`] (`ge25519_from_uniform`,
//!   used by VRF draft-03) takes it from the input, [`elligator2_from_hash`]
//!   (`ge25519_from_hash`, used by VRF draft-13) derives it from the
//!   quadratic character of the Montgomery curve equation.
//!
//! The arithmetic itself comes from dependency; this module only fixes the
//! encodings, the sign conventions and the exceptional cases.

use eccoxide::curve::curve25519::{FieldElement, Point, Scalar};
use eccoxide::curve::field::Sign;

/// Size of a compressed point, and of a scalar.
pub const POINT_SIZE: usize = 32;
/// Size of a scalar.
pub const SCALAR_SIZE: usize = 32;

/// A = 486662, the Montgomery curve coefficient of curve25519.
fn montgomery_a() -> FieldElement {
    FieldElement::from_u64(486662)
}

/// `ed25519_sqrtam2` = sqrt(-486664).
///
/// Note that this is the *negative* of the square root eccoxide uses
/// internally for its own Montgomery/Edwards map, and the sign is
/// observable in the output of [`elligator2_from_hash`], so the constant is
/// spelled out here with libsodium's choice of root.
const SQRT_AM2_BE: [u8; 32] = [
    0x0f, 0x26, 0xed, 0xf4, 0x60, 0xa0, 0x06, 0xbb, 0xd2, 0x7b, 0x08, 0xdc, 0x03, 0xfc, 0x4f, 0x7e,
    0xc5, 0xa1, 0xd3, 0xd1, 0x4b, 0x7d, 0x1a, 0x82, 0xcc, 0x6e, 0x04, 0xaa, 0xff, 0x45, 0x7e, 0x06,
];

fn sqrt_am2() -> FieldElement {
    FieldElement::from_bytes_be(&SQRT_AM2_BE).expect("sqrt(-486664) is a valid field element")
}

/// Multiplicative inverse, returning zero for zero.
///
/// `fe25519_invert` computes `x^(p-2)`, which is 0 for x = 0; eccoxide's
/// `inverse` panics instead, so the exceptional cases of the maps below (all
/// unreachable for honest inputs, but reachable for chosen ones) would abort.
fn invert_or_zero(x: &FieldElement) -> FieldElement {
    if x.is_zero() {
        FieldElement::zero()
    } else {
        x.inverse()
    }
}

/// `fe25519_isnegative`: the least significant bit of the canonical encoding.
///
/// Taken from the encoding rather than from eccoxide's `sign`, which reads the
/// parity of a representation that is not always reduced: a zero obtained by
/// negation reports itself negative.
fn fe_is_negative(x: &FieldElement) -> bool {
    x.to_bytes_le()[0] & 1 == 1
}

fn sign_of_bit(bit: bool) -> Sign {
    if bit { Sign::Negative } else { Sign::Positive }
}

/// `fe25519_frombytes`: read a field element from 32 little-endian bytes,
/// ignoring the most significant bit and reducing modulo p.
///
/// Values in `[p, 2^255)` are therefore accepted (and reduced) rather than
/// rejected, which is what makes non-canonical point encodings decodable.
pub fn fe_from_bytes(bytes: &[u8; 32]) -> FieldElement {
    let mut b = *bytes;
    b[31] &= 0x7f;
    if let Some(fe) = FieldElement::from_bytes_le(&b) {
        return fe;
    }
    // b is in [p, 2^255), so b - p = b + 19 - 2^255: add 19 and drop the carry
    // out of bit 254.
    let mut carry = 19u16;
    for x in b.iter_mut() {
        let v = u16::from(*x) + carry;
        *x = v as u8;
        carry = v >> 8;
    }
    b[31] &= 0x7f;
    FieldElement::from_bytes_le(&b).expect("b - p < p")
}

/// `fe25519_tobytes`: canonical little-endian encoding.
pub fn fe_to_bytes(fe: &FieldElement) -> [u8; 32] {
    fe.to_bytes_le()
}

/// `fe25519_notsquare`: true when `x` is not a square modulo p.
///
/// Zero is reported as a square, matching the Jacobi-symbol based
/// implementation of `ref10`.
pub fn fe_is_not_square(x: &FieldElement) -> bool {
    x.sqrt().into_option().is_none()
}

/// `ge25519_p3_tobytes`: compress a point to 32 bytes (little-endian y, with
/// the sign of x in the top bit).
pub fn point_encode(p: &Point) -> [u8; POINT_SIZE] {
    let (x, y) = p.to_affine();
    let mut out = y.to_bytes_le();
    if fe_is_negative(&x) {
        out[31] |= 0x80;
    }
    out
}

/// `ge25519_frombytes`: decompress a point.
///
/// Returns `None` when the y coordinate does not belong to any curve point.
/// Non-canonical encodings (y >= p) are accepted, exactly like `ref10`; use
/// [`point_is_canonical`] first where the reference implementation does.
pub fn point_decode(bytes: &[u8; POINT_SIZE]) -> Option<Point> {
    let y = fe_from_bytes(bytes);
    Point::decompress(&y, sign_of_bit(bytes[31] >> 7 == 1))
}

/// `ge25519_is_canonical`: true when the encoded y coordinate is reduced mod p.
///
/// The sign bit is not part of the test.
pub fn point_is_canonical(s: &[u8; POINT_SIZE]) -> bool {
    let mut c = (s[31] & 0x7f) ^ 0x7f;
    for i in (1..31).rev() {
        c |= s[i] ^ 0xff;
    }
    let c = (u32::from(c).wrapping_sub(1)) >> 8;
    let d = (0xedu32.wrapping_sub(1).wrapping_sub(u32::from(s[0]))) >> 8;
    (1 - (c & d & 1)) == 1
}

/// The 7 encodings of small-order points, from `ge25519_has_small_order`.
const SMALL_ORDER_BLACKLIST: [[u8; 32]; 7] = [
    // 0 (order 4)
    [0; 32],
    // 1 (order 1)
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    // order 8
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // order 8
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // p-1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p (= 0, order 4)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p+1 (= 1, order 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// `ge25519_has_small_order`: true when the encoding is one of the points of
/// order 1, 2, 4 or 8 (the test is on the encoding, so the sign bit is
/// ignored).
pub fn point_has_small_order(s: &[u8; POINT_SIZE]) -> bool {
    let mut c = [0u8; 7];
    for j in 0..31 {
        for (i, entry) in SMALL_ORDER_BLACKLIST.iter().enumerate() {
            c[i] |= s[j] ^ entry[j];
        }
    }
    for (i, entry) in SMALL_ORDER_BLACKLIST.iter().enumerate() {
        c[i] |= (s[31] & 0x7f) ^ entry[31];
    }
    let mut k = 0u32;
    for ci in c.iter() {
        k |= u32::from(*ci).wrapping_sub(1);
    }
    ((k >> 8) & 1) == 1
}

/// `sc25519_is_canonical`: true when the scalar encoding is reduced mod l.
pub fn scalar_is_canonical(s: &[u8; SCALAR_SIZE]) -> bool {
    // l = 2^252 + 27742317777372353535851937790883648493, little-endian
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut c = 0u8;
    let mut n = 1u8;
    for i in (0..32).rev() {
        c |= (((u32::from(s[i]).wrapping_sub(u32::from(L[i]))) >> 8) as u8) & n;
        n &= (((u32::from(s[i] ^ L[i])).wrapping_sub(1)) >> 8) as u8;
    }
    c != 0
}

/// `ge25519_clear_cofactor`: multiply by 8.
pub fn clear_cofactor(p: &Point) -> Point {
    p.double().double().double()
}

/// `sc25519_reduce`: reduce a 64-byte little-endian integer modulo l.
pub fn scalar_reduce_wide(bytes: &[u8; 64]) -> Scalar {
    Scalar::init_from_wide_bytes_le(*bytes)
}

/// Reduce a 32-byte little-endian integer modulo l.
pub fn scalar_reduce(bytes: &[u8; SCALAR_SIZE]) -> Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes);
    scalar_reduce_wide(&wide)
}

/// Read a scalar from its canonical little-endian encoding, or fail.
pub fn scalar_from_canonical_bytes(bytes: &[u8; SCALAR_SIZE]) -> Option<Scalar> {
    Scalar::from_bytes_le(bytes)
}

/// Canonical little-endian encoding of a scalar.
pub fn scalar_to_bytes(s: &Scalar) -> [u8; SCALAR_SIZE] {
    s.to_bytes_le()
}

/// The clamped secret scalar of an Ed25519 (or VRF) secret key: SHA-512 of the
/// seed, with the low 3 bits of the first byte and the top bit of the last byte
/// cleared, and bit 254 set.
///
/// Returns the scalar and the second half of the hash, which Ed25519 uses as
/// the nonce prefix and the VRF as `truncated_hashed_sk_string`.
pub fn expand_seed(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h = crate::hash::sha512(seed);
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&h[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    // The clamped value is < 2^255 and is used as a scalar; reducing it mod l
    // changes nothing for scalar multiplication of prime-order points nor for
    // the mod-l arithmetic `sc25519_muladd` performs.
    (scalar_reduce(&clamped), prefix)
}

/// Elligator2 as `ge25519_elligator2`: map a field element to a Montgomery
/// point, returning `(u, v, is_not_square)`.
///
/// `u = -A/(1+2r^2)` when `u^3 + A u^2 + u` is a square, and `u = -u - A`
/// otherwise; `v` is the (arbitrary sign) square root of the curve equation at
/// `u`, the caller fixes the sign.
fn elligator2(r: &FieldElement) -> (FieldElement, FieldElement, bool) {
    let a = montgomery_a();
    let one = FieldElement::one();

    // rr2 = 1/(2r^2 + 1)
    let rr2 = invert_or_zero(&(&r.square().double() + &one));
    let x1 = -&(&a * &rr2);

    let x2 = x1.square();
    let x3 = &x1 * &x2;
    // gx1 = x1^3 + A*x1^2 + x1
    let gx1 = &(&x3 + &x1) + &(&x2 * &a);

    let not_square = fe_is_not_square(&gx1);
    let x = if not_square { &(-&x1) - &a } else { x1 };

    // recover v = sqrt(x^3 + A x^2 + x); such a root always exists for the
    // selected x, so this cannot fail
    let xx = x.square();
    let gx = &(&(&xx * &x) + &x) + &(&xx * &a);
    let y = gx
        .sqrt()
        .into_option()
        .expect("elligator2: x is on the curve");

    (x, y, not_square)
}

/// `ge25519_mont_to_ed`: the birational map from the Montgomery curve to
/// edwards25519, `(u, v) -> (sqrt(-A-2)*u/v, (u-1)/(u+1))`.
fn mont_to_ed(u: &FieldElement, v: &FieldElement) -> (FieldElement, FieldElement) {
    let one = FieldElement::one();
    let u_plus_one = u + &one;
    let u_minus_one = u - &one;

    let inv = invert_or_zero(&(&u_plus_one * v));
    // xed = sqrt(-A-2) * u / v = sqrt(-A-2) * u * (u+1) / ((u+1) * v)
    let xed = &(&(&sqrt_am2() * u) * &inv) * &u_plus_one;
    // yed = (u-1)/(u+1) = (u-1) * v / ((u+1) * v), and 1 when the inverse
    // does not exist
    let yed = if inv.is_zero() {
        one
    } else {
        &(&inv * v) * &u_minus_one
    };
    (xed, yed)
}

/// `ge25519_from_uniform`: the Elligator2 map used by VRF draft-03.
///
/// The sign of the resulting x coordinate is taken from the top bit of the
/// input (VRF draft-03 always clears it before calling this), and the result is
/// multiplied by the cofactor.
pub fn elligator2_from_uniform(r: &[u8; 32]) -> Point {
    let x_sign = r[31] >> 7 == 1;
    let r_fe = fe_from_bytes(r);
    let (u, v, _) = elligator2(&r_fe);
    let (xed, yed) = mont_to_ed(&u, &v);
    let xed = if fe_is_negative(&xed) != x_sign {
        -&xed
    } else {
        xed
    };
    let p = Point::from_coordinate(&xed, &yed).expect("elligator2 output is on the curve");
    clear_cofactor(&p)
}

/// `ge25519_from_hash`: the Elligator2 map of RFC 9380 (as libsodium
/// implements it), used by VRF draft-13.
///
/// `h` is a 64-byte little-endian integer, reduced mod p; the sign of the
/// Montgomery v coordinate is the complement of the quadratic character
/// computed by the map, and the result is multiplied by the cofactor.
pub fn elligator2_from_hash(h: &[u8; 64]) -> Point {
    let r_fe = fe_reduce64(h);
    let (u, v, not_square) = elligator2(&r_fe);
    let y_sign = !not_square;
    let v = if fe_is_negative(&v) != y_sign { -&v } else { v };
    let (xed, yed) = mont_to_ed(&u, &v);
    let p = Point::from_coordinate(&xed, &yed).expect("elligator2 output is on the curve");
    clear_cofactor(&p)
}

/// `fe25519_reduce64`: reduce a 64-byte little-endian integer modulo p.
fn fe_reduce64(h: &[u8; 64]) -> FieldElement {
    let mut wide = [0u8; 64];
    wide.copy_from_slice(h);
    FieldElement::init_from_wide_bytes_le(wide)
}

/// `crypto_core_ed25519_from_string` with SHA-512: hash `msg` to a point of the
/// prime-order subgroup, in the non-uniform (single field element) variant of
/// RFC 9380.
pub fn hash_to_point_sha512(dst: &[u8], msg: &[u8]) -> Point {
    // L = 48 bytes of uniform output, read as a big-endian integer, which
    // `ge25519_from_hash` then reduces mod p from a little-endian buffer
    let be = crate::hash::expand_message_xmd_sha512(dst, msg, 48);
    let mut le = [0u8; 64];
    for (i, b) in be.iter().enumerate() {
        le[47 - i] = *b;
    }
    elligator2_from_hash(&le)
}

/// `a * A + b * B` where `B` is the generator, as
/// `ge25519_double_scalarmult_vartime`.
pub fn double_scalarmult_base(a: &Scalar, big_a: &Point, b: &Scalar) -> Point {
    &big_a.scale(a) + &Point::mul_base(b)
}

/// `a * A + b * C`, as `ge25519_double_scalarmult_vartime_variable`.
pub fn double_scalarmult(a: &Scalar, big_a: &Point, b: &Scalar, big_c: &Point) -> Point {
    &big_a.scale(a) + &big_c.scale(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{hex_array, to_hex};

    #[test]
    fn canonical_point_encodings() {
        // p-1 is canonical, p and p+1 are not
        let mut p_minus_1 = [0xffu8; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        assert!(point_is_canonical(&p_minus_1));

        let mut p = p_minus_1;
        p[0] = 0xed;
        assert!(!point_is_canonical(&p));

        let mut p_plus_1 = p_minus_1;
        p_plus_1[0] = 0xee;
        assert!(!point_is_canonical(&p_plus_1));

        // the sign bit is not part of the test
        let mut signed = p_minus_1;
        signed[31] |= 0x80;
        assert!(point_is_canonical(&signed));

        // the generator is canonical
        assert!(point_is_canonical(&point_encode(&Point::GENERATOR)));
    }

    #[test]
    fn small_order_detection() {
        for entry in SMALL_ORDER_BLACKLIST.iter() {
            assert!(point_has_small_order(entry));
            let mut with_sign = *entry;
            with_sign[31] |= 0x80;
            assert!(point_has_small_order(&with_sign));
        }
        assert!(!point_has_small_order(&point_encode(&Point::GENERATOR)));
    }

    #[test]
    fn canonical_scalars() {
        // l itself is not canonical, l-1 is
        let mut l =
            hex_array::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        assert!(!scalar_is_canonical(&l));
        l[0] -= 1;
        assert!(scalar_is_canonical(&l));
        assert!(scalar_is_canonical(&[0u8; 32]));
        assert!(!scalar_is_canonical(&[0xffu8; 32]));
    }

    #[test]
    fn point_roundtrip() {
        let p = Point::mul_base(&scalar_reduce(&[7u8; 32]));
        let bytes = point_encode(&p);
        let q = point_decode(&bytes).expect("valid point");
        assert!(p == q);
        assert_eq!(point_encode(&q), bytes);
    }

    #[test]
    fn non_canonical_point_decodes_like_ref10() {
        // y = p + 1 decodes to the same point as y = 1 (the identity), which is
        // exactly why the VRF code has to check canonicity separately.
        let p_plus_1 =
            hex_array::<32>("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let one =
            hex_array::<32>("0100000000000000000000000000000000000000000000000000000000000000");
        let a = point_decode(&p_plus_1).expect("decodes");
        let b = point_decode(&one).expect("decodes");
        assert!(a == b);
        assert!(!point_is_canonical(&p_plus_1));
    }

    #[test]
    fn expand_message_xmd_rfc9380_vectors() {
        // RFC 9380 appendix K.3: expand_message_xmd(SHA-512), DST =
        // "QUUX-V01-CS02-with-expander-SHA512-256"
        use crate::hash::expand_message_xmd_sha512;
        let dst = b"QUUX-V01-CS02-with-expander-SHA512-256";

        let out = expand_message_xmd_sha512(dst, b"", 0x20);
        assert_eq!(
            to_hex(&out),
            "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba"
        );
        let out = expand_message_xmd_sha512(dst, b"abc", 0x20);
        assert_eq!(
            to_hex(&out),
            "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc"
        );
        let out = expand_message_xmd_sha512(dst, b"abcdef0123456789", 0x20);
        assert_eq!(
            to_hex(&out),
            "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58"
        );

        // len_in_bytes = 0x80 exercises the multi-block output path
        let out = expand_message_xmd_sha512(dst, b"", 0x80);
        assert_eq!(
            to_hex(&out),
            "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921\
             b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e\
             0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7e\
             b00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961"
        );
        let out = expand_message_xmd_sha512(dst, b"abc", 0x80);
        assert_eq!(
            to_hex(&out),
            "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11\
             bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb134\
             7ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b48843\
             1851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1"
        );
    }
}

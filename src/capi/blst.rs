//! The blst API `cardano-crypto-class` uses for BLS12-381 (CIP-0381).
//!
//! # Representation
//!
//! blst's structs are byte buffers to everyone but blst, and the same is true
//! here; what matters is that the sizes match, which the header asserts. A
//! `blst_p1`/`blst_p2` holds the projective point exactly
//! represents it, so that arithmetic costs no conversion, while a
//! `blst_p1_affine`/`blst_p2_affine` holds canonical big-endian coordinates
//! with all-zero meaning the point at infinity — blst's own convention, and
//! necessary because an affine point cannot be the identity.
//!
//! A `blst_scalar` is 32 bytes little-endian, as blst's is, and a `blst_fr`
//! holds the same value reduced modulo `r`; `blst_fp12` holds an
//! [`MlResult`].
//!
//! # Where this differs from blst
//!
//! * `blst_p1s_mult_pippenger` is a plain sum of scalar multiplications rather
//!   than Pippenger's algorithm; the scratch space is therefore unused, and
//!   `..._scratch_sizeof` returns a size the caller can allocate but that
//!   nothing reads. The result is the same, the cost for many points is higher.
//! * `blst_hash_to_g1`/`_g2` are given at most a 255-byte domain separation
//!   tag, which is all CIP-0381 allows and all `plutus-core` will pass; a
//!   longer one yields the point at infinity rather than the RFC 9380
//!   `H2C-OVERSIZE-DST-` behaviour, since these functions cannot report an
//!   error.
//! * `blst_fp12` values are the fixed power of the pairing that
//!   [`crate::plutus::bls12_381`] computes; see that module for why multiplying
//!   and comparing them is unaffected.

use core::ffi::c_int;
use core::mem::{needs_drop, size_of};

use eccoxide::curve::bls12_381::{Fp, Fp2, g1, g2};

use crate::hash::sha256;
use crate::plutus::bls12_381::{
    G1, G2, MlResult, Scalar, g1_in_subgroup, g2_in_subgroup, miller_loop,
};

const P1_SIZE: usize = 144;
const P2_SIZE: usize = 288;
const AFFINE1_SIZE: usize = 96;
const AFFINE2_SIZE: usize = 192;
const FP12_SIZE: usize = 576;
const SCALAR_SIZE: usize = 32;

// The C structs are exactly as large as the values kept in them, and those
// values are plain data: moving one in or out of a caller-owned buffer is a
// copy, with nothing to run on drop.
const _: () = assert!(size_of::<g1::Point>() == P1_SIZE);
const _: () = assert!(size_of::<g2::Point>() == P2_SIZE);
const _: () = assert!(size_of::<MlResult>() == FP12_SIZE);
const _: () = assert!(!needs_drop::<g1::Point>());
const _: () = assert!(!needs_drop::<g2::Point>());
const _: () = assert!(!needs_drop::<MlResult>());

/* ---------------------------------------------------------------- */
/* Moving values in and out of the caller's buffers                 */
/* ---------------------------------------------------------------- */

// The buffers come from Haskell and are only guaranteed to be word aligned, so
// every access is unaligned.

unsafe fn read_p1(p: *const u8) -> g1::Point {
    unsafe { (p as *const g1::Point).read_unaligned() }
}

unsafe fn write_p1(p: *mut u8, value: &g1::Point) {
    unsafe { (p as *mut g1::Point).write_unaligned(value.clone()) }
}

unsafe fn read_p2(p: *const u8) -> g2::Point {
    unsafe { (p as *const g2::Point).read_unaligned() }
}

unsafe fn write_p2(p: *mut u8, value: &g2::Point) {
    unsafe { (p as *mut g2::Point).write_unaligned(value.clone()) }
}

unsafe fn read_fp12(p: *const u8) -> MlResult {
    unsafe { (p as *const MlResult).read_unaligned() }
}

unsafe fn write_fp12(p: *mut u8, value: &MlResult) {
    unsafe { (p as *mut MlResult).write_unaligned(value.clone()) }
}

/// Read an affine G1 point. Anything that is not a valid encoding — which the
/// functions that write these buffers never produce — reads back as infinity.
unsafe fn read_affine1(p: *const u8) -> g1::Point {
    unsafe {
        let x: [u8; 48] = super::read_array(p);
        let y: [u8; 48] = super::read_array(p.add(48));
        if is_zero(&x) && is_zero(&y) {
            return g1::Point::INFINITY;
        }
        match (Fp::from_bytes_be(&x), Fp::from_bytes_be(&y)) {
            (Some(x), Some(y)) => match g1::PointAffine::from_coordinate(&x, &y) {
                Some(affine) => g1::Point::from_affine(&affine),
                None => g1::Point::INFINITY,
            },
            _ => g1::Point::INFINITY,
        }
    }
}

unsafe fn write_affine1(p: *mut u8, point: &g1::Point) {
    unsafe {
        match point.to_affine() {
            None => core::ptr::write_bytes(p, 0, AFFINE1_SIZE),
            Some(affine) => {
                let (x, y) = affine.to_coordinate();
                super::write_bytes(p, &x.to_bytes_be());
                super::write_bytes(p.add(48), &y.to_bytes_be());
            }
        }
    }
}

unsafe fn read_affine2(p: *const u8) -> g2::Point {
    unsafe {
        let x0: [u8; 48] = super::read_array(p);
        let x1: [u8; 48] = super::read_array(p.add(48));
        let y0: [u8; 48] = super::read_array(p.add(96));
        let y1: [u8; 48] = super::read_array(p.add(144));
        if is_zero(&x0) && is_zero(&x1) && is_zero(&y0) && is_zero(&y1) {
            return g2::Point::INFINITY;
        }
        let coords = (
            Fp::from_bytes_be(&x0),
            Fp::from_bytes_be(&x1),
            Fp::from_bytes_be(&y0),
            Fp::from_bytes_be(&y1),
        );
        match coords {
            (Some(x0), Some(x1), Some(y0), Some(y1)) => {
                let x = Fp2::new(x0, x1);
                let y = Fp2::new(y0, y1);
                match g2::PointAffine::from_coordinate(&x, &y) {
                    Some(affine) => g2::Point::from_affine(&affine),
                    None => g2::Point::INFINITY,
                }
            }
            _ => g2::Point::INFINITY,
        }
    }
}

unsafe fn write_affine2(p: *mut u8, point: &g2::Point) {
    unsafe {
        match point.to_affine() {
            None => core::ptr::write_bytes(p, 0, AFFINE2_SIZE),
            Some(affine) => {
                let (x, y) = affine.to_coordinate();
                super::write_bytes(p, &x.c0.to_bytes_be());
                super::write_bytes(p.add(48), &x.c1.to_bytes_be());
                super::write_bytes(p.add(96), &y.c0.to_bytes_be());
                super::write_bytes(p.add(144), &y.c1.to_bytes_be());
            }
        }
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

/// The big-endian value of a `blst_scalar`, which stores it little-endian.
unsafe fn scalar_be(p: *const u8) -> [u8; SCALAR_SIZE] {
    unsafe {
        let mut bytes: [u8; SCALAR_SIZE] = super::read_array(p);
        bytes.reverse();
        bytes
    }
}

/// Store a big-endian value as a `blst_scalar`.
unsafe fn write_scalar_be(p: *mut u8, mut be: [u8; SCALAR_SIZE]) {
    unsafe {
        be.reverse();
        super::write_bytes(p, &be);
    }
}

/// The scalar to multiply by: the low `nbits` bits of the stored value, reduced
/// modulo `r`.
unsafe fn mult_scalar(p: *const u8, nbits: usize) -> Scalar {
    unsafe {
        let mut le: [u8; SCALAR_SIZE] = super::read_array(p);
        let nbits = core::cmp::min(nbits, SCALAR_SIZE * 8);
        for (i, byte) in le.iter_mut().enumerate() {
            let low = i * 8;
            if low >= nbits {
                *byte = 0;
            } else if low + 8 > nbits {
                *byte &= (1u16 << (nbits - low)).wrapping_sub(1) as u8;
            }
        }
        le.reverse();
        Scalar::from_be_bytes_mod_order(&le)
    }
}

/* ---------------------------------------------------------------- */
/* Scalars                                                          */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_scalar_from_bendian(out: *mut u8, a: *const u8) {
    unsafe {
        super::write_bytes(out, &{
            let mut bytes: [u8; SCALAR_SIZE] = super::read_array(a);
            bytes.reverse();
            bytes
        });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_bendian_from_scalar(out: *mut u8, a: *const u8) {
    unsafe {
        super::write_bytes(out, &scalar_be(a));
    }
}

/// Reduce a big-endian integer of any length modulo `r`; false when the result
/// is zero, which is what blst reports.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_scalar_from_be_bytes(
    out: *mut u8,
    input: *const u8,
    len: usize,
) -> bool {
    unsafe {
        let scalar = Scalar::from_be_bytes_mod_order(super::as_slice(input, len));
        write_scalar_be(out, scalar.to_bytes());
        !scalar.is_zero()
    }
}

/// Whether the scalar is below `r`: reduction leaves a canonical value alone.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_scalar_fr_check(a: *const u8) -> bool {
    unsafe {
        let be = scalar_be(a);
        Scalar::from_be_bytes_mod_order(&be).to_bytes() == be
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_fr_from_scalar(out: *mut u8, a: *const u8) {
    unsafe {
        // blst's conversion into Montgomery form reduces modulo r; an `Fr` here is
        // the reduced value.
        let scalar = Scalar::from_be_bytes_mod_order(&scalar_be(a));
        write_scalar_be(out, scalar.to_bytes());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_scalar_from_fr(out: *mut u8, a: *const u8) {
    unsafe {
        super::write_bytes(out, &super::read_array::<SCALAR_SIZE>(a));
    }
}

/// `KeyGen` of draft-irtf-cfrg-bls-signature: HKDF-SHA-256 over the input key
/// material, reduced modulo `r`, with the salt rehashed until the result is
/// non-zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_keygen(
    out_sk: *mut u8,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
) {
    unsafe {
        // blst refuses to derive a key from less than 256 bits of entropy
        if ikm_len < 32 {
            core::ptr::write_bytes(out_sk, 0, SCALAR_SIZE);
            return;
        }
        let ikm = super::as_slice(ikm, ikm_len);
        let info = super::as_slice(info, info_len);

        let mut salt: [u8; 32] = [0; 32];
        let mut salt_len = 20;
        salt[..salt_len].copy_from_slice(b"BLS-SIG-KEYGEN-SALT-");

        loop {
            let mut okm = [0u8; 48];
            // L = 48, big-endian, as the specification's `I2OSP(L, 2)`
            super::mac::hkdf_sha256(
                &salt[..salt_len],
                &[ikm, &[0x00]],
                &[info, &[0x00, 48]],
                &mut okm,
            );
            let scalar = Scalar::from_be_bytes_mod_order(&okm);
            if !scalar.is_zero() {
                write_scalar_be(out_sk, scalar.to_bytes());
                return;
            }
            salt = sha256(&salt[..salt_len]);
            salt_len = 32;
        }
    }
}

/* ---------------------------------------------------------------- */
/* G1                                                               */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_on_curve(p: *const u8) -> bool {
    unsafe {
        match read_p1(p).to_affine() {
            None => true,
            Some(affine) => {
                let (x, y) = affine.to_coordinate();
                g1::PointAffine::from_coordinate(x, y).is_some()
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_in_g1(p: *const u8) -> bool {
    unsafe { g1_in_subgroup(&read_p1(p)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_is_inf(p: *const u8) -> bool {
    unsafe { read_p1(p).to_affine().is_none() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_is_equal(a: *const u8, b: *const u8) -> bool {
    unsafe { read_p1(a) == read_p1(b) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_add_or_double(out: *mut u8, a: *const u8, b: *const u8) {
    unsafe {
        write_p1(out, &(&read_p1(a) + &read_p1(b)));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_mult(out: *mut u8, p: *const u8, scalar: *const u8, nbits: usize) {
    unsafe {
        let point = G1::from_point(read_p1(p));
        write_p1(
            out,
            point.scalar_mul(&mult_scalar(scalar, nbits)).as_point(),
        );
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_cneg(p: *mut u8, cbit: bool) {
    unsafe {
        if cbit {
            write_p1(p, &-&read_p1(p));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_generator() -> *const u8 {
    use std::sync::OnceLock;
    static GENERATOR: OnceLock<[u8; P1_SIZE]> = OnceLock::new();
    GENERATOR
        .get_or_init(|| {
            let mut slot = [0u8; P1_SIZE];
            unsafe { write_p1(slot.as_mut_ptr(), &g1::Point::GENERATOR) };
            slot
        })
        .as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_compress(out: *mut u8, p: *const u8) {
    unsafe {
        super::write_bytes(out, &G1::from_point(read_p1(p)).compress());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_serialize(out: *mut u8, p: *const u8) {
    unsafe {
        super::write_bytes(out, &G1::from_point(read_p1(p)).serialize());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_uncompress(out: *mut u8, input: *const u8) -> c_int {
    unsafe {
        match G1::uncompress_point(&super::read_array::<48>(input)) {
            Ok(point) => {
                write_affine1(out, &point);
                BLST_SUCCESS
            }
            Err(e) => blst_error(e),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_deserialize(out: *mut u8, input: *const u8) -> c_int {
    unsafe {
        match G1::deserialize_point(&super::read_array::<96>(input)) {
            Ok(point) => {
                write_affine1(out, &point);
                BLST_SUCCESS
            }
            Err(e) => blst_error(e),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_to_affine(out: *mut u8, p: *const u8) {
    unsafe {
        write_affine1(out, &read_p1(p));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_from_affine(out: *mut u8, p: *const u8) {
    unsafe {
        write_p1(out, &read_affine1(p));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1_affine_in_g1(p: *const u8) -> bool {
    unsafe { g1_in_subgroup(&read_affine1(p)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_hash_to_g1(
    out: *mut u8,
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    aug: *const u8,
    aug_len: usize,
) {
    unsafe {
        let message = augmented(msg, msg_len, aug, aug_len);
        match G1::hash_to_group(&message, super::as_slice(dst, dst_len)) {
            Ok(point) => write_p1(out, point.as_point()),
            Err(_) => write_p1(out, &g1::Point::INFINITY),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_sk_to_pk_in_g1(out_pk: *mut u8, sk: *const u8) {
    unsafe {
        let scalar = Scalar::from_be_bytes_mod_order(&scalar_be(sk));
        write_p1(out_pk, G1::generator().scalar_mul(&scalar).as_point());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_sign_pk_in_g1(out_sig: *mut u8, hash: *const u8, sk: *const u8) {
    unsafe {
        let scalar = Scalar::from_be_bytes_mod_order(&scalar_be(sk));
        let point = G2::from_point(read_p2(hash));
        write_p2(out_sig, point.scalar_mul(&scalar).as_point());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1s_mult_pippenger_scratch_sizeof(npoints: usize) -> usize {
    // Nothing reads the scratch space; this is a size the caller can allocate.
    P1_SIZE * (npoints + 1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1s_to_affine(
    dst: *mut u8,
    points: *const *const u8,
    npoints: usize,
) {
    unsafe {
        for i in 0..npoints {
            let point = read_p1(nth_point(points, i, P1_SIZE));
            write_affine1(dst.add(i * AFFINE1_SIZE), &point);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p1s_mult_pippenger(
    ret: *mut u8,
    points: *const *const u8,
    npoints: usize,
    scalars: *const *const u8,
    nbits: usize,
    _scratch: *mut u8,
) {
    unsafe {
        let mut acc = g1::Point::INFINITY;
        for i in 0..npoints {
            let point = G1::from_point(read_affine1(nth_point(points, i, AFFINE1_SIZE)));
            let scalar = mult_scalar(nth_point(scalars, i, SCALAR_SIZE), nbits);
            acc = &acc + point.scalar_mul(&scalar).as_point();
        }
        write_p1(ret, &acc);
    }
}

/* ---------------------------------------------------------------- */
/* G2                                                               */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_on_curve(p: *const u8) -> bool {
    unsafe {
        match read_p2(p).to_affine() {
            None => true,
            Some(affine) => {
                let (x, y) = affine.to_coordinate();
                g2::PointAffine::from_coordinate(x, y).is_some()
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_in_g2(p: *const u8) -> bool {
    unsafe { g2_in_subgroup(&read_p2(p)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_is_inf(p: *const u8) -> bool {
    unsafe { read_p2(p).to_affine().is_none() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_is_equal(a: *const u8, b: *const u8) -> bool {
    unsafe { read_p2(a) == read_p2(b) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_add_or_double(out: *mut u8, a: *const u8, b: *const u8) {
    unsafe {
        write_p2(out, &(&read_p2(a) + &read_p2(b)));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_mult(out: *mut u8, p: *const u8, scalar: *const u8, nbits: usize) {
    unsafe {
        let point = G2::from_point(read_p2(p));
        write_p2(
            out,
            point.scalar_mul(&mult_scalar(scalar, nbits)).as_point(),
        );
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_cneg(p: *mut u8, cbit: bool) {
    unsafe {
        if cbit {
            write_p2(p, &-&read_p2(p));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_generator() -> *const u8 {
    use std::sync::OnceLock;
    static GENERATOR: OnceLock<[u8; P2_SIZE]> = OnceLock::new();
    GENERATOR
        .get_or_init(|| {
            let mut slot = [0u8; P2_SIZE];
            unsafe { write_p2(slot.as_mut_ptr(), &g2::Point::GENERATOR) };
            slot
        })
        .as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_compress(out: *mut u8, p: *const u8) {
    unsafe {
        super::write_bytes(out, &G2::from_point(read_p2(p)).compress());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_serialize(out: *mut u8, p: *const u8) {
    unsafe {
        super::write_bytes(out, &G2::from_point(read_p2(p)).serialize());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_uncompress(out: *mut u8, input: *const u8) -> c_int {
    unsafe {
        match G2::uncompress_point(&super::read_array::<96>(input)) {
            Ok(point) => {
                write_affine2(out, &point);
                BLST_SUCCESS
            }
            Err(e) => blst_error(e),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_deserialize(out: *mut u8, input: *const u8) -> c_int {
    unsafe {
        match G2::deserialize_point(&super::read_array::<192>(input)) {
            Ok(point) => {
                write_affine2(out, &point);
                BLST_SUCCESS
            }
            Err(e) => blst_error(e),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_to_affine(out: *mut u8, p: *const u8) {
    unsafe {
        write_affine2(out, &read_p2(p));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_from_affine(out: *mut u8, p: *const u8) {
    unsafe {
        write_p2(out, &read_affine2(p));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2_affine_in_g2(p: *const u8) -> bool {
    unsafe { g2_in_subgroup(&read_affine2(p)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_hash_to_g2(
    out: *mut u8,
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    aug: *const u8,
    aug_len: usize,
) {
    unsafe {
        let message = augmented(msg, msg_len, aug, aug_len);
        match G2::hash_to_group(&message, super::as_slice(dst, dst_len)) {
            Ok(point) => write_p2(out, point.as_point()),
            Err(_) => write_p2(out, &g2::Point::INFINITY),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_sk_to_pk_in_g2(out_pk: *mut u8, sk: *const u8) {
    unsafe {
        let scalar = Scalar::from_be_bytes_mod_order(&scalar_be(sk));
        write_p2(out_pk, G2::generator().scalar_mul(&scalar).as_point());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_sign_pk_in_g2(out_sig: *mut u8, hash: *const u8, sk: *const u8) {
    unsafe {
        let scalar = Scalar::from_be_bytes_mod_order(&scalar_be(sk));
        let point = G1::from_point(read_p1(hash));
        write_p1(out_sig, point.scalar_mul(&scalar).as_point());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2s_mult_pippenger_scratch_sizeof(npoints: usize) -> usize {
    P2_SIZE * (npoints + 1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2s_to_affine(
    dst: *mut u8,
    points: *const *const u8,
    npoints: usize,
) {
    unsafe {
        for i in 0..npoints {
            let point = read_p2(nth_point(points, i, P2_SIZE));
            write_affine2(dst.add(i * AFFINE2_SIZE), &point);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_p2s_mult_pippenger(
    ret: *mut u8,
    points: *const *const u8,
    npoints: usize,
    scalars: *const *const u8,
    nbits: usize,
    _scratch: *mut u8,
) {
    unsafe {
        let mut acc = g2::Point::INFINITY;
        for i in 0..npoints {
            let point = G2::from_point(read_affine2(nth_point(points, i, AFFINE2_SIZE)));
            let scalar = mult_scalar(nth_point(scalars, i, SCALAR_SIZE), nbits);
            acc = &acc + point.scalar_mul(&scalar).as_point();
        }
        write_p2(ret, &acc);
    }
}

/* ---------------------------------------------------------------- */
/* Pairing                                                          */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_miller_loop(ret: *mut u8, q: *const u8, p: *const u8) {
    unsafe {
        let p1 = G1::from_point(read_affine1(p));
        let p2 = G2::from_point(read_affine2(q));
        write_fp12(ret, &miller_loop(&p1, &p2));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_fp12_mul(ret: *mut u8, a: *const u8, b: *const u8) {
    unsafe {
        write_fp12(ret, &read_fp12(a).mul(&read_fp12(b)));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_fp12_is_equal(a: *const u8, b: *const u8) -> bool {
    unsafe { read_fp12(a) == read_fp12(b) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blst_fp12_finalverify(gt1: *const u8, gt2: *const u8) -> bool {
    unsafe { read_fp12(gt1).final_verify(&read_fp12(gt2)) }
}

/// `e(pk, H(msg)) == e(G1, signature)`, with the checks blst performs first.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn blst_core_verify_pk_in_g1(
    pk: *const u8,
    signature: *const u8,
    hash_or_encode: bool,
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    aug: *const u8,
    aug_len: usize,
) -> c_int {
    unsafe {
        if !hash_or_encode {
            // only hash-to-curve (the `RO` suites) is implemented; the caller in
            // cardano-crypto-class always asks for it
            return BLST_AGGR_TYPE_MISMATCH;
        }
        let pk_point = G1::from_point(read_affine1(pk));
        if pk_point.is_zero() {
            return BLST_PK_IS_INFINITY;
        }
        let sig_point = G2::from_point(read_affine2(signature));
        if !pk_point.in_subgroup() || !sig_point.in_subgroup() {
            return BLST_POINT_NOT_IN_GROUP;
        }
        let message = augmented(msg, msg_len, aug, aug_len);
        let Ok(hash) = G2::hash_to_group(&message, super::as_slice(dst, dst_len)) else {
            return BLST_BAD_ENCODING;
        };
        let lhs = miller_loop(&G1::generator(), &sig_point);
        let rhs = miller_loop(&pk_point, &hash);
        if lhs.final_verify(&rhs) {
            BLST_SUCCESS
        } else {
            BLST_VERIFY_FAIL
        }
    }
}

/// `e(H(msg), pk) == e(signature, G2)`, the same with the groups swapped.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn blst_core_verify_pk_in_g2(
    pk: *const u8,
    signature: *const u8,
    hash_or_encode: bool,
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    aug: *const u8,
    aug_len: usize,
) -> c_int {
    unsafe {
        if !hash_or_encode {
            return BLST_AGGR_TYPE_MISMATCH;
        }
        let pk_point = G2::from_point(read_affine2(pk));
        if pk_point.is_zero() {
            return BLST_PK_IS_INFINITY;
        }
        let sig_point = G1::from_point(read_affine1(signature));
        if !pk_point.in_subgroup() || !sig_point.in_subgroup() {
            return BLST_POINT_NOT_IN_GROUP;
        }
        let message = augmented(msg, msg_len, aug, aug_len);
        let Ok(hash) = G1::hash_to_group(&message, super::as_slice(dst, dst_len)) else {
            return BLST_BAD_ENCODING;
        };
        let lhs = miller_loop(&sig_point, &G2::generator());
        let rhs = miller_loop(&hash, &pk_point);
        if lhs.final_verify(&rhs) {
            BLST_SUCCESS
        } else {
            BLST_VERIFY_FAIL
        }
    }
}

/* ---------------------------------------------------------------- */
/* Shared helpers                                                   */
/* ---------------------------------------------------------------- */

const BLST_SUCCESS: c_int = 0;
const BLST_BAD_ENCODING: c_int = 1;
const BLST_POINT_NOT_ON_CURVE: c_int = 2;
const BLST_POINT_NOT_IN_GROUP: c_int = 3;
const BLST_AGGR_TYPE_MISMATCH: c_int = 4;
const BLST_VERIFY_FAIL: c_int = 5;
const BLST_PK_IS_INFINITY: c_int = 6;

fn blst_error(e: crate::plutus::bls12_381::BlsError) -> c_int {
    use crate::plutus::bls12_381::BlsError::*;
    match e {
        BadEncoding | InvalidLength { .. } | DstTooLong(_) => BLST_BAD_ENCODING,
        NotOnCurve => BLST_POINT_NOT_ON_CURVE,
        NotInGroup => BLST_POINT_NOT_IN_GROUP,
    }
}

/// The message a hash-to-curve call actually hashes: the augmentation, if any,
/// followed by the message.
unsafe fn augmented(msg: *const u8, msg_len: usize, aug: *const u8, aug_len: usize) -> Vec<u8> {
    unsafe {
        let msg = super::as_slice(msg, msg_len);
        let aug = super::as_slice(aug, aug_len);
        let mut out = Vec::with_capacity(aug.len() + msg.len());
        out.extend_from_slice(aug);
        out.extend_from_slice(msg);
        out
    }
}

/// The `i`th element of one of blst's arrays of pointers.
///
/// blst lets the caller pass a single pointer to a contiguous array instead, by
/// putting a null in the second slot; `cardano-crypto-class` passes pointers,
/// but both are accepted here.
unsafe fn nth_point(array: *const *const u8, i: usize, stride: usize) -> *const u8 {
    unsafe {
        if i > 0 && (*array.add(1)).is_null() {
            (*array).add(i * stride)
        } else {
            *array.add(i)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct P1([u8; P1_SIZE]);
    struct P2([u8; P2_SIZE]);

    fn p1() -> P1 {
        P1([0; P1_SIZE])
    }
    fn p2() -> P2 {
        P2([0; P2_SIZE])
    }

    /// The generator, uncompressed and back, agrees with the crate's own view.
    #[test]
    fn generator_round_trips_through_compression() {
        unsafe {
            let generator = blst_p1_generator();
            let mut compressed = [0u8; 48];
            blst_p1_compress(compressed.as_mut_ptr(), generator);
            assert_eq!(compressed, G1::generator().compress());

            let mut affine = [0u8; AFFINE1_SIZE];
            assert_eq!(
                blst_p1_uncompress(affine.as_mut_ptr(), compressed.as_ptr()),
                BLST_SUCCESS
            );
            let mut back = p1();
            blst_p1_from_affine(back.0.as_mut_ptr(), affine.as_ptr());
            assert!(blst_p1_is_equal(back.0.as_ptr(), generator));
            assert!(blst_p1_in_g1(back.0.as_ptr()));
            assert!(blst_p1_on_curve(back.0.as_ptr()));
            assert!(!blst_p1_is_inf(back.0.as_ptr()));
        }
    }

    #[test]
    fn point_at_infinity_survives_the_affine_round_trip() {
        unsafe {
            let zero = [0u8; 48];
            let mut infinity = zero;
            infinity[0] = 0xc0;
            let mut affine = [0u8; AFFINE1_SIZE];
            assert_eq!(
                blst_p1_uncompress(affine.as_mut_ptr(), infinity.as_ptr()),
                BLST_SUCCESS
            );
            assert!(affine.iter().all(|b| *b == 0));
            let mut point = p1();
            blst_p1_from_affine(point.0.as_mut_ptr(), affine.as_ptr());
            assert!(blst_p1_is_inf(point.0.as_ptr()));
            assert!(blst_p1_in_g1(point.0.as_ptr()));

            let mut again = [0u8; AFFINE1_SIZE];
            blst_p1_to_affine(again.as_mut_ptr(), point.0.as_ptr());
            assert_eq!(again, affine);

            let mut compressed = [0u8; 48];
            blst_p1_compress(compressed.as_mut_ptr(), point.0.as_ptr());
            assert_eq!(compressed, infinity);
        }
    }

    #[test]
    fn arithmetic_agrees_with_the_rust_api() {
        unsafe {
            let generator = blst_p1_generator();
            let mut two = p1();
            blst_p1_add_or_double(two.0.as_mut_ptr(), generator, generator);
            let mut scalar = [0u8; SCALAR_SIZE];
            write_scalar_be(scalar.as_mut_ptr(), Scalar::from_u64(2).to_bytes());
            let mut twice = p1();
            blst_p1_mult(twice.0.as_mut_ptr(), generator, scalar.as_ptr(), 256);
            assert!(blst_p1_is_equal(two.0.as_ptr(), twice.0.as_ptr()));

            // negation, and that cneg with a false bit leaves the point alone
            let mut neg = P1(two.0);
            blst_p1_cneg(neg.0.as_mut_ptr(), true);
            let mut sum = p1();
            blst_p1_add_or_double(sum.0.as_mut_ptr(), two.0.as_ptr(), neg.0.as_ptr());
            assert!(blst_p1_is_inf(sum.0.as_ptr()));
            let mut same = P1(two.0);
            blst_p1_cneg(same.0.as_mut_ptr(), false);
            assert_eq!(same.0, two.0);
        }
    }

    #[test]
    fn multi_scalar_multiplication_matches_repeated_addition() {
        unsafe {
            // 3*G + 5*G == 8*G
            let mut a = p1();
            let mut b = p1();
            let mut sa = [0u8; SCALAR_SIZE];
            let mut sb = [0u8; SCALAR_SIZE];
            write_p1(a.0.as_mut_ptr(), G1::generator().as_point());
            write_p1(b.0.as_mut_ptr(), G1::generator().as_point());
            write_scalar_be(sa.as_mut_ptr(), Scalar::from_u64(3).to_bytes());
            write_scalar_be(sb.as_mut_ptr(), Scalar::from_u64(5).to_bytes());

            let mut affines = [0u8; 2 * AFFINE1_SIZE];
            let point_ptrs = [a.0.as_ptr(), b.0.as_ptr(), core::ptr::null()];
            blst_p1s_to_affine(affines.as_mut_ptr(), point_ptrs.as_ptr(), 2);
            let affine_ptrs = [affines.as_ptr(), affines.as_ptr().add(AFFINE1_SIZE)];
            let scalar_ptrs = [sa.as_ptr(), sb.as_ptr(), core::ptr::null()];

            let mut result = p1();
            blst_p1s_mult_pippenger(
                result.0.as_mut_ptr(),
                affine_ptrs.as_ptr(),
                2,
                scalar_ptrs.as_ptr(),
                255,
                core::ptr::null_mut(),
            );
            let expected = G1::generator().scalar_mul(&Scalar::from_u64(8));
            let mut expected_slot = p1();
            write_p1(expected_slot.0.as_mut_ptr(), expected.as_point());
            assert!(blst_p1_is_equal(
                result.0.as_ptr(),
                expected_slot.0.as_ptr()
            ));
        }
    }

    #[test]
    fn scalars_round_trip_and_are_checked() {
        unsafe {
            let mut scalar = [0u8; SCALAR_SIZE];
            let be = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff,
            ];
            blst_scalar_from_bendian(scalar.as_mut_ptr(), be.as_ptr());
            let mut back = [0u8; SCALAR_SIZE];
            blst_bendian_from_scalar(back.as_mut_ptr(), scalar.as_ptr());
            assert_eq!(back, be);
            assert!(blst_scalar_fr_check(scalar.as_ptr()));

            // r itself is not a canonical scalar, and reduces to zero
            let r = [
                0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
                0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x01,
            ];
            blst_scalar_from_bendian(scalar.as_mut_ptr(), r.as_ptr());
            assert!(!blst_scalar_fr_check(scalar.as_ptr()));
            assert!(!blst_scalar_from_be_bytes(
                scalar.as_mut_ptr(),
                r.as_ptr(),
                32
            ));
            assert!(blst_scalar_from_be_bytes(
                scalar.as_mut_ptr(),
                be.as_ptr(),
                32
            ));

            // an Fr round trip preserves a canonical scalar
            let mut fr = [0u8; SCALAR_SIZE];
            blst_scalar_from_bendian(scalar.as_mut_ptr(), be.as_ptr());
            blst_fr_from_scalar(fr.as_mut_ptr(), scalar.as_ptr());
            let mut scalar2 = [0u8; SCALAR_SIZE];
            blst_scalar_from_fr(scalar2.as_mut_ptr(), fr.as_ptr());
            assert_eq!(scalar2, scalar);
        }
    }

    #[test]
    fn keygen_produces_a_usable_key() {
        unsafe {
            let ikm = [3u8; 32];
            let mut sk = [0u8; SCALAR_SIZE];
            blst_keygen(
                sk.as_mut_ptr(),
                ikm.as_ptr(),
                ikm.len(),
                core::ptr::null(),
                0,
            );
            assert!(sk.iter().any(|b| *b != 0));
            assert!(blst_scalar_fr_check(sk.as_ptr()));
            // too little input key material gives the zero key, as in blst
            let mut short = [0xffu8; SCALAR_SIZE];
            blst_keygen(short.as_mut_ptr(), ikm.as_ptr(), 31, core::ptr::null(), 0);
            assert_eq!(short, [0u8; SCALAR_SIZE]);
        }
    }

    /// The BLS signature scheme through the C entry points: sign in G2 with a
    /// key whose public part is in G1, and verify the pairing.
    #[test]
    fn core_verify_accepts_a_signature_and_rejects_a_forgery() {
        unsafe {
            let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
            let ikm = [7u8; 32];
            let mut sk = [0u8; SCALAR_SIZE];
            blst_keygen(
                sk.as_mut_ptr(),
                ikm.as_ptr(),
                ikm.len(),
                core::ptr::null(),
                0,
            );

            let mut pk = p1();
            blst_sk_to_pk_in_g1(pk.0.as_mut_ptr(), sk.as_ptr());

            let msg = b"a message";
            let mut hash = p2();
            blst_hash_to_g2(
                hash.0.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            );
            let mut sig = p2();
            blst_sign_pk_in_g1(sig.0.as_mut_ptr(), hash.0.as_ptr(), sk.as_ptr());

            let mut pk_affine = [0u8; AFFINE1_SIZE];
            let mut sig_affine = [0u8; AFFINE2_SIZE];
            blst_p1_to_affine(pk_affine.as_mut_ptr(), pk.0.as_ptr());
            blst_p2_to_affine(sig_affine.as_mut_ptr(), sig.0.as_ptr());

            assert_eq!(
                blst_core_verify_pk_in_g1(
                    pk_affine.as_ptr(),
                    sig_affine.as_ptr(),
                    true,
                    msg.as_ptr(),
                    msg.len(),
                    dst.as_ptr(),
                    dst.len(),
                    core::ptr::null(),
                    0
                ),
                BLST_SUCCESS
            );
            assert_eq!(
                blst_core_verify_pk_in_g1(
                    pk_affine.as_ptr(),
                    sig_affine.as_ptr(),
                    true,
                    b"another message".as_ptr(),
                    15,
                    dst.as_ptr(),
                    dst.len(),
                    core::ptr::null(),
                    0
                ),
                BLST_VERIFY_FAIL
            );
            // the infinity public key is refused outright
            let infinity = [0u8; AFFINE1_SIZE];
            assert_eq!(
                blst_core_verify_pk_in_g1(
                    infinity.as_ptr(),
                    sig_affine.as_ptr(),
                    true,
                    msg.as_ptr(),
                    msg.len(),
                    dst.as_ptr(),
                    dst.len(),
                    core::ptr::null(),
                    0
                ),
                BLST_PK_IS_INFINITY
            );
        }
    }

    #[test]
    fn miller_loop_and_final_verify_check_a_pairing() {
        unsafe {
            // e(2*G1, 3*G2) == e(3*G1, 2*G2)
            let make1 = |k: u64| {
                let mut slot = p1();
                write_p1(
                    slot.0.as_mut_ptr(),
                    G1::generator().scalar_mul(&Scalar::from_u64(k)).as_point(),
                );
                let mut affine = [0u8; AFFINE1_SIZE];
                blst_p1_to_affine(affine.as_mut_ptr(), slot.0.as_ptr());
                affine
            };
            let make2 = |k: u64| {
                let mut slot = p2();
                write_p2(
                    slot.0.as_mut_ptr(),
                    G2::generator().scalar_mul(&Scalar::from_u64(k)).as_point(),
                );
                let mut affine = [0u8; AFFINE2_SIZE];
                blst_p2_to_affine(affine.as_mut_ptr(), slot.0.as_ptr());
                affine
            };

            let mut lhs = [0u8; FP12_SIZE];
            let mut rhs = [0u8; FP12_SIZE];
            blst_miller_loop(lhs.as_mut_ptr(), make2(3).as_ptr(), make1(2).as_ptr());
            blst_miller_loop(rhs.as_mut_ptr(), make2(2).as_ptr(), make1(3).as_ptr());
            assert!(blst_fp12_finalverify(lhs.as_ptr(), rhs.as_ptr()));

            let mut other = [0u8; FP12_SIZE];
            blst_miller_loop(other.as_mut_ptr(), make2(2).as_ptr(), make1(2).as_ptr());
            assert!(!blst_fp12_finalverify(lhs.as_ptr(), other.as_ptr()));

            // e(P, Q) * e(P, Q) is the pairing squared, and equality is exact
            let mut product = [0u8; FP12_SIZE];
            blst_fp12_mul(product.as_mut_ptr(), lhs.as_ptr(), lhs.as_ptr());
            assert!(!blst_fp12_is_equal(product.as_ptr(), lhs.as_ptr()));
            assert!(blst_fp12_is_equal(lhs.as_ptr(), lhs.as_ptr()));
        }
    }

    #[test]
    fn uncompress_reports_the_error_blst_would() {
        unsafe {
            let mut affine = [0u8; AFFINE1_SIZE];
            // the compression bit must be set
            let mut bad = G1::generator().compress();
            bad[0] &= 0x7f;
            assert_eq!(
                blst_p1_uncompress(affine.as_mut_ptr(), bad.as_ptr()),
                BLST_BAD_ENCODING
            );
            // x = 1 is not on the curve
            let mut bad = [0u8; 48];
            bad[0] = 0x80;
            bad[47] = 1;
            assert_eq!(
                blst_p1_uncompress(affine.as_mut_ptr(), bad.as_ptr()),
                BLST_POINT_NOT_ON_CURVE
            );
        }
    }

    /// G2 gets the same treatment as G1, through its own entry points.
    #[test]
    fn g2_round_trips() {
        unsafe {
            let generator = blst_p2_generator();
            let mut compressed = [0u8; 96];
            blst_p2_compress(compressed.as_mut_ptr(), generator);
            assert_eq!(compressed, G2::generator().compress());

            let mut affine = [0u8; AFFINE2_SIZE];
            assert_eq!(
                blst_p2_uncompress(affine.as_mut_ptr(), compressed.as_ptr()),
                BLST_SUCCESS
            );
            let mut back = p2();
            blst_p2_from_affine(back.0.as_mut_ptr(), affine.as_ptr());
            assert!(blst_p2_is_equal(back.0.as_ptr(), generator));
            assert!(blst_p2_in_g2(back.0.as_ptr()));
            assert!(blst_p2_affine_in_g2(affine.as_ptr()));
            assert!(blst_p2_on_curve(back.0.as_ptr()));

            let mut serialized = [0u8; 192];
            blst_p2_serialize(serialized.as_mut_ptr(), generator);
            let mut affine2 = [0u8; AFFINE2_SIZE];
            assert_eq!(
                blst_p2_deserialize(affine2.as_mut_ptr(), serialized.as_ptr()),
                BLST_SUCCESS
            );
            assert_eq!(affine2, affine);
        }
    }
}

//! The libsecp256k1 API `cardano-crypto-class` uses: ECDSA and BIP-340 Schnorr
//! over secp256k1.
//!
//! Verification goes through [`crate::plutus::secp256k1`], which is written
//! against libsecp256k1's acceptance rules (low-`s` only, `x(R) == r + n`
//! accepted, x-only keys lifted to even `y`). Signing is here, because the
//! library only needs it for tests and key handling: ECDSA uses the RFC 6979
//! nonce libsecp256k1 uses by default, and Schnorr the BIP-340 nonce with the
//! all-zero auxiliary randomness libsecp256k1 substitutes when none is given.
//!
//! The opaque structs hold uncompressed affine coordinates:
//!
//! * `secp256k1_pubkey`, `secp256k1_xonly_pubkey`: `x || y`, 32 bytes each,
//!   big-endian (the x-only form always stores the even `y`);
//! * `secp256k1_ecdsa_signature`: `r || s`, big-endian;
//! * `secp256k1_keypair`: `sk || x || y`.

use core::ffi::{c_int, c_uint, c_void};

use eccoxide::curve::field::Sign;
use eccoxide::curve::sec2::p256k1::{FieldElement, Point, PointAffine, Scalar};

use super::mac::Rfc6979;
use crate::plutus::secp256k1::{
    lift_x, scalar_from_bytes_mod_order, scalar_is_high, verify_ecdsa, verify_schnorr,
};

/// The context libsecp256k1 needs for its precomputed tables and blinding; here
/// there is nothing to keep, but a distinct non-null pointer must be handed out
/// and freed, since that is what the caller does with it.
const CONTEXT_MAGIC: u64 = 0x6361_7264_6372_7970;

/* ---------------------------------------------------------------- */
/* Context                                                          */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_context_create(_flags: c_uint) -> *mut c_void {
    Box::into_raw(Box::new(CONTEXT_MAGIC)) as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_context_clone(_ctx: *const c_void) -> *mut c_void {
    unsafe { secp256k1_context_create(0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_context_destroy(ctx: *mut c_void) {
    unsafe {
        if !ctx.is_null() {
            drop(Box::from_raw(ctx as *mut u64));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_context_randomize(
    _ctx: *mut c_void,
    _seed32: *const u8,
) -> c_int {
    // Blinding is what upstream randomizes; there is nothing to re-blind here.
    1
}

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

/// Read a secret key: canonical and non-zero, as `secp256k1_ec_seckey_verify`
/// requires.
fn secret_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = Scalar::from_bytes_be(bytes)?;
    if s.is_zero() { None } else { Some(s) }
}

/// The affine point of a `secp256k1_pubkey`-shaped `x || y`.
unsafe fn point_from_internal(p: *const u8) -> Option<PointAffine> {
    unsafe {
        let x = FieldElement::from_bytes_be(&super::read_array::<32>(p))?;
        let y = FieldElement::from_bytes_be(&super::read_array::<32>(p.add(32)))?;
        PointAffine::from_coordinate(&x, &y)
    }
}

/// Store an affine point as `x || y`.
unsafe fn point_to_internal(out: *mut u8, point: &PointAffine) {
    unsafe {
        let (x, y) = point.to_coordinate();
        super::write_bytes(out, &x.to_bytes_be());
        super::write_bytes(out.add(32), &y.to_bytes_be());
    }
}

/// The 33-byte compressed encoding of a stored point.
unsafe fn compressed_from_internal(p: *const u8) -> Option<[u8; 33]> {
    unsafe {
        let point = point_from_internal(p)?;
        let (x, sign) = point.compress();
        let mut out = [0u8; 33];
        out[0] = if sign == Sign::Positive { 0x02 } else { 0x03 };
        out[1..].copy_from_slice(&x.to_bytes_be());
        Some(out)
    }
}

fn point_of_secret(secret: &Scalar) -> PointAffine {
    Point::mul_base(secret)
        .to_affine()
        .expect("a non-zero scalar times the generator is not the identity")
}

/* ---------------------------------------------------------------- */
/* Public keys                                                      */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ec_pubkey_parse(
    _ctx: *const c_void,
    pubkey: *mut u8,
    input: *const u8,
    inputlen: usize,
) -> c_int {
    unsafe {
        let bytes = super::as_slice(input, inputlen);
        let point = match (inputlen, bytes.first().copied()) {
            (33, Some(tag @ (0x02 | 0x03))) => {
                let sign = if tag == 0x02 {
                    Sign::Positive
                } else {
                    Sign::Negative
                };
                let mut x = [0u8; 32];
                x.copy_from_slice(&bytes[1..]);
                FieldElement::from_bytes_be(&x)
                    .and_then(|x| PointAffine::decompress(&x, sign).into_option())
            }
            (65, Some(tag @ (0x04 | 0x06 | 0x07))) => {
                let mut xb = [0u8; 32];
                let mut yb = [0u8; 32];
                xb.copy_from_slice(&bytes[1..33]);
                yb.copy_from_slice(&bytes[33..]);
                let odd_y = yb[31] & 1 == 1;
                // for the hybrid forms the tag has to agree with the parity of y
                if (tag == 0x06 && odd_y) || (tag == 0x07 && !odd_y) {
                    None
                } else {
                    match (
                        FieldElement::from_bytes_be(&xb),
                        FieldElement::from_bytes_be(&yb),
                    ) {
                        (Some(x), Some(y)) => PointAffine::from_coordinate(&x, &y),
                        _ => None,
                    }
                }
            }
            _ => None,
        };
        match point {
            Some(point) => {
                point_to_internal(pubkey, &point);
                1
            }
            None => {
                core::ptr::write_bytes(pubkey, 0, 64);
                0
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ec_pubkey_serialize(
    _ctx: *const c_void,
    output: *mut u8,
    outputlen: *mut usize,
    pubkey: *const u8,
    flags: c_uint,
) -> c_int {
    unsafe {
        let compressed = flags & (1 << 8) != 0;
        if compressed {
            match compressed_from_internal(pubkey) {
                Some(bytes) => {
                    super::write_bytes(output, &bytes);
                    outputlen.write_unaligned(33);
                    1
                }
                None => {
                    outputlen.write_unaligned(0);
                    0
                }
            }
        } else {
            let mut out = [0u8; 65];
            out[0] = 0x04;
            out[1..].copy_from_slice(&super::read_array::<64>(pubkey));
            super::write_bytes(output, &out);
            outputlen.write_unaligned(65);
            1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ec_pubkey_create(
    _ctx: *const c_void,
    pubkey: *mut u8,
    seckey: *const u8,
) -> c_int {
    unsafe {
        match secret_from_bytes(&super::read_array(seckey)) {
            Some(secret) => {
                point_to_internal(pubkey, &point_of_secret(&secret));
                1
            }
            None => {
                core::ptr::write_bytes(pubkey, 0, 64);
                0
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ec_seckey_verify(
    _ctx: *const c_void,
    seckey: *const u8,
) -> c_int {
    unsafe { c_int::from(secret_from_bytes(&super::read_array(seckey)).is_some()) }
}

/* ---------------------------------------------------------------- */
/* ECDSA                                                            */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ecdsa_signature_parse_compact(
    _ctx: *const c_void,
    sig: *mut u8,
    input64: *const u8,
) -> c_int {
    unsafe {
        let bytes: [u8; 64] = super::read_array(input64);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        // upstream rejects an r or s that is not below the group order, and leaves
        // behind a signature that cannot verify
        if Scalar::from_bytes_be(&r).is_none() || Scalar::from_bytes_be(&s).is_none() {
            core::ptr::write_bytes(sig, 0, 64);
            return 0;
        }
        super::write_bytes(sig, &bytes);
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ecdsa_signature_serialize_compact(
    _ctx: *const c_void,
    output64: *mut u8,
    sig: *const u8,
) -> c_int {
    unsafe {
        super::write_bytes(output64, &super::read_array::<64>(sig));
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ecdsa_signature_normalize(
    _ctx: *const c_void,
    sigout: *mut u8,
    sigin: *const u8,
) -> c_int {
    unsafe {
        let bytes: [u8; 64] = super::read_array(sigin);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..]);
        let high = scalar_is_high(&s);
        if !sigout.is_null() {
            let mut out = bytes;
            if high {
                if let Some(scalar) = Scalar::from_bytes_be(&s) {
                    out[32..].copy_from_slice(&(-&scalar).to_bytes_be());
                }
            }
            super::write_bytes(sigout, &out);
        }
        c_int::from(high)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ecdsa_verify(
    _ctx: *const c_void,
    sig: *const u8,
    msghash32: *const u8,
    pubkey: *const u8,
) -> c_int {
    unsafe {
        let Some(pk) = compressed_from_internal(pubkey) else {
            return 0;
        };
        let sig: [u8; 64] = super::read_array(sig);
        let msg: [u8; 32] = super::read_array(msghash32);
        c_int::from(verify_ecdsa(&pk, &msg, &sig).is_ok())
    }
}

/// Sign with the RFC 6979 nonce, retrying exactly as
/// `secp256k1_ecdsa_sign` does, and normalising `s` to the lower half.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_ecdsa_sign(
    _ctx: *const c_void,
    sig: *mut u8,
    msghash32: *const u8,
    seckey: *const u8,
    _noncefp: *const c_void,
    _ndata: *const c_void,
) -> c_int {
    unsafe {
        let key_bytes: [u8; 32] = super::read_array(seckey);
        let msg_bytes: [u8; 32] = super::read_array(msghash32);
        let Some(secret) = secret_from_bytes(&key_bytes) else {
            core::ptr::write_bytes(sig, 0, 64);
            return 0;
        };
        let msg = scalar_from_bytes_mod_order(&msg_bytes);

        let mut rng = Rfc6979::new(&key_bytes, &msg_bytes);
        loop {
            let nonce = rng.next_nonce();
            let Some(k) = secret_from_bytes(&nonce) else {
                continue;
            };
            let Some(big_r) = Point::mul_base(&k).to_affine() else {
                continue;
            };
            let (x, _) = big_r.to_coordinate();
            let r = scalar_from_bytes_mod_order(&x.to_bytes_be());
            if r.is_zero() {
                continue;
            }
            let s = &k.inverse() * &(&msg + &(&r * &secret));
            if s.is_zero() {
                continue;
            }
            let s_bytes = s.to_bytes_be();
            let s = if scalar_is_high(&s_bytes) { -&s } else { s };

            super::write_bytes(sig, &r.to_bytes_be());
            super::write_bytes(sig.add(32), &s.to_bytes_be());
            return 1;
        }
    }
}

/* ---------------------------------------------------------------- */
/* x-only keys and key pairs                                        */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_xonly_pubkey_parse(
    _ctx: *const c_void,
    pubkey: *mut u8,
    input32: *const u8,
) -> c_int {
    unsafe {
        match lift_x(&super::read_array(input32)) {
            Ok(point) => {
                point_to_internal(pubkey, &point);
                1
            }
            Err(_) => {
                core::ptr::write_bytes(pubkey, 0, 64);
                0
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_xonly_pubkey_serialize(
    _ctx: *const c_void,
    output32: *mut u8,
    pubkey: *const u8,
) -> c_int {
    unsafe {
        super::write_bytes(output32, &super::read_array::<32>(pubkey));
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_xonly_pubkey_from_pubkey(
    _ctx: *const c_void,
    xonly_pubkey: *mut u8,
    pk_parity: *mut c_int,
    pubkey: *const u8,
) -> c_int {
    unsafe {
        let Some(point) = point_from_internal(pubkey) else {
            return 0;
        };
        let (x, y) = point.to_coordinate();
        let odd = y.sign() != Sign::Positive;
        if !pk_parity.is_null() {
            pk_parity.write_unaligned(c_int::from(odd));
        }
        // the x-only form always keeps the even y, which is BIP-340's convention
        let y_even = if odd { -y } else { y.clone() };
        super::write_bytes(xonly_pubkey, &x.to_bytes_be());
        super::write_bytes(xonly_pubkey.add(32), &y_even.to_bytes_be());
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_xonly_pubkey_cmp(
    _ctx: *const c_void,
    pk1: *const u8,
    pk2: *const u8,
) -> c_int {
    unsafe {
        let a: [u8; 32] = super::read_array(pk1);
        let b: [u8; 32] = super::read_array(pk2);
        match a.cmp(&b) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_keypair_create(
    _ctx: *const c_void,
    keypair: *mut u8,
    seckey: *const u8,
) -> c_int {
    unsafe {
        let bytes: [u8; 32] = super::read_array(seckey);
        match secret_from_bytes(&bytes) {
            Some(secret) => {
                super::write_bytes(keypair, &bytes);
                point_to_internal(keypair.add(32), &point_of_secret(&secret));
                1
            }
            None => {
                core::ptr::write_bytes(keypair, 0, 96);
                0
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_keypair_sec(
    _ctx: *const c_void,
    seckey: *mut u8,
    keypair: *const u8,
) -> c_int {
    unsafe {
        super::write_bytes(seckey, &super::read_array::<32>(keypair));
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_keypair_pub(
    _ctx: *const c_void,
    pubkey: *mut u8,
    keypair: *const u8,
) -> c_int {
    unsafe {
        super::write_bytes(pubkey, &super::read_array::<64>(keypair.add(32)));
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_keypair_xonly_pub(
    ctx: *const c_void,
    pubkey: *mut u8,
    pk_parity: *mut c_int,
    keypair: *const u8,
) -> c_int {
    unsafe { secp256k1_xonly_pubkey_from_pubkey(ctx, pubkey, pk_parity, keypair.add(32)) }
}

/* ---------------------------------------------------------------- */
/* BIP-340 Schnorr                                                  */
/* ---------------------------------------------------------------- */

/// BIP-340 signing.
///
/// `aux_rand` is the auxiliary randomness; libsecp256k1 substitutes 32 zero
/// bytes when the caller supplies none, which is what `sign_custom` with no
/// extra parameters does and therefore what `cardano-crypto-class` gets.
unsafe fn schnorr_sign(
    sig64: *mut u8,
    msg: &[u8],
    keypair: *const u8,
    aux_rand: [u8; 32],
) -> c_int {
    unsafe {
        let key_bytes: [u8; 32] = super::read_array(keypair);
        let Some(secret) = secret_from_bytes(&key_bytes) else {
            return 0;
        };

        // the secret is taken with the sign that makes the public y even
        let point = point_of_secret(&secret);
        let (px, py) = point.to_coordinate();
        let px_bytes = px.to_bytes_be();
        let d = if py.sign() == Sign::Positive {
            secret
        } else {
            -&secret
        };
        let d_bytes = d.to_bytes_be();

        let mask = crate::plutus::secp256k1::tagged_hash(b"BIP0340/aux", &[&aux_rand]);
        let mut t = [0u8; 32];
        for i in 0..32 {
            t[i] = d_bytes[i] ^ mask[i];
        }

        let rand = crate::plutus::secp256k1::tagged_hash(b"BIP0340/nonce", &[&t, &px_bytes, msg]);
        let k0 = scalar_from_bytes_mod_order(&rand);
        if k0.is_zero() {
            return 0;
        }
        let big_r = Point::mul_base(&k0)
            .to_affine()
            .expect("a non-zero scalar times the generator is not the identity");
        let (rx, ry) = big_r.to_coordinate();
        let rx_bytes = rx.to_bytes_be();
        let k = if ry.sign() == Sign::Positive {
            k0
        } else {
            -&k0
        };

        let e = scalar_from_bytes_mod_order(&crate::plutus::secp256k1::tagged_hash(
            b"BIP0340/challenge",
            &[&rx_bytes, &px_bytes, msg],
        ));
        let s = &k + &(&e * &d);

        super::write_bytes(sig64, &rx_bytes);
        super::write_bytes(sig64.add(32), &s.to_bytes_be());
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_schnorrsig_sign32(
    _ctx: *const c_void,
    sig64: *mut u8,
    msg32: *const u8,
    keypair: *const u8,
    aux_rand32: *const u8,
) -> c_int {
    unsafe {
        let aux = if aux_rand32.is_null() {
            [0u8; 32]
        } else {
            super::read_array(aux_rand32)
        };
        schnorr_sign(sig64, &super::read_array::<32>(msg32), keypair, aux)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_schnorrsig_sign_custom(
    _ctx: *const c_void,
    sig64: *mut u8,
    msg: *const u8,
    msglen: usize,
    keypair: *const u8,
    _extraparams: *const c_void,
) -> c_int {
    unsafe { schnorr_sign(sig64, super::as_slice(msg, msglen), keypair, [0u8; 32]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn secp256k1_schnorrsig_verify(
    _ctx: *const c_void,
    sig64: *const u8,
    msg: *const u8,
    msglen: usize,
    pubkey: *const u8,
) -> c_int {
    unsafe {
        let pk: [u8; 32] = super::read_array(pubkey);
        let sig: [u8; 64] = super::read_array(sig64);
        c_int::from(verify_schnorr(&pk, super::as_slice(msg, msglen), &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn ctx() -> *mut c_void {
        unsafe { secp256k1_context_create(0) }
    }

    #[test]
    fn ecdsa_sign_verify_round_trip() {
        unsafe {
            let ctx = ctx();
            let sk = [3u8; 32];
            let msg = crate::hash::sha256(b"a message");
            let mut pubkey = [0u8; 64];
            assert_eq!(
                secp256k1_ec_pubkey_create(ctx, pubkey.as_mut_ptr(), sk.as_ptr()),
                1
            );

            let mut sig = [0u8; 64];
            assert_eq!(
                secp256k1_ecdsa_sign(
                    ctx,
                    sig.as_mut_ptr(),
                    msg.as_ptr(),
                    sk.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(
                secp256k1_ecdsa_verify(ctx, sig.as_ptr(), msg.as_ptr(), pubkey.as_ptr()),
                1
            );

            // the signature survives a serialise / parse round trip
            let mut compact = [0u8; 64];
            assert_eq!(
                secp256k1_ecdsa_signature_serialize_compact(
                    ctx,
                    compact.as_mut_ptr(),
                    sig.as_ptr()
                ),
                1
            );
            let mut parsed = [0u8; 64];
            assert_eq!(
                secp256k1_ecdsa_signature_parse_compact(ctx, parsed.as_mut_ptr(), compact.as_ptr()),
                1
            );
            assert_eq!(parsed, sig);
            assert_eq!(
                secp256k1_ecdsa_verify(ctx, parsed.as_ptr(), msg.as_ptr(), pubkey.as_ptr()),
                1
            );

            // and signing is deterministic
            let mut again = [0u8; 64];
            secp256k1_ecdsa_sign(
                ctx,
                again.as_mut_ptr(),
                msg.as_ptr(),
                sk.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(again, sig);

            // s is normalised to the lower half
            let mut s = [0u8; 32];
            s.copy_from_slice(&sig[32..]);
            assert!(!scalar_is_high(&s));

            secp256k1_context_destroy(ctx);
        }
    }

    #[test]
    fn pubkey_serialisation_round_trips() {
        unsafe {
            let ctx = ctx();
            let sk = [5u8; 32];
            let mut pubkey = [0u8; 64];
            secp256k1_ec_pubkey_create(ctx, pubkey.as_mut_ptr(), sk.as_ptr());

            for (flags, len) in [(1u32 << 8 | 2, 33usize), (2, 65)] {
                let mut out = [0u8; 65];
                let mut outlen = out.len();
                assert_eq!(
                    secp256k1_ec_pubkey_serialize(
                        ctx,
                        out.as_mut_ptr(),
                        &mut outlen,
                        pubkey.as_ptr(),
                        flags
                    ),
                    1
                );
                assert_eq!(outlen, len);
                let mut back = [0u8; 64];
                assert_eq!(
                    secp256k1_ec_pubkey_parse(ctx, back.as_mut_ptr(), out.as_ptr(), outlen),
                    1
                );
                assert_eq!(back, pubkey);
            }

            // garbage does not parse
            let bad = [0u8; 33];
            let mut back = [0u8; 64];
            assert_eq!(
                secp256k1_ec_pubkey_parse(ctx, back.as_mut_ptr(), bad.as_ptr(), 33),
                0
            );
            secp256k1_context_destroy(ctx);
        }
    }

    #[test]
    fn schnorr_sign_verify_round_trip() {
        unsafe {
            let ctx = ctx();
            let sk = [7u8; 32];
            let mut keypair = [0u8; 96];
            assert_eq!(
                secp256k1_keypair_create(ctx, keypair.as_mut_ptr(), sk.as_ptr()),
                1
            );
            let mut xonly = [0u8; 64];
            let mut parity = 0;
            assert_eq!(
                secp256k1_keypair_xonly_pub(ctx, xonly.as_mut_ptr(), &mut parity, keypair.as_ptr()),
                1
            );
            let mut xonly_bytes = [0u8; 32];
            assert_eq!(
                secp256k1_xonly_pubkey_serialize(ctx, xonly_bytes.as_mut_ptr(), xonly.as_ptr()),
                1
            );

            let msg = b"message of any length";
            let mut sig = [0u8; 64];
            assert_eq!(
                secp256k1_schnorrsig_sign_custom(
                    ctx,
                    sig.as_mut_ptr(),
                    msg.as_ptr(),
                    msg.len(),
                    keypair.as_ptr(),
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(
                secp256k1_schnorrsig_verify(
                    ctx,
                    sig.as_ptr(),
                    msg.as_ptr(),
                    msg.len(),
                    xonly.as_ptr()
                ),
                1
            );
            // the x-only key parses back to the same internal form
            let mut parsed = [0u8; 64];
            assert_eq!(
                secp256k1_xonly_pubkey_parse(ctx, parsed.as_mut_ptr(), xonly_bytes.as_ptr()),
                1
            );
            assert_eq!(parsed, xonly);
            // a tampered message does not verify
            assert_eq!(
                secp256k1_schnorrsig_verify(
                    ctx,
                    sig.as_ptr(),
                    b"other".as_ptr(),
                    5,
                    xonly.as_ptr()
                ),
                0
            );
            secp256k1_context_destroy(ctx);
        }
    }

    #[test]
    fn parse_compact_rejects_out_of_range_scalars() {
        unsafe {
            let ctx = ctx();
            let mut sig = [0u8; 64];
            // r = s = 0xffff...ff is above the group order
            let bad = [0xffu8; 64];
            assert_eq!(
                secp256k1_ecdsa_signature_parse_compact(ctx, sig.as_mut_ptr(), bad.as_ptr()),
                0
            );
            assert_eq!(sig, [0u8; 64]);
            secp256k1_context_destroy(ctx);
        }
    }
}

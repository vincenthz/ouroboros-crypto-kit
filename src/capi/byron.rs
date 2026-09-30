//! `cardano-crypto`'s C: the `wallet_encrypted_*` functions of
//! `cbits/encrypted_sign.c`, which back `Cardano.Crypto.Wallet`, and the
//! `cardano_crypto_ed25519_*` functions of its vendored ed25519-donna, which
//! back `Crypto.ECC.Ed25519Donna`.
//!
//! An encrypted key is the 128-byte `XPrv` serialisation, a public key the
//! 32-byte verification key followed (for derivation) by a separate 32-byte
//! chain code.

use core::ffi::c_int;

use crate::byron::{DerivationScheme, HARDENED_INDEX, XPUB_SIZE, XPrv, donna};

/// `derivation_scheme_mode`: 1 is V1, 2 is V2. The C code does nothing
/// sensible for any other value (it reads an uninitialised index buffer); here
/// anything but 1 is V2.
fn scheme(mode: c_int) -> DerivationScheme {
    if mode == 1 {
        DerivationScheme::V1
    } else {
        DerivationScheme::V2
    }
}

unsafe fn read_xprv(ptr: *const u8) -> XPrv {
    unsafe { XPrv::from_bytes(super::read_array(ptr)) }
}

unsafe fn pass<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    unsafe { super::as_slice(ptr, len as usize) }
}

/* ---------------------------------------------------------------- */
/* encrypted_sign.c                                                 */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_encrypted_from_secret(
    pass_ptr: *const u8,
    pass_len: u32,
    seed: *const u8,
    cc: *const u8,
    encrypted_key: *mut u8,
) -> c_int {
    unsafe {
        let seed: [u8; 32] = super::read_array(seed);
        let cc: [u8; 32] = super::read_array(cc);
        match XPrv::from_secret(&seed, &cc, pass(pass_ptr, pass_len)) {
            Some(k) => {
                super::write_bytes(encrypted_key, k.as_bytes());
                0
            }
            None => 1,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_encrypted_new_from_mkg(
    pass_ptr: *const u8,
    pass_len: u32,
    master_key: *const u8,
    encrypted_key: *mut u8,
) -> c_int {
    unsafe {
        let mut master: [u8; 96] = super::read_array(master_key);
        let k = XPrv::from_master_key(&master, pass(pass_ptr, pass_len));
        crate::ed25519::wipe(&mut master);
        super::write_bytes(encrypted_key, k.as_bytes());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_encrypted_sign(
    encrypted_key: *const u8,
    pass_ptr: *const u8,
    pass_len: u32,
    data: *const u8,
    data_len: u32,
    signature: *mut u8,
) {
    unsafe {
        let k = read_xprv(encrypted_key);
        let sig = k.sign(
            pass(pass_ptr, pass_len),
            super::as_slice(data, data_len as usize),
        );
        super::write_bytes(signature, sig.as_bytes());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_encrypted_change_pass(
    input: *const u8,
    old_pass: *const u8,
    old_pass_len: u32,
    new_pass: *const u8,
    new_pass_len: u32,
    out: *mut u8,
) {
    unsafe {
        let k = read_xprv(input);
        let k = k.change_passphrase(pass(old_pass, old_pass_len), pass(new_pass, new_pass_len));
        super::write_bytes(out, k.as_bytes());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_encrypted_derive_private(
    input: *const u8,
    pass_ptr: *const u8,
    pass_len: u32,
    index: u32,
    out: *mut u8,
    mode: c_int,
) {
    unsafe {
        let k = read_xprv(input);
        let child = k.derive(scheme(mode), pass(pass_ptr, pass_len), index);
        super::write_bytes(out, child.as_bytes());
    }
}

/// When the parent verification key does not decode, the C code ignores the
/// failure of the point addition and leaves `pub_out` as it was; so does this.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_encrypted_derive_public(
    pub_in: *const u8,
    cc_in: *const u8,
    index: u32,
    pub_out: *mut u8,
    cc_out: *mut u8,
    mode: c_int,
) -> c_int {
    unsafe {
        if index >= HARDENED_INDEX {
            return 1;
        }
        let mut xpub = [0u8; XPUB_SIZE];
        xpub[..32].copy_from_slice(&super::read_array::<32>(pub_in));
        xpub[32..].copy_from_slice(&super::read_array::<32>(cc_in));
        let (child_pk, child_cc) = donna::derive_public(&xpub, scheme(mode), index);
        if let Some(pk) = child_pk {
            super::write_bytes(pub_out, &pk);
        }
        super::write_bytes(cc_out, &child_cc);
        0
    }
}

/* ---------------------------------------------------------------- */
/* ed25519-donna                                                    */
/* ---------------------------------------------------------------- */

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cardano_crypto_ed25519_publickey(sk: *const u8, pk: *mut u8) {
    unsafe {
        super::write_bytes(pk, &donna::publickey(&super::read_array(sk)));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cardano_crypto_ed25519_sign_open(
    m: *const u8,
    mlen: usize,
    pk: *const u8,
    rs: *const u8,
) -> c_int {
    unsafe {
        let ok = donna::sign_open(
            &super::read_array(pk),
            super::as_slice(m, mlen),
            &super::read_array(rs),
        );
        if ok { 0 } else { -1 }
    }
}

/// The salt is unused, as it is in the C code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cardano_crypto_ed25519_sign(
    m: *const u8,
    mlen: usize,
    _salt: *const u8,
    _slen: usize,
    sk: *const u8,
    pk: *const u8,
    rs: *mut u8,
) {
    unsafe {
        let mut secret: [u8; 64] = super::read_array(sk);
        let sig = donna::sign(&secret, &super::read_array(pk), super::as_slice(m, mlen));
        crate::ed25519::wipe(&mut secret);
        super::write_bytes(rs, &sig);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cardano_crypto_ed25519_scalar_add(
    sk1: *const u8,
    sk2: *const u8,
    res: *mut u8,
) -> c_int {
    unsafe {
        let sum = donna::scalar_add(&super::read_array(sk1), &super::read_array(sk2));
        super::write_bytes(res, &sum);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cardano_crypto_ed25519_point_add(
    pk1: *const u8,
    pk2: *const u8,
    res: *mut u8,
) -> c_int {
    unsafe {
        match donna::point_add(&super::read_array(pk1), &super::read_array(pk2)) {
            Some(sum) => {
                super::write_bytes(res, &sum);
                0
            }
            None => -1,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cardano_crypto_ed25519_extend(seed: *const u8, secret: *mut u8) -> c_int {
    unsafe {
        let (mut extended, valid) = donna::extend(&super::read_array(seed));
        super::write_bytes(secret, &extended);
        crate::ed25519::wipe(&mut extended);
        if valid { 0 } else { 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byron;

    /// The C entry points agree with the Rust API along a derivation path.
    #[test]
    fn matches_rust_api() {
        let pass = b"pw";
        let key = byron::generate_new(&[3u8; 32], b"", pass);
        for mode in [1, 2] {
            let rust = key
                .derive(scheme(mode), pass, 0x8000_0001)
                .derive(scheme(mode), pass, 7);
            let mut hard = [0u8; 128];
            let mut child = [0u8; 128];
            let mut sig = [0u8; 64];
            let mut pk = [0u8; 32];
            let mut cc = [0u8; 32];
            unsafe {
                wallet_encrypted_derive_private(
                    key.as_bytes().as_ptr(),
                    pass.as_ptr(),
                    2,
                    0x8000_0001,
                    hard.as_mut_ptr(),
                    mode,
                );
                wallet_encrypted_derive_private(
                    hard.as_ptr(),
                    pass.as_ptr(),
                    2,
                    7,
                    child.as_mut_ptr(),
                    mode,
                );
                wallet_encrypted_sign(
                    child.as_ptr(),
                    pass.as_ptr(),
                    2,
                    b"msg".as_ptr(),
                    3,
                    sig.as_mut_ptr(),
                );
                assert_eq!(
                    wallet_encrypted_derive_public(
                        hard[64..].as_ptr(),
                        hard[96..].as_ptr(),
                        7,
                        pk.as_mut_ptr(),
                        cc.as_mut_ptr(),
                        mode
                    ),
                    0
                );
                assert_eq!(
                    cardano_crypto_ed25519_sign_open(b"msg".as_ptr(), 3, pk.as_ptr(), sig.as_ptr()),
                    0
                );
            }
            assert_eq!(child[..], rust.as_bytes()[..]);
            assert_eq!(sig, *rust.sign(pass, b"msg").as_bytes());
            assert_eq!(pk[..], child[64..96]);
            assert_eq!(cc[..], child[96..]);
        }
    }
}

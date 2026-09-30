//! Byron-era signing keys: the extended Ed25519 keys of `cardano-crypto`.
//!
//! Every Byron signature — block headers, delegation certificates, transaction
//! witnesses, update proposals and votes — is made with a
//! `Cardano.Crypto.Wallet.XPrv` and checked against an `XPub`, which is what
//! `cardano-crypto-wrapper`'s `SigningKey` and `VerificationKey` wrap. This
//! module reproduces that package (`cbits/encrypted_sign.c` and its vendored
//! ed25519-donna) byte for byte:
//!
//! * an [`XPrv`] is 128 bytes: the 64-byte extended secret, encrypted under a
//!   passphrase (in the clear when the passphrase is empty, which is how the
//!   node's own keys are held), the 32-byte verification key and the 32-byte
//!   chain code;
//! * an [`XPub`] is 64 bytes: the verification key and the chain code;
//! * signing uses the extended secret directly (no seed hashing), with the
//!   scalar reduced mod l first, as ed25519-donna does;
//! * [`generate`] and [`generate_new`] are the two master key generations
//!   (`Wallet.generate`, `Wallet.generateNew`), and [`XPrv::derive`] /
//!   [`XPub::derive`] the two derivation schemes, including the bugs of
//!   [`DerivationScheme::V1`] that are part of every Byron-era address;
//! * [`verify`] is `Wallet.verify`, which is crypton's `Ed25519.verify`, and
//!   also what checks the plain Ed25519 signatures of AVVM redeem keys.
//!
//! # Verification is not the node's Shelley verification
//!
//! Byron signatures are checked by crypton's ed25519-donna rather than by
//! libsodium, and the two disagree on edge cases. [`verify`] (like donna):
//!
//! 1. rejects an `s` with any of its top 3 bits set, or that is not reduced
//!    mod l;
//! 2. decodes the verification key *without* rejecting a non-canonical
//!    encoding (y >= p) or a point of small order;
//! 3. places no restriction on `R` beyond the final comparison, so a
//!    small-order `R` is accepted;
//! 4. compares `R` to `[s]B - [k]A` byte for byte, so a non-canonically
//!    encoded `R` never matches.
//!
//! [`crate::ed25519::verify`] rejects points 2 and 3, so using it on Byron
//! data would reject blocks the node accepts.

use eccoxide::curve::curve25519::{Point, Scalar};
use eccoxide::curve::field::Sign;

use crate::ed25519::{PublicKey, Signature, wipe};
use crate::edwards25519 as ed;
use crate::hash::sha512;

/// Size of a serialised [`XPrv`].
pub const XPRV_SIZE: usize = 128;
/// Size of a serialised [`XPub`].
pub const XPUB_SIZE: usize = 64;
/// Size of a chain code.
pub const CHAIN_CODE_SIZE: usize = 32;
/// Size of the (possibly encrypted) extended secret at the start of an
/// [`XPrv`].
pub const EXTENDED_SECRET_SIZE: usize = 64;
/// Size of the output of the master key generation that
/// [`XPrv::from_master_key`] takes.
pub const MASTER_KEY_SIZE: usize = 96;

/// Derivation indices at or above this one are hardened.
pub const HARDENED_INDEX: u32 = 0x8000_0000;

/// The two BIP32-Ed25519 derivation schemes of `cardano-crypto`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DerivationScheme {
    /// `DerivationScheme1`, used by Byron-era (Daedalus "random") wallets.
    ///
    /// It has three bugs that are reproduced here because the chain is full of
    /// addresses derived with them: the multiplication of `ZL` by 8 drops the
    /// bits carried between bytes, the addition of the right halves drops the
    /// carry between bytes, and the index is serialised big-endian.
    V1,
    /// `DerivationScheme2`, the BIP32-Ed25519 of Icarus and Shelley.
    V2,
}

/// A `Cardano.Crypto.Wallet.XPrv`: the extended secret (encrypted under the
/// key's passphrase), the verification key and the chain code.
#[derive(Clone)]
pub struct XPrv([u8; XPRV_SIZE]);

/// A `Cardano.Crypto.Wallet.XPub`: the verification key and the chain code.
///
/// This is what a Byron `VerificationKey` is, and what Byron addresses and
/// genesis delegation certificates commit to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct XPub([u8; XPUB_SIZE]);

impl Drop for XPrv {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// A 64-byte extended secret held in the clear, wiped on drop.
struct Secret([u8; EXTENDED_SECRET_SIZE]);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Secret {
    /// `cardano_crypto_ed25519_publickey`: the scalar is reduced mod l before
    /// multiplying, so a derived key whose left half exceeds l still has a
    /// well-defined verification key.
    fn public(&self) -> [u8; 32] {
        public_from_scalar_bytes(&self.left())
    }

    fn left(&self) -> [u8; 32] {
        let mut l = [0u8; 32];
        l.copy_from_slice(&self.0[..32]);
        l
    }

    /// `cardano_crypto_ed25519_sign` with `VARIANT_CODE`: an ordinary Ed25519
    /// signature, except that the secret is the extended key itself.
    fn sign(&self, message: &[u8]) -> Signature {
        self.sign_with(&self.public(), message)
    }

    /// Sign with `public` as the key hashed into the challenge, which the C
    /// function takes as an argument rather than deriving.
    fn sign_with(&self, public: &[u8; 32], message: &[u8]) -> Signature {
        let a = ed::scalar_reduce(&self.left());

        let mut ctx = cryptoxide::hashing::sha2::Context512::new();
        ctx.update_mut(&self.0[32..]);
        ctx.update_mut(message);
        let r = ed::scalar_reduce_wide(&ctx.finalize());
        let big_r = ed::point_encode(&Point::mul_base(&r));

        let h = hram(&big_r, public, message);
        let s = &(&h * &a) + &r;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&ed::scalar_to_bytes(&s));
        Signature::from_bytes(sig)
    }
}

fn public_from_scalar_bytes(k: &[u8; 32]) -> [u8; 32] {
    ed::point_encode(&Point::mul_base(&ed::scalar_reduce(k)))
}

/// `H(R || A || M)` reduced mod l.
fn hram(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> Scalar {
    let mut ctx = cryptoxide::hashing::sha2::Context512::new();
    ctx.update_mut(r);
    ctx.update_mut(a);
    ctx.update_mut(message);
    ed::scalar_reduce_wide(&ctx.finalize())
}

/// `memory_combine`: the in-memory encryption of the extended secret.
///
/// With an empty passphrase the secret is stored in the clear. Otherwise the
/// passphrase is stretched with PBKDF2-HMAC-SHA512 (15000 iterations, salt
/// `"encrypted wallet salt"` *including* its NUL terminator) into a 32-byte key
/// and an 8-byte nonce for the original (64-bit nonce) ChaCha20, whose
/// keystream is XORed in. The operation is its own inverse.
fn combine(passphrase: &[u8], data: &mut [u8; EXTENDED_SECRET_SIZE]) {
    if passphrase.is_empty() {
        return;
    }
    const SALT: &[u8] = b"encrypted wallet salt\0";
    let mut buf = [0u8; 40];
    cryptoxide::pbkdf2::pbkdf2::<cryptoxide::hashing::sha2::Sha512>(
        passphrase, SALT, 15000, &mut buf,
    );
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&buf[32..]);
    let mut cipher = cryptoxide::chacha20::ChaChaOriginal::<20>::new(&buf[..32], &nonce);
    wipe(&mut buf);
    cipher.process_mut(data);
}

/// `ed25519_extsk` and the check of `cardano_crypto_ed25519_extend`: the
/// usual Ed25519 expansion of a seed, refused when bit 253 is set.
fn extend(seed: &[u8; 32]) -> Option<Secret> {
    let mut secret = Secret(sha512(seed));
    secret.0[0] &= 248;
    secret.0[31] &= 127;
    secret.0[31] |= 64;
    if secret.0[31] & 0x20 != 0 {
        return None;
    }
    Some(secret)
}

type HmacSha512 = cryptoxide::hmac::Context<cryptoxide::hashing::sha2::Sha512>;

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut ctx = HmacSha512::new(key);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 64];
    ctx.finalize_at(&mut out);
    out
}

/// `Wallet.generate`: the legacy ("retry-old") master key generation, used by
/// Byron genesis and by `cardano-crypto-wrapper`'s key generation.
///
/// `HMAC-SHA512(seed, "Root Seed Chain " ++ show i)` for `i = 1, 2, ...` gives a
/// 32-byte Ed25519 seed and a chain code; the first `i` whose expanded seed has
/// bit 253 clear wins. Returns `None` for a seed shorter than 32 bytes, where
/// `Wallet.generate` calls `error`.
pub fn generate(seed: &[u8], passphrase: &[u8]) -> Option<XPrv> {
    if seed.len() < 32 {
        return None;
    }
    // `Wallet.generate` gives up (with `error`) after 1000 attempts; each one
    // succeeds with probability 1/2, so that never happens.
    for i in 1..=1000u32 {
        let phrase = format!("Root Seed Chain {i}");
        let mut out = hmac_sha512(seed, &[phrase.as_bytes()]);
        let mut ed_seed = [0u8; 32];
        ed_seed.copy_from_slice(&out[..32]);
        let mut cc = [0u8; 32];
        cc.copy_from_slice(&out[32..]);
        wipe(&mut out);
        let key = XPrv::from_secret(&ed_seed, &cc, passphrase);
        wipe(&mut ed_seed);
        if key.is_some() {
            return key;
        }
    }
    None
}

/// `Wallet.generateNew`: the Icarus master key generation.
///
/// `PBKDF2-HMAC-SHA512(generation_passphrase, seed, 4096 iterations, 96 bytes)`
/// fed to [`XPrv::from_master_key`], encrypted under `passphrase`.
pub fn generate_new(seed: &[u8], generation_passphrase: &[u8], passphrase: &[u8]) -> XPrv {
    let mut out = [0u8; MASTER_KEY_SIZE];
    cryptoxide::pbkdf2::pbkdf2::<cryptoxide::hashing::sha2::Sha512>(
        generation_passphrase,
        seed,
        4096,
        &mut out,
    );
    let key = XPrv::from_master_key(&out, passphrase);
    wipe(&mut out);
    key
}

impl XPrv {
    /// Read an `XPrv` from its 128-byte serialisation (`Wallet.xprv`).
    ///
    /// Like `Wallet.xprv`, nothing but the size is checked.
    pub fn from_bytes(bytes: [u8; XPRV_SIZE]) -> Self {
        XPrv(bytes)
    }

    /// Read an `XPrv` from a slice of exactly 128 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(XPrv(bytes.try_into().ok()?))
    }

    /// The 128-byte serialisation (`Wallet.unXPrv`).
    pub fn as_bytes(&self) -> &[u8; XPRV_SIZE] {
        &self.0
    }

    /// `encryptedCreate` / `wallet_encrypted_from_secret`: an `XPrv` from a
    /// 32-byte Ed25519 seed, expanded the usual way.
    ///
    /// Returns `None` when bit 253 of the expanded scalar is set, which BIP32
    /// Ed25519 excludes so that derived keys cannot overflow.
    pub fn from_secret(
        seed: &[u8; 32],
        chain_code: &[u8; CHAIN_CODE_SIZE],
        passphrase: &[u8],
    ) -> Option<Self> {
        let secret = extend(seed)?;
        Some(Self::initialize(passphrase, secret, chain_code))
    }

    /// `encryptedCreateDirectWithTweak` / `wallet_encrypted_new_from_mkg`: an
    /// `XPrv` from 96 bytes of master key material (extended secret, then chain
    /// code), clamping the secret and clearing bit 253.
    pub fn from_master_key(master: &[u8; MASTER_KEY_SIZE], passphrase: &[u8]) -> Self {
        let mut secret = Secret([0u8; EXTENDED_SECRET_SIZE]);
        secret.0.copy_from_slice(&master[..64]);
        secret.0[0] &= 248;
        secret.0[31] &= 0x1f;
        secret.0[31] |= 64;
        let mut cc = [0u8; CHAIN_CODE_SIZE];
        cc.copy_from_slice(&master[64..]);
        Self::initialize(passphrase, secret, &cc)
    }

    /// `wallet_encrypted_initialize`.
    fn initialize(passphrase: &[u8], secret: Secret, chain_code: &[u8; CHAIN_CODE_SIZE]) -> Self {
        let public = secret.public();
        let mut out = [0u8; XPRV_SIZE];
        let mut ekey = [0u8; EXTENDED_SECRET_SIZE];
        ekey.copy_from_slice(&secret.0);
        combine(passphrase, &mut ekey);
        out[..64].copy_from_slice(&ekey);
        out[64..96].copy_from_slice(&public);
        out[96..].copy_from_slice(chain_code);
        XPrv(out)
    }

    /// The extended secret, decrypted with `passphrase`.
    ///
    /// A wrong passphrase is not detected: it yields a different secret, as it
    /// does in `cardano-crypto`.
    fn decrypt(&self, passphrase: &[u8]) -> Secret {
        let mut secret = Secret([0u8; EXTENDED_SECRET_SIZE]);
        secret.0.copy_from_slice(&self.0[..64]);
        combine(passphrase, &mut secret.0);
        secret
    }

    /// The stored verification key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_slice(&self.0[64..96]).expect("32 bytes")
    }

    /// The chain code.
    pub fn chain_code(&self) -> [u8; CHAIN_CODE_SIZE] {
        self.0[96..].try_into().expect("32 bytes")
    }

    /// `Wallet.toXPub`: the stored verification key and chain code.
    pub fn to_xpub(&self) -> XPub {
        XPub(self.0[64..].try_into().expect("64 bytes"))
    }

    /// `Wallet.sign` / `wallet_encrypted_sign`.
    ///
    /// The verification key hashed into the challenge is recomputed from the
    /// decrypted secret, not read from the key: with the wrong passphrase the
    /// result is a valid signature under some other key.
    pub fn sign(&self, passphrase: &[u8], message: &[u8]) -> Signature {
        self.decrypt(passphrase).sign(message)
    }

    /// `Wallet.xPrvChangePass`: re-encrypt the secret under a new passphrase.
    pub fn change_passphrase(&self, old: &[u8], new: &[u8]) -> Self {
        let secret = self.decrypt(old);
        let mut out = self.0;
        let mut ekey = [0u8; EXTENDED_SECRET_SIZE];
        ekey.copy_from_slice(&secret.0);
        combine(new, &mut ekey);
        out[..64].copy_from_slice(&ekey);
        wipe(&mut ekey);
        XPrv(out)
    }

    /// `Wallet.deriveXPrv` / `wallet_encrypted_derive_private`: the child key
    /// at `index` (hardened when `index >= HARDENED_INDEX`), encrypted under
    /// the same passphrase.
    pub fn derive(&self, scheme: DerivationScheme, passphrase: &[u8], index: u32) -> Self {
        let parent = self.decrypt(passphrase);
        let idx = serialize_index(index, scheme);
        let cc = self.chain_code();

        // A hardened child commits to the secret, a normal one to the stored
        // verification key.
        let (z_tag, cc_tag, input): (u8, u8, &[u8]) = if index >= HARDENED_INDEX {
            (0x00, 0x01, &parent.0[..])
        } else {
            (0x02, 0x03, &self.0[64..96])
        };
        let mut z = hmac_sha512(&cc, &[&[z_tag], input, &idx]);
        let mut child_cc_full = hmac_sha512(&cc, &[&[cc_tag], input, &idx]);

        let mut child = Secret([0u8; EXTENDED_SECRET_SIZE]);
        let zl8 = multiply8(&z, scheme);
        let left: [u8; 32] = match scheme {
            // cardano_crypto_ed25519_scalar_add: both reduced mod l, sum
            // reduced mod l
            DerivationScheme::V1 => {
                let mut zl8_32 = [0u8; 32];
                zl8_32.copy_from_slice(&zl8[..32]);
                let s = &ed::scalar_reduce(&zl8_32) + &ed::scalar_reduce(&parent.left());
                ed::scalar_to_bytes(&s)
            }
            // scalar_add_no_overflow: plain 256-bit addition, carry out dropped
            DerivationScheme::V2 => add_256(&zl8[..32], &parent.0[..32], true),
        };
        child.0[..32].copy_from_slice(&left);
        // Kr = Zr + parent Kr, with (V2) or without (V1) carries between bytes
        let right = add_256(&z[32..], &parent.0[32..], scheme == DerivationScheme::V2);
        child.0[32..].copy_from_slice(&right);

        let mut child_cc = [0u8; CHAIN_CODE_SIZE];
        child_cc.copy_from_slice(&child_cc_full[32..]);
        wipe(&mut z);
        wipe(&mut child_cc_full);
        Self::initialize(passphrase, child, &child_cc)
    }
}

impl XPub {
    /// Read an `XPub` from its 64-byte serialisation (`Wallet.xpub`).
    pub fn from_bytes(bytes: [u8; XPUB_SIZE]) -> Self {
        XPub(bytes)
    }

    /// Read an `XPub` from a slice of exactly 64 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(XPub(bytes.try_into().ok()?))
    }

    /// The 64-byte serialisation (`Wallet.unXPub`).
    pub fn as_bytes(&self) -> &[u8; XPUB_SIZE] {
        &self.0
    }

    /// The verification key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_slice(&self.0[..32]).expect("32 bytes")
    }

    /// The chain code.
    pub fn chain_code(&self) -> [u8; CHAIN_CODE_SIZE] {
        self.0[32..].try_into().expect("32 bytes")
    }

    /// `Wallet.verify`: see [`verify`].
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        verify(&self.public_key(), message, signature)
    }

    /// `Wallet.deriveXPub` / `wallet_encrypted_derive_public`: the normal
    /// child at `index`.
    ///
    /// Returns `None` for a hardened index, which needs the secret, and for a
    /// verification key that does not decode (where the C code leaves the
    /// output uninitialised).
    pub fn derive(&self, scheme: DerivationScheme, index: u32) -> Option<Self> {
        if index >= HARDENED_INDEX {
            return None;
        }
        let (child_pk, child_cc) = derive_public(&self.0, scheme, index);
        let mut out = [0u8; XPUB_SIZE];
        out[..32].copy_from_slice(&child_pk?);
        out[32..].copy_from_slice(&child_cc);
        Some(XPub(out))
    }
}

/// The normal-index half of `wallet_encrypted_derive_public`: the child
/// verification key (if the parent's decodes) and the child chain code.
fn derive_public(
    xpub: &[u8; XPUB_SIZE],
    scheme: DerivationScheme,
    index: u32,
) -> (Option<[u8; 32]>, [u8; CHAIN_CODE_SIZE]) {
    let idx = serialize_index(index, scheme);
    let (pk, cc) = xpub.split_at(32);
    let z = hmac_sha512(cc, &[&[0x02], pk, &idx]);
    let child_cc = hmac_sha512(cc, &[&[0x03], pk, &idx]);

    let zl8 = multiply8(&z, scheme);
    let zl8: [u8; 32] = zl8[..32].try_into().expect("32 bytes");
    let pk: [u8; 32] = pk.try_into().expect("32 bytes");
    let child_pk = point_add(&public_from_scalar_bytes(&zl8), &pk);
    (child_pk, child_cc[32..].try_into().expect("32 bytes"))
}

fn serialize_index(index: u32, scheme: DerivationScheme) -> [u8; 4] {
    match scheme {
        DerivationScheme::V1 => index.to_be_bytes(),
        DerivationScheme::V2 => index.to_le_bytes(),
    }
}

/// `8 * ZL`, as a 64-byte little-endian buffer whose upper half is zero.
///
/// `multiply8_v1` shifts all 32 bytes of `ZL` left by 3 but masks the bits
/// carried in from the previous byte with `& 0x8`, which is always zero, so
/// they are lost. `multiply8_v2` multiplies the first 28 bytes correctly, into
/// 29.
fn multiply8(z: &[u8; 64], scheme: DerivationScheme) -> [u8; 64] {
    let mut out = [0u8; 64];
    match scheme {
        DerivationScheme::V1 => {
            for i in 0..32 {
                out[i] = z[i] << 3;
            }
        }
        DerivationScheme::V2 => {
            let mut prev = 0u8;
            for i in 0..28 {
                out[i] = (z[i] << 3) | (prev & 0x7);
                prev = z[i] >> 5;
            }
            out[28] = z[27] >> 5;
        }
    }
    out
}

/// Byte-wise little-endian addition of two 32-byte numbers, dropping the final
/// carry and, unless `carry` (`add_256bits_v1`), every carry between bytes.
fn add_256(a: &[u8], b: &[u8], carry: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut c = 0u16;
    for i in 0..32 {
        let r = u16::from(a[i]) + u16::from(b[i]) + c;
        out[i] = r as u8;
        c = if carry { r >> 8 } else { 0 };
    }
    out
}

/// `ge25519_unpack_negative_vartime`: decode the *negation* of an encoded
/// point.
///
/// Like `ref10`, donna ignores the top bit of y and reduces it mod p, so
/// non-canonical encodings decode; and it never rejects "negative zero" (x = 0
/// with the sign bit set), which it decodes like the positive one.
fn unpack_negative(bytes: &[u8; 32]) -> Option<Point> {
    let y = ed::fe_from_bytes(bytes);
    // p0 is the point with an even x; the encoding names p0 when its sign bit
    // is clear and -p0 when it is set (for x = 0 the two coincide).
    let p0 = Point::decompress(&y, Sign::Positive)?;
    Some(if bytes[31] & 0x80 != 0 { p0 } else { -p0 })
}

/// `cardano_crypto_ed25519_point_add`: decode both points negated, add them,
/// and flip the sign bit of the encoded (negated) sum.
///
/// When the sum has x = 0 this produces the "negative zero" encoding, which is
/// what donna does too.
fn point_add(p: &[u8; 32], q: &[u8; 32]) -> Option<[u8; 32]> {
    let p = unpack_negative(p)?;
    let q = unpack_negative(q)?;
    let mut out = ed::point_encode(&(&p + &q));
    out[31] ^= 0x80;
    Some(out)
}

/// ed25519-donna's `ed25519_sign_open`, with or without crypton's check that
/// `s` is reduced mod l.
fn donna_verify(public_key: &[u8; 32], message: &[u8], sig: &[u8; 64], canonical_s: bool) -> bool {
    if sig[63] & 0xe0 != 0 {
        return false;
    }
    let Some(neg_a) = unpack_negative(public_key) else {
        return false;
    };
    let r: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    let s = if canonical_s {
        match ed::scalar_from_canonical_bytes(&s_bytes) {
            Some(s) => s,
            None => return false,
        }
    } else {
        ed::scalar_reduce(&s_bytes)
    };
    let h = hram(&r, public_key, message);
    ed::point_encode(&ed::double_scalarmult_base(&h, &neg_a, &s)) == r
}

/// `Wallet.verify`, i.e. crypton's `Crypto.PubKey.Ed25519.verify`: how the
/// node checks every Byron signature, and the plain Ed25519 signatures of AVVM
/// redeem keys (`Cardano.Crypto.Signing.Redeem`).
///
/// See the [module documentation](self) for how this differs from
/// [`crate::ed25519::verify`].
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    donna_verify(public_key.as_bytes(), message, signature.as_bytes(), true)
}

/// The primitives of `cardano-crypto`'s `cbits/ed25519/ed25519.c`, for the C
/// ABI, which exports them under their C names.
#[cfg(feature = "capi")]
pub(crate) mod donna {
    use super::*;

    pub(crate) fn publickey(sk: &[u8; 32]) -> [u8; 32] {
        public_from_scalar_bytes(sk)
    }

    pub(crate) fn sign(sk: &[u8; 64], pk: &[u8; 32], message: &[u8]) -> [u8; 64] {
        *Secret(*sk).sign_with(pk, message).as_bytes()
    }

    /// `cardano_crypto_ed25519_sign_open`: unlike crypton's copy, this donna
    /// does not require `s` to be reduced.
    pub(crate) fn sign_open(pk: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
        donna_verify(pk, message, sig, false)
    }

    pub(crate) fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        ed::scalar_to_bytes(&(&ed::scalar_reduce(a) + &ed::scalar_reduce(b)))
    }

    pub(crate) fn point_add(p: &[u8; 32], q: &[u8; 32]) -> Option<[u8; 32]> {
        super::point_add(p, q)
    }

    /// `cardano_crypto_ed25519_extend`, which writes the expanded secret even
    /// when it then reports it invalid.
    pub(crate) fn extend(seed: &[u8; 32]) -> ([u8; 64], bool) {
        let mut secret = sha512(seed);
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        let valid = secret[31] & 0x20 == 0;
        (secret, valid)
    }

    pub(crate) fn derive_public(
        xpub: &[u8; XPUB_SIZE],
        scheme: DerivationScheme,
        index: u32,
    ) -> (Option<[u8; 32]>, [u8; CHAIN_CODE_SIZE]) {
        super::derive_public(xpub, scheme, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::SecretKey;
    use crate::testutil::hex_array;

    fn key() -> XPrv {
        generate(&[7u8; 32], b"").expect("seed is long enough")
    }

    #[test]
    fn sign_verify_roundtrip() {
        let k = key();
        let sig = k.sign(b"", b"message");
        assert!(k.to_xpub().verify(b"message", &sig));
        assert!(!k.to_xpub().verify(b"messagf", &sig));
    }

    #[test]
    fn stored_public_key_matches_secret() {
        let k = key();
        assert_eq!(*k.public_key().as_bytes(), k.decrypt(b"").public());
    }

    #[test]
    fn short_seed_is_refused() {
        assert!(generate(&[0u8; 31], b"").is_none());
    }

    #[test]
    fn passphrase_roundtrip() {
        let clear = key();
        let enc = clear.change_passphrase(b"", b"secret");
        assert_ne!(enc.as_bytes()[..64], clear.as_bytes()[..64]);
        assert_eq!(enc.as_bytes()[64..], clear.as_bytes()[64..]);
        assert_eq!(enc.sign(b"secret", b"m"), clear.sign(b"", b"m"));
        assert_eq!(
            enc.change_passphrase(b"secret", b"").as_bytes(),
            clear.as_bytes()
        );
    }

    #[test]
    fn public_derivation_matches_private() {
        for scheme in [DerivationScheme::V1, DerivationScheme::V2] {
            let k = key();
            for index in [0u32, 1, 42, HARDENED_INDEX - 1] {
                let child = k.derive(scheme, b"", index);
                let pub_child = k.to_xpub().derive(scheme, index).expect("normal index");
                assert_eq!(child.to_xpub(), pub_child, "{scheme:?} {index}");
            }
            assert!(k.to_xpub().derive(scheme, HARDENED_INDEX).is_none());
        }
    }

    #[test]
    fn redeem_keys_verify() {
        // AVVM redeem keys are plain RFC 8032 keys
        let sk = SecretKey::from_bytes([5u8; 32]);
        let sig = sk.sign(b"redeem");
        assert!(verify(&sk.public(), b"redeem", &sig));
    }

    fn sig_with_s(sig: &Signature, s: &[u8; 32]) -> Signature {
        let mut b = *sig.as_bytes();
        b[32..].copy_from_slice(s);
        Signature::from_bytes(b)
    }

    #[test]
    fn rejects_unreduced_s() {
        let k = key();
        let sig = k.sign(b"", b"m");
        // s + l, still below 2^253
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let s = add_256(&sig.as_bytes()[32..], &L, true);
        assert_eq!(s[31] & 0xe0, 0);
        let malleated = sig_with_s(&sig, &s);
        assert!(!k.to_xpub().verify(b"m", &malleated));
        // cardano-crypto's own donna has no such check
        let pk = *k.public_key().as_bytes();
        assert!(donna_verify(&pk, b"m", malleated.as_bytes(), false));
    }

    #[test]
    fn accepts_small_order_key_and_r() {
        // with A = identity and R = identity, [s]B - [k]A = R for s = 0
        let identity =
            hex_array::<32>("0100000000000000000000000000000000000000000000000000000000000000");
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity);
        let sig = Signature::from_bytes(sig);
        let pk = PublicKey::from_bytes(identity);
        assert!(verify(&pk, b"anything", &sig));
        assert!(!crate::ed25519::verify(&pk, b"anything", &sig));
    }

    #[test]
    fn accepts_non_canonical_key() {
        // p + 1 encodes the identity non-canonically
        let pk = PublicKey::from_bytes(hex_array::<32>(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ));
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let sig = Signature::from_bytes(sig);
        assert!(verify(&pk, b"anything", &sig));
        assert!(!crate::ed25519::verify(&pk, b"anything", &sig));
    }

    #[test]
    fn accepts_negative_zero_key() {
        // the identity with the sign bit set
        let pk = PublicKey::from_bytes(hex_array::<32>(
            "0100000000000000000000000000000000000000000000000000000000000080",
        ));
        let mut sig = [0u8; 64];
        sig[0] = 1;
        assert!(verify(&pk, b"anything", &Signature::from_bytes(sig)));
    }

    #[test]
    fn rejects_non_canonical_r() {
        // R = p + 1 would be the identity, but R is compared byte for byte
        let pk = PublicKey::from_bytes(hex_array::<32>(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ));
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&hex_array::<32>(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ));
        assert!(!verify(&pk, b"anything", &Signature::from_bytes(sig)));
    }
}

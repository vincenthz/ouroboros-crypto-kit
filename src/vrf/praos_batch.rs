//! The batch-compatible VRF of `draft-irtf-cfrg-vrf-13`
//! (`PraosBatchCompatVRF` in `cardano-base`).
//!
//! This is a port of
//! `cardano-crypto-praos/cbits/vrf13_batchcompat/{prove,verify}.c`. Compared to
//! [`super::praos`] (draft-03):
//!
//! * the proof is 128 bytes and carries the two announcements `U` and `V`
//!   rather than the 16-byte challenge, so verification recomputes the
//!   challenge from the proof and then *compares* announcements — which is what
//!   makes batch verification possible;
//! * `hash_to_curve` is the RFC 9380 `encode_to_curve` (non-uniform) with
//!   `expand_message_xmd(SHA-512)` and DST
//!   `ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04`, instead of hashing straight
//!   into Elligator2;
//! * the verification key is part of the challenge input, and a `0x00` byte is
//!   appended to both the challenge and the output hash.

use super::{OUTPUT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SEED_SIZE, VrfError};
use crate::ed25519::wipe;
use crate::edwards25519 as ed;
use crate::hash::Sha512Context;
use eccoxide::curve::curve25519::Point;

/// Size of a batch-compatible proof.
pub const PROOF_SIZE: usize = 128;

const SUITE: u8 = 0x04;
const TWO: u8 = 0x02;
const THREE: u8 = 0x03;
const ZERO: u8 = 0x00;

/// The `hash_to_curve` domain separation tag, including the trailing suite
/// byte (40 bytes in total).
pub const H2C_DST: &[u8] = b"ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04";

/// A VRF signing key: seed followed by the verification key (64 bytes).
#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

/// A VRF verification key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

/// A batch-compatible VRF proof.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Proof([u8; PROOF_SIZE]);

/// A VRF output (`beta_string`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Output([u8; OUTPUT_SIZE]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl SecretKey {
    /// Derive a signing key from a seed.
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        let (scalar, _) = ed::expand_seed(seed);
        let public = ed::point_encode(&Point::mul_base(&scalar));
        let mut out = [0u8; SECRET_KEY_SIZE];
        out[..32].copy_from_slice(seed);
        out[32..].copy_from_slice(&public);
        SecretKey(out)
    }

    /// Read a signing key from its 64-byte serialisation (seed || key).
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> Self {
        SecretKey(*bytes)
    }

    /// The 64-byte serialisation of this key.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.0
    }

    /// The seed half of this key.
    pub fn seed(&self) -> &[u8] {
        &self.0[..32]
    }

    /// The verification key this signing key carries.
    pub fn public(&self) -> PublicKey {
        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        pk.copy_from_slice(&self.0[32..]);
        PublicKey(pk)
    }

    /// `crypto_vrf_ietfdraft13_prove_batchcompat`.
    pub fn prove(&self, alpha: &[u8]) -> Proof {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.0[..32]);
        let (x, truncated_hashed_sk) = ed::expand_seed(&seed);
        wipe(&mut seed);
        let pk = &self.0[32..];

        let h_string = hash_to_curve(pk, alpha);
        let h_point = ed::point_decode(&h_string).expect("hash_to_curve output decodes");
        let gamma = h_point.scale(&x);

        let mut ctx = Sha512Context::new();
        ctx.update_mut(&truncated_hashed_sk);
        ctx.update_mut(&h_string);
        let k = ed::scalar_reduce_wide(&ctx.finalize());

        let kb_string = ed::point_encode(&Point::mul_base(&k));
        let kh_string = ed::point_encode(&h_point.scale(&k));
        let gamma_string = ed::point_encode(&gamma);

        let challenge = compute_challenge(pk, &h_string, &gamma_string, &kb_string, &kh_string);
        let mut c_bytes = [0u8; 32];
        c_bytes[..16].copy_from_slice(&challenge);
        let c = ed::scalar_reduce(&c_bytes);
        let s = &(&c * &x) + &k;

        let mut proof = [0u8; PROOF_SIZE];
        proof[..32].copy_from_slice(&gamma_string);
        proof[32..64].copy_from_slice(&kb_string);
        proof[64..96].copy_from_slice(&kh_string);
        proof[96..].copy_from_slice(&ed::scalar_to_bytes(&s));
        Proof(proof)
    }
}

impl PublicKey {
    /// Read a verification key from its 32 bytes.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }

    /// Read a verification key from a slice of exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, VrfError> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(VrfError::InvalidLength);
        }
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        out.copy_from_slice(bytes);
        Ok(PublicKey(out))
    }

    /// The 32 bytes of this key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Canonically encoded, on the curve, and not of small order.
    pub fn is_valid(&self) -> bool {
        self.decode().is_ok()
    }

    fn decode(&self) -> Result<Point, VrfError> {
        if ed::point_has_small_order(&self.0) || !ed::point_is_canonical(&self.0) {
            return Err(VrfError::InvalidKey);
        }
        ed::point_decode(&self.0).ok_or(VrfError::InvalidKey)
    }
}

impl Proof {
    /// Read a proof from its 128 bytes.
    pub fn from_bytes(bytes: [u8; PROOF_SIZE]) -> Self {
        Proof(bytes)
    }

    /// Read a proof from a slice of exactly 128 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, VrfError> {
        if bytes.len() != PROOF_SIZE {
            return Err(VrfError::InvalidLength);
        }
        let mut out = [0u8; PROOF_SIZE];
        out.copy_from_slice(bytes);
        Ok(Proof(out))
    }

    /// The 128 bytes of this proof.
    pub fn as_bytes(&self) -> &[u8; PROOF_SIZE] {
        &self.0
    }

    /// `crypto_vrf_ietfdraft13_proof_to_hash_batchcompat`:
    /// `beta = SHA512(suite || 0x03 || point_to_string(8 * gamma) || 0x00)`.
    pub fn to_hash(&self) -> Result<Output, VrfError> {
        let mut gamma_bytes = [0u8; 32];
        gamma_bytes.copy_from_slice(&self.0[..32]);
        if !ed::point_is_canonical(&gamma_bytes) {
            return Err(VrfError::InvalidProof);
        }
        let gamma = ed::point_decode(&gamma_bytes).ok_or(VrfError::InvalidProof)?;

        let mut s = [0u8; 32];
        s.copy_from_slice(&self.0[96..]);
        if (s[31] & 240) != 0 && !ed::scalar_is_canonical(&s) {
            return Err(VrfError::InvalidProof);
        }

        let mut ctx = Sha512Context::new();
        ctx.update_mut(&[SUITE, THREE]);
        ctx.update_mut(&ed::point_encode(&ed::clear_cofactor(&gamma)));
        ctx.update_mut(&[ZERO]);
        Ok(Output(ctx.finalize()))
    }
}

impl Output {
    /// Read an output from its 64 bytes.
    pub fn from_bytes(bytes: [u8; OUTPUT_SIZE]) -> Self {
        Output(bytes)
    }

    /// The 64 bytes of this output.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_SIZE] {
        &self.0
    }
}

/// `crypto_core_ed25519_from_string(DST, pk || alpha, SHA-512)`.
fn hash_to_curve(pk: &[u8], alpha: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(pk.len() + alpha.len());
    msg.extend_from_slice(pk);
    msg.extend_from_slice(alpha);
    ed::point_encode(&ed::hash_to_point_sha512(H2C_DST, &msg))
}

/// The 16-byte challenge:
/// `SHA512(suite || 0x02 || Y || H || Gamma || U || V || 0x00)[..16]`.
fn compute_challenge(
    pk: &[u8],
    h: &[u8; 32],
    gamma: &[u8; 32],
    u: &[u8; 32],
    v: &[u8; 32],
) -> [u8; 16] {
    let mut ctx = Sha512Context::new();
    ctx.update_mut(&[SUITE, TWO]);
    ctx.update_mut(pk);
    ctx.update_mut(h);
    ctx.update_mut(gamma);
    ctx.update_mut(u);
    ctx.update_mut(v);
    ctx.update_mut(&[ZERO]);
    let full = ctx.finalize();
    let mut c = [0u8; 16];
    c.copy_from_slice(&full[..16]);
    c
}

/// `crypto_vrf_ietfdraft13_verify_batchcompat`.
pub fn verify(public_key: &PublicKey, proof: &Proof, alpha: &[u8]) -> Result<Output, VrfError> {
    let y = public_key.decode()?;

    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&proof.0[..32]);
    if !ed::point_is_canonical(&gamma_bytes) {
        return Err(VrfError::InvalidProof);
    }
    let gamma = ed::point_decode(&gamma_bytes).ok_or(VrfError::InvalidProof)?;

    let h_string = hash_to_curve(public_key.as_bytes(), alpha);

    let mut u_bytes = [0u8; 32];
    u_bytes.copy_from_slice(&proof.0[32..64]);
    let mut v_bytes = [0u8; 32];
    v_bytes.copy_from_slice(&proof.0[64..96]);

    let challenge = compute_challenge(
        public_key.as_bytes(),
        &h_string,
        &gamma_bytes,
        &u_bytes,
        &v_bytes,
    );

    let mut s = [0u8; 32];
    s.copy_from_slice(&proof.0[96..]);
    if (s[31] & 240) != 0 && !ed::scalar_is_canonical(&s) {
        return Err(VrfError::InvalidProof);
    }

    let mut c_bytes = [0u8; 32];
    c_bytes[..16].copy_from_slice(&challenge);
    let neg_c = -&ed::scalar_reduce(&c_bytes);
    let s_scalar = ed::scalar_reduce(&s);

    let h_point = ed::point_decode(&h_string).expect("hash_to_curve output decodes");
    let u = ed::double_scalarmult_base(&neg_c, &y, &s_scalar);
    let v = ed::double_scalarmult(&neg_c, &gamma, &s_scalar, &h_point);

    if ed::point_encode(&u) != u_bytes || ed::point_encode(&v) != v_bytes {
        return Err(VrfError::VerificationFailed);
    }
    proof.to_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{hex, hex_array};

    /// (seed, public key, proof, output, alpha), from
    /// cardano-base cardano-crypto-praos/test_vectors/vrf_ver13_*
    fn cardano_vectors() -> Vec<[&'static str; 5]> {
        vec![
            // standard_10
            [
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f762f5c178b68f0cddcc1157918edf45ec334ac8e8286601a3256c3bbf858edd94652eba1c4612e6fce762977a59420b451e12964adbe4fbecd58a7aeff5860afcafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
                "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
                "",
            ],
        ]
    }

    #[test]
    fn cardano_test_vectors() {
        for v in cardano_vectors() {
            let sk = SecretKey::from_seed(&hex_array::<32>(v[0]));
            let pk = sk.public();
            assert_eq!(pk.as_bytes()[..], hex(v[1])[..], "public key");

            let alpha = hex(v[4]);
            let proof = sk.prove(&alpha);
            assert_eq!(proof.as_bytes()[..], hex(v[2])[..], "proof");

            let output = verify(&pk, &proof, &alpha).expect("verifies");
            assert_eq!(output.as_bytes()[..], hex(v[3])[..], "output");
        }
    }

    #[test]
    fn roundtrip_and_negative_cases() {
        let sk = SecretKey::from_seed(&[7u8; 32]);
        let pk = sk.public();
        let proof = sk.prove(b"alpha");
        assert!(verify(&pk, &proof, b"alpha").is_ok());
        assert_eq!(
            verify(&pk, &proof, b"alphb").unwrap_err(),
            VrfError::VerificationFailed
        );

        // tampering with an announcement makes the announcements disagree
        let mut bad = *proof.as_bytes();
        bad[40] ^= 1;
        assert!(verify(&pk, &Proof::from_bytes(bad), b"alpha").is_err());
    }
}

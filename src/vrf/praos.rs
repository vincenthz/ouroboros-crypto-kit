//! `ECVRF-ED25519-SHA512-Elligator2`, `draft-irtf-cfrg-vrf-03`: the VRF that
//! has been securing Praos since Shelley (`PraosVRF` in `cardano-base`).
//!
//! This is a port of `cardano-crypto-praos/cbits/vrf03/{prove,verify}.c`. Two
//! details of that code are worth knowing, because they make it incompatible
//! with any implementation that follows the draft literally:
//!
//! * `hash_to_curve` clears the sign bit of the SHA-512 output *before*
//!   calling Elligator2, so the resulting point always has an even x
//!   coordinate. The draft only clears it inside the map.
//! * the challenge is 16 bytes, zero-extended to 32 for the `s = c*x + k`
//!   computation, and only those 16 bytes are compared during verification.
//!
//! ```
//! use ouroboros_crypto_kit::vrf::praos;
//!
//! let sk = praos::SecretKey::from_seed(&[42u8; 32]);
//! let pk = sk.public();
//! let proof = sk.prove(b"slot 1234");
//! let output = praos::verify(&pk, &proof, b"slot 1234").unwrap();
//! assert_eq!(output.as_bytes(), &proof.to_hash().unwrap().as_bytes()[..]);
//! ```

use super::{OUTPUT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SEED_SIZE, VrfError};
use crate::ed25519::wipe;
use crate::edwards25519 as ed;
use crate::hash::Sha512Context;
use eccoxide::curve::curve25519::Point;

/// Size of a draft-03 proof.
pub const PROOF_SIZE: usize = 80;

/// `suite_string` of `ECVRF-ED25519-SHA512-Elligator2`.
const SUITE: u8 = 0x04;
const ONE: u8 = 0x01;
const TWO: u8 = 0x02;
const THREE: u8 = 0x03;

/// A VRF signing key: the seed together with the verification key it derives,
/// which is how `cardano-base` serialises it (64 bytes).
#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

/// A VRF verification key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

/// A draft-03 VRF proof.
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
    /// `crypto_vrf_ietfdraft03_keypair_from_seed`.
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        let (scalar, _) = ed::expand_seed(seed);
        let public = ed::point_encode(&Point::mul_base(&scalar));
        let mut out = [0u8; SECRET_KEY_SIZE];
        out[..32].copy_from_slice(seed);
        out[32..].copy_from_slice(&public);
        SecretKey(out)
    }

    /// Read a signing key from its 64-byte serialisation (seed || key).
    ///
    /// The verification key half is not recomputed, matching the node, which
    /// trusts its own key file.
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

    /// `crypto_vrf_ietfdraft03_prove`: produce a proof for `alpha`.
    pub fn prove(&self, alpha: &[u8]) -> Proof {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.0[..32]);
        let (x, truncated_hashed_sk) = ed::expand_seed(&seed);
        wipe(&mut seed);
        let pk = &self.0[32..];

        let h_string = hash_to_curve(pk, alpha);
        let h_point = ed::point_decode(&h_string).expect("elligator2 output decodes");

        let gamma = h_point.scale(&x);

        // nonce = SHA512(truncated_hashed_sk || H) mod l
        let mut ctx = Sha512Context::new();
        ctx.update_mut(&truncated_hashed_sk);
        ctx.update_mut(&h_string);
        let k = ed::scalar_reduce_wide(&ctx.finalize());

        let kb = Point::mul_base(&k);
        let kh = h_point.scale(&k);

        let gamma_string = ed::point_encode(&gamma);
        let challenge = hash_points(&[
            &h_string,
            &gamma_string,
            &ed::point_encode(&kb),
            &ed::point_encode(&kh),
        ]);

        // s = c * x + k mod l, with c zero-extended from 16 to 32 bytes
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&challenge);
        let c = ed::scalar_reduce(&c_scalar_bytes);
        let s = &(&c * &x) + &k;

        let mut proof = [0u8; PROOF_SIZE];
        proof[..32].copy_from_slice(&gamma_string);
        proof[32..48].copy_from_slice(&challenge);
        proof[48..].copy_from_slice(&ed::scalar_to_bytes(&s));
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

    /// `crypto_vrf_ietfdraft03_is_valid_key`: canonically encoded, on the
    /// curve, and not of small order.
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
    /// Read a proof from its 80 bytes.
    pub fn from_bytes(bytes: [u8; PROOF_SIZE]) -> Self {
        Proof(bytes)
    }

    /// Read a proof from a slice of exactly 80 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, VrfError> {
        if bytes.len() != PROOF_SIZE {
            return Err(VrfError::InvalidLength);
        }
        let mut out = [0u8; PROOF_SIZE];
        out.copy_from_slice(bytes);
        Ok(Proof(out))
    }

    /// The 80 bytes of this proof.
    pub fn as_bytes(&self) -> &[u8; PROOF_SIZE] {
        &self.0
    }

    /// `crypto_vrf_ietfdraft03_proof_to_hash`: the output this proof commits
    /// to, without verifying the proof.
    ///
    /// `beta = SHA512(suite || 0x03 || point_to_string(8 * gamma))`.
    pub fn to_hash(&self) -> Result<Output, VrfError> {
        let mut gamma_bytes = [0u8; 32];
        gamma_bytes.copy_from_slice(&self.0[..32]);
        if !ed::point_is_canonical(&gamma_bytes) {
            return Err(VrfError::InvalidProof);
        }
        let gamma = ed::point_decode(&gamma_bytes).ok_or(VrfError::InvalidProof)?;

        let mut s = [0u8; 32];
        s.copy_from_slice(&self.0[48..]);
        if (s[31] & 240) != 0 && !ed::scalar_is_canonical(&s) {
            return Err(VrfError::InvalidProof);
        }

        let gamma_cofactor = ed::clear_cofactor(&gamma);
        let mut ctx = Sha512Context::new();
        ctx.update_mut(&[SUITE, THREE]);
        ctx.update_mut(&ed::point_encode(&gamma_cofactor));
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

/// `_vrf_ietfdraft03_hash_to_curve_elligator2_25519`.
///
/// Note the `r_string[31] &= 0x7f` before the map: this is the deviation from
/// the draft that makes Cardano's VRF its own thing.
fn hash_to_curve(pk: &[u8], alpha: &[u8]) -> [u8; 32] {
    let mut ctx = Sha512Context::new();
    ctx.update_mut(&[SUITE, ONE]);
    ctx.update_mut(pk);
    ctx.update_mut(alpha);
    let hash = ctx.finalize();

    let mut r = [0u8; 32];
    r.copy_from_slice(&hash[..32]);
    r[31] &= 0x7f; /* clear sign bit */
    ed::point_encode(&ed::elligator2_from_uniform(&r))
}

/// `_vrf_ietfdraft03_hash_points`: the 16-byte challenge.
fn hash_points(points: &[&[u8; 32]]) -> [u8; 16] {
    let mut ctx = Sha512Context::new();
    ctx.update_mut(&[SUITE, TWO]);
    for p in points {
        ctx.update_mut(&p[..]);
    }
    let full = ctx.finalize();
    let mut c = [0u8; 16];
    c.copy_from_slice(&full[..16]);
    c
}

/// `crypto_vrf_ietfdraft03_verify`: verify `proof` for `alpha` under
/// `public_key`, returning the VRF output on success.
pub fn verify(public_key: &PublicKey, proof: &Proof, alpha: &[u8]) -> Result<Output, VrfError> {
    let y = public_key.decode()?;

    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&proof.0[..32]);
    if !ed::point_is_canonical(&gamma_bytes) {
        return Err(VrfError::InvalidProof);
    }
    let gamma = ed::point_decode(&gamma_bytes).ok_or(VrfError::InvalidProof)?;

    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&proof.0[32..48]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&proof.0[48..]);
    if (s[31] & 240) != 0 && !ed::scalar_is_canonical(&s) {
        return Err(VrfError::InvalidProof);
    }

    let c_scalar = ed::scalar_reduce(&c);
    let s_scalar = ed::scalar_reduce(&s);
    let neg_c = -&c_scalar;

    let h_string = hash_to_curve(public_key.as_bytes(), alpha);
    let h_point = ed::point_decode(&h_string).expect("elligator2 output decodes");

    // U = s*B - c*Y ; V = s*H - c*Gamma
    let u = ed::double_scalarmult_base(&neg_c, &y, &s_scalar);
    let v = ed::double_scalarmult(&neg_c, &gamma, &s_scalar, &h_point);

    let expected = hash_points(&[
        &h_string,
        &gamma_bytes,
        &ed::point_encode(&u),
        &ed::point_encode(&v),
    ]);

    if expected[..] != proof.0[32..48] {
        return Err(VrfError::VerificationFailed);
    }
    proof.to_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{hex, hex_array};

    /// (seed, public key, proof, output, alpha)
    fn cardano_vectors() -> Vec<[&'static str; 5]> {
        // cardano-base cardano-crypto-praos/test_vectors/vrf_ver03_*
        vec![
            // standard_10
            [
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900",
                "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",
                "",
            ],
            // standard_11
            [
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07",
                "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",
                "72",
            ],
            // standard_12
            [
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055b561ece45e1009",
                "2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde9d0aa489a4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded",
                "af82",
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
            assert_eq!(proof.to_hash().unwrap(), output);
        }
    }

    #[test]
    fn wrong_key_or_message_fails() {
        let sk = SecretKey::from_seed(&[1u8; 32]);
        let pk = sk.public();
        let proof = sk.prove(b"hello");
        assert!(verify(&pk, &proof, b"hello").is_ok());
        assert_eq!(
            verify(&pk, &proof, b"hellp").unwrap_err(),
            VrfError::VerificationFailed
        );

        let other = SecretKey::from_seed(&[2u8; 32]);
        assert_eq!(
            verify(&other.public(), &proof, b"hello").unwrap_err(),
            VrfError::VerificationFailed
        );
    }

    #[test]
    fn rejects_small_order_and_non_canonical_keys() {
        let sk = SecretKey::from_seed(&[1u8; 32]);
        let proof = sk.prove(b"hello");

        let identity = PublicKey::from_bytes(hex_array::<32>(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ));
        assert!(!identity.is_valid());
        assert_eq!(
            verify(&identity, &proof, b"hello").unwrap_err(),
            VrfError::InvalidKey
        );

        let non_canonical = PublicKey::from_bytes(hex_array::<32>(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ));
        assert!(!non_canonical.is_valid());
    }

    #[test]
    fn rejects_non_canonical_gamma() {
        let sk = SecretKey::from_seed(&[1u8; 32]);
        let pk = sk.public();
        let mut bytes = *sk.prove(b"hello").as_bytes();
        // p + 1: decodes to the identity, but non-canonically
        bytes[..32].copy_from_slice(&hex(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ));
        let proof = Proof::from_bytes(bytes);
        assert_eq!(
            verify(&pk, &proof, b"hello").unwrap_err(),
            VrfError::InvalidProof
        );
        assert_eq!(proof.to_hash().unwrap_err(), VrfError::InvalidProof);
    }
}

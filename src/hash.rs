//! The hash functions used by Cardano.
//!
//! The chain itself only uses Blake2b (256 bits for block, transaction and
//! script hashes, 224 bits for credential hashes, 160 bits for a couple of
//! legacy Byron hashes) and, for Byron addresses, SHA3-256 followed by
//! Blake2b-224. Plutus additionally exposes SHA-256, SHA3-256, Keccak-256,
//! RIPEMD-160 and Blake2b-224/256 as builtins.
//!
//! Both a one-shot function and an incremental `*_Context` are provided for
//! each algorithm; the incremental form matters when hashing a CBOR encoding
//! that is produced lazily.

use cryptoxide::hashing;

/// Incremental Blake2b context with a `BITS`-bit digest.
///
/// `BITS` must be a multiple of 8 between 8 and 512; the sizes used by Cardano
/// are 160, 224, 256 and 512.
pub type Blake2bContext<const BITS: usize> = hashing::blake2b::Context<BITS>;

/// Incremental SHA-256 context.
pub type Sha256Context = hashing::sha2::Context256;
/// Incremental SHA-512 context.
pub type Sha512Context = hashing::sha2::Context512;
/// Incremental SHA3-256 context.
pub type Sha3_256Context = hashing::sha3::Context256;
/// Incremental Keccak-256 context (the pre-standard padding, as used by
/// Ethereum and by the Plutus `keccak_256` builtin).
pub type Keccak256Context = hashing::keccak::Context256;
/// Incremental RIPEMD-160 context.
pub type Ripemd160Context = hashing::ripemd160::Context;

/// Compute Blake2b with a `BITS`-bit digest over `data`.
///
/// ```
/// # use ouroboros_crypto_kit::hash::blake2b;
/// let digest: [u8; 32] = blake2b::<256, 32>(b"hello");
/// ```
pub fn blake2b<const BITS: usize, const OUT: usize>(data: &[u8]) -> [u8; OUT] {
    assert_eq!(BITS, OUT * 8, "digest size mismatch");
    let mut out = [0u8; OUT];
    hashing::blake2b::Blake2b::<BITS>::new()
        .update(data)
        .finalize_at(&mut out);
    out
}

/// Compute Blake2b-160 over `data`.
pub fn blake2b_160(data: &[u8]) -> [u8; 20] {
    blake2b::<160, 20>(data)
}

/// Compute Blake2b-224 over `data`; this is the hash of a Cardano credential
/// (payment key hash, script hash of the Byron era, ...).
pub fn blake2b_224(data: &[u8]) -> [u8; 28] {
    hashing::blake2b_224(data)
}

/// Compute Blake2b-256 over `data`; this is *the* Cardano hash: block ids,
/// transaction ids, script hashes, ...
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    hashing::blake2b_256(data)
}

/// Compute Blake2b-512 over `data`.
pub fn blake2b_512(data: &[u8]) -> [u8; 64] {
    hashing::blake2b_512(data)
}

/// Compute SHA-256 over `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    hashing::sha256(data)
}

/// Compute SHA-512 over `data`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    hashing::sha512(data)
}

/// Compute SHA3-256 over `data`.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    hashing::sha3_256(data)
}

/// Compute Keccak-256 over `data` (pre-standard padding, as used by Ethereum).
pub fn keccak_256(data: &[u8]) -> [u8; 32] {
    hashing::keccak256(data)
}

/// Compute RIPEMD-160 over `data`.
pub fn ripemd_160(data: &[u8]) -> [u8; 20] {
    hashing::ripemd160(data)
}

/// `expand_message_xmd` of RFC 9380 with SHA-256, the expander of the BLS12-381
/// hash-to-curve suites (which `plutus::bls12_381` reaches through `eccoxide`'s
/// own copy rather than this one).
pub fn expand_message_xmd_sha256(dst: &[u8], msg: &[u8], len_in_bytes: usize) -> Vec<u8> {
    expand_message_xmd::<64, 32, _, _>(dst, msg, len_in_bytes, sha256, |parts| {
        let mut ctx = Sha256Context::new();
        for p in parts {
            ctx.update_mut(p);
        }
        ctx.finalize()
    })
}

/// `expand_message_xmd` of RFC 9380 with SHA-512, as used by the Cardano VRF
/// (draft-13) hash-to-curve.
pub fn expand_message_xmd_sha512(dst: &[u8], msg: &[u8], len_in_bytes: usize) -> Vec<u8> {
    expand_message_xmd::<128, 64, _, _>(dst, msg, len_in_bytes, sha512, |parts| {
        let mut ctx = Sha512Context::new();
        for p in parts {
            ctx.update_mut(p);
        }
        ctx.finalize()
    })
}

/// The body of `expand_message_xmd`, parameterised by the hash function's block
/// size `B`, digest size `N`, and a way to hash a sequence of slices.
///
/// An over-long DST is replaced by `H("H2C-OVERSIZE-DST-" || DST)`, as the
/// specification prescribes.
fn expand_message_xmd<const B: usize, const N: usize, H, M>(
    dst: &[u8],
    msg: &[u8],
    len_in_bytes: usize,
    hash_one: H,
    hash_many: M,
) -> Vec<u8>
where
    H: Fn(&[u8]) -> [u8; N],
    M: Fn(&[&[u8]]) -> [u8; N],
{
    assert!(len_in_bytes > 0, "expand_message_xmd: empty output");
    let ell = len_in_bytes.div_ceil(N);
    assert!(ell <= 255, "expand_message_xmd: output too long");
    assert!(
        len_in_bytes <= 0xffff,
        "expand_message_xmd: output too long"
    );

    let oversize;
    let dst = if dst.len() > 255 {
        let mut long = Vec::with_capacity(17 + dst.len());
        long.extend_from_slice(b"H2C-OVERSIZE-DST-");
        long.extend_from_slice(dst);
        oversize = hash_one(&long);
        &oversize[..]
    } else {
        dst
    };
    let dst_len = [dst.len() as u8];

    // b_0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime)
    let z_pad = [0u8; B];
    let l_i_b_str = [(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0u8];
    let b0 = hash_many(&[&z_pad, msg, &l_i_b_str, dst, &dst_len]);

    let mut out = Vec::with_capacity(len_in_bytes);
    let mut b_i = [0u8; N];
    for i in 1..=ell {
        // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
        let mut xored = [0u8; N];
        for (x, (a, b)) in xored.iter_mut().zip(b0.iter().zip(b_i.iter())) {
            *x = a ^ b;
        }
        b_i = hash_many(&[&xored, &[i as u8], dst, &dst_len]);
        let take = core::cmp::min(N, len_in_bytes - out.len());
        out.extend_from_slice(&b_i[..take]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::hex;

    #[test]
    fn blake2b_known_answers() {
        // Cardano credential hash of an empty input, and the digests pallas
        // and cardano-base use in their own test suites.
        assert_eq!(
            blake2b_256(b"hello").as_slice(),
            hex("324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf")
        );
        assert_eq!(
            blake2b_224(b"My Public Key").as_slice(),
            hex("c123c9bc0e9e31a20a4aa23518836ec5fb54bdc85735c56b38eb79a5")
        );
        assert_eq!(
            blake2b_256(b"My transaction").as_slice(),
            hex("0d8d00cdd4657ac84d82f0a56067634a7adfdf43da41cb534bcaa45060973d21")
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let mut ctx = Blake2bContext::<256>::new();
        ctx.update_mut(b"My ");
        ctx.update_mut(b"transaction");
        assert_eq!(ctx.finalize(), blake2b_256(b"My transaction"));
    }

    #[test]
    fn plutus_hash_builtins() {
        // sha2_256 / sha3_256 / keccak_256 / ripemd_160 of the empty string
        assert_eq!(
            sha256(b"").as_slice(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha3_256(b"").as_slice(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        assert_eq!(
            keccak_256(b"").as_slice(),
            hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        assert_eq!(
            ripemd_160(b"").as_slice(),
            hex("9c1185a5c5e9fc54612808977ee8f548b2258d31")
        );
    }
}

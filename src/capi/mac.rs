//! HMAC-SHA-256 and the two constructions built on it that the C libraries
//! being replaced use: libsecp256k1's RFC 6979 nonce generator and the HKDF of
//! blst's `blst_keygen`.

use cryptoxide::hashing::sha2::Sha256;
use cryptoxide::hmac;

/// HMAC-SHA-256 over the concatenation of `parts`.
pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = hmac::Context::<Sha256>::new(key);
    for p in parts {
        ctx.update(p);
    }
    ctx.finalize().0
}

/// HKDF-SHA-256 (RFC 5869), as `blst_keygen` uses it.
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[&[u8]], info: &[&[u8]], out: &mut [u8]) {
    let prk = hmac_sha256(salt, ikm);

    let mut t: [u8; 32] = [0; 32];
    let mut written = 0;
    let mut counter = 1u8;
    while written < out.len() {
        let mut ctx = hmac::Context::<Sha256>::new(&prk);
        if counter > 1 {
            ctx.update(&t);
        }
        for p in info {
            ctx.update(p);
        }
        ctx.update(&[counter]);
        t = ctx.finalize().0;

        let n = core::cmp::min(32, out.len() - written);
        out[written..written + n].copy_from_slice(&t[..n]);
        written += n;
        counter += 1;
    }
}

/// libsecp256k1's RFC 6979 deterministic nonce generator, which is the default
/// `secp256k1_ecdsa_sign` uses when no nonce function is given.
///
/// The generator is stateful: successive calls to [`Rfc6979::next_nonce`]
/// produce the nonces `secp256k1_ecdsa_sign` would ask for as it increments its
/// counter.
pub(crate) struct Rfc6979 {
    k: [u8; 32],
    v: [u8; 32],
    retry: bool,
}

impl Rfc6979 {
    /// Seed the generator with `key || msg`, the key material libsecp256k1 uses
    /// when neither extra data nor an algorithm tag is supplied.
    pub(crate) fn new(key32: &[u8; 32], msg32: &[u8; 32]) -> Self {
        let mut k = [0x00u8; 32];
        let mut v = [0x01u8; 32];

        k = hmac_sha256(&k, &[&v, &[0x00], key32, msg32]);
        v = hmac_sha256(&k, &[&v]);
        k = hmac_sha256(&k, &[&v, &[0x01], key32, msg32]);
        v = hmac_sha256(&k, &[&v]);

        Rfc6979 { k, v, retry: false }
    }

    pub(crate) fn next_nonce(&mut self) -> [u8; 32] {
        if self.retry {
            self.k = hmac_sha256(&self.k, &[&self.v, &[0x00]]);
            self.v = hmac_sha256(&self.k, &[&self.v]);
        }
        self.v = hmac_sha256(&self.k, &[&self.v]);
        self.retry = true;
        self.v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2.
    #[test]
    fn hmac_sha256_vector() {
        let mac = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 5869 test case 1.
    #[test]
    fn hkdf_sha256_vector() {
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256(&salt, &[&ikm], &[&info], &mut okm);
        assert_eq!(
            okm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    /// The generator is deterministic in the key and message, and each call
    /// produces a fresh nonce — the two properties `secp256k1_ecdsa_sign`
    /// relies on when it retries with an incremented counter.
    #[test]
    fn rfc6979_first_nonce_is_deterministic() {
        let key = [1u8; 32];
        let msg = [2u8; 32];
        let mut a = Rfc6979::new(&key, &msg);
        let mut b = Rfc6979::new(&key, &msg);
        let first = a.next_nonce();
        assert_eq!(first, b.next_nonce());
        // and the second differs from the first
        assert_ne!(first, a.next_nonce());
    }
}

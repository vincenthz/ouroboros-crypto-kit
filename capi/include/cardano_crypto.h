/*
 * The C functions of the `cardano-crypto` Haskell package — its
 * `cbits/encrypted_sign.c` and the `cardano_crypto_`-prefixed ed25519-donna
 * of `cbits/ed25519/` — implemented by `ouroboros-crypto-kit` in Rust.
 *
 * `Cardano.Crypto.Wallet` (and through it `cardano-crypto-wrapper`, i.e. every
 * Byron-era signature) imports the `wallet_encrypted_*` functions;
 * `Crypto.ECC.Ed25519Donna` imports the `cardano_crypto_ed25519_*` ones.
 * Unlike libsodium, libsecp256k1 and blst, `cardano-crypto` compiles this C
 * into itself rather than linking a system library, so these symbols replace
 * it only when the package is built without its `c-sources` and linked against
 * this library instead.
 *
 * Layouts, all little-endian:
 *
 *   encrypted key (128 bytes): extended secret (64) | public key (32) | chain code (32)
 *   extended secret (64 bytes): scalar kL (32) | nonce prefix kR (32)
 *
 * The extended secret is held in the clear when the passphrase is empty, and
 * otherwise XORed with the ChaCha20 (original, 8-byte nonce) keystream of
 * PBKDF2-HMAC-SHA512(passphrase, "encrypted wallet salt\0", 15000) — 32 bytes
 * of key then 8 of nonce. A wrong passphrase is not detected.
 */

#ifndef OUROBOROS_CRYPTO_KIT_CARDANO_CRYPTO_H
#define OUROBOROS_CRYPTO_KIT_CARDANO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Extended keys (encrypted_sign.c)                                   */
/* ------------------------------------------------------------------ */

/* `derivation_scheme_mode`: 1 = DerivationScheme1 (Byron, with its carry
 * bugs, big-endian index), 2 = DerivationScheme2 (Icarus/Shelley). */
typedef enum {
    DERIVATION_V1 = 1,
    DERIVATION_V2 = 2,
} derivation_scheme_mode;

/* Expand a 32-byte Ed25519 seed (SHA-512, clamped) into an encrypted key with
 * chain code `cc`. Returns 1, writing nothing, when bit 253 of the scalar is
 * set; 0 otherwise. */
int wallet_encrypted_from_secret(const uint8_t *pass, uint32_t pass_len,
                                 const uint8_t seed[32], const uint8_t cc[32],
                                 uint8_t encrypted_key[128]);

/* An encrypted key from 96 bytes of master key material (extended secret then
 * chain code); the scalar is clamped and bit 253 cleared. Returns 0. */
int wallet_encrypted_new_from_mkg(const uint8_t *pass, uint32_t pass_len,
                                  const uint8_t master_key[96],
                                  uint8_t encrypted_key[128]);

/* Ed25519-sign `data` with the decrypted extended secret. The public key in
 * the challenge is recomputed from the secret, not read from the key. */
void wallet_encrypted_sign(const uint8_t encrypted_key[128],
                           const uint8_t *pass, uint32_t pass_len,
                           const uint8_t *data, uint32_t data_len,
                           uint8_t signature[64]);

/* Re-encrypt `in` under `new_pass`. */
void wallet_encrypted_change_pass(const uint8_t in[128],
                                  const uint8_t *old_pass, uint32_t old_pass_len,
                                  const uint8_t *new_pass, uint32_t new_pass_len,
                                  uint8_t out[128]);

/* BIP32-Ed25519 child of `in` at `index` (hardened when index >= 2^31),
 * encrypted under the same passphrase. */
void wallet_encrypted_derive_private(const uint8_t in[128],
                                     const uint8_t *pass, uint32_t pass_len,
                                     uint32_t index, uint8_t out[128],
                                     derivation_scheme_mode mode);

/* Public child of (`pub_in`, `cc_in`) at a normal `index`. Returns 1, writing
 * nothing, for a hardened index; 0 otherwise. If `pub_in` does not decode,
 * `pub_out` is left untouched (the C original ignores that failure too). */
int wallet_encrypted_derive_public(const uint8_t pub_in[32], const uint8_t cc_in[32],
                                   uint32_t index,
                                   uint8_t pub_out[32], uint8_t cc_out[32],
                                   derivation_scheme_mode mode);

/* ------------------------------------------------------------------ */
/* ed25519-donna (cbits/ed25519/ed25519.h, VARIANT_CODE)              */
/* ------------------------------------------------------------------ */

/* Public key of an extended secret: (kL mod l) * B. Only the first 32 bytes
 * of `sk` are read. */
void cardano_crypto_ed25519_publickey(const unsigned char sk[64], unsigned char pk[32]);

/* Verify: 0 if valid, -1 otherwise. Rejects an `s` with any of its top 3 bits
 * set and a key that does not decode; accepts a non-canonical or small-order
 * key, a small-order R and an s in [l, 2^253). R is compared byte for byte. */
int cardano_crypto_ed25519_sign_open(const unsigned char *m, size_t mlen,
                                     const unsigned char pk[32], const unsigned char RS[64]);

/* Sign with an extended secret, hashing `pk` (as given) into the challenge.
 * `salt` is unused. */
void cardano_crypto_ed25519_sign(const unsigned char *m, size_t mlen,
                                 const unsigned char *salt, size_t slen,
                                 const unsigned char sk[64], const unsigned char pk[32],
                                 unsigned char RS[64]);

/* (sk1 mod l + sk2 mod l) mod l, over the first 32 bytes of each; writes 32
 * bytes of `res`. Returns 0. */
int cardano_crypto_ed25519_scalar_add(const unsigned char sk1[64], const unsigned char sk2[64],
                                      unsigned char res[64]);

/* pk1 + pk2. Returns -1, writing nothing, if either does not decode; 0
 * otherwise. */
int cardano_crypto_ed25519_point_add(const unsigned char pk1[32], const unsigned char pk2[32],
                                     unsigned char res[32]);

/* SHA-512 of `seed`, clamped, into `secret`. Returns 1 (having written
 * `secret` anyway) if bit 253 is set, 0 otherwise. */
int cardano_crypto_ed25519_extend(const unsigned char seed[32], unsigned char secret[64]);

#ifdef __cplusplus
}
#endif

#endif

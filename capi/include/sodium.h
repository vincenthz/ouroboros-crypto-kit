/*
 * The subset of libsodium's API that `cardano-crypto-class` and
 * `cardano-crypto-praos` use, including the VRF primitives of the
 * input-output-hk fork, implemented by `ouroboros-crypto-kit` in Rust.
 *
 * Only the declarations the node's Haskell packages actually need are here.
 * The opaque state structs are sized so that they can hold the corresponding
 * Rust hash context; the sizes match libsodium's own so that anything that
 * hard-codes them keeps working.
 */

#ifndef OUROBOROS_CRYPTO_KIT_SODIUM_H
#define OUROBOROS_CRYPTO_KIT_SODIUM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SODIUM_VERSION_STRING "ouroboros-crypto-kit"

/* ------------------------------------------------------------------ */
/* Initialization                                                     */
/* ------------------------------------------------------------------ */

int sodium_init(void);
const char *sodium_version_string(void);

/* ------------------------------------------------------------------ */
/* Memory management                                                  */
/* ------------------------------------------------------------------ */

void sodium_memzero(void *pnt, size_t len);
void *sodium_malloc(size_t size);
void sodium_free(void *ptr);
int sodium_mlock(void *addr, size_t len);
int sodium_munlock(void *addr, size_t len);

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

int sodium_compare(const void *b1_, const void *b2_, size_t len);
int sodium_is_zero(const unsigned char *n, size_t nlen);
int sodium_memcmp(const void *b1_, const void *b2_, size_t len);

/* ------------------------------------------------------------------ */
/* Random bytes                                                       */
/* ------------------------------------------------------------------ */

void randombytes_buf(void *buf, size_t size);

/* ------------------------------------------------------------------ */
/* SHA-2                                                              */
/* ------------------------------------------------------------------ */

#define crypto_hash_sha256_BYTES 32U
#define crypto_hash_sha512_BYTES 64U

typedef struct crypto_hash_sha256_state {
  unsigned char opaque[128];
} crypto_hash_sha256_state;

typedef struct crypto_hash_sha512_state {
  unsigned char opaque[256];
} crypto_hash_sha512_state;

size_t crypto_hash_sha256_bytes(void);
size_t crypto_hash_sha512_bytes(void);

int crypto_hash_sha256(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);
int crypto_hash_sha256_init(crypto_hash_sha256_state *state);
int crypto_hash_sha256_update(crypto_hash_sha256_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);
int crypto_hash_sha256_final(crypto_hash_sha256_state *state,
                             unsigned char *out);

int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);
int crypto_hash_sha512_init(crypto_hash_sha512_state *state);
int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);
int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                             unsigned char *out);

/* ------------------------------------------------------------------ */
/* Blake2b (generic hashing)                                          */
/* ------------------------------------------------------------------ */

#define crypto_generichash_blake2b_BYTES_MIN 16U
#define crypto_generichash_blake2b_BYTES_MAX 64U
#define crypto_generichash_blake2b_BYTES 32U
#define crypto_generichash_blake2b_KEYBYTES_MIN 16U
#define crypto_generichash_blake2b_KEYBYTES_MAX 64U
#define crypto_generichash_blake2b_KEYBYTES 32U

typedef struct crypto_generichash_blake2b_state {
  unsigned char opaque[384];
} crypto_generichash_blake2b_state;

size_t crypto_generichash_blake2b_bytes(void);
size_t crypto_generichash_blake2b_statebytes(void);

int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *key, size_t keylen);
int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state *state,
                                    const unsigned char *key,
                                    const size_t keylen, const size_t outlen);
int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state,
                                      const unsigned char *in,
                                      unsigned long long inlen);
int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state,
                                     unsigned char *out, const size_t outlen);

/* ------------------------------------------------------------------ */
/* Ed25519                                                            */
/* ------------------------------------------------------------------ */

#define crypto_sign_ed25519_BYTES 64U
#define crypto_sign_ed25519_SEEDBYTES 32U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SECRETKEYBYTES 64U

size_t crypto_sign_ed25519_bytes(void);
size_t crypto_sign_ed25519_seedbytes(void);
size_t crypto_sign_ed25519_publickeybytes(void);
size_t crypto_sign_ed25519_secretkeybytes(void);

int crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed);
int crypto_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk);
int crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);
int crypto_sign_ed25519_detached(unsigned char *sig,
                                 unsigned long long *siglen_p,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *sk);
int crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *pk);

/* ------------------------------------------------------------------ */
/* VRF (input-output-hk/libsodium extension)                          */
/* ------------------------------------------------------------------ */

/* draft-irtf-cfrg-vrf-03, the VRF every Shelley-era block uses. */

#define crypto_vrf_ietfdraft03_BYTES 80U
#define crypto_vrf_ietfdraft03_OUTPUTBYTES 64U
#define crypto_vrf_ietfdraft03_SEEDBYTES 32U
#define crypto_vrf_ietfdraft03_PUBLICKEYBYTES 32U
#define crypto_vrf_ietfdraft03_SECRETKEYBYTES 64U

size_t crypto_vrf_ietfdraft03_bytes(void);
size_t crypto_vrf_ietfdraft03_outputbytes(void);
size_t crypto_vrf_ietfdraft03_seedbytes(void);
size_t crypto_vrf_ietfdraft03_publickeybytes(void);
size_t crypto_vrf_ietfdraft03_secretkeybytes(void);

int crypto_vrf_ietfdraft03_keypair_from_seed(unsigned char *pk,
                                             unsigned char *sk,
                                             const unsigned char *seed);
void crypto_vrf_ietfdraft03_sk_to_pk(unsigned char *pk,
                                     const unsigned char *skpk);
void crypto_vrf_ietfdraft03_sk_to_seed(unsigned char *seed,
                                       const unsigned char *skpk);
int crypto_vrf_ietfdraft03_prove(unsigned char *proof,
                                 const unsigned char *skpk,
                                 const unsigned char *m,
                                 unsigned long long mlen);
int crypto_vrf_ietfdraft03_verify(unsigned char *output,
                                  const unsigned char *pk,
                                  const unsigned char *proof,
                                  const unsigned char *m,
                                  unsigned long long mlen);
int crypto_vrf_ietfdraft03_proof_to_hash(unsigned char *hash,
                                         const unsigned char *proof);

/* draft-irtf-cfrg-vrf-13, batch-compatible (128-byte proofs). */

#define crypto_vrf_ietfdraft13_BYTES_BATCHCOMPAT 128U
#define crypto_vrf_ietfdraft13_OUTPUTBYTES 64U
#define crypto_vrf_ietfdraft13_SEEDBYTES 32U
#define crypto_vrf_ietfdraft13_PUBLICKEYBYTES 32U
#define crypto_vrf_ietfdraft13_SECRETKEYBYTES 64U

size_t crypto_vrf_ietfdraft13_bytes_batchcompat(void);
size_t crypto_vrf_ietfdraft13_outputbytes(void);
size_t crypto_vrf_ietfdraft13_seedbytes(void);
size_t crypto_vrf_ietfdraft13_publickeybytes(void);
size_t crypto_vrf_ietfdraft13_secretkeybytes(void);

int crypto_vrf_ietfdraft13_prove_batchcompat(unsigned char *proof,
                                             const unsigned char *skpk,
                                             const unsigned char *m,
                                             unsigned long long mlen);
int crypto_vrf_ietfdraft13_verify_batchcompat(unsigned char *output,
                                              const unsigned char *pk,
                                              const unsigned char *proof,
                                              const unsigned char *m,
                                              unsigned long long mlen);
int crypto_vrf_ietfdraft13_proof_to_hash_batchcompat(unsigned char *hash,
                                                     const unsigned char *proof);

/* The generic entry points; as in the fork, they are the draft-03 ones (the
 * key format and its derivation are shared by both drafts). */

size_t crypto_vrf_bytes(void);
size_t crypto_vrf_outputbytes(void);
size_t crypto_vrf_seedbytes(void);
size_t crypto_vrf_publickeybytes(void);
size_t crypto_vrf_secretkeybytes(void);

int crypto_vrf_keypair(unsigned char *pk, unsigned char *sk);
int crypto_vrf_seed_keypair(unsigned char *pk, unsigned char *sk,
                            const unsigned char *seed);
int crypto_vrf_sk_to_pk(unsigned char *pk, const unsigned char *skpk);
int crypto_vrf_sk_to_seed(unsigned char *seed, const unsigned char *skpk);
int crypto_vrf_prove(unsigned char *proof, const unsigned char *skpk,
                     const unsigned char *m, unsigned long long mlen);
int crypto_vrf_verify(unsigned char *output, const unsigned char *pk,
                      const unsigned char *proof, const unsigned char *m,
                      unsigned long long mlen);
int crypto_vrf_proof_to_hash(unsigned char *hash, const unsigned char *proof);

#ifdef __cplusplus
}
#endif

#endif /* OUROBOROS_CRYPTO_KIT_SODIUM_H */

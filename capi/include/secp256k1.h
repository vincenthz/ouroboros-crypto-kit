/*
 * The subset of libsecp256k1's API that `cardano-crypto-class` uses, backed by
 * `ouroboros-crypto-kit`.
 *
 * The opaque `secp256k1_pubkey` and `secp256k1_ecdsa_signature` keep their
 * upstream sizes (64 bytes each); their contents are private to this
 * implementation, exactly as upstream's are, and are only ever produced and
 * consumed through the functions below.
 */

#ifndef OUROBOROS_CRYPTO_KIT_SECP256K1_H
#define OUROBOROS_CRYPTO_KIT_SECP256K1_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct secp256k1_context_struct secp256k1_context;

/* A public key, in this implementation the affine coordinates x || y, each 32
 * bytes big-endian. */
typedef struct {
  unsigned char data[64];
} secp256k1_pubkey;

/* An ECDSA signature, in this implementation r || s, each 32 bytes
 * big-endian. */
typedef struct {
  unsigned char data[64];
} secp256k1_ecdsa_signature;

typedef int (*secp256k1_nonce_function)(unsigned char *nonce32,
                                        const unsigned char *msg32,
                                        const unsigned char *key32,
                                        const unsigned char *algo16,
                                        void *data, unsigned int attempt);

#define SECP256K1_FLAGS_TYPE_MASK ((1 << 8) - 1)
#define SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
#define SECP256K1_FLAGS_TYPE_COMPRESSION (1 << 1)
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY (1 << 8)
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN (1 << 9)
#define SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY (1 << 10)
#define SECP256K1_FLAGS_BIT_COMPRESSION (1 << 8)

#define SECP256K1_CONTEXT_NONE (SECP256K1_FLAGS_TYPE_CONTEXT)
#define SECP256K1_CONTEXT_VERIFY                                               \
  (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
#define SECP256K1_CONTEXT_SIGN                                                 \
  (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
#define SECP256K1_CONTEXT_DECLASSIFY                                           \
  (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY)

#define SECP256K1_EC_COMPRESSED                                                \
  (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
#define SECP256K1_EC_UNCOMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION)

#define SECP256K1_TAG_PUBKEY_EVEN 0x02
#define SECP256K1_TAG_PUBKEY_ODD 0x03
#define SECP256K1_TAG_PUBKEY_UNCOMPRESSED 0x04
#define SECP256K1_TAG_PUBKEY_HYBRID_EVEN 0x06
#define SECP256K1_TAG_PUBKEY_HYBRID_ODD 0x07

secp256k1_context *secp256k1_context_create(unsigned int flags);
secp256k1_context *secp256k1_context_clone(const secp256k1_context *ctx);
void secp256k1_context_destroy(secp256k1_context *ctx);
int secp256k1_context_randomize(secp256k1_context *ctx,
                                const unsigned char *seed32);

int secp256k1_ec_pubkey_parse(const secp256k1_context *ctx,
                              secp256k1_pubkey *pubkey,
                              const unsigned char *input, size_t inputlen);
int secp256k1_ec_pubkey_serialize(const secp256k1_context *ctx,
                                  unsigned char *output, size_t *outputlen,
                                  const secp256k1_pubkey *pubkey,
                                  unsigned int flags);
int secp256k1_ec_pubkey_create(const secp256k1_context *ctx,
                               secp256k1_pubkey *pubkey,
                               const unsigned char *seckey);
int secp256k1_ec_seckey_verify(const secp256k1_context *ctx,
                               const unsigned char *seckey);

int secp256k1_ecdsa_signature_parse_compact(
    const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig,
    const unsigned char *input64);
int secp256k1_ecdsa_signature_serialize_compact(
    const secp256k1_context *ctx, unsigned char *output64,
    const secp256k1_ecdsa_signature *sig);
int secp256k1_ecdsa_signature_normalize(const secp256k1_context *ctx,
                                        secp256k1_ecdsa_signature *sigout,
                                        const secp256k1_ecdsa_signature *sigin);
int secp256k1_ecdsa_verify(const secp256k1_context *ctx,
                           const secp256k1_ecdsa_signature *sig,
                           const unsigned char *msghash32,
                           const secp256k1_pubkey *pubkey);
int secp256k1_ecdsa_sign(const secp256k1_context *ctx,
                         secp256k1_ecdsa_signature *sig,
                         const unsigned char *msghash32,
                         const unsigned char *seckey,
                         secp256k1_nonce_function noncefp, const void *ndata);

#ifdef __cplusplus
}
#endif

#endif /* OUROBOROS_CRYPTO_KIT_SECP256K1_H */

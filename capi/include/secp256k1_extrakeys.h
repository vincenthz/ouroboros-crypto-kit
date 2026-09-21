/*
 * The x-only public keys and key pairs of libsecp256k1's `extrakeys` module,
 * as used by `Cardano.Crypto.DSIGN.SchnorrSecp256k1`.
 */

#ifndef OUROBOROS_CRYPTO_KIT_SECP256K1_EXTRAKEYS_H
#define OUROBOROS_CRYPTO_KIT_SECP256K1_EXTRAKEYS_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* An x-only public key, in this implementation the affine coordinates x || y
 * with y even, each 32 bytes big-endian. */
typedef struct {
  unsigned char data[64];
} secp256k1_xonly_pubkey;

/* A key pair, in this implementation the secret key (32 bytes big-endian)
 * followed by the affine coordinates x || y of the public key. */
typedef struct {
  unsigned char data[96];
} secp256k1_keypair;

int secp256k1_xonly_pubkey_parse(const secp256k1_context *ctx,
                                 secp256k1_xonly_pubkey *pubkey,
                                 const unsigned char *input32);
int secp256k1_xonly_pubkey_serialize(const secp256k1_context *ctx,
                                     unsigned char *output32,
                                     const secp256k1_xonly_pubkey *pubkey);
int secp256k1_xonly_pubkey_from_pubkey(const secp256k1_context *ctx,
                                      secp256k1_xonly_pubkey *xonly_pubkey,
                                      int *pk_parity,
                                      const secp256k1_pubkey *pubkey);
int secp256k1_xonly_pubkey_cmp(const secp256k1_context *ctx,
                               const secp256k1_xonly_pubkey *pk1,
                               const secp256k1_xonly_pubkey *pk2);

int secp256k1_keypair_create(const secp256k1_context *ctx,
                             secp256k1_keypair *keypair,
                             const unsigned char *seckey);
int secp256k1_keypair_sec(const secp256k1_context *ctx, unsigned char *seckey,
                          const secp256k1_keypair *keypair);
int secp256k1_keypair_pub(const secp256k1_context *ctx,
                          secp256k1_pubkey *pubkey,
                          const secp256k1_keypair *keypair);
int secp256k1_keypair_xonly_pub(const secp256k1_context *ctx,
                                secp256k1_xonly_pubkey *pubkey, int *pk_parity,
                                const secp256k1_keypair *keypair);

#ifdef __cplusplus
}
#endif

#endif /* OUROBOROS_CRYPTO_KIT_SECP256K1_EXTRAKEYS_H */

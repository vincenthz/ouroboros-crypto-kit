/*
 * BIP-340 Schnorr signatures, as used by
 * `Cardano.Crypto.DSIGN.SchnorrSecp256k1` and the Plutus builtin
 * `verifySchnorrSecp256k1Signature`.
 */

#ifndef OUROBOROS_CRYPTO_KIT_SECP256K1_SCHNORRSIG_H
#define OUROBOROS_CRYPTO_KIT_SECP256K1_SCHNORRSIG_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*secp256k1_nonce_function_hardened)(
    unsigned char *nonce32, const unsigned char *msg, size_t msglen,
    const unsigned char *key32, const unsigned char *xonly_pk32,
    const unsigned char *algo, size_t algolen, void *data);

typedef struct {
  unsigned char magic[4];
  secp256k1_nonce_function_hardened noncefp;
  void *ndata;
} secp256k1_schnorrsig_extraparams;

int secp256k1_schnorrsig_sign32(const secp256k1_context *ctx,
                                unsigned char *sig64,
                                const unsigned char *msg32,
                                const secp256k1_keypair *keypair,
                                const unsigned char *aux_rand32);
int secp256k1_schnorrsig_sign_custom(
    const secp256k1_context *ctx, unsigned char *sig64,
    const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair,
    secp256k1_schnorrsig_extraparams *extraparams);
int secp256k1_schnorrsig_verify(const secp256k1_context *ctx,
                                const unsigned char *sig64,
                                const unsigned char *msg, size_t msglen,
                                const secp256k1_xonly_pubkey *pubkey);

#ifdef __cplusplus
}
#endif

#endif /* OUROBOROS_CRYPTO_KIT_SECP256K1_SCHNORRSIG_H */

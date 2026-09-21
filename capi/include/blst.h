/*
 * The subset of blst's API that `cardano-crypto-class` uses for BLS12-381
 * (CIP-0381), backed by `ouroboros-crypto-kit`.
 *
 * The types keep blst's sizes, which `cardano-crypto-class`'s `blst_util.h`
 * asserts and its Haskell side relies on:
 *
 *   blst_p1 144, blst_p2 288, blst_p1_affine 96, blst_p2_affine 192,
 *   blst_scalar 32, blst_fr 32, blst_fp12 576.
 *
 * Their contents are private to this implementation: a `blst_p1` holds the
 * projective point as `ouroboros-crypto-kit` represents it, and a `blst_p1_affine` the
 * affine coordinates as canonical big-endian field elements (all-zero being the
 * point at infinity). Everything that produces or consumes them goes through
 * the functions below, so the representation is never observed from outside.
 */

#ifndef OUROBOROS_CRYPTO_KIT_BLST_H
#define OUROBOROS_CRYPTO_KIT_BLST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t byte;
typedef uint64_t limb_t;

typedef struct {
  limb_t l[384 / 8 / sizeof(limb_t)];
} blst_fp;

typedef struct {
  blst_fp fp[2];
} blst_fp2;

typedef struct {
  blst_fp2 fp2[3];
} blst_fp6;

typedef struct {
  blst_fp6 fp6[2];
} blst_fp12;

typedef struct {
  blst_fp x, y, z;
} blst_p1;

typedef struct {
  blst_fp x, y;
} blst_p1_affine;

typedef struct {
  blst_fp2 x, y, z;
} blst_p2;

typedef struct {
  blst_fp2 x, y;
} blst_p2_affine;

typedef struct {
  byte b[256 / 8];
} blst_scalar;

typedef struct {
  limb_t l[256 / 8 / sizeof(limb_t)];
} blst_fr;

typedef enum {
  BLST_SUCCESS = 0,
  BLST_BAD_ENCODING,
  BLST_POINT_NOT_ON_CURVE,
  BLST_POINT_NOT_IN_GROUP,
  BLST_AGGR_TYPE_MISMATCH,
  BLST_VERIFY_FAIL,
  BLST_PK_IS_INFINITY,
  BLST_BAD_SCALAR,
} BLST_ERROR;

/* ------------------------------------------------------------------ */
/* Scalars                                                            */
/* ------------------------------------------------------------------ */

void blst_scalar_from_fr(blst_scalar *out, const blst_fr *a);
void blst_fr_from_scalar(blst_fr *out, const blst_scalar *a);
void blst_scalar_from_bendian(blst_scalar *out, const byte a[32]);
void blst_bendian_from_scalar(byte out[32], const blst_scalar *a);
bool blst_scalar_from_be_bytes(blst_scalar *out, const byte *in, size_t len);
bool blst_scalar_fr_check(const blst_scalar *a);
void blst_keygen(blst_scalar *out_SK, const byte *IKM, size_t IKM_len,
                 const byte *info, size_t info_len);

/* ------------------------------------------------------------------ */
/* G1                                                                 */
/* ------------------------------------------------------------------ */

bool blst_p1_on_curve(const blst_p1 *p);
bool blst_p1_in_g1(const blst_p1 *p);
bool blst_p1_is_inf(const blst_p1 *p);
bool blst_p1_is_equal(const blst_p1 *a, const blst_p1 *b);
void blst_p1_add_or_double(blst_p1 *out, const blst_p1 *a, const blst_p1 *b);
void blst_p1_mult(blst_p1 *out, const blst_p1 *p, const byte *scalar,
                  size_t nbits);
void blst_p1_cneg(blst_p1 *p, bool cbit);
const blst_p1 *blst_p1_generator(void);

void blst_p1_compress(byte out[48], const blst_p1 *in);
void blst_p1_serialize(byte out[96], const blst_p1 *in);
BLST_ERROR blst_p1_uncompress(blst_p1_affine *out, const byte in[48]);
BLST_ERROR blst_p1_deserialize(blst_p1_affine *out, const byte in[96]);

void blst_p1_to_affine(blst_p1_affine *out, const blst_p1 *in);
void blst_p1_from_affine(blst_p1 *out, const blst_p1_affine *in);
bool blst_p1_affine_in_g1(const blst_p1_affine *p);

void blst_hash_to_g1(blst_p1 *out, const byte *msg, size_t msg_len,
                     const byte *DST, size_t DST_len, const byte *aug,
                     size_t aug_len);

void blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
void blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash,
                        const blst_scalar *SK);

size_t blst_p1s_mult_pippenger_scratch_sizeof(size_t npoints);
void blst_p1s_to_affine(blst_p1_affine dst[], const blst_p1 *const points[],
                        size_t npoints);
void blst_p1s_mult_pippenger(blst_p1 *ret, const blst_p1_affine *const points[],
                             size_t npoints, const byte *const scalars[],
                             size_t nbits, limb_t *scratch);

/* ------------------------------------------------------------------ */
/* G2                                                                 */
/* ------------------------------------------------------------------ */

bool blst_p2_on_curve(const blst_p2 *p);
bool blst_p2_in_g2(const blst_p2 *p);
bool blst_p2_is_inf(const blst_p2 *p);
bool blst_p2_is_equal(const blst_p2 *a, const blst_p2 *b);
void blst_p2_add_or_double(blst_p2 *out, const blst_p2 *a, const blst_p2 *b);
void blst_p2_mult(blst_p2 *out, const blst_p2 *p, const byte *scalar,
                  size_t nbits);
void blst_p2_cneg(blst_p2 *p, bool cbit);
const blst_p2 *blst_p2_generator(void);

void blst_p2_compress(byte out[96], const blst_p2 *in);
void blst_p2_serialize(byte out[192], const blst_p2 *in);
BLST_ERROR blst_p2_uncompress(blst_p2_affine *out, const byte in[96]);
BLST_ERROR blst_p2_deserialize(blst_p2_affine *out, const byte in[192]);

void blst_p2_to_affine(blst_p2_affine *out, const blst_p2 *in);
void blst_p2_from_affine(blst_p2 *out, const blst_p2_affine *in);
bool blst_p2_affine_in_g2(const blst_p2_affine *p);

void blst_hash_to_g2(blst_p2 *out, const byte *msg, size_t msg_len,
                     const byte *DST, size_t DST_len, const byte *aug,
                     size_t aug_len);

void blst_sk_to_pk_in_g2(blst_p2 *out_pk, const blst_scalar *SK);
void blst_sign_pk_in_g2(blst_p1 *out_sig, const blst_p1 *hash,
                        const blst_scalar *SK);

size_t blst_p2s_mult_pippenger_scratch_sizeof(size_t npoints);
void blst_p2s_to_affine(blst_p2_affine dst[], const blst_p2 *const points[],
                        size_t npoints);
void blst_p2s_mult_pippenger(blst_p2 *ret, const blst_p2_affine *const points[],
                             size_t npoints, const byte *const scalars[],
                             size_t nbits, limb_t *scratch);

/* ------------------------------------------------------------------ */
/* Pairing                                                            */
/* ------------------------------------------------------------------ */

void blst_miller_loop(blst_fp12 *ret, const blst_p2_affine *Q,
                      const blst_p1_affine *P);
void blst_fp12_mul(blst_fp12 *ret, const blst_fp12 *a, const blst_fp12 *b);
bool blst_fp12_is_equal(const blst_fp12 *a, const blst_fp12 *b);
bool blst_fp12_finalverify(const blst_fp12 *gt1, const blst_fp12 *gt2);

BLST_ERROR blst_core_verify_pk_in_g1(const blst_p1_affine *pk,
                                     const blst_p2_affine *signature,
                                     bool hash_or_encode, const byte *msg,
                                     size_t msg_len, const byte *DST,
                                     size_t DST_len, const byte *aug,
                                     size_t aug_len);
BLST_ERROR blst_core_verify_pk_in_g2(const blst_p2_affine *pk,
                                     const blst_p1_affine *signature,
                                     bool hash_or_encode, const byte *msg,
                                     size_t msg_len, const byte *DST,
                                     size_t DST_len, const byte *aug,
                                     size_t aug_len);

#ifdef __cplusplus
}
#endif

#endif /* OUROBOROS_CRYPTO_KIT_BLST_H */

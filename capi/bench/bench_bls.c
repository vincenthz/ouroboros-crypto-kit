/*
 * BLS12-381 microbenchmarks over the blst API.
 *
 * Because ouroboros-crypto-kit exports blst's symbols with blst's struct
 * layouts, this file compiles unchanged against either library, which is what
 * makes the comparison exact:
 *
 *   cc -O2 capi/bench/bench_bls.c -I blst/bindings -L blst -lblst -o bench_blst
 *   cc -O2 capi/bench/bench_bls.c -I ../prefix/include -L ../prefix/lib \
 *      -louroboros_crypto_kit -o bench_kit
 *
 * Only the subset of blst that `cardano-crypto-class` uses appears here, so
 * nothing in it depends on which of the two provides the symbols. Each row is
 * timed by doubling the iteration count until the batch takes at least
 * MIN_NANOS, so the same binary gives sensible numbers for implementations an
 * order of magnitude apart. Results are ns/op; take the best of a few quiet
 * runs. See ../../../BUILD.md for the recorded comparison.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <blst.h>

#define MIN_NANOS 200000000ull /* 0.2 s per row */

/* Somewhere for results to go, so that -O2 cannot delete the work. */
static volatile uint64_t sink;

static uint64_t now_nanos(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/*
 * Run the body in batches of doubling size until one batch takes MIN_NANOS, then
 * report that batch's cost per operation. Variadic so that a body containing
 * commas — a multi-statement pairing check, say — needs no extra parentheses.
 */
#define BENCH(label, ...)                                                      \
  do {                                                                         \
    uint64_t iters = 1, elapsed = 0;                                           \
    for (;;) {                                                                 \
      uint64_t start = now_nanos();                                            \
      for (uint64_t i = 0; i < iters; i++) {                                   \
        __VA_ARGS__;                                                           \
      }                                                                        \
      elapsed = now_nanos() - start;                                           \
      if (elapsed >= MIN_NANOS)                                                \
        break;                                                                 \
      iters *= 2;                                                              \
    }                                                                          \
    printf("%-24s %10.0f\n", (label), (double)elapsed / (double)iters);         \
    fflush(stdout);                                                            \
  } while (0)

int main(void) {
  const byte dst[] = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
  const size_t dst_len = sizeof(dst) - 1;
  const byte msg[] = "ouroboros-crypto-kit bench";
  const size_t msg_len = sizeof(msg) - 1;

  /* A scalar with every limb populated, so no multiplication is short. */
  byte be[32];
  for (size_t i = 0; i < sizeof(be); i++) {
    be[i] = (byte)(0x9d + i);
  }
  be[0] = 0x0f; /* keep it below the group order */
  blst_scalar scalar;
  blst_scalar_from_bendian(&scalar, be);

  blst_p1 g1 = *blst_p1_generator();
  blst_p2 g2 = *blst_p2_generator();

  /* A second pair of points, so `add` is an addition and not a doubling. */
  blst_p1 g1b;
  blst_p2 g2b;
  blst_p1_mult(&g1b, &g1, scalar.b, 255);
  blst_p2_mult(&g2b, &g2, scalar.b, 255);

  blst_p1_affine g1_aff, g1b_aff;
  blst_p2_affine g2_aff, g2b_aff;
  blst_p1_to_affine(&g1_aff, &g1);
  blst_p1_to_affine(&g1b_aff, &g1b);
  blst_p2_to_affine(&g2_aff, &g2);
  blst_p2_to_affine(&g2b_aff, &g2b);

  byte c1[48], c2[96];
  blst_p1_compress(c1, &g1);
  blst_p2_compress(c2, &g2);

  blst_fp12 ml1, ml2;
  blst_miller_loop(&ml1, &g2_aff, &g1_aff);
  blst_miller_loop(&ml2, &g2b_aff, &g1b_aff);

  /* Scratch space, reused by the rows below. */
  blst_p1 p1;
  blst_p2 p2;
  blst_p1_affine a1;
  blst_p2_affine a2;
  blst_fp12 f12;
  byte out1[48], out2[96];

  printf("%-24s %10s\n", "operation", "ns/op");
  printf("%-24s %10s\n", "------------------------", "----------");

  BENCH("G1 add", blst_p1_add_or_double(&p1, &g1, &g1b));
  BENCH("G2 add", blst_p2_add_or_double(&p2, &g2, &g2b));

  BENCH("G1 scalar mul", blst_p1_mult(&p1, &g1, scalar.b, 255));
  BENCH("G2 scalar mul", blst_p2_mult(&p2, &g2, scalar.b, 255));

  BENCH("G1 subgroup check", sink += blst_p1_in_g1(&g1));
  BENCH("G2 subgroup check", sink += blst_p2_in_g2(&g2));

  BENCH("G1 compress", blst_p1_compress(out1, &g1));
  BENCH("G2 compress", blst_p2_compress(out2, &g2));

  BENCH("G1 uncompress", sink += blst_p1_uncompress(&a1, c1));
  BENCH("G2 uncompress", sink += blst_p2_uncompress(&a2, c2));

  BENCH("G1 hash-to-curve",
        blst_hash_to_g1(&p1, msg, msg_len, dst, dst_len, NULL, 0));
  BENCH("G2 hash-to-curve",
        blst_hash_to_g2(&p2, msg, msg_len, dst, dst_len, NULL, 0));

  BENCH("Fp12 mul", blst_fp12_mul(&f12, &ml1, &ml2));
  BENCH("miller loop", blst_miller_loop(&f12, &g2_aff, &g1_aff));
  BENCH("final verify", sink += blst_fp12_finalverify(&ml1, &ml2));

  /* What a Plutus pairing check costs: one Miller loop, then one final verify. */
  BENCH("pairing", blst_miller_loop(&f12, &g2_aff, &g1_aff);
        sink += blst_fp12_finalverify(&f12, &ml2));

  /* Keep the sink observably live. */
  if (sink == 0xdeadbeef) {
    printf("unreachable\n");
  }
  return 0;
}

/*
 * `cardano-crypto-class` imports `randombytes_buf` through this path, which is
 * where libsodium keeps it.
 */

#ifndef OUROBOROS_CRYPTO_KIT_SODIUM_RANDOMBYTES_H
#define OUROBOROS_CRYPTO_KIT_SODIUM_RANDOMBYTES_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void randombytes_buf(void *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* OUROBOROS_CRYPTO_KIT_SODIUM_RANDOMBYTES_H */

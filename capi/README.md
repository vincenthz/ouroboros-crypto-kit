# ouroboros-crypto-kit's C ABI

| library it replaces | .pc name / version | symbols | what asks for it |
|---|---|---:|---|
| libsodium, with the input-output-hk VRF extension | `libsodium` 1.0.20 | 69 | `cardano-crypto-class`, `cardano-crypto-praos` |
| libsecp256k1 | `libsecp256k1` 0.6.0 | 24 | `cardano-crypto-class` (CIP-0049) |
| blst | `libblst` 0.3.14 | 55 | `cardano-crypto-class` (CIP-0381) |
| `cardano-crypto`'s bundled C (`cbits/`) | — | 12 | `cardano-crypto` (`Cardano.Crypto.Wallet`, `Crypto.ECC.Ed25519Donna`) |

Only the subset each package actually imports is provided — the VRF, hashes,
Ed25519, guarded allocation and CSPRNG from libsodium; ECDSA, Schnorr/BIP-340
and their key handling from libsecp256k1; G1/G2 arithmetic, (de)serialisation,
hash-to-group and the pairing from blst. Nothing else in those libraries' APIs
is implemented.

`cardano-crypto` — the Byron-era keys behind `cardano-crypto-wrapper` — is
different: it compiles `cbits/encrypted_sign.c` and a copy of ed25519-donna
into itself (`c-sources`), and `cardano-crypto.h` declares the same 12 symbols
it defines there. An unmodified build therefore keeps using its own C; to use
this library instead, build `cardano-crypto` from a `source-repository-package`
whose cabal file drops `c-sources` and adds `pkgconfig-depends: libsodium`
(any of the three `.pc` files resolves to this library). `cardano-crypto`
still depends on crypton for its Haskell-side hashing; only the C it compiles
itself is replaced.

## Building and installing

```sh
./capi/install.sh [PREFIX]           # PREFIX defaults to ../prefix
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
```

That installs the headers, `libouroboros_crypto_kit.{dylib,a}` and one `.pc` per
replaced library, each pointing at this one library. `../BUILD.md` covers
building the node against it and the one cabal trap that matters: the package
hash covers a `pkgconfig-depends` name and version, not the `Libs` line it
resolves to, so changing this library's *contents* is free but renaming it means
store surgery.

The installed shared library records its absolute path as its install name, so
GHC's runtime linker finds it when it loads the library for Template Haskell, and
the built node finds it at run time, without `DYLD_LIBRARY_PATH`.

## The headers are the contract

`capi/include/` holds the prototypes, and they are the documentation for each
function — the Rust in `src/capi/` deliberately carries no duplicate doc
comments, so the two cannot drift. The headers also fix the sizes of the opaque
structs the Haskell side allocates, which is the one part of the layout that is
not ours to choose: `cardano-crypto-class`'s `blst_util.h` asserts blst's sizes,
and libsodium's state sizes are baked into the packages' `Foreign.Storable`
instances.

| struct | size | holds |
|---|---:|---|
| `crypto_hash_sha256_state` | 128 | SHA-256 context |
| `crypto_hash_sha512_state` | 256 | SHA-512 context |
| `crypto_generichash_blake2b_state` | 384 | Blake2b context + output length |
| `blst_p1` / `blst_p2` | 144 / 288 | projective point |
| `blst_p1_affine` / `blst_p2_affine` | 96 / 192 | canonical big-endian coordinates |
| `blst_fp12` | 576 | an `MlResult` |
| `blst_scalar` / `blst_fr` | 32 / 32 | little-endian / canonical scalar |
| `secp256k1_pubkey` / `_xonly_pubkey` | 64 | affine `x \|\| y`, big-endian |
| `secp256k1_ecdsa_signature` | 64 | `r \|\| s`, big-endian |
| `secp256k1_keypair` | 96 | `sk \|\| x \|\| y`, big-endian |

Within those sizes the contents are private to this implementation. Nothing
outside `src/capi/` looks inside them, so what has to agree with the C libraries
is the *behaviour* of the functions — which is what the rest of the crate
provides, against the same test vectors.

## Conventions

* libsodium's functions return `0` for success and `-1` for failure;
  libsecp256k1's return `1` for success and `0` for failure; blst's return a
  `BLST_ERROR`.
* Pointers are trusted to be non-null and to point at as many bytes as the
  corresponding C prototype promises, which is what the callers do. A
  `(pointer, length)` pair with length zero may have a null pointer.
* `sodium_malloc` / `sodium_free` allocate through Rust's allocator with the
  size recorded ahead of the returned block; `sodium_mlock` / `sodium_munlock`
  are real `mlock` / `munlock`. The node's mlocked-key handling therefore works
  as it does against libsodium.
* `sodium_init` returns `0` and does nothing: there is no global state to set
  up, and the CSPRNG is the OS's.

## How it is validated

The most direct check available is that the cardano-base crypto test suites run
unchanged against it — `cardano-crypto-praos:test:tests` in full, and
`cardano-crypto-class:test:tests` covering Ed25519, ECDSA, Schnorr, every KES
tree variant, the hashes, mlocked memory and the BLS12-381 primitives.

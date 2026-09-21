# ouroboros-crypto-kit

The cryptography a Cardano node needs, implemented in Rust by default. Optional
feature flags select the upstream `blst` and `libsecp256k1` C implementations
behind the same public API.

```
cargo test                                  # 80 tests
cargo test --features capi                  # 108, the C ABI included
cargo test --features blst                  # native blst backend
cargo test --features secp256k1             # native libsecp256k1 backend
cargo test --features blst,secp256k1        # both native Plutus backends
./scripts/test-feature-matrix.sh            # every backend/C-ABI combination
cargo run --release --example timings
./capi/install.sh                           # the C ABI, for an unmodified node
```

with `capi/install.sh` run and `PKG_CONFIG_PATH` set, an unmodified
`cardano-node` links this library in place of all three of its C cryptography
libraries. See `../BUILD.md`.

The `capi` feature always uses the Rust BLS implementation because that build
itself exports the `blst_*` symbol set; selecting upstream `blst` there would
define every symbol twice. The Rust-level API and all other feature
combinations use the requested backend.

## What is in it

| module | what it covers |
|---|---|
| `hash` | Blake2b-160/224/256/512, SHA-256/512, SHA3-256, Keccak-256, RIPEMD-160, and `expand_message_xmd` for both SHA-256 and SHA-512 |
| `ed25519` | signing and verification, with the node's exact acceptance rules |
| `edwards25519` | the low-level `ref10`-compatible layer: point encoding, both Elligator2 variants, canonicity and small-order checks |
| `vrf::praos` | `draft-irtf-cfrg-vrf-03`, the VRF every block since Shelley uses (80-byte proofs) |
| `vrf::praos_batch` | `draft-irtf-cfrg-vrf-13` batch-compatible (128-byte proofs) |
| `kes` | `SumKES` and `CompactSumKES` over Ed25519/Blake2b-256, depths 0–7 |
| `plutus::secp256k1` | `verifyEcdsaSecp256k1Signature`, `verifySchnorrSecp256k1Signature` |
| `plutus::bls12_381` | the Plutus surface over G1/G2, hash-to-curve and ZCash (de)serialisation: `blst`'s error taxonomy, the DST limit, scalar reduction, and `millerLoop`/`mulMlResult`/`finalVerify` |
| `capi` | the C ABI, behind the `capi` feature — see `capi/README.md` |

## The C ABI

`capi/` exports 148 symbols under the names, signatures and struct layouts that
`cardano-crypto-class` and `cardano-crypto-praos` already expect:

* 69 for libsodium (the input-output-hk VRF extension included)
* 24 for libsecp256k1
* 55 for blst.

The headers in `capi/include/` are the contract and the documentation;
`capi/install.sh` builds the library and writes one `.pc` per replaced library,
all pointing at it. Because the blst struct layouts are blst's,
`capi/bench/bench_bls.c` compiles unchanged against either library, which is
how the comparison is made exact.

## How it is validated

The point of this crate is to agree with the node byte for byte, so it is
written against the implementation the node runs rather than against the
specification the implementation claims to follow, and it is tested against
vectors produced by other people's code.

| what | vectors | source |
| ---- | ------- | ------ |
| VRF draft-03 | 7 + 31 | `cardano-base` `test_vectors/vrf_ver03_*`, and libsodium's own `test/default/vrf.c` |
| VRF draft-13 | 7 | `cardano-base` `test_vectors/vrf_ver13_*` |
| KES | 14 files | Haskell-generated keys, evolutions and signatures for `Sum{0,1,6}KES` and `CompactSum{0,1,6}KES` |
| Ed25519 | 3 + edge cases | RFC 8032, plus the small-order / non-canonical rejections |
| `expand_message_xmd` | 5 | RFC 9380 appendix K.3 |
| BLS hash-to-curve | 10 | RFC 9380 appendices J.9.1 and J.10.1, extracted from the RFC text |
| BLS everything else | 78 | `ethereum/bls12-381-tests` v0.1.2 (generated with `py_ecc` and `blst`): compressed-point deserialisation including every malformed case, signing, verification, aggregation |
| Schnorr (BIP-340) | 19 | the BIPs repository's `test-vectors.csv`, including all the rejection cases |
| ECDSA | 252 | Wycheproof `ecdsa_secp256k1_sha256_p1363` |

Beyond the vectors, the most direct check available is that the cardano-base
crypto test suites — `cardano-crypto-praos` and `cardano-crypto-class` — run
unchanged against the C ABI.

## Deviations from the specifications, reproduced deliberately

* **VRF draft-03** clears the sign bit of the SHA-512 output *before* Elligator2
  rather than inside the map, so Cardano's VRF output differs from any
  implementation that follows the draft. `edwards25519::elligator2_from_uniform`.
* **VRF draft-13** uses RFC 9380 `encode_to_curve` with
  `expand_message_xmd(SHA-512)` and DST
  `ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04`, and includes the verification
  key in the challenge. The `vrf_dalek` crate's `vrf10_batchcompat` does neither
  and is *not* compatible with `PraosBatchCompatVRF`.
* **Ed25519 verification** additionally rejects a small-order `R`, and a
  verification key that is non-canonically encoded or of small order — the three
  checks libsodium performs and a plain `cryptoxide::ed25519::verify` does not.
* **KES verification** places no bound on the period, matching `verifyKES`: a
  period beyond the tree's capacity walks to the right-most leaf instead of
  being rejected. The consensus layer is what bounds it.
* **ECDSA** rejects an `s` in the upper half of the scalar field and accepts
  `x(R) == r + n`, both because `libsecp256k1` does.

`MlResult` is the one place where the representation is deliberately *not*
`blst`'s, and it does not have to be: Plutus can only multiply and compare
`MlResult`s, never observe their bytes, so only the comparison has to agree.

## Status and caveats

* Batch VRF verification (`crypto_vrf_ietfdraft13_batch_verify`) is not
  implemented; it is an optimisation, and the node does not use it.
* The Rust `kes` module keeps keys in ordinary heap memory and does not `mlock`
  them. A node going through the C ABI is unaffected — it allocates its own
  mlocked memory through `sodium_malloc` and `sodium_mlock`, which `capi`
  implements — but a direct Rust caller gets no such protection.

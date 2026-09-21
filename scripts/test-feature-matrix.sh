#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

# The first four entries are the complete 2x2 Rust API backend matrix.
# The remaining entries verify the exported C ABI, including its supported
# interaction with the native secp256k1 verifier and the intentionally ignored
# blst selector (the C ABI itself owns the blst_* symbols).
names=(
  "pure Rust"
  "native blst"
  "native secp256k1"
  "native blst + secp256k1"
  "C ABI"
  "C ABI + secp256k1"
  "all features"
)

features=(
  ""
  "blst"
  "secp256k1"
  "blst,secp256k1"
  "capi"
  "capi,secp256k1"
  "capi,blst,secp256k1"
)

for i in "${!names[@]}"; do
  printf '\n==> Testing %s\n' "${names[$i]}"
  if [[ -z "${features[$i]}" ]]; then
    cargo test
  else
    cargo test --features "${features[$i]}"
  fi
done

printf '\nFeature matrix passed (%d configurations).\n' "${#names[@]}"

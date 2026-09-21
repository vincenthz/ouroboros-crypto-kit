#!/usr/bin/env bash
#
# Build ouroboros-crypto-kit's C ABI and install it where pkg-config can find it.
#
#   ./capi/install.sh [PREFIX]
#
# PREFIX defaults to ../prefix. Afterwards:
#
#   export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
#
# and cabal resolves `pkgconfig-depends: libsodium`, `libsecp256k1` and `libblst`
# — which is what cardano-crypto-class and cardano-crypto-praos declare — to the
# three .pc files written here, all of which point at this one library. See
# ../../BUILD.md for building the node against it.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
kit=$(dirname "$here")
prefix=${1:-$(cd "$kit/.." && pwd)/prefix}

libname=libouroboros_crypto_kit
case $(uname -s) in
Darwin) libext=dylib ;;
*) libext=so ;;
esac

mkdir -p "$prefix/include/sodium" "$prefix/lib/pkgconfig"

# The shared library records where it is installed, so that anything linked
# against it — including GHC's runtime linker, when it loads the library for
# Template Haskell — finds it without a search path.
if [ "$libext" = dylib ]; then
  export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-install_name,$prefix/lib/$libname.$libext"
fi

echo "building $libname.$libext"
(cd "$kit" && cargo build --release --features capi)

echo "installing into $prefix"
install -m 644 "$here/include/sodium.h" "$prefix/include/sodium.h"
install -m 644 "$here/include/sodium/randombytes.h" "$prefix/include/sodium/randombytes.h"
install -m 644 "$here/include/secp256k1.h" "$prefix/include/secp256k1.h"
install -m 644 "$here/include/secp256k1_extrakeys.h" "$prefix/include/secp256k1_extrakeys.h"
install -m 644 "$here/include/secp256k1_schnorrsig.h" "$prefix/include/secp256k1_schnorrsig.h"
install -m 644 "$here/include/blst.h" "$prefix/include/blst.h"
install -m 644 "$kit/target/release/$libname.$libext" "$prefix/lib/$libname.$libext"
install -m 644 "$kit/target/release/$libname.a" "$prefix/lib/$libname.a"

# One .pc per library being replaced, each claiming the version of the upstream
# release whose API this implements — that is what a cabal `pkgconfig-depends`
# constraint is checked against.
#
# Note the cabal trap documented in ../../BUILD.md: the package hash covers a
# pkg-config dependency's name and version, not the resolved Libs line. Changing
# this library's *contents* is free; renaming it means store surgery.
write_pc() {
  local name=$1 version=$2 description=$3
  cat >"$prefix/lib/pkgconfig/$name.pc" <<EOF
prefix=$prefix
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: $name
Description: $description
Version: $version
Libs: -L\${libdir} -l${libname#lib}
Cflags: -I\${includedir}
EOF
}

write_pc libsodium 1.0.20 \
  "ouroboros-crypto-kit's implementation of the libsodium API used by Cardano, VRF included"
write_pc libsecp256k1 0.6.0 \
  "ouroboros-crypto-kit's implementation of the libsecp256k1 API used by Cardano"
write_pc libblst 0.3.14 \
  "ouroboros-crypto-kit's implementation of the blst API used by Cardano"

echo
echo "installed:"
echo "  $prefix/include/{sodium.h,sodium/randombytes.h,secp256k1*.h,blst.h}"
echo "  $prefix/lib/$libname.$libext"
echo "  $prefix/lib/$libname.a"
ls -1 "$prefix/lib/pkgconfig" | sed 's|^|  '"$prefix"'/lib/pkgconfig/|'
echo
echo "use it with:"
echo "  export PKG_CONFIG_PATH=$prefix/lib/pkgconfig"

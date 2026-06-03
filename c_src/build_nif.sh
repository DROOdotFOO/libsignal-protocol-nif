#!/bin/sh
# c_src/build_nif.sh
#
# Runs at consumer compile time via the post-compile hook in rebar.config.
# Skips if the NIF binaries are already present. Otherwise:
#   1. Detects the platform triplet via uname.
#   2. Tries to download the matching pre-built tarball from this version's
#      GitHub Release.
#   3. Falls back to cmake + make in c_src/ if the download fails, the
#      platform isn't supported, or LIBSIGNAL_NIF_BUILD_FROM_SOURCE=1 is set.
#
# The script ships inside the Hex tarball under c_src/ so it's available to
# downstream consumers as well as to local dev builds.

set -e

# Repo coordinates for the GitHub Release that hosts the pre-built tarballs.
REPO="Hydepwns/libsignal-protocol-nif"

# Resolve the project root from the script location. Works whether the script
# is invoked from the project root or from a deps tree.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Read VERSION; missing or empty means we can't build a release URL, so we
# skip the download and go straight to source build.
VERSION=""
if [ -f "${PROJECT_ROOT}/VERSION" ]; then
    VERSION="$(cat "${PROJECT_ROOT}/VERSION" | tr -d '[:space:]')"
fi

# Skip everything if the NIF binaries are already in priv/.
for ext in so dylib; do
    if [ -f "${PROJECT_ROOT}/priv/signal_nif.${ext}" ] && \
       [ -f "${PROJECT_ROOT}/priv/libsignal_protocol_nif.${ext}" ]; then
        exit 0
    fi
done

mkdir -p "${PROJECT_ROOT}/priv"

# Detect target triplet. Match what the release workflow names its tarballs.
SYSTEM="$(uname -s)"
MACHINE="$(uname -m)"
TRIPLET=""
EXT=""
case "${SYSTEM}-${MACHINE}" in
    Darwin-arm64)   TRIPLET="aarch64-apple-darwin";      EXT="dylib" ;;
    Darwin-x86_64)  TRIPLET="x86_64-apple-darwin";       EXT="dylib" ;;
    Linux-aarch64)  TRIPLET="aarch64-unknown-linux-gnu"; EXT="so" ;;
    Linux-arm64)    TRIPLET="aarch64-unknown-linux-gnu"; EXT="so" ;;
    Linux-x86_64)   TRIPLET="x86_64-unknown-linux-gnu";  EXT="so" ;;
esac

# Try the pre-built download unless explicitly opted out.
if [ -n "${TRIPLET}" ] && [ -n "${VERSION}" ] && \
   [ -z "${LIBSIGNAL_NIF_BUILD_FROM_SOURCE:-}" ] && \
   command -v curl >/dev/null 2>&1; then
    NAME="libsignal_protocol_nif-${TRIPLET}-${VERSION}"
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/${NAME}.tar.gz"
    TMP="/tmp/${NAME}.$$"
    echo "Fetching pre-built NIF: ${URL}"
    if curl -fsSL -o "${TMP}.tar.gz" "${URL}" 2>/dev/null; then
        mkdir -p "${TMP}"
        if tar -xzf "${TMP}.tar.gz" -C "${TMP}" 2>/dev/null; then
            cp "${TMP}/${NAME}/signal_nif.${EXT}" "${PROJECT_ROOT}/priv/"
            cp "${TMP}/${NAME}/libsignal_protocol_nif.${EXT}" "${PROJECT_ROOT}/priv/"
            rm -rf "${TMP}" "${TMP}.tar.gz"
            echo "Pre-built NIF installed for ${TRIPLET}."
            exit 0
        fi
        rm -rf "${TMP}" "${TMP}.tar.gz"
    fi
    echo "Pre-built download unavailable; falling back to source build."
fi

# Source build fallback. Requires cmake + libsodium + openssl headers on the
# system; on macOS the keg-only openssl@3 needs DYLD_LIBRARY_PATH at run time.
if ! command -v cmake >/dev/null 2>&1; then
    echo "ERROR: cmake not found and no pre-built binary available."
    echo "       Install cmake, libsodium-dev, and libssl-dev (Debian) or"
    echo "       brew install libsodium openssl@3 cmake (macOS)."
    echo "       Or download a release tarball manually from"
    echo "       https://github.com/${REPO}/releases"
    exit 1
fi

echo "Building NIF from source in c_src/..."
cd "${PROJECT_ROOT}/c_src"
cmake . -DCMAKE_BUILD_TYPE=Release
make
# Clean in-tree cmake droppings so they don't pollute future rebar3 hex builds.
rm -rf CMakeFiles CMakeCache.txt cmake_install.cmake Makefile
echo "Source build complete."

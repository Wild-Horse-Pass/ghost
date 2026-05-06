#!/usr/bin/env bash
# release-wraith.sh — package the three Wraith Wallet binaries into a
# versioned tarball.
#
# Output: dist/wraith-wallet-<version>-<host-triple>.tar.gz
#         dist/wraith-wallet-<version>-<host-triple>.tar.gz.sha256
#
# Layout inside the tarball:
#   wraith-wallet-<version>/
#     bin/wraithd
#     bin/wraith
#     bin/wraith-gui
#     completions/wraith.bash
#     completions/_wraith            (zsh)
#     completions/wraith.fish
#     README.md                       (the wallet README, not the repo root)
#     LICENSE                         (MIT)
#
# Phase 15 first slice: signing + auto-update tooling come later. This
# script is what you'd run on a build host to produce a clean, immutable
# artifact ready for upload + manual signing.
#
# Usage:
#   bash scripts/release-wraith.sh [version]
#
#   version defaults to the workspace version from Cargo.toml.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(awk -F'"' '/^version *=/ {print $2; exit}' Cargo.toml)}"
TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"
NAME="wraith-wallet-${VERSION}-${TRIPLE}"
STAGING="dist/${NAME}"
TARBALL="dist/${NAME}.tar.gz"

echo "==> Wraith Wallet release ${VERSION} for ${TRIPLE}"
mkdir -p dist
rm -rf "$STAGING" "$TARBALL" "${TARBALL}.sha256"
mkdir -p "$STAGING/bin" "$STAGING/completions"

echo "==> Building release binaries (this will take a while on a cold cache)"
cargo build --release \
  -p wraith-wallet-daemon \
  -p wraith-wallet-cli \
  -p wraith-wallet-gui

cp target/release/wraithd      "$STAGING/bin/"
cp target/release/wraith       "$STAGING/bin/"
cp target/release/wraith-gui   "$STAGING/bin/"

echo "==> Stripping debug info"
strip "$STAGING/bin/wraithd" "$STAGING/bin/wraith" "$STAGING/bin/wraith-gui" 2>/dev/null || true

echo "==> Generating shell completions"
"$STAGING/bin/wraith" completions bash > "$STAGING/completions/wraith.bash"
"$STAGING/bin/wraith" completions zsh  > "$STAGING/completions/_wraith"
"$STAGING/bin/wraith" completions fish > "$STAGING/completions/wraith.fish"

echo "==> Copying docs"
cp apps/wraith-wallet/README.md "$STAGING/README.md"
# Repo-root LICENSE; fall back to a minimal stub if the file isn't tracked.
if [[ -f LICENSE ]]; then
  cp LICENSE "$STAGING/LICENSE"
else
  printf 'MIT — see https://github.com/bitcoin-ghost/ghost\n' > "$STAGING/LICENSE"
fi

echo "==> Recording build metadata"
{
  echo "version: ${VERSION}"
  echo "triple:  ${TRIPLE}"
  echo "built:   $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "commit:  $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "rustc:   $(rustc --version)"
} > "$STAGING/BUILDINFO.txt"

echo "==> Packing tarball"
( cd dist && tar czf "${NAME}.tar.gz" "${NAME}" )
( cd dist && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )

echo "==> Done"
echo "    $TARBALL"
echo "    ${TARBALL}.sha256"
( cd dist && cat "${NAME}.tar.gz.sha256" )

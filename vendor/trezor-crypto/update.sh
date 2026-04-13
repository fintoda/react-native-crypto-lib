#!/usr/bin/env bash
# Re-sync vendor/trezor-crypto/crypto/ from trezor-firmware at a given commit.
#
# Usage: ./vendor/trezor-crypto/update.sh <commit-sha>
#
# Run from the repository root. The script clones trezor-firmware with a
# sparse checkout of the crypto/ subtree, replaces the local copy, and
# updates the pinned SHA in VENDOR.md. Review the resulting diff before
# committing.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <commit-sha>" >&2
  exit 2
fi

SHA="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Cloning trezor-firmware @ $SHA ..."
git clone --filter=blob:none --no-checkout --quiet \
  https://github.com/trezor/trezor-firmware.git "$TMP_DIR/tf"
git -C "$TMP_DIR/tf" sparse-checkout init --cone
git -C "$TMP_DIR/tf" sparse-checkout set crypto
git -C "$TMP_DIR/tf" checkout --quiet "$SHA"

echo "Replacing $SCRIPT_DIR/crypto ..."
rm -rf "$SCRIPT_DIR/crypto"
cp -R "$TMP_DIR/tf/crypto" "$SCRIPT_DIR/crypto"

echo "Updating pinned SHA in VENDOR.md ..."
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' -E "s/^- Pinned commit: \`[0-9a-f]+\`/- Pinned commit: \`$SHA\`/" "$SCRIPT_DIR/VENDOR.md"
else
  sed -i -E "s/^- Pinned commit: \`[0-9a-f]+\`/- Pinned commit: \`$SHA\`/" "$SCRIPT_DIR/VENDOR.md"
fi

echo "Done. Review with: git diff vendor/trezor-crypto"

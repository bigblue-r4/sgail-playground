#!/bin/sh
# Re-copy the witness code this page runs from kiss-protocol, at a given ref.
#
#   witness/scripts/sync-from-kiss.sh <path-to-kiss-protocol-checkout> [ref]   (ref defaults to the latest v* tag)
#
# Go does not allow importing another module's internal/ packages, so these are
# copies. Run this after a kiss-protocol release, then `go test ./...` and commit.
set -eu
KISS=${1:?usage: $0 <kiss-protocol checkout> [ref]}
REF=${2:-$(git -C "$KISS" describe --tags --abbrev=0 --match 'v*')}
SHA=$(git -C "$KISS" rev-parse --short "$REF^{commit}")
HERE=$(cd "$(dirname "$0")/.." && pwd)

FILES="
internal/store/store.go internal/store/log_test.go internal/store/treehead_missing_test.go internal/store/treehead_signer_test.go
internal/encrypt/encrypt.go internal/encrypt/encrypt_test.go
internal/merkle/tree.go internal/merkle/proof.go internal/merkle/tree_test.go internal/merkle/proof_test.go
internal/signer/signer.go internal/signer/dev.go internal/signer/dev_test.go internal/signer/piv_stub.go
"
rm -rf "$HERE/internal"
for f in $FILES; do
  mkdir -p "$HERE/$(dirname "$f")"
  git -C "$KISS" show "$REF:$f" > "$HERE/$f"
done
find "$HERE/internal" -name '*.go' -exec sed -i \
  's#github.com/bigblue-r4/kiss-protocol/internal/#github.com/bigblue-r4/sgail-playground/witness/internal/#g' {} +
cat > "$HERE/internal/SOURCE.md" <<MD
# Source of the code in internal/

Copied from [kiss-protocol](https://github.com/bigblue-r4/kiss-protocol) **$REF** (commit \`$SHA\`)
by \`scripts/sync-from-kiss.sh\`. Do not edit these files here: fix them in kiss-protocol, release,
and re-sync. Import paths are rewritten to this module.
MD
echo "synced from kiss-protocol $REF ($SHA)"

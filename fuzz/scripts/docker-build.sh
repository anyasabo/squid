#!/usr/bin/env bash
#
# Build the squid-fuzz Docker image.
#
# Since fuzz/ lives inside the squid repo, we create a temporary build context
# with squid/ (excluding .git) and fuzz/ to keep the Docker context small.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SQUID_SRC="$(cd "$FUZZ_DIR/.." && pwd)"
DOCKER_TAG="${DOCKER_TAG:-squid-fuzz}"

if [[ ! -f "$SQUID_SRC/bootstrap.sh" ]]; then
    echo "ERROR: Squid source not found at $SQUID_SRC" >&2
    exit 1
fi

echo "Squid source: $SQUID_SRC"
echo "Docker tag:   $DOCKER_TAG"

CONTEXT=$(mktemp -d)
trap 'rm -rf "$CONTEXT"' EXIT

echo "Copying Squid source (excluding .git, fuzz/build, fuzz/corpus, fuzz/crashes)..."
rsync -a \
    --exclude='.git' \
    --exclude='fuzz/build' \
    --exclude='fuzz/corpus' \
    --exclude='fuzz/crashes' \
    "$SQUID_SRC/" "$CONTEXT/squid/"

echo "Copying Dockerfile..."
cp "$FUZZ_DIR/Dockerfile" "$CONTEXT/"

echo "Building Docker image (this takes several minutes on first run)..."
docker build -t "$DOCKER_TAG" "$CONTEXT"

echo ""
echo "Done. Run with:"
echo "  cd $FUZZ_DIR && make docker-run"

#!/bin/bash
set -euo pipefail

OPENCLAW_REF="/Users/gfw/clawd/02-Projects/clawbureau/openclaw-ref"

if [ ! -d "$OPENCLAW_REF/.git" ]; then
  echo "openclaw-ref not found at $OPENCLAW_REF"
  exit 1
fi

cd "$OPENCLAW_REF"

if [ -n "$(git status --porcelain)" ]; then
  echo "openclaw-ref has local changes. Refusing to pull."
  git status -sb
  exit 2
fi

echo "Updating openclaw-ref..."
git fetch origin main

git checkout main >/dev/null 2>&1 || true

git pull --ff-only origin main

echo "openclaw-ref updated to: $(git rev-parse --short HEAD)"

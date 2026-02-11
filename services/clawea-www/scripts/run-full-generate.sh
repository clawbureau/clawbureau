#!/bin/bash
set -e
cd "$(dirname "$0")/.."
echo "Starting full SEO generation at $(date)"
echo "Working directory: $(pwd)"
echo "GOOGLE_API_KEY set: $([ -n "$GOOGLE_API_KEY" ] && echo yes || echo no)"

# Resume mode in case of interruption, 30 concurrent workers
npx tsx scripts/generate.ts --resume --concurrency 30 2>&1 | tee articles/_generation.log

echo "Generation complete at $(date)"

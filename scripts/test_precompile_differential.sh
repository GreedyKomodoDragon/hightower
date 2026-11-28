#!/usr/bin/env bash
set -euo pipefail
seed=${1:-114}
count=${2:-2}
cases=$(mktemp)
trap 'rm -f "$cases"' EXIT
(
  cd scripts/geth-discovery-probe
  go test ./precompile-differential
  go run ./precompile-differential --seed "$seed" --count "$count" > "$cases"
)
zig build precompile-differential
zig-out/bin/precompile-differential "$cases"

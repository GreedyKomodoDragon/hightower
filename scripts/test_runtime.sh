#!/usr/bin/env bash
set -euo pipefail

server_log=$(mktemp)
./zig-out/bin/hightower --config tests/runtime/config.json >"$server_log" 2>&1 &
server_pid=$!
cleanup() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    rm -f "$server_log"
}
trap cleanup EXIT

for _ in {1..30}; do
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:18081/eth/v1/node/health || true)
    if [[ "$status" == "200" ]]; then
        metrics=$(curl --fail --silent http://127.0.0.1:18081/metrics)
        grep --fixed-strings --quiet 'hightower_slot 0' <<<"$metrics"
        grep --fixed-strings --quiet 'hightower_finalized_epoch 0' <<<"$metrics"
        exit 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$server_log"
        exit 1
    fi
    sleep 1
done

cat "$server_log"
echo "Hightower runtime did not become ready" >&2
exit 1

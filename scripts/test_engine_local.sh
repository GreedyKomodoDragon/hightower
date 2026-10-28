#!/usr/bin/env bash
set -euo pipefail

genesis_hash=0xd5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f
test_dir=$(mktemp -d /tmp/hightower-engine-local.XXXXXX)
server_pid=

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$test_dir"
}
trap cleanup EXIT

openssl rand -hex 32 > "$test_dir/jwt.hex"
zig build engine-test-server engine-probe
./zig-out/bin/hightower-engine-test-server 18553 "$test_dir/jwt.hex" docs/engine/osaka-genesis.json > "$test_dir/server.log" 2>&1 &
server_pid=$!
for _ in {1..30}; do
    if curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18553/; then break; fi
    if ! kill -0 "$server_pid" 2>/dev/null; then cat "$test_dir/server.log"; exit 1; fi
    sleep 1
done
if ! curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18553/; then
    cat "$test_dir/server.log"
    echo 'Engine API server did not become ready' >&2
    exit 1
fi

for authorization in '' 'Authorization: Bearer invalid'; do
    if [[ -n "$authorization" ]]; then
        status=$(curl --silent --max-time 2 --output /dev/null --write-out '%{http_code}' --request POST --data-binary '' --header "$authorization" http://127.0.0.1:18553/)
    else
        status=$(curl --silent --max-time 2 --output /dev/null --write-out '%{http_code}' --request POST --data-binary '' http://127.0.0.1:18553/)
    fi
    if [[ "$status" != 401 ]]; then
        echo "Expected HTTP 401 for invalid JWT; got $status" >&2
        exit 1
    fi
done

./zig-out/bin/hightower-engine-probe http://127.0.0.1:18553 "$test_dir/jwt.hex" "$genesis_hash"

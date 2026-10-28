#!/usr/bin/env bash
set -euo pipefail

geth_image=${1:-ethereum/client-go@sha256:6e9669cca5359cdb2c5571198d51e78fc18128b56bff50a1f8422d1c2946fd64}
genesis_hash=0xd5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f
interop_dir=$(mktemp -d /tmp/hightower-engine-interop.XXXXXX)
geth_container=
fixture_pid=

# Stop both engines and remove the temporary chain after every outcome.
cleanup() {
    if [[ -n "$fixture_pid" ]]; then
        kill "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
    fi
    if [[ -n "$geth_container" ]]; then docker rm -f "$geth_container" >/dev/null 2>&1 || true; fi
    rm -rf "$interop_dir"
}
trap cleanup EXIT

openssl rand -hex 32 > "$interop_dir/jwt.hex"
mkdir "$interop_dir/data"
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/docs/engine/osaka-genesis.json:/genesis.json:ro" -v "$interop_dir/data:/data" "$geth_image" --datadir /data init /genesis.json
geth_container=$(docker run -d --rm --user "$(id -u):$(id -g)" -p 127.0.0.1:18551:8551 -v "$interop_dir/data:/data" -v "$interop_dir/jwt.hex:/jwt.hex:ro" "$geth_image" --datadir /data --networkid 1337 --authrpc.addr 0.0.0.0 --authrpc.vhosts '*' --authrpc.jwtsecret /jwt.hex --nodiscover --maxpeers 0)

zig build engine-test-server engine-probe
./zig-out/bin/hightower-engine-test-server 18552 "$interop_dir/jwt.hex" docs/engine/osaka-genesis.json > "$interop_dir/fixture.log" 2>&1 &
fixture_pid=$!
for _ in {1..30}; do
    if curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18551/ && curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18552/; then break; fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then cat "$interop_dir/fixture.log"; exit 1; fi
    sleep 1
done
if ! curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18551/ || ! curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18552/; then
    docker logs "$geth_container"
    cat "$interop_dir/fixture.log"
    echo 'Engine API servers did not become ready' >&2
    exit 1
fi
cat "$interop_dir/fixture.log"
./zig-out/bin/hightower-engine-probe http://127.0.0.1:18552 http://127.0.0.1:18551 "$interop_dir/jwt.hex" "$genesis_hash"

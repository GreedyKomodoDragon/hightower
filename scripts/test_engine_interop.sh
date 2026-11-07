#!/usr/bin/env bash
set -euo pipefail
umask 077
source scripts/network_diagnostics.sh

geth_version=${1:-v1.17.10}
geth_version=${geth_version#v}
geth_bin=${GETH_BIN:-geth}
genesis_hash=0xd5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f
interop_dir=$(mktemp -d /tmp/hightower-engine-interop.XXXXXX)
geth_pid=
fixture_pid=

# Stop Geth and the fixture server, then remove the temporary chain.
cleanup() {
    local status=$?
    if [[ -n "$fixture_pid" ]]; then
        kill "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
    fi
    if [[ -n "$geth_pid" ]]; then
        kill "$geth_pid" 2>/dev/null || true
        wait "$geth_pid" 2>/dev/null || true
    fi
    network_diagnostics_stop || status=1
    if [[ $status == 0 && ${KEEP_INTEROP_DIR:-0} != 1 && ${NETWORK_PROXY:-0} != 1 ]]; then rm -rf "$interop_dir"; else echo "Interop files: $interop_dir"; fi
    exit "$status"
}
trap cleanup EXIT

openssl rand -hex 32 > "$interop_dir/jwt.hex"
mkdir "$interop_dir/data"
if ! command -v "$geth_bin" >/dev/null 2>&1; then
    echo "Geth binary not found: $geth_bin (install Geth or set GETH_BIN)" >&2
    exit 1
fi
actual_version=$("$geth_bin" version | awk -F ': ' '/^Version:/ { split($2, parts, "-"); print parts[1] }')
if [[ "$actual_version" != "$geth_version" ]]; then
    echo "Expected Geth $geth_version, found $actual_version at $geth_bin" >&2
    exit 1
fi
"$geth_bin" --datadir "$interop_dir/data" init docs/engine/osaka-genesis.json
"$geth_bin" --datadir "$interop_dir/data" --networkid 1337 --authrpc.addr 127.0.0.1 --authrpc.port 18551 --authrpc.vhosts '*' --authrpc.jwtsecret "$interop_dir/jwt.hex" --nodiscover --maxpeers 0 > "$interop_dir/geth.log" 2>&1 &
geth_pid=$!

zig build engine-test-server engine-probe
./zig-out/bin/hightower-engine-test-server 18552 "$interop_dir/jwt.hex" docs/engine/osaka-genesis.json > "$interop_dir/fixture.log" 2>&1 &
fixture_pid=$!
for _ in {1..30}; do
    if curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18551/ && curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18552/; then break; fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then cat "$interop_dir/fixture.log"; exit 1; fi
    sleep 1
done
if ! curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18551/ || ! curl --silent --max-time 1 --output /dev/null http://127.0.0.1:18552/; then
    cat "$interop_dir/geth.log"
    cat "$interop_dir/fixture.log"
    echo 'Engine API servers did not become ready' >&2
    exit 1
fi
cat "$interop_dir/fixture.log"
network_diagnostics_init
fixture_port=18552
geth_port=18551
if [[ ${NETWORK_PROXY:-0} == 1 ]]; then
    network_proxy_start engine-fixture-proxy tcp 19552 18552
    network_proxy_start engine-geth-proxy tcp 19551 18551
    fixture_port=19552
    geth_port=19551
fi
./zig-out/bin/hightower-engine-probe "http://127.0.0.1:$fixture_port" "http://127.0.0.1:$geth_port" "$interop_dir/jwt.hex" "$genesis_hash"

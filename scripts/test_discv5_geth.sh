#!/usr/bin/env bash
set -euo pipefail
umask 077
source scripts/network_diagnostics.sh

interop_dir=$(mktemp -d /tmp/hightower-discv5-geth.XXXXXX)
fixture_pid=

# Stop the loopback fixture and remove its temporary output.
cleanup() {
    local status=$?
    if [[ -n "$fixture_pid" ]]; then
        kill "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
    fi
    network_diagnostics_stop || status=1
    if [[ $status == 0 && ${KEEP_INTEROP_DIR:-0} != 1 && ${NETWORK_PROXY:-0} != 1 && ${NETWORK_TRACE:-0} != 1 ]]; then rm -rf "$interop_dir"; else echo "Interop files: $interop_dir"; fi
    exit "$status"
}
trap cleanup EXIT

network_diagnostics_init
if [[ ${NETWORK_PROXY:-0} == 1 ]]; then
    export HIGHTOWER_DISCOVERY_PORT=19004
    export HIGHTOWER_DISCOVERY_PROXY=127.0.0.1:19504
    export HIGHTOWER_DISCOVERY_SOURCE=127.0.0.1:19505
    network_proxy_start discovery-proxy udp 19504 19004 "$HIGHTOWER_DISCOVERY_SOURCE"
fi
zig build discv5-interop-fixture
(
    cd scripts/geth-discovery-probe
    go build -o "$interop_dir/geth-discovery-probe" .
)
./zig-out/bin/hightower-discv5-interop-fixture > "$interop_dir/enr" 2> "$interop_dir/fixture.log" &
fixture_pid=$!
for _ in {1..50}; do
    if [[ -s "$interop_dir/enr" ]]; then break; fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then cat "$interop_dir/fixture.log"; exit 1; fi
    sleep 0.1
done
if [[ ! -s "$interop_dir/enr" ]]; then
    cat "$interop_dir/fixture.log"
    echo 'Hightower discovery fixture did not print an ENR' >&2
    exit 1
fi
if command -v timeout >/dev/null 2>&1; then
    timeout 30s "$interop_dir/geth-discovery-probe" "$(head -n 1 "$interop_dir/enr")"
else
    "$interop_dir/geth-discovery-probe" "$(head -n 1 "$interop_dir/enr")"
fi
if ! kill -0 "$fixture_pid" 2>/dev/null; then
    cat "$interop_dir/fixture.log"
    echo 'Hightower discovery fixture exited early' >&2
    exit 1
fi

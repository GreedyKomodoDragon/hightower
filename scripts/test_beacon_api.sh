#!/usr/bin/env bash
set -euo pipefail

server_pid=
server_log=
# Stop the current fixture server and remove its captured output.
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [[ -n "$server_log" ]]; then rm -f "$server_log"; fi
    server_pid=
    server_log=
}
trap cleanup EXIT

# Start one test mode, wait for its expected health status, and run its collection.
run_suite() {
    local mode=$1 expected_status=$2 suite=$3 status=000
    server_log=$(mktemp)
    ./zig-out/bin/hightower-api-test-server "$mode" >"$server_log" 2>&1 &
    server_pid=$!
    for _ in {1..30}; do
        status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:18080/eth/v1/node/health || true)
        if [[ "$status" == "$expected_status" ]]; then break; fi
        if ! kill -0 "$server_pid" 2>/dev/null; then cat "$server_log"; exit 1; fi
        sleep 1
    done
    if [[ "$status" != "$expected_status" ]]; then
        cat "$server_log"
        echo "Beacon API test server did not become ready in $mode mode" >&2
        exit 1
    fi
    (cd tests/bruno/beacon-api && bru run "$suite" --env local --bail)
    cleanup
}

run_suite ready 200 ready
run_suite syncing 206 scenarios/syncing.bru
run_suite unavailable 503 scenarios/unavailable.bru

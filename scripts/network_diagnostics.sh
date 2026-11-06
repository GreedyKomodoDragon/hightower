#!/usr/bin/env bash
# Shared opt-in lifecycle for local interoperability diagnostics; source from repo root.
proxy_pids=()

# Build once and opt into protocol traces independently of socket proxying.
network_diagnostics_init() {
    if [[ ${NETWORK_PROXY:-0} == 1 ]]; then zig build network-proxy; fi
    if [[ ${NETWORK_TRACE:-0} == 1 ]]; then
        export HIGHTOWER_NETWORK_TRACE="$interop_dir/network-trace.jsonl"
    fi
}

# Start a separate destination proxy and require initialized capture metadata.
network_proxy_start() {
    local name=$1 protocol=$2 listen=$3 upstream=$4
    shift 4
    ./zig-out/bin/hightower-network-proxy "$protocol" "$listen" "$upstream" "$interop_dir/$name" "$@" > "$interop_dir/$name.log" 2>&1 &
    local pid=$!
    proxy_pids+=("$pid")
    for _ in {1..100}; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$interop_dir/$name.log" >&2; return 1; fi
        if python3 - "$interop_dir/$name/events.jsonl" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as stream:
        event = json.loads(stream.readline())
    assert event['event'] == 'ready'
except (OSError, ValueError, AssertionError):
    sys.exit(1)
PY
        then return 0; fi
        sleep 0.1
    done
    echo "Proxy readiness timed out: $name" >&2
    return 1
}

# Stop and wait for recording flushes; proxy failure makes the harness fail too.
network_diagnostics_stop() {
    local pid failed=0
    for pid in "${proxy_pids[@]+${proxy_pids[@]}}"; do
        if ! kill -0 "$pid" 2>/dev/null; then failed=1; fi
        kill "$pid" 2>/dev/null || true
        if ! wait "$pid"; then failed=1; fi
    done
    return "$failed"
}

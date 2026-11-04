#!/usr/bin/env bash
set -euo pipefail

geth_bin=${GETH_BIN:-geth}
prysm_dir=${PRYSM_BIN_DIR:-}
for binary in "$geth_bin" "$prysm_dir/prysmctl" "$prysm_dir/beacon-chain" "$prysm_dir/validator"; do
    if ! command -v "$binary" >/dev/null 2>&1; then echo "Missing binary: $binary" >&2; exit 1; fi
done

interop_dir=$(mktemp -d /tmp/hightower-prysm-geth.XXXXXX)
geth_pid= producer_pid= validator_pid= fresh_pid= relay_pid= blob_pid=
cleanup() {
    local pid
    for pid in "$relay_pid" "$blob_pid" "$validator_pid" "$producer_pid" "$fresh_pid" "$geth_pid"; do
        if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    if [[ ${KEEP_INTEROP_DIR:-0} != 1 ]]; then rm -rf "$interop_dir"; else echo "Interop files: $interop_dir"; fi
}
trap cleanup EXIT
fail() {
    echo "$1" >&2
    for log in "$interop_dir"/*.log; do if [[ -f "$log" ]]; then echo "== $log ==" >&2; tail -80 "$log" >&2; fi; done
    exit 1
}
# Wait for a process-produced result file and surface its logs on failure.
wait_file() {
    local path=$1 pid=$2
    for _ in {1..180}; do
        [[ -s "$path" ]] && return 0
        kill -0 "$pid" 2>/dev/null || fail "Process exited before writing $path"
        sleep 1
    done
    fail "Timed out waiting for $path"
}
# Fetch a signed ENR from the running Prysm Beacon API.
wait_enr() {
    local url=$1 path=$2 pid=$3
    for _ in {1..90}; do
        if python3 - "$url" "$path" <<'PY'
import json, sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=1) as response:
        enr = json.load(response)['data']['enr']
    assert enr.startswith('enr:')
    open(sys.argv[2], 'w').write(enr + '\n')
except (OSError, KeyError, ValueError, AssertionError):
    sys.exit(1)
PY
        then return 0; fi
        kill -0 "$pid" 2>/dev/null || fail "Prysm exited before publishing its ENR"
        sleep 1
    done
    fail "Timed out waiting for Prysm ENR at $url"
}

zig build -Dpreset=mainnet p2p-interop-fixture p2p-interop-keys
(
    cd scripts/prysm-interop/blobtx
    go build -o "$interop_dir/blobtx" .
)
mkdir -p "$interop_dir/geth" "$interop_dir/keys"
"$interop_dir/blobtx" -predeploys > "$interop_dir/predeploys.json"
printf 'interop-only-password' > "$interop_dir/password"
openssl rand -hex 32 > "$interop_dir/jwt.hex"
"$geth_bin" account new --datadir "$interop_dir/geth" --password "$interop_dir/password" > "$interop_dir/account.log"
python3 - "$interop_dir" <<'PY'
import glob, json, os, sys
root = sys.argv[1]
keyfile, = glob.glob(os.path.join(root, 'geth', 'keystore', '*'))
with open(keyfile) as stream:
    address = json.load(stream)['address']
with open(os.path.join(root, 'account-path'), 'w') as stream:
    stream.write(keyfile)
with open(os.path.join(root, 'predeploys.json')) as stream:
    predeploys = json.load(stream)
genesis = {
    'config': {'chainId': 1337, 'homesteadBlock': 0, 'eip150Block': 0,
               'eip155Block': 0, 'eip158Block': 0, 'byzantiumBlock': 0,
               'constantinopleBlock': 0, 'petersburgBlock': 0, 'istanbulBlock': 0,
               'berlinBlock': 0, 'londonBlock': 0, 'terminalTotalDifficulty': 0,
               'shanghaiTime': 0, 'cancunTime': 0, 'pragueTime': 0, 'osakaTime': 0,
               'blobSchedule': {'cancun': {'target': 3, 'max': 6, 'baseFeeUpdateFraction': 3338477},
                                'prague': {'target': 6, 'max': 9, 'baseFeeUpdateFraction': 5007716}}},
    'nonce': '0x0', 'timestamp': '0x0', 'extraData': '0x',
    'gasLimit': '0x1c9c380', 'difficulty': '0x0',
    'mixHash': '0x' + '00' * 32, 'coinbase': '0x' + '00' * 20,
    'alloc': {address: {'balance': str(10**27)}},
    'baseFeePerGas': '0x3b9aca00',
}
genesis['alloc'].update(predeploys)
with open(os.path.join(root, 'geth-genesis-in.json'), 'w') as stream:
    json.dump(genesis, stream)
PY
cat > "$interop_dir/chain.yaml" <<'YAML'
CONFIG_NAME: hightower-interop
PRESET_BASE: mainnet
TERMINAL_BLOCK_HASH: 0x0000000000000000000000000000000000000000000000000000000000000000
GENESIS_FORK_VERSION: 0x000000aa
ALTAIR_FORK_VERSION: 0x010000aa
BELLATRIX_FORK_VERSION: 0x020000aa
CAPELLA_FORK_VERSION: 0x030000aa
DENEB_FORK_VERSION: 0x040000aa
ELECTRA_FORK_VERSION: 0x050000aa
FULU_FORK_VERSION: 0x060000aa
GLOAS_FORK_VERSION: 0x070000aa
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_EPOCH: 0
CAPELLA_FORK_EPOCH: 0
DENEB_FORK_EPOCH: 0
ELECTRA_FORK_EPOCH: 0
FULU_FORK_EPOCH: 0
MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 4
BLOB_SCHEDULE:
  - EPOCH: 0
    MAX_BLOBS_PER_BLOCK: 9
YAML
"$prysm_dir/prysmctl" testnet generate-genesis --fork=fulu --num-validators=4 --genesis-time-delay="${GENESIS_DELAY:-90}" --chain-config-file="$interop_dir/chain.yaml" --geth-genesis-json-in="$interop_dir/geth-genesis-in.json" --geth-genesis-json-out="$interop_dir/geth-genesis.json" --output-ssz="$interop_dir/genesis.ssz" > "$interop_dir/genesis.log" 2>&1 || fail 'Prysm genesis generation failed'
./zig-out/bin/hightower-p2p-interop-keys "$interop_dir/keys" 4
"$geth_bin" --datadir "$interop_dir/geth" init "$interop_dir/geth-genesis.json" > "$interop_dir/geth-init.log" 2>&1 || fail 'Geth init failed'
"$geth_bin" --datadir "$interop_dir/geth" --networkid 1337 --cache 128 --http --http.addr 127.0.0.1 --http.port 18545 --http.api eth,net,web3 --authrpc.addr 127.0.0.1 --authrpc.port 18551 --authrpc.vhosts '*' --authrpc.jwtsecret "$interop_dir/jwt.hex" --nodiscover --maxpeers 0 > "$interop_dir/geth.log" 2>&1 &
geth_pid=$!

for keyfile in "$interop_dir"/keys/*.hex; do
    "$prysm_dir/validator" accounts import --wallet-dir="$interop_dir/wallet" --wallet-password-file="$interop_dir/password" --keys-dir="$interop_dir/keys" --import-private-key-file="$keyfile" --account-password-file="$interop_dir/password" --accept-terms-of-use > "$interop_dir/import.log" 2>&1 || fail 'Validator key import failed'
done
"$prysm_dir/beacon-chain" --chain-id=1337 --chain-config-file="$interop_dir/chain.yaml" --genesis-state="$interop_dir/genesis.ssz" --datadir="$interop_dir/producer" --execution-endpoint=http://127.0.0.1:18551 --jwt-secret="$interop_dir/jwt.hex" --p2p-host-ip=127.0.0.1 --p2p-local-ip=127.0.0.1 --p2p-tcp-port=19000 --p2p-udp-port=19000 --p2p-max-peers=1 --min-sync-peers=0 --supernode --subscribe-all-subnets --grpc-gateway-port=13500 --rpc-port=14000 --accept-terms-of-use > "$interop_dir/producer.log" 2>&1 &
producer_pid=$!
wait_enr http://127.0.0.1:13500/eth/v1/node/identity "$interop_dir/producer.enr" "$producer_pid"
python3 - "$interop_dir/genesis-root" <<'PY' || fail 'Could not read Prysm genesis root'
import json, sys, urllib.request
with urllib.request.urlopen('http://127.0.0.1:13500/eth/v1/beacon/genesis', timeout=5) as response:
    root = json.load(response)['data']['genesis_validators_root']
assert len(root) == 66 and root.startswith('0x')
with open(sys.argv[1], 'w') as stream:
    stream.write(root)
PY
"$prysm_dir/validator" --chain-config-file="$interop_dir/chain.yaml" --wallet-dir="$interop_dir/wallet" --wallet-password-file="$interop_dir/password" --datadir="$interop_dir/validator" --beacon-rpc-provider=127.0.0.1:14000 --accept-terms-of-use > "$interop_dir/validator.log" 2>&1 &
validator_pid=$!
"$interop_dir/blobtx" -rpc http://127.0.0.1:18545 -keystore "$(cat "$interop_dir/account-path")" -password "$interop_dir/password" > "$interop_dir/blob.json" 2> "$interop_dir/blob.log" &
blob_pid=$!
wait_file "$interop_dir/blob.json" "$blob_pid"
python3 - "$interop_dir/blob.json" <<'PY' || fail 'Blob transaction did not mine'
import json, sys
with open(sys.argv[1]) as stream: result = json.load(stream)
assert result['block_number'] == 1 and result['blob_hash'].startswith('0x')
PY
for _ in {1..30}; do
    if python3 - <<'PY'
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:13500/eth/v2/beacon/blocks/1', timeout=2) as response:
    block = json.load(response)['data']['message']
assert int(block['slot']) == 1 and len(block['body']['blob_kzg_commitments']) == 1
PY
    then break; fi
    sleep 1
done
python3 - <<'PY' || fail 'Producer did not import the blob block'
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:13500/eth/v2/beacon/blocks/1', timeout=2) as response:
    block = json.load(response)['data']['message']
assert int(block['slot']) == 1 and len(block['body']['blob_kzg_commitments']) == 1
PY
kill "$validator_pid" 2>/dev/null || true; wait "$validator_pid" 2>/dev/null || true; validator_pid=
GOLOG_LOG_LEVEL=debug "$prysm_dir/beacon-chain" --verbosity=debug --chain-id=1337 --chain-config-file="$interop_dir/chain.yaml" --genesis-state="$interop_dir/genesis.ssz" --datadir="$interop_dir/fresh" --execution-endpoint=http://127.0.0.1:18551 --jwt-secret="$interop_dir/jwt.hex" --p2p-host-ip=127.0.0.1 --p2p-local-ip=127.0.0.1 --p2p-tcp-port=19001 --p2p-udp-port=19001 --p2p-max-peers=1 --min-sync-peers=0 --supernode --grpc-gateway-port=13501 --rpc-port=14001 --accept-terms-of-use > "$interop_dir/fresh.log" 2>&1 &
fresh_pid=$!
wait_enr http://127.0.0.1:13501/eth/v1/node/identity "$interop_dir/fresh.enr" "$fresh_pid"
./zig-out/bin/hightower-p2p-interop-fixture "$(cat "$interop_dir/genesis-root")" 0x060000aa "$interop_dir/producer.enr" "$interop_dir/fresh.enr" "$interop_dir/relay.json" > "$interop_dir/relay.log" 2>&1 &
relay_pid=$!
wait_file "$interop_dir/relay.json" "$relay_pid"
python3 - "$interop_dir/relay.json" http://127.0.0.1:13501 <<'PY' || fail 'Fresh Prysm did not import relayed block and columns'
import json, sys, time, urllib.error, urllib.request
with open(sys.argv[1]) as stream: relay = json.load(stream)
assert relay['slot'] == 1 and relay['columns'] == 128
deadline = time.time() + 45
while True:
    try:
        with urllib.request.urlopen(sys.argv[2] + '/eth/v2/beacon/blocks/1', timeout=5) as response:
            block = json.load(response)['data']
        with urllib.request.urlopen(sys.argv[2] + '/eth/v1/beacon/headers/1', timeout=5) as response:
            header = json.load(response)['data']
        assert int(block['message']['slot']) == 1
        assert len(block['message']['body']['blob_kzg_commitments']) == 1
        assert header['root'].lower() == relay['block_root'].lower()
        break
    except (OSError, urllib.error.HTTPError, KeyError, ValueError, AssertionError):
        if time.time() >= deadline: raise
        time.sleep(1)
print('Prysm imported Fulu slot 1 with one blob through Hightower; 128 columns relayed')
PY

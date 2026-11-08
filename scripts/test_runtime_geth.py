#!/usr/bin/env python3
"""Validate two Hightower peers against separate Geth execution clients."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

from test_runtime_network import KEY_A, KEY_B, NODE, ROOT, head, listening, port, start, stop, wait_for


GETH = os.environ.get("GETH_BIN") or shutil.which("geth") or "/tmp/hightower-interop-bins/geth"
PRYSM = Path(os.environ.get("PRYSM_BIN_DIR", "/tmp/hightower-interop-bins"))
FIXTURE = ROOT / "zig-out/bin/hightower-runtime-fixture"
KEYS = ROOT / "zig-out/bin/hightower-p2p-interop-keys"
CHAIN = """CONFIG_NAME: hightower-interop
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
"""


def relative(path):
    """Use repository-relative paths with Zig's cwd-based file API."""
    return os.path.relpath(path, ROOT)


def rpc(port_number, method, params):
    """Read one Geth JSON-RPC result, rejecting protocol errors."""
    request = Request(f"http://127.0.0.1:{port_number}", json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), {"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=2) as response:
            body = json.load(response)
        assert body["id"] == 1 and body["jsonrpc"] == "2.0" and "error" not in body
        return body["result"]
    except (OSError, KeyError, ValueError):
        return None


def jwt(secret):
    """Sign a short-lived Engine API token with the disposable test secret."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()).rstrip(b"=")
    claims = base64.urlsafe_b64encode(json.dumps({"iat": int(time.time())}).encode()).rstrip(b"=")
    message = header + b"." + claims
    signature = base64.urlsafe_b64encode(hmac.new(bytes.fromhex(secret), message, hashlib.sha256).digest()).rstrip(b"=")
    return "Bearer " + (message + b"." + signature).decode()


def reject_corrupt_payload(port_number, public_port, secret):
    """Require Geth to reject a changed block hash before the peer import."""
    block = rpc(public_port, "eth_getBlockByNumber", ["0x1", False])
    assert block and not block["transactions"]
    names = ("parentHash", "stateRoot", "receiptsRoot", "logsBloom", "gasLimit", "gasUsed", "timestamp", "extraData", "baseFeePerGas", "transactions", "withdrawals", "blobGasUsed", "excessBlobGas")
    payload = {name: block[name] for name in names}
    payload.update(feeRecipient=block["miner"], prevRandao=block["mixHash"], blockNumber=block["number"], blockHash="0x" + "00" * 32)
    body = {"jsonrpc": "2.0", "id": 1, "method": "engine_newPayloadV4", "params": [payload, [], block.get("parentBeaconBlockRoot", "0x" + "00" * 32), []]}
    request = Request(f"http://127.0.0.1:{port_number}", json.dumps(body).encode(), {"Content-Type": "application/json", "Authorization": jwt(secret)})
    with urlopen(request, timeout=5) as response:
        result = json.load(response)
    assert result["id"] == 1 and result["result"]["status"] in ("INVALID", "INVALID_BLOCK_HASH"), result


def beacon_ssz(port_number, slot, path):
    """Fetch a signed Fulu block in SSZ from Prysm's Beacon API."""
    try:
        request = Request(f"http://127.0.0.1:{port_number}/eth/v2/beacon/blocks/{slot}", headers={"Accept": "application/octet-stream"})
        with urlopen(request, timeout=2) as response:
            assert response.headers.get_content_type() == "application/octet-stream"
            path.write_bytes(response.read())
        return path.stat().st_size > 0
    except (OSError, ValueError):
        return False


def main():
    """Build real blocks, import them through two nodes, and check Geth heads."""
    os.umask(0o077)
    for binary in (GETH, PRYSM / "prysmctl", PRYSM / "beacon-chain", PRYSM / "validator", NODE, FIXTURE, KEYS):
        if not Path(binary).is_file():
            raise FileNotFoundError(f"required binary: {binary}")
    with tempfile.TemporaryDirectory(prefix="hightower-geth-", dir=ROOT / ".zig-cache") as name:
        work = Path(name)
        processes = []
        try:
            (work / "chain.yaml").write_text(CHAIN)
            (work / "password").write_text("interop-only-password")
            (work / "jwt").write_text("0" * 63 + "3" + "\n")
            (work / "keys").mkdir()
            subprocess.run([KEYS, relative(work / "keys"), "4"], cwd=ROOT, check=True, capture_output=True)
            for key in sorted((work / "keys").glob("*.hex")):
                subprocess.run([PRYSM / "validator", "accounts", "import", f"--wallet-dir={work / 'wallet'}", f"--wallet-password-file={work / 'password'}", f"--keys-dir={work / 'keys'}", f"--import-private-key-file={key}", f"--account-password-file={work / 'password'}", "--accept-terms-of-use"], cwd=ROOT, check=True, stdout=(work / "import.log").open("ab"), stderr=subprocess.STDOUT)
            subprocess.run([PRYSM / "prysmctl", "testnet", "generate-genesis", "--fork=fulu", "--num-validators=4", "--genesis-time-delay=45", f"--chain-config-file={work / 'chain.yaml'}", f"--geth-genesis-json-in={ROOT / 'docs/engine/osaka-genesis.json'}", f"--geth-genesis-json-out={work / 'geth-genesis.json'}", f"--output-ssz={work / 'genesis.ssz'}"], cwd=ROOT, check=True, stdout=(work / "genesis.log").open("wb"), stderr=subprocess.STDOUT)
            ports = [port() for _ in range(9)]
            api_a, api_b, auth_a, auth_b, http_a, http_b, prysm_api, prysm_rpc, prysm_p2p = ports
            for label, auth, http in (("a", auth_a, http_a), ("b", auth_b, http_b)):
                data = work / f"geth-{label}"
                subprocess.run([GETH, "--datadir", str(data), "init", str(work / "geth-genesis.json")], cwd=ROOT, check=True, stdout=(work / f"init-{label}.log").open("wb"), stderr=subprocess.STDOUT)
                processes.append(start([GETH, "--datadir", str(data), "--networkid", "1337", "--syncmode", "full", "--port", "0", "--http", "--http.addr", "127.0.0.1", "--http.port", str(http), "--http.api", "eth,net,web3", "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(auth), "--authrpc.vhosts", "*", "--authrpc.jwtsecret", str(work / "jwt"), "--nodiscover", "--maxpeers", "0", "--ipcdisable"], work / f"geth-{label}.log"))
            wait_for(lambda: listening(auth_a) and listening(auth_b) and rpc(http_a, "eth_getBlockByNumber", ["0x0", False]) and rpc(http_b, "eth_getBlockByNumber", ["0x0", False]), processes)
            genesis_hash = rpc(http_a, "eth_getBlockByNumber", ["0x0", False])["hash"]
            assert rpc(http_b, "eth_getBlockByNumber", ["0x0", False])["hash"] == genesis_hash
            producer = start([PRYSM / "beacon-chain", "--chain-id=1337", f"--chain-config-file={work / 'chain.yaml'}", f"--genesis-state={work / 'genesis.ssz'}", f"--datadir={work / 'prysm'}", f"--execution-endpoint=http://127.0.0.1:{auth_a}", f"--jwt-secret={work / 'jwt'}", "--p2p-host-ip=127.0.0.1", "--p2p-local-ip=127.0.0.1", f"--p2p-tcp-port={prysm_p2p}", f"--p2p-udp-port={prysm_p2p}", "--p2p-max-peers=1", "--min-sync-peers=0", f"--grpc-gateway-port={prysm_api}", f"--rpc-port={prysm_rpc}", "--accept-terms-of-use"], work / "prysm.log")
            processes.append(producer)
            wait_for(lambda: beacon_ssz(prysm_api, 0, work / "block-0.ssz"), processes, 60)
            validator = start([PRYSM / "validator", f"--chain-config-file={work / 'chain.yaml'}", f"--wallet-dir={work / 'wallet'}", f"--wallet-password-file={work / 'password'}", f"--datadir={work / 'validator'}", f"--beacon-rpc-provider=127.0.0.1:{prysm_rpc}", "--accept-terms-of-use"], work / "validator.log")
            processes.append(validator)
            wait_for(lambda: beacon_ssz(prysm_api, 1, work / "block-1.ssz") and beacon_ssz(prysm_api, 2, work / "block-2.ssz"), processes, 100)
            stop(validator)
            processes.remove(validator)
            stop(producer)
            processes.remove(producer)
            expected_execution = rpc(http_a, "eth_getBlockByNumber", ["latest", False])["hash"]
            reject_corrupt_payload(auth_b, http_a, (work / "jwt").read_text().strip())
            expected = subprocess.check_output([FIXTURE, relative(work), relative(work / "genesis.ssz"), relative(work / "block-0.ssz"), relative(work / "block-1.ssz"), relative(work / "block-2.ssz"), f"http://127.0.0.1:{auth_a}", relative(work / "jwt")], cwd=ROOT, text=True).strip()
            assert "0x" + (work / "execution.fixture-hashes").read_text().splitlines()[1] == expected_execution
            base = {"anchor_state": relative(work / "anchor-state.ssz"), "anchor_block": relative(work / "anchor-block.ssz"), "trusted_setup": "src/execution/trusted_setup.txt"}
            configs = []
            for i, (label, api, auth) in enumerate((("a", api_a, auth_a), ("b", api_b, auth_b))):
                config = dict(base, listen_address=f"127.0.0.1:{api}", data_dir=relative(work / ("source" if i == 0 else "target")), engine_url=f"http://127.0.0.1:{auth}", bootstrap_enr="")
                path = work / f"node-{label}.json"
                path.write_text(json.dumps(config))
                configs.append(path)
            secret = (work / "jwt").read_text().strip()
            env_a = dict(os.environ, HIGHTOWER_NODE_KEY=KEY_A, HIGHTOWER_ENGINE_JWT_SECRET=secret)
            source = start([NODE, "--config", relative(configs[0])], work / "source.log", env_a)
            processes.append(source)
            wait_for(lambda: head(api_a) == (expected, 2), processes)
            enr = wait_for(lambda: (match.group(1) if (match := re.search(r"local ENR: (enr:[^\s]+)", (work / "source.log").read_text())) else None), processes)
            config_b = json.loads(configs[1].read_text())
            config_b["bootstrap_enr"] = enr
            configs[1].write_text(json.dumps(config_b))
            env_b = dict(os.environ, HIGHTOWER_NODE_KEY=KEY_B, HIGHTOWER_ENGINE_JWT_SECRET=secret)
            target = start([NODE, "--config", relative(configs[1])], work / "target.log", env_b)
            processes.append(target)
            wait_for(lambda: head(api_a) == (expected, 2) and head(api_b) == (expected, 2) and rpc(http_b, "eth_getBlockByNumber", ["latest", False])["hash"] == expected_execution, processes, 60)
            stop(target)
            processes.remove(target)
            target = start([NODE, "--config", relative(configs[1])], work / "target-restart.log", env_b)
            processes.append(target)
            wait_for(lambda: head(api_a) == (expected, 2) and head(api_b) == (expected, 2) and rpc(http_a, "eth_getBlockByNumber", ["latest", False])["hash"] == expected_execution and rpc(http_b, "eth_getBlockByNumber", ["latest", False])["hash"] == expected_execution, processes)
            for log in work.glob("*.log"):
                output = log.read_text(errors="replace")
                assert KEY_A not in output and KEY_B not in output and secret not in output, f"credential leaked in {log.name}"
            print(f"two nodes and Geth converged at slot 2: consensus {expected}, execution {expected_execution}; target recovered")
        except Exception:
            if os.environ.get("KEEP_RUNTIME_GETH_DIR") == "1":
                saved = ROOT / ".zig-cache/hightower-geth-failure"
                if saved.exists():
                    shutil.rmtree(saved)
                shutil.copytree(work, saved)
                print(f"Saved artifacts: {saved}")
            for log in work.glob("*.log"):
                output = log.read_text(errors="replace")[-2000:]
                for secret in (KEY_A, KEY_B, (work / "jwt").read_text().strip()):
                    output = output.replace(secret, "[REDACTED]")
                print(f"--- {log.name} ---\n{output}")
            raise
        finally:
            for process in reversed(processes):
                stop(process)


if __name__ == "__main__":
    main()

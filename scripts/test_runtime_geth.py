#!/usr/bin/env python3
"""Validate two Hightower peers against separate Geth execution clients."""

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
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


class EngineProxy(ThreadingHTTPServer):
    """Forward authenticated Engine calls and inject one response fault."""

    def __init__(self, listen_port, geth_port):
        self.geth_port = geth_port
        self.fault = None
        self.hit = threading.Event()
        self.release = threading.Event()
        self.calls = []
        self.snapshot_path = None
        self.snapshot_digest = None
        super().__init__(("127.0.0.1", listen_port), EngineProxyHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        """Release a paused reply and stop the proxy thread."""
        self.release.set()
        self.shutdown()
        self.server_close()
        self.thread.join()


class EngineProxyHandler(BaseHTTPRequestHandler):
    """Keep test JWTs in memory while forwarding the exact request body."""

    def do_POST(self):
        """Forward a request before applying its one-shot response fault."""
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(body)
        method = request["method"]
        params = request["params"]
        block_number = int(params[0]["blockNumber"], 16) if method.startswith("engine_newPayload") else None
        choice_head = params[0]["headBlockHash"] if method.startswith("engine_forkchoiceUpdated") else None
        server = self.server
        server.calls.append((method, block_number, choice_head))
        forwarded = Request(f"http://127.0.0.1:{server.geth_port}", body, {"Content-Type": "application/json", "Authorization": self.headers["Authorization"]})
        with urlopen(forwarded, timeout=10) as response:
            result = json.load(response)
        assert result["jsonrpc"] == "2.0" and result["id"] == request["id"] and "error" not in result, result
        fault = server.fault
        if fault and method == fault[0] and (block_number == fault[1] or choice_head == fault[1]):
            server.fault = None
            if server.snapshot_path.is_file():
                server.snapshot_digest = hashlib.sha256(server.snapshot_path.read_bytes()).digest()
            server.hit.set()
            action = fault[2]
            if action == "pause":
                server.release.wait(15)
            if action == "drop":
                self.close_connection = True
                return
            if action != "pause":
                result["result"]["payloadStatus"]["status"] = action
                result["result"]["payloadStatus"]["latestValidHash"] = None
        encoded = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except BrokenPipeError:
            pass

    def log_message(self, *_):
        """Avoid logging authenticated request headers or bodies."""


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


def saved_head(path):
    """Read the selected root from the checked snapshot's fixed header fields."""
    snapshot = path.read_bytes()
    assert snapshot[:8] == b"HTFC0002"
    assert int.from_bytes(snapshot[8:16], "little") == len(snapshot) - 48
    assert hashlib.sha256(snapshot[48:]).digest() == snapshot[16:48]
    # Header, two times, four checkpoints, and proposer boost precede the head.
    return "0x" + snapshot[256:288].hex()


def run_recovery_case(work, processes, base, enr, secret, genesis_hash, expected, expected_execution, slot_one_hash, slot_one_root, anchor_root, name, method, match, action):
    """Crash or reject one Engine reply, then recover from the saved head."""
    case = work / name
    case.mkdir()
    geth_data = case / "geth"
    subprocess.run([GETH, "--datadir", str(geth_data), "init", str(work / "geth-genesis.json")], cwd=ROOT, check=True, stdout=(case / "init.log").open("wb"), stderr=subprocess.STDOUT)
    api_port, auth_port, http_port, proxy_port = [port() for _ in range(4)]
    geth = start([GETH, "--datadir", str(geth_data), "--networkid", "1337", "--syncmode", "full", "--port", "0", "--http", "--http.addr", "127.0.0.1", "--http.port", str(http_port), "--http.api", "eth,net,web3", "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(auth_port), "--authrpc.vhosts", "*", "--authrpc.jwtsecret", str(work / "jwt"), "--nodiscover", "--maxpeers", "0", "--ipcdisable"], case / "geth.log")
    processes.append(geth)
    proxy = EngineProxy(proxy_port, auth_port)
    proxy.snapshot_path = case / "target/fork-choice.bin"
    try:
        wait_for(lambda: listening(auth_port) and rpc(http_port, "eth_getBlockByNumber", ["latest", False]), processes)
        config = dict(base, listen_address=f"127.0.0.1:{api_port}", data_dir=relative(case / "target"), engine_url=f"http://127.0.0.1:{proxy_port}", bootstrap_enr=enr)
        config_path = case / "target.json"
        config_path.write_text(json.dumps(config))
        node_key = hashlib.sha256(name.encode()).hexdigest()
        env = dict(os.environ, HIGHTOWER_NODE_KEY=node_key, HIGHTOWER_ENGINE_JWT_SECRET=secret)
        proxy.fault = (method, match, action)
        target = start([NODE, "--config", relative(config_path)], case / "target.log", env)
        processes.append(target)
        try:
            wait_for(lambda: proxy.hit.is_set(), [process for process in processes if process is not target], 60)
            if action == "pause":
                target.kill()
                target.wait(timeout=5)
                proxy.release.set()
            else:
                wait_for(lambda: target.poll() is not None or False, [process for process in processes if process is not target], 20)
                assert target.returncode != 0, f"{name} did not fail closed"
            assert not listening(api_port), f"{name} left its Beacon API open"
            if name == "startup_syncing":
                assert "local ENR:" not in (case / "target.log").read_text(), "startup opened P2P before Engine validation"
            durable = case / "target/fork-choice.bin"
            if proxy.snapshot_digest is not None:
                assert hashlib.sha256(durable.read_bytes()).digest() == proxy.snapshot_digest, f"{name} changed the previous snapshot"
            actual_head = saved_head(durable) if durable.exists() else anchor_root
            assert actual_head == (anchor_root if name in ("startup_syncing", "after_new_payload", "after_forkchoice") else slot_one_root), (name, actual_head)
            execution_head = rpc(http_port, "eth_getBlockByNumber", ["latest", False])["hash"]
            expected_execution_head = genesis_hash if name in ("startup_syncing", "after_new_payload") else expected_execution if name in ("syncing", "invalid", "drop") else slot_one_hash
            assert execution_head == expected_execution_head, (name, execution_head)
        finally:
            stop(target)
            processes.remove(target)
        for log in case.glob("*.log"):
            assert node_key not in log.read_text(errors="replace"), f"node key leaked in {log}"
        proxy.calls.clear()
        target = start([NODE, "--config", relative(config_path)], case / "restart.log", env)
        processes.append(target)
        try:
            wait_for(lambda: any(call[0].startswith("engine_forkchoiceUpdated") for call in proxy.calls), processes)
            first = next(call for call in proxy.calls if call[0].startswith("engine_forkchoiceUpdated"))
            expected_hash = slot_one_hash if actual_head == slot_one_root else genesis_hash
            assert first[2] == expected_hash, (name, first, expected_hash)
            wait_for(lambda: head(api_port) == (expected, 2) and rpc(http_port, "eth_getBlockByNumber", ["latest", False])["hash"] == expected_execution, processes, 60)
        finally:
            stop(target)
            processes.remove(target)
    finally:
        proxy.close()
        stop(geth)
        processes.remove(geth)


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
            api_a, auth_a, http_a, prysm_api, prysm_rpc, prysm_p2p = [port() for _ in range(6)]
            data = work / "geth-a"
            subprocess.run([GETH, "--datadir", str(data), "init", str(work / "geth-genesis.json")], cwd=ROOT, check=True, stdout=(work / "init-a.log").open("wb"), stderr=subprocess.STDOUT)
            processes.append(start([GETH, "--datadir", str(data), "--networkid", "1337", "--syncmode", "full", "--port", "0", "--http", "--http.addr", "127.0.0.1", "--http.port", str(http_a), "--http.api", "eth,net,web3", "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(auth_a), "--authrpc.vhosts", "*", "--authrpc.jwtsecret", str(work / "jwt"), "--nodiscover", "--maxpeers", "0", "--ipcdisable"], work / "geth-a.log"))
            wait_for(lambda: listening(auth_a) and rpc(http_a, "eth_getBlockByNumber", ["0x0", False]), processes)
            genesis_hash = rpc(http_a, "eth_getBlockByNumber", ["0x0", False])["hash"]
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
            reject_corrupt_payload(auth_a, http_a, (work / "jwt").read_text().strip())
            expected = subprocess.check_output([FIXTURE, relative(work), relative(work / "genesis.ssz"), relative(work / "block-0.ssz"), relative(work / "block-1.ssz"), relative(work / "block-2.ssz"), f"http://127.0.0.1:{auth_a}", relative(work / "jwt")], cwd=ROOT, text=True).strip()
            fixture_hashes = (work / "execution.fixture-hashes").read_text().splitlines()
            assert len(fixture_hashes) == 3 and "0x" + fixture_hashes[0] == genesis_hash and "0x" + fixture_hashes[2] == expected_execution
            base = {"anchor_state": relative(work / "anchor-state.ssz"), "anchor_block": relative(work / "anchor-block.ssz"), "trusted_setup": "src/execution/trusted_setup.txt"}
            source_config = work / "source.json"
            source_config.write_text(json.dumps(dict(base, listen_address=f"127.0.0.1:{api_a}", data_dir=relative(work / "source"), engine_url=f"http://127.0.0.1:{auth_a}", bootstrap_enr="")))
            secret = (work / "jwt").read_text().strip()
            env_a = dict(os.environ, HIGHTOWER_NODE_KEY=KEY_A, HIGHTOWER_ENGINE_JWT_SECRET=secret)
            source = start([NODE, "--config", relative(source_config)], work / "source.log", env_a)
            processes.append(source)
            wait_for(lambda: head(api_a) == (expected, 2), processes)
            enr = wait_for(lambda: (match.group(1) if (match := re.search(r"local ENR: (enr:[^\s]+)", (work / "source.log").read_text())) else None), processes)
            with urlopen(f"http://127.0.0.1:{api_a}/eth/v1/beacon/blocks/0/root") as response:
                anchor_root = json.load(response)["data"]["root"]
            with urlopen(f"http://127.0.0.1:{api_a}/eth/v1/beacon/blocks/1/root") as response:
                slot_one_root = json.load(response)["data"]["root"]
            slot_one_hash = "0x" + fixture_hashes[1]
            cases = (("startup_syncing", "engine_forkchoiceUpdatedV3", genesis_hash, "SYNCING"), ("after_new_payload", "engine_newPayloadV4", 1, "pause"), ("after_forkchoice", "engine_forkchoiceUpdatedV3", slot_one_hash, "pause"), ("after_snapshot", "engine_newPayloadV4", 2, "pause"), ("syncing", "engine_forkchoiceUpdatedV3", expected_execution, "SYNCING"), ("invalid", "engine_forkchoiceUpdatedV3", expected_execution, "INVALID"), ("drop", "engine_forkchoiceUpdatedV3", expected_execution, "drop"))
            for index, case in enumerate(cases):
                if index:
                    stop(source)
                    processes.remove(source)
                    source = start([NODE, "--config", relative(source_config)], work / f"source-{index}.log", env_a)
                    processes.append(source)
                    wait_for(lambda: head(api_a) == (expected, 2), processes)
                    enr = wait_for(lambda: (match.group(1) if (match := re.search(r"local ENR: (enr:[^\s]+)", (work / f"source-{index}.log").read_text())) else None), processes)
                run_recovery_case(work, processes, base, enr, secret, genesis_hash, expected, expected_execution, slot_one_hash, slot_one_root, anchor_root, *case)
                print(f"recovery case {case[0]} passed", flush=True)
            for log in (path for path in work.rglob("*.log") if path.parent == work or path.parent.parent == work):
                output = log.read_text(errors="replace")
                assert KEY_A not in output and KEY_B not in output and secret not in output, f"credential leaked in {log.name}"
            print(f"seven Geth recovery cases converged at slot 2: consensus {expected}, execution {expected_execution}")
        except Exception:
            if os.environ.get("KEEP_RUNTIME_GETH_DIR") == "1":
                saved = ROOT / ".zig-cache/hightower-geth-failure"
                if saved.exists():
                    shutil.rmtree(saved)
                shutil.copytree(work, saved)
                print(f"Saved artifacts: {saved}")
            for log in (path for path in work.rglob("*.log") if path.parent == work or path.parent.parent == work):
                output = log.read_text(errors="replace")[-2000:]
                for secret in (KEY_A, KEY_B, (work / "jwt").read_text().strip()):
                    output = output.replace(secret, "[REDACTED]")
                for case_dir in work.iterdir():
                    if (case_dir / "target.json").exists():
                        output = output.replace(hashlib.sha256(case_dir.name.encode()).hexdigest(), "[REDACTED]")
                print(f"--- {log.name} ---\n{output}")
            raise
        finally:
            for process in reversed(processes):
                stop(process)


if __name__ == "__main__":
    main()

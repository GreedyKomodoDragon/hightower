#!/usr/bin/env python3
"""Exercise the production Engine and public RPC listeners across recovery."""

import base64
import argparse
import hashlib
import hmac
import json
import pathlib
import resource
import secrets
import socket
import subprocess
import signal
import tempfile
import threading
import time
import statistics
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
ZERO = "0x" + "00" * 32
ENGINE_MAX_BODY = 32 * 1024 * 1024
SENDER = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
COUNTER = "0xf2e246bb76df876cef8b38ae84130f4f55de395b"
CONTRACT = "0x2946259e0334f33a064106302415ad3391bed384"


def port():
    """Reserve an unused local TCP port for a test listener."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def token(secret):
    """Sign the Engine API's HS256 issued-at token."""
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = encode(json.dumps({"iat": int(time.time())}, separators=(",", ":")).encode())
    message = f"{header}.{payload}"
    return "Bearer " + message + "." + encode(hmac.new(secret, message.encode(), hashlib.sha256).digest())


def request(port_number, method, params, bearer=None):
    """Send one structured JSON-RPC request and check its response."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    headers = {"Content-Type": "application/json"}
    if bearer is not None:
        headers["Authorization"] = bearer
    req = urllib.request.Request(f"http://127.0.0.1:{port_number}/", body, headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        raise AssertionError(f"{method}: HTTP {error.code}: {error.read()!r}") from error
    assert result["id"] == 1 and "error" not in result, result
    return result["result"]


def get(port_number, path):
    """Read a local non-RPC service endpoint."""
    with urllib.request.urlopen(f"http://127.0.0.1:{port_number}{path}", timeout=5) as response:
        return response.status, response.read().decode()


def database_bytes(path):
    """Return allocated file lengths for the execution database directory."""
    return sum(file.stat().st_size for file in path.rglob("*") if file.is_file())


def median_rpc_latency(port_number, calls):
    """Measure median local RPC round-trip time for a small fixed sample."""
    samples = []
    for _ in range(20):
        for method, params in calls:
            started = time.perf_counter_ns()
            request(port_number, method, params)
            samples.append(time.perf_counter_ns() - started)
    return statistics.median(samples) / 1_000


def measure_archive_history(temporary, config, secret, block_count=130):
    """Import and restart an archive node, then measure retained history."""
    archive_config = dict(config)
    archive_config.update(
        data_dir=str(temporary / "archive-data"),
        engine_bind=f"127.0.0.1:{port()}",
        rpc_bind=f"127.0.0.1:{port()}",
        archive=True,
        retained_canonical_blocks=16,
    )
    archive_config.pop("transfer_contract", None)
    config_path = temporary / "archive-config.json"
    config_path.write_text(json.dumps(archive_config))
    engine_port = int(archive_config["engine_bind"].split(":")[-1])
    rpc_port = int(archive_config["rpc_bind"].split(":")[-1])
    process = subprocess.Popen(
        [str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(config_path)],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        wait_ready(process, rpc_port)
        initial_bytes = database_bytes(temporary / "archive-data")
        bearer = token(secret)
        parent = request(rpc_port, "eth_getBlockByNumber", ["latest", False])
        for _ in range(block_count):
            timestamp = int(parent["timestamp"], 16) + 1
            choice = {"headBlockHash": parent["hash"], "safeBlockHash": parent["hash"], "finalizedBlockHash": parent["hash"]}
            attributes = {"timestamp": hex(timestamp), "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}
            update = request(engine_port, "engine_forkchoiceUpdatedV3", [choice, attributes], bearer)
            built = request(engine_port, "engine_getPayloadV5", [update["payloadId"]], bearer)
            payload = built["executionPayload"]
            assert request(engine_port, "engine_newPayloadV4", [payload, [], ZERO, built["executionRequests"]], bearer)["status"] == "VALID"
            selected = {"headBlockHash": payload["blockHash"], "safeBlockHash": parent["hash"], "finalizedBlockHash": parent["hash"]}
            assert request(engine_port, "engine_forkchoiceUpdatedV3", [selected, None], bearer)["payloadStatus"]["status"] == "VALID"
            parent = {"hash": payload["blockHash"], "timestamp": payload["timestamp"]}

        calls = (
            ("eth_getBalance", [SENDER, "0x1"]),
            ("eth_getCode", [SENDER, "0x1"]),
            ("eth_getStorageAt", [SENDER, "0x0", "0x1"]),
            ("eth_call", [{"to": SENDER}, "0x1"]),
        )
        results = [request(rpc_port, method, params) for method, params in calls]
        assert request(rpc_port, "eth_getBlockByNumber", ["0x1", False]) is not None
        growth = database_bytes(temporary / "archive-data") - initial_bytes
        latency_us = median_rpc_latency(rpc_port, calls)
        stop(process, secret)
        process = None
        process = subprocess.Popen(
            [str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(config_path)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        wait_ready(process, rpc_port, attempts=1_200)
        assert request(rpc_port, "eth_getBlockByNumber", ["0x1", False]) is not None
        assert [request(rpc_port, method, params) for method, params in calls] == results
        print(f"execution archive sample: {block_count} blocks, database +{growth} bytes, historical RPC median {latency_us:.1f} us over 80 calls")
    finally:
        if process and not process.stderr.closed:
            stop(process, secret)


def stop(process, secret):
    """Stop a child and reject any stderr disclosure of its JWT secret."""
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    logs = process.stderr.read()
    process.stderr.close()
    assert secret.hex().encode() not in logs, logs


def wait_ready(process, port_number, attempts=100):
    """Wait until the public listener accepts TCP connections."""
    for _ in range(attempts):
        assert process.poll() is None, "execution service exited during startup"
        try:
            with socket.create_connection(("127.0.0.1", port_number), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("execution service did not start")


def compare_block(hightower_port, geth_port, number):
    """Compare canonical block, receipts, and logs with mismatch coordinates."""
    tag = hex(number)
    left = request(hightower_port, "eth_getBlockByNumber", [tag, False])
    right = request(geth_port, "eth_getBlockByNumber", [tag, False])
    for field in ("hash", "stateRoot", "receiptsRoot", "gasUsed", "transactions"):
        if left[field] != right[field]:
            raise AssertionError(f"block {number} {field} mismatch: Hightower={left[field]!r}; Geth={right[field]!r}")
    for index, tx_hash in enumerate(left["transactions"]):
        lreceipt = request(hightower_port, "eth_getTransactionReceipt", [tx_hash])
        rreceipt = request(geth_port, "eth_getTransactionReceipt", [tx_hash])
        for field in ("status", "gasUsed", "cumulativeGasUsed"):
            if lreceipt[field] != rreceipt[field]:
                raise AssertionError(f"block {number} transaction {index} {tx_hash} {field} mismatch: Hightower={lreceipt!r}; Geth={rreceipt!r}")
        for log_index, (llog, rlog) in enumerate(zip(lreceipt["logs"], rreceipt["logs"])):
            for field in ("address", "topics", "data"):
                left_value, right_value = llog[field], rlog[field]
                equal = left_value.lower() == right_value.lower() if isinstance(left_value, str) else left_value == right_value
                if not equal:
                    raise AssertionError(f"block {number} transaction {index} log {log_index} {field} mismatch: Hightower={llog!r}; Geth={rlog!r}")
        if len(lreceipt["logs"]) != len(rreceipt["logs"]):
            raise AssertionError(f"block {number} transaction {index} log count mismatch: Hightower={lreceipt!r}; Geth={rreceipt!r}")
    for method, params in (("eth_getBalance", [SENDER, tag]), ("eth_getStorageAt", [COUNTER, "0x0", tag])):
        lresult = request(hightower_port, method, params)
        rresult = request(geth_port, method, params)
        if lresult.lower() != rresult.lower():
            raise AssertionError(f"block {number} {method} mismatch: Hightower={lresult!r}; Geth={rresult!r}")


def test_peer_catchup(temporary, config, secret, geth_rpc_port, geth_engine_port, peer_bin, head, number, payload, execution_requests):
    """Fetch Geth's blocks over eth/69 into a fresh Hightower database."""
    fresh = dict(config, data_dir=str(temporary / "peer-data"), engine_bind=f"127.0.0.1:{port()}", rpc_bind=f"127.0.0.1:{port()}")
    fresh.pop("transfer_contract", None)
    fresh_path = temporary / "peer-config.json"
    fresh_path.write_text(json.dumps(fresh))
    enode = request(geth_rpc_port, "admin_nodeInfo", [])["enode"]
    peer_log = (temporary / "execution-peer.log").open("wb")
    service = None
    worker = None
    try:
        service = subprocess.Popen([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(fresh_path)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        wait_ready(service, int(fresh["rpc_bind"].split(":")[-1]))
        fresh_engine = int(fresh["engine_bind"].split(":")[-1])
        missing = request(fresh_engine, "engine_newPayloadV4", [payload, [], ZERO, execution_requests], token(secret))
        assert missing["status"] == "SYNCING", missing
        assert request(fresh_engine, "hightower_missingExecutionParents", [], token(secret)) == [payload["parentHash"]]
        worker = subprocess.Popen([peer_bin, "--config", str(fresh_path), "--peer", enode], cwd=ROOT, stdout=peer_log, stderr=peer_log)
        for _ in range(300):
            assert worker.poll() is None, f"execution peer exited: {(temporary / 'execution-peer.log').read_text()}"
            if request(fresh_engine, "hightower_hasExecutionBlock", [head], token(secret)):
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"execution peer did not import Geth head: {(temporary / 'execution-peer.log').read_text()}")
        assert request(fresh_engine, "hightower_missingExecutionParents", [], token(secret)) == []
        worker.terminate()
        worker.wait(timeout=5)
        worker = None
        stop(service, secret)
        service = subprocess.Popen([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(fresh_path)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        fresh_rpc = int(fresh["rpc_bind"].split(":")[-1])
        wait_ready(service, fresh_rpc)
        assert request(fresh_engine, "hightower_hasExecutionBlock", [head], token(secret)) is True
        assert request(fresh_rpc, "eth_blockNumber", []) == "0x0"
        worker = subprocess.Popen([peer_bin, "--config", str(fresh_path), "--peer", enode], cwd=ROOT, stdout=peer_log, stderr=peer_log)
        time.sleep(2)
        assert worker.poll() is None, f"execution peer failed after staged restart: {(temporary / 'execution-peer.log').read_text()}"
        anchor = request(int(fresh["rpc_bind"].split(":")[-1]), "eth_getBlockByNumber", ["0x0", False])["hash"]
        choice = {"headBlockHash": head, "safeBlockHash": anchor, "finalizedBlockHash": anchor}
        selected = request(int(fresh["engine_bind"].split(":")[-1]), "engine_forkchoiceUpdatedV3", [choice, None], token(secret))
        assert selected["payloadStatus"]["status"] == "VALID", selected
        assert request(fresh_rpc, "eth_blockNumber", []) == hex(number)
        compare_block(fresh_rpc, geth_rpc_port, number)
        worker.terminate()
        worker.wait(timeout=5)
        worker = None
        stop(service, secret)
        service = subprocess.Popen([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(fresh_path)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        wait_ready(service, fresh_rpc)
        assert request(fresh_rpc, "eth_getBlockByNumber", ["latest", False])["hash"] == head
        assert request(fresh_engine, "hightower_executionSyncCursor", [], token(secret)) == hex(number)
        worker = subprocess.Popen([peer_bin, "--config", str(fresh_path), "--peer", enode], cwd=ROOT, stdout=peer_log, stderr=peer_log)
        time.sleep(2)
        assert worker.poll() is None, f"execution peer failed after restart: {(temporary / 'execution-peer.log').read_text()}"
        assert request(fresh_rpc, "eth_syncing", []) is False
        worker.terminate()
        worker.wait(timeout=5)
        worker = None
        stop(service, secret)
        service = None

        header_file = temporary / "snap-header.rlp"
        header_file.write_bytes(bytes.fromhex(request(geth_rpc_port, "debug_getRawHeader", [hex(number)])[2:]))
        snap = dict(fresh, data_dir=str(temporary / "snap-data"), engine_bind=f"127.0.0.1:{port()}", rpc_bind=f"127.0.0.1:{port()}")
        snap.update(checkpoint_header=str(header_file), checkpoint_state=str(temporary / "snap-state.bin"), checkpoint_hash=head)
        snap_path = temporary / "snap-config.json"
        snap_path.write_text(json.dumps(snap))
        downloaded = subprocess.run([peer_bin, "--snapshot", "--config", str(snap_path), "--peer", enode], cwd=ROOT, capture_output=True, timeout=60)
        assert downloaded.returncode == 0, f"SNAP download failed: {downloaded.stderr.decode()}; Geth log tail={(temporary / 'geth.log').read_text()[-4000:]}"
        service = subprocess.Popen([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(snap_path)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        snap_rpc = int(snap["rpc_bind"].split(":")[-1])
        wait_ready(service, snap_rpc)
        assert request(snap_rpc, "eth_blockNumber", []) == hex(number)
        compare_block(snap_rpc, geth_rpc_port, number)
        primary_rpc = int(config["rpc_bind"].split(":")[-1])
        genesis_hash = request(primary_rpc, "eth_getBlockByNumber", ["0x0", False])["hash"]
        primary_engine = int(config["engine_bind"].split(":")[-1])
        choice = {"headBlockHash": head, "safeBlockHash": genesis_hash, "finalizedBlockHash": genesis_hash}
        attributes = {"timestamp": hex(number + 1), "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}
        update = request(primary_engine, "engine_forkchoiceUpdatedV3", [choice, attributes], token(secret))
        successor = request(primary_engine, "engine_getPayloadV5", [update["payloadId"]], token(secret))
        next_payload = successor["executionPayload"]
        assert request(primary_engine, "engine_newPayloadV4", [next_payload, [], ZERO, successor["executionRequests"]], token(secret))["status"] == "VALID"
        assert request(geth_engine_port, "engine_newPayloadV4", [next_payload, [], ZERO, successor["executionRequests"]], token(secret))["status"] == "VALID"
        next_hash = next_payload["blockHash"]
        next_choice = {"headBlockHash": next_hash, "safeBlockHash": head, "finalizedBlockHash": head}
        assert request(geth_engine_port, "engine_forkchoiceUpdatedV3", [next_choice, None], token(secret))["payloadStatus"]["status"] == "VALID"
        worker = subprocess.Popen([peer_bin, "--config", str(snap_path), "--peer", enode], cwd=ROOT, stdout=peer_log, stderr=peer_log)
        snap_engine = int(snap["engine_bind"].split(":")[-1])
        for _ in range(100):
            assert worker.poll() is None, f"SNAP successor worker exited: {(temporary / 'execution-peer.log').read_text()}"
            if request(snap_engine, "hightower_hasExecutionBlock", [next_hash], token(secret)):
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"SNAP checkpoint did not import successor: {(temporary / 'execution-peer.log').read_text()}")
        assert request(snap_rpc, "eth_blockNumber", []) == hex(number)
        assert request(snap_engine, "engine_forkchoiceUpdatedV3", [next_choice, None], token(secret))["payloadStatus"]["status"] == "VALID"
        compare_block(snap_rpc, geth_rpc_port, number + 1)
    finally:
        if worker and worker.poll() is None:
            worker.terminate()
            worker.wait(timeout=5)
        if service and not service.stderr.closed:
            stop(service, secret)
        peer_log.close()


def run(geth_bin=None, peer_bin=None):
    """Import two blocks, query canonical RPC, restart, and query again."""
    if peer_bin and not geth_bin:
        raise ValueError("--peer-bin requires --geth-bin")
    with tempfile.TemporaryDirectory() as directory:
        temporary = pathlib.Path(directory)
        secret = secrets.token_bytes(32)
        (temporary / "jwt.hex").write_text(secret.hex())
        genesis = json.loads((ROOT / "docs/engine/osaka-genesis.json").read_text())
        genesis["config"]["chainId"] = 1
        genesis["baseFeePerGas"] = "0x1"
        genesis["nonce"] = "0x1"
        genesis["mixHash"] = "0x" + "ab" * 32
        genesis["coinbase"] = "0x" + "bc" * 20
        genesis["alloc"][SENDER[2:]] = {"balance": "0x3b9aca00"}
        genesis["alloc"]["aa" * 20] = {"balance": "0x0", "storage": {"0x" + "0" * 63 + "1": "0x" + "0" * 63 + "2"}}
        (temporary / "genesis.json").write_text(json.dumps(genesis))
        signed = json.loads((ROOT / "src/execution/fixtures/solidity/reference.json").read_text())["signedTransactions"]
        engine_port, rpc_port = port(), port()
        assert engine_port != rpc_port
        geth_process = None
        geth_log = None
        geth_rpc_port = None
        geth_engine_port = None
        if geth_bin:
            version = subprocess.check_output([geth_bin, "version"], text=True)
            if "1.17.10" not in version:
                raise AssertionError(f"expected pinned Geth v1.17.10, got {version.splitlines()[0]}")
            geth_rpc_port, geth_engine_port = port(), port()
            geth_data = temporary / "geth-data"
            initialized = subprocess.run([geth_bin, "--datadir", str(geth_data), "init", str(temporary / "genesis.json")], capture_output=True, timeout=30)
            assert initialized.returncode == 0, initialized.stderr.decode()
            geth_log = (temporary / "geth.log").open("wb")
            geth_args = [geth_bin, "--datadir", str(geth_data), "--networkid", "1", "--syncmode", "full", "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(geth_engine_port), "--authrpc.vhosts", "*", "--authrpc.jwtsecret", str(temporary / "jwt.hex"), "--http", "--http.addr", "127.0.0.1", "--http.port", str(geth_rpc_port), "--http.api", "eth,net,web3,admin,debug" if peer_bin else "eth,net,web3", "--nodiscover", "--maxpeers", "2" if peer_bin else "0"]
            if peer_bin:
                geth_args += ["--port", str(port()), "--nat", "extip:127.0.0.1"]
            geth_process = subprocess.Popen(
                geth_args,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=geth_log,
            )
            for _ in range(100):
                assert geth_process.poll() is None, "Geth exited during startup"
                try:
                    request(geth_rpc_port, "eth_blockNumber", [])
                    break
                except (OSError, urllib.error.URLError, AssertionError):
                    time.sleep(0.1)
            else:
                raise AssertionError("Geth RPC did not start")
        config = {
            "genesis": str(temporary / "genesis.json"),
            "data_dir": str(temporary / "data"),
            "jwt_secret": str(temporary / "jwt.hex"),
            "trusted_setup": str(ROOT / "src/execution/trusted_setup.txt"),
            "engine_bind": f"127.0.0.1:{engine_port}",
            "rpc_bind": f"127.0.0.1:{rpc_port}",
            "transfer_contract": CONTRACT,
        }
        (temporary / "config.json").write_text(json.dumps(config))
        events = (temporary / "events.jsonl").open("ab")

        def start(ignore_file_size_signal=False):
            """Start one service process against the retained database."""
            previous_handler = None
            if ignore_file_size_signal and hasattr(signal, "SIGXFSZ"):
                previous_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            try:
                process = subprocess.Popen(
                    [str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(temporary / "config.json")],
                    cwd=ROOT,
                    stdout=events,
                    stderr=subprocess.PIPE,
                    restore_signals=not ignore_file_size_signal,
                )
            finally:
                if previous_handler is not None:
                    signal.signal(signal.SIGXFSZ, previous_handler)
            wait_ready(process, rpc_port)
            return process

        process = None
        try:
            process = start()
            initial_database_bytes = database_bytes(temporary / "data")
            status, health = get(rpc_port, "/health")
            assert status == 200 and health == "ok\n", (status, health)
            assert request(rpc_port, "eth_syncing", []) is False
            status, metrics = get(rpc_port, "/metrics")
            assert status == 200
            for metric in ("execution_head_number", "execution_safe_number", "execution_finalized_number", "execution_syncing", "execution_pool_entries", "execution_pool_bytes", "execution_rpc_requests_total", "execution_rpc_errors_total", "execution_payload_build_nanoseconds_total", "execution_storage_healthy"):
                assert f"hightower_{metric} " in metrics, metric
            assert secret.hex() not in metrics
            bad = urllib.request.Request(
                f"http://127.0.0.1:{engine_port}/",
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "engine_exchangeCapabilities", "params": [[]]}).encode(),
                {"Authorization": "Bearer invalid"},
            )
            try:
                urllib.request.urlopen(bad, timeout=5)
                raise AssertionError("invalid JWT was accepted")
            except urllib.error.HTTPError as error:
                assert error.code == 401
            with socket.create_connection(("127.0.0.1", engine_port), timeout=5) as oversized:
                oversized.sendall(
                    f"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {token(secret)}\r\nContent-Length: {ENGINE_MAX_BODY + 1}\r\n\r\n".encode()
                )
                assert b" 413 " in oversized.recv(1024)
            assert request(rpc_port, "eth_chainId", []) == "0x1"
            anchor = request(rpc_port, "eth_getBlockByNumber", ["0x0", False])
            assert anchor["nonce"] == "0x0000000000000001"
            assert anchor["mixHash"] == genesis["mixHash"] and anchor["miner"] == genesis["coinbase"]
            assert request(rpc_port, "eth_getStorageAt", ["0x" + "aa" * 20, "0x1", "latest"]) == "0x" + "00" * 31 + "02"
            head = anchor["hash"]
            safe_hash = anchor["hash"]
            stop_reads = threading.Event()
            read_errors = []

            def read_during_import():
                """Check public reads while Engine changes the canonical head."""
                while not stop_reads.is_set():
                    try:
                        assert int(request(rpc_port, "eth_blockNumber", []), 16) <= (18 if peer_bin else 2)
                        request(rpc_port, "eth_getBalance", [SENDER, "latest"])
                    except Exception as error:
                        read_errors.append(error)
                        break

            reader = threading.Thread(target=read_during_import)
            reader.start()
            for number in (range(1, 19) if peer_bin else (1, 2)):
                bearer = token(secret)
                raws = signed[:2] if number == 1 else [] if peer_bin else signed[2:]
                hashes = [request(rpc_port, "eth_sendRawTransaction", [raw]) for raw in raws]
                choice = {"headBlockHash": head, "safeBlockHash": safe_hash if geth_process else head, "finalizedBlockHash": safe_hash if geth_process else head}
                attributes = {
                    "timestamp": hex(number),
                    "prevRandao": ZERO,
                    "suggestedFeeRecipient": "0x" + "00" * 20,
                    "withdrawals": [],
                    "parentBeaconBlockRoot": ZERO,
                }
                update = request(engine_port, "engine_forkchoiceUpdatedV3", [choice, attributes], bearer)
                assert update["payloadStatus"]["status"] == "VALID"
                built = request(engine_port, "engine_getPayloadV5", [update["payloadId"]], bearer)
                payload = built["executionPayload"]
                verdict = request(engine_port, "engine_newPayloadV4", [payload, [], ZERO, built["executionRequests"]], bearer)
                assert verdict["status"] == "VALID"
                if geth_process:
                    geth_verdict = request(geth_engine_port, "engine_newPayloadV4", [payload, [], ZERO, built["executionRequests"]], bearer)
                    assert geth_verdict["status"] == "VALID", f"Geth rejected block {number}: {geth_verdict!r}; Geth log tail={(temporary / 'geth.log').read_text()[-4000:]}"
                    geth_choice = {"headBlockHash": payload["blockHash"], "safeBlockHash": safe_hash if geth_process else payload["blockHash"], "finalizedBlockHash": safe_hash if geth_process else payload["blockHash"]}
                    selected = request(geth_engine_port, "engine_forkchoiceUpdatedV3", [geth_choice, None], bearer)
                    assert selected["payloadStatus"]["status"] == "VALID", f"Geth did not select block {number}: {selected!r}"
                head = payload["blockHash"]
                choice = {"headBlockHash": head, "safeBlockHash": safe_hash if geth_process else head, "finalizedBlockHash": safe_hash if geth_process else head}
                assert request(engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
                assert request(rpc_port, "eth_blockNumber", []) == hex(number)
                assert request(rpc_port, "eth_getBlockByNumber", [hex(number), False])["hash"] == head
                if geth_process:
                    compare_block(rpc_port, geth_rpc_port, number)
                for tx_hash in hashes:
                    assert request(rpc_port, "eth_getTransactionReceipt", [tx_hash])["blockHash"] == head
            stop_reads.set()
            reader.join(timeout=5)
            assert not read_errors, read_errors
            if peer_bin:
                test_peer_catchup(temporary, config, secret, geth_rpc_port, geth_engine_port, peer_bin, head, 18, payload, built["executionRequests"])
                return
            assert request(rpc_port, "eth_getBalance", [SENDER, "latest"]) != "0x3b9aca00"
            logs = request(rpc_port, "eth_getLogs", [{"fromBlock": "0x1"}])
            assert len(logs) == 2 and all(log["address"].lower() == CONTRACT for log in logs), logs
            assert request(rpc_port, "eth_getStorageAt", [COUNTER, "0x0", "latest"]) == "0x" + "00" * 31 + "2a"
            balance_call = "0x70a08231" + "00" * 12 + SENDER[2:]
            assert int(request(rpc_port, "eth_call", [{"to": CONTRACT, "data": balance_call}, "latest"]), 16) == 925
            transfer_trace = request(rpc_port, "debug_traceTransaction", [hashes[1], {"tracer": "callTracer"}])
            assert transfer_trace["type"] == "CALL" and transfer_trace["to"].lower() == CONTRACT
            assert transfer_trace["output"].endswith("01") and "error" not in transfer_trace
            reverted_trace = request(rpc_port, "debug_traceTransaction", [hashes[2], {"tracer": "callTracer"}])
            assert reverted_trace["error"] == "execution reverted" and reverted_trace["output"].startswith("0x08c379a0")
            historical_calls = (
                ("eth_getBalance", [SENDER, "0x1"]),
                ("eth_getCode", [CONTRACT, "0x1"]),
                ("eth_getStorageAt", [CONTRACT, "0x0", "0x1"]),
                ("eth_call", [{"to": CONTRACT, "data": balance_call}, "0x1"]),
            )
            historical_results = [request(rpc_port, method, params) for method, params in historical_calls]
            historical_latency_us = median_rpc_latency(rpc_port, historical_calls)
            retained_database_bytes = database_bytes(temporary / "data")
            metrics = get(rpc_port, "/metrics")[1]
            assert "hightower_execution_rpc_errors_total 0\n" in metrics, metrics
            stop(process, secret)
            lines = (temporary / "events.jsonl").read_text().splitlines()
            if not geth_process:
                assert len(lines) == 2
                minted = json.loads(lines[0])
                assert minted["contract"] == CONTRACT and minted["amount"].endswith("03e8")
                event = json.loads(lines[1])
                assert event["id"] == f"{head}:0"
                assert event["contract"] == CONTRACT and event["from"] == SENDER
                assert event["to"] == "0x" + "44" * 20 and event["amount"].endswith("4b")
                assert event["transaction_hash"] == hashes[1]
                assert event["block_number"] == 2 and event["log_index"] == 0
            else:
                assert lines == []
            process = start()
            status, health = get(rpc_port, "/health")
            assert status == 200 and health == "ok\n", (status, health)
            assert secret.hex() not in get(rpc_port, "/metrics")[1]
            assert request(rpc_port, "eth_blockNumber", []) == "0x2"
            assert request(rpc_port, "eth_getBlockByHash", [head, False])["number"] == "0x2"
            assert request(rpc_port, "eth_getLogs", [{"fromBlock": "0x1"}]) == logs
            assert [request(rpc_port, method, params) for method, params in historical_calls] == historical_results
            print(
                f"execution history sample: 2 blocks, database +{retained_database_bytes - initial_database_bytes} bytes, "
                f"historical RPC median {historical_latency_us:.1f} us over 80 calls"
            )
            assert request(rpc_port, "eth_getTransactionReceipt", [hashes[1]])["status"] == "0x1"
            assert request(rpc_port, "debug_traceTransaction", [hashes[1], {"tracer": "callTracer"}])["output"] == transfer_trace["output"]
            assert len((temporary / "events.jsonl").read_text().splitlines()) == (0 if geth_process else 2)
            bearer = token(secret)
            parent_head = head
            choice = {"headBlockHash": head, "safeBlockHash": safe_hash if geth_process else head, "finalizedBlockHash": safe_hash if geth_process else head}
            attributes = {"timestamp": "0x3", "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}
            update = request(engine_port, "engine_forkchoiceUpdatedV3", [choice, attributes], bearer)
            built = request(engine_port, "engine_getPayloadV5", [update["payloadId"]], bearer)
            payload = built["executionPayload"]
            assert request(engine_port, "engine_newPayloadV4", [payload, [], ZERO, built["executionRequests"]], bearer)["status"] == "VALID"
            if geth_process:
                assert request(geth_engine_port, "engine_newPayloadV4", [payload, [], ZERO, built["executionRequests"]], bearer)["status"] == "VALID"
            head = payload["blockHash"]
            choice = {"headBlockHash": head, "safeBlockHash": safe_hash if geth_process else head, "finalizedBlockHash": safe_hash if geth_process else head}
            assert request(engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
            if geth_process:
                assert request(geth_engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
                compare_block(rpc_port, geth_rpc_port, 3)
                orphaned_head = head
                choice = {"headBlockHash": parent_head, "safeBlockHash": safe_hash, "finalizedBlockHash": safe_hash}
                update = request(engine_port, "engine_forkchoiceUpdatedV3", [choice, {"timestamp": "0x4", "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}], bearer)
                alternate = request(engine_port, "engine_getPayloadV5", [update["payloadId"]], bearer)
                alternate_payload = alternate["executionPayload"]
                assert request(engine_port, "engine_newPayloadV4", [alternate_payload, [], ZERO, alternate["executionRequests"]], bearer)["status"] == "VALID"
                assert request(geth_engine_port, "engine_newPayloadV4", [alternate_payload, [], ZERO, alternate["executionRequests"]], bearer)["status"] == "VALID"
                alternate_head = alternate_payload["blockHash"]
                choice = {"headBlockHash": alternate_head, "safeBlockHash": safe_hash, "finalizedBlockHash": safe_hash}
                assert request(engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
                assert request(geth_engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
                choice = {"headBlockHash": alternate_head, "safeBlockHash": alternate_head, "finalizedBlockHash": alternate_head}
                assert request(engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
                assert request(geth_engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
                assert orphaned_head != alternate_head
                assert request(rpc_port, "eth_getBlockByNumber", ["0x3", False])["hash"] == alternate_head
                assert request(geth_rpc_port, "eth_getBlockByNumber", ["0x3", False])["hash"] == alternate_head
                compare_block(rpc_port, geth_rpc_port, 3)
                lines = (temporary / "events.jsonl").read_text().splitlines()
                assert len(lines) == 2
                assert json.loads(lines[1])["transaction_hash"] == hashes[1]
            assert request(rpc_port, "eth_blockNumber", []) == "0x3"
            stop(process, secret)
            for changed, expected in (("chainId", "ExecutionIdentityMismatch"), ("gasLimit", "GenesisMismatch"), ("slotNumber", "UnsupportedGenesisHeaderField")):
                wrong = json.loads((temporary / "genesis.json").read_text())
                if changed == "chainId":
                    wrong["config"][changed] = 2
                elif changed == "slotNumber":
                    wrong[changed] = "0x1"
                else:
                    wrong[changed] = "0xaf79e1"
                (temporary / "wrong-genesis.json").write_text(json.dumps(wrong))
                bad_config = dict(config, genesis=str(temporary / "wrong-genesis.json"))
                (temporary / "wrong-config.json").write_text(json.dumps(bad_config))
                failed = subprocess.run(
                    [str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(temporary / "wrong-config.json")],
                    cwd=ROOT,
                    capture_output=True,
                    timeout=5,
                )
                assert failed.returncode != 0 and expected.encode() in failed.stderr, failed.stderr
            invalid_storage = dict(config, data_dir=str(temporary / "genesis.json"))
            (temporary / "invalid-storage-config.json").write_text(json.dumps(invalid_storage))
            failed = subprocess.run(
                [str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(temporary / "invalid-storage-config.json")],
                cwd=ROOT,
                capture_output=True,
                timeout=5,
            )
            assert failed.returncode != 0 and b"NotDir" in failed.stderr, failed.stderr
            assert secret.hex().encode() not in failed.stderr
            measure_archive_history(temporary, config, secret)
            if hasattr(resource, "prlimit") and hasattr(signal, "SIGXFSZ"):
                process = start(ignore_file_size_signal=True)
                latest = request(rpc_port, "eth_getBlockByNumber", ["latest", False])
                parent_hash = latest["hash"]
                bearer = token(secret)
                choice = {"headBlockHash": parent_hash, "safeBlockHash": parent_hash, "finalizedBlockHash": parent_hash}
                attributes = {"timestamp": hex(int(latest["timestamp"], 16) + 1), "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}
                update = request(engine_port, "engine_forkchoiceUpdatedV3", [choice, attributes], bearer)
                built = request(engine_port, "engine_getPayloadV5", [update["payloadId"]], bearer)
                payload = built["executionPayload"]
                assert request(engine_port, "engine_newPayloadV4", [payload, [], ZERO, built["executionRequests"]], bearer)["status"] == "VALID"
                resource.prlimit(process.pid, resource.RLIMIT_FSIZE, (0, 0))
                assert resource.prlimit(process.pid, resource.RLIMIT_FSIZE) == (0, 0)
                choice = {"headBlockHash": payload["blockHash"], "safeBlockHash": payload["blockHash"], "finalizedBlockHash": payload["blockHash"]}
                failed_request = urllib.request.Request(
                    f"http://127.0.0.1:{engine_port}/",
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "engine_forkchoiceUpdatedV3", "params": [choice, None]}).encode(),
                    {"Content-Type": "application/json", "Authorization": bearer},
                )
                with urllib.request.urlopen(failed_request, timeout=5) as response:
                    failed_choice = json.load(response)
                assert failed_choice.get("error", {}).get("code") == -32000, failed_choice
                try:
                    get(rpc_port, "/health")
                    raise AssertionError("health remained ready after the durable write failed")
                except urllib.error.HTTPError as error:
                    assert error.code == 503 and error.read() == b"storage unavailable\n"
                status, metrics = get(rpc_port, "/metrics")
                assert status == 200 and "hightower_execution_storage_healthy 0\n" in metrics
        finally:
            if process and not process.stderr.closed:
                stop(process, secret)
            if geth_process and geth_process.poll() is None:
                geth_process.terminate()
                geth_process.wait(timeout=5)
            if geth_log:
                geth_log.close()
            events.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--geth-bin", help="run the differential checks against pinned Geth v1.17.10")
    parser.add_argument("--peer-bin", help="also sync a fresh database through the eth/69 worker")
    arguments = parser.parse_args()
    run(arguments.geth_bin, arguments.peer_bin)

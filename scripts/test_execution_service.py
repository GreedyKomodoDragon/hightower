#!/usr/bin/env python3
"""Exercise the production Engine and public RPC listeners across recovery."""

import base64
import argparse
import hashlib
import hmac
import json
import pathlib
import secrets
import socket
import subprocess
import tempfile
import threading
import time
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


def wait_ready(process, port_number):
    """Wait until the public listener accepts TCP connections."""
    for _ in range(100):
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


def run(geth_bin=None):
    """Import two blocks, query canonical RPC, restart, and query again."""
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
        genesis["alloc"]["aa" * 20] = {"storage": {"0x1": "0x2"}}
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
            subprocess.run([geth_bin, "--datadir", str(geth_data), "init", str(temporary / "genesis.json")], check=True, capture_output=True, timeout=30)
            geth_log = (temporary / "geth.log").open("wb")
            geth_process = subprocess.Popen(
                [geth_bin, "--datadir", str(geth_data), "--networkid", "1", "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(geth_engine_port), "--authrpc.vhosts", "*", "--authrpc.jwtsecret", str(temporary / "jwt.hex"), "--http", "--http.addr", "127.0.0.1", "--http.port", str(geth_rpc_port), "--http.api", "eth,net,web3", "--nodiscover", "--maxpeers", "0"],
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

        def start():
            """Start one service process against the retained database."""
            process = subprocess.Popen(
                [str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(temporary / "config.json")],
                cwd=ROOT,
                stdout=events,
                stderr=subprocess.PIPE,
            )
            wait_ready(process, rpc_port)
            return process

        process = None
        try:
            process = start()
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
                        assert request(rpc_port, "eth_blockNumber", []) in ("0x0", "0x1", "0x2")
                        request(rpc_port, "eth_getBalance", [SENDER, "latest"])
                    except Exception as error:
                        read_errors.append(error)
                        break

            reader = threading.Thread(target=read_during_import)
            reader.start()
            for number in (1, 2):
                bearer = token(secret)
                raws = signed[:2] if number == 1 else signed[2:]
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
                    assert geth_verdict["status"] == "VALID", f"Geth rejected block {number}: {geth_verdict!r}; Hightower payload={payload!r}"
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
            process.terminate()
            process.wait(timeout=5)
            process.stderr.close()
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
            process.terminate()
            process.wait(timeout=5)
            process.stderr.close()
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
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            if process:
                process.stderr.close()
            if geth_process and geth_process.poll() is None:
                geth_process.terminate()
                geth_process.wait(timeout=5)
            if geth_log:
                geth_log.close()
            events.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--geth-bin", help="run the differential checks against pinned Geth v1.17.10")
    arguments = parser.parse_args()
    run(arguments.geth_bin)

#!/usr/bin/env python3
"""Exercise the production Engine and public RPC listeners across recovery."""

import base64
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
CONTRACT = "0xf2e246bb76df876cef8b38ae84130f4f55de395b"


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


def run():
    """Import two blocks, query canonical RPC, restart, and query again."""
    with tempfile.TemporaryDirectory() as directory:
        temporary = pathlib.Path(directory)
        secret = secrets.token_bytes(32)
        (temporary / "jwt.hex").write_text(secret.hex())
        genesis = json.loads((ROOT / "docs/engine/osaka-genesis.json").read_text())
        genesis["config"]["chainId"] = 1
        genesis["baseFeePerGas"] = "0x1"
        genesis["alloc"][SENDER[2:]] = {"balance": "0x3b9aca00"}
        (temporary / "genesis.json").write_text(json.dumps(genesis))
        signed = json.loads((ROOT / "src/execution/fixtures/local_token_signed.json").read_text())
        engine_port, rpc_port = port(), port()
        assert engine_port != rpc_port
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

        process = start()
        try:
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
            head = request(rpc_port, "eth_getBlockByNumber", ["0x0", False])["hash"]
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
                raws = [signed["deployment"]] if number == 1 else [signed["transfer"], signed["reverted"]]
                hashes = [request(rpc_port, "eth_sendRawTransaction", [raw]) for raw in raws]
                choice = {"headBlockHash": head, "safeBlockHash": head, "finalizedBlockHash": head}
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
                head = payload["blockHash"]
                choice = {"headBlockHash": head, "safeBlockHash": head, "finalizedBlockHash": head}
                assert request(engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
                assert request(rpc_port, "eth_blockNumber", []) == hex(number)
                assert request(rpc_port, "eth_getBlockByNumber", [hex(number), False])["hash"] == head
                for tx_hash in hashes:
                    assert request(rpc_port, "eth_getTransactionReceipt", [tx_hash])["blockHash"] == head
            stop_reads.set()
            reader.join(timeout=5)
            assert not read_errors, read_errors
            assert request(rpc_port, "eth_getBalance", [SENDER, "latest"]) != "0x3b9aca00"
            logs = request(rpc_port, "eth_getLogs", [{}])
            assert len(logs) == 1 and logs[0]["address"].lower() == CONTRACT
            process.terminate()
            process.wait(timeout=5)
            process.stderr.close()
            lines = (temporary / "events.jsonl").read_text().splitlines()
            assert len(lines) == 1
            event = json.loads(lines[0])
            assert event["id"] == f"{head}:0"
            assert event["contract"] == CONTRACT and event["from"] == SENDER
            assert event["to"] == "0x" + "44" * 20 and event["amount"].endswith("4b")
            assert event["transaction_hash"] == hashes[0]
            assert event["block_number"] == 2 and event["log_index"] == 0
            process = start()
            assert request(rpc_port, "eth_blockNumber", []) == "0x2"
            assert request(rpc_port, "eth_getBlockByHash", [head, False])["number"] == "0x2"
            assert request(rpc_port, "eth_getLogs", [{}]) == logs
            assert request(rpc_port, "eth_getTransactionReceipt", [hashes[0]])["status"] == "0x1"
            assert len((temporary / "events.jsonl").read_text().splitlines()) == 1
            bearer = token(secret)
            choice = {"headBlockHash": head, "safeBlockHash": head, "finalizedBlockHash": head}
            attributes = {"timestamp": "0x3", "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}
            update = request(engine_port, "engine_forkchoiceUpdatedV3", [choice, attributes], bearer)
            built = request(engine_port, "engine_getPayloadV5", [update["payloadId"]], bearer)
            payload = built["executionPayload"]
            assert request(engine_port, "engine_newPayloadV4", [payload, [], ZERO, built["executionRequests"]], bearer)["status"] == "VALID"
            head = payload["blockHash"]
            choice = {"headBlockHash": head, "safeBlockHash": head, "finalizedBlockHash": head}
            assert request(engine_port, "engine_forkchoiceUpdatedV3", [choice, None], bearer)["payloadStatus"]["status"] == "VALID"
            assert request(rpc_port, "eth_blockNumber", []) == "0x3"
            process.terminate()
            process.wait(timeout=5)
            process.stderr.close()
            for changed, expected in (("chainId", "ExecutionIdentityMismatch"), ("gasLimit", "GenesisMismatch")):
                wrong = json.loads((temporary / "genesis.json").read_text())
                if changed == "chainId":
                    wrong["config"][changed] = 2
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
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stderr.close()
            events.close()


if __name__ == "__main__":
    run()

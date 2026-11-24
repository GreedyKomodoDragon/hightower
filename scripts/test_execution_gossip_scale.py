#!/usr/bin/env python3
"""Exercise bounded transaction gossip beyond 256 entries and 3 MiB."""

import json
import pathlib
import secrets
import subprocess
import tempfile
import time

from test_execution_service import ROOT, ZERO, get, port, request, token, wait_ready


def main():
    """Relay a late selectable transaction and four large transactions, then restart."""
    generated = subprocess.run(["go", "run", "./txpool-fixture"], cwd=ROOT / "scripts/geth-discovery-probe", capture_output=True, text=True, check=True)
    transactions = json.loads(generated.stdout)
    assert len(transactions) == 304
    assert sum((len(item["raw"]) - 2) // 2 for item in transactions[300:]) > 3 * 1024 * 1024
    with tempfile.TemporaryDirectory() as directory:
        temporary = pathlib.Path(directory)
        secret = secrets.token_bytes(32)
        (temporary / "jwt.hex").write_text(secret.hex())
        genesis = json.loads((ROOT / "docs/engine/osaka-genesis.json").read_text())
        genesis["config"]["chainId"] = 1
        genesis["baseFeePerGas"] = "0x1"
        for item in transactions:
            genesis["alloc"][item["address"][2:].lower()] = {"balance": "0x3b9aca00"}
        (temporary / "genesis.json").write_text(json.dumps(genesis))
        seed_rpc, seed_engine, seed_peer, leaf_rpc, leaf_engine, leaf_peer = (port() for _ in range(6))
        base = {"genesis": str(temporary / "genesis.json"), "jwt_secret": str(temporary / "jwt.hex"), "trusted_setup": str(ROOT / "src/execution/trusted_setup.txt")}
        seed_config = dict(base, data_dir=str(temporary / "seed-data"), rpc_bind=f"127.0.0.1:{seed_rpc}", engine_bind=f"127.0.0.1:{seed_engine}", execution_p2p_bind=f"127.0.0.1:{seed_peer}")
        seed_path = temporary / "seed.json"
        seed_path.write_text(json.dumps(seed_config))
        running = []

        def launch(path, rpc_port, label):
            """Start one production service and retain its log for failure details."""
            log_path = temporary / f"{label}.log"
            with log_path.open("wb") as output:
                process = subprocess.Popen([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(path)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=output)
            running.append((process, log_path))
            try:
                wait_ready(process, rpc_port)
            except AssertionError as error:
                raise AssertionError(f"{error}: {log_path.read_text(errors='replace')}") from error
            return process, log_path

        def wait_enr(path):
            """Read the signed bootstrap address logged at startup."""
            for _ in range(100):
                log = path.read_text(errors="replace")
                if "execution peer ENR: " in log:
                    return log.split("execution peer ENR: ", 1)[1].split()[0]
                time.sleep(0.05)
            raise AssertionError(path.read_text())

        def wait_pending(rpc_port, address):
            """Wait for a peer's shared pool to contain one signed transaction."""
            for _ in range(300):
                if request(rpc_port, "eth_getTransactionCount", [address, "pending"]) == "0x1":
                    return
                time.sleep(0.05)
            raise AssertionError(f"pending transaction did not reach {address}")

        def stop(process, log_path):
            """Terminate a service without exposing its JWT in logs."""
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            assert secret.hex().encode() not in log_path.read_bytes()

        try:
            seed, seed_log = launch(seed_path, seed_rpc, "seed")
            leaf_config = dict(base, data_dir=str(temporary / "leaf-data"), rpc_bind=f"127.0.0.1:{leaf_rpc}", engine_bind=f"127.0.0.1:{leaf_engine}", execution_p2p_bind=f"127.0.0.1:{leaf_peer}", execution_bootnodes=[wait_enr(seed_log)])
            leaf_path = temporary / "leaf.json"
            leaf_path.write_text(json.dumps(leaf_config))
            leaf, leaf_log = launch(leaf_path, leaf_rpc, "leaf")
            for item in transactions[:256]:
                request(seed_rpc, "eth_sendRawTransaction", [item["raw"]])
            wait_pending(leaf_rpc, transactions[255]["address"])
            for item in transactions[256:300]:
                request(seed_rpc, "eth_sendRawTransaction", [item["raw"]])
            wait_pending(leaf_rpc, transactions[299]["address"])
            parent = request(leaf_rpc, "eth_getBlockByNumber", ["latest", False])
            choice = {"headBlockHash": parent["hash"], "safeBlockHash": parent["hash"], "finalizedBlockHash": parent["hash"]}
            attributes = {"timestamp": hex(int(parent["timestamp"], 16) + 1), "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}
            bearer = token(secret)
            update = request(leaf_engine, "engine_forkchoiceUpdatedV3", [choice, attributes], bearer)
            payload = request(leaf_engine, "engine_getPayloadV5", [update["payloadId"]], bearer)["executionPayload"]
            assert transactions[299]["raw"].lower() in {raw.lower() for raw in payload["transactions"]}
            for item in transactions[300:]:
                request(seed_rpc, "eth_sendRawTransaction", [item["raw"]])
            wait_pending(leaf_rpc, transactions[-1]["address"])
            stop(leaf, leaf_log)
            running.remove((leaf, leaf_log))
            leaf, leaf_log = launch(leaf_path, leaf_rpc, "leaf-restarted")
            wait_pending(leaf_rpc, transactions[-1]["address"])
            pool_entries = next(line for line in get(leaf_rpc, "/metrics")[1].splitlines() if line.startswith("hightower_execution_pool_entries "))
            assert pool_entries == "hightower_execution_pool_entries 304", pool_entries
        finally:
            for process, log_path in running:
                stop(process, log_path)
    print("execution gossip scale and restart: ok")


if __name__ == "__main__":
    main()

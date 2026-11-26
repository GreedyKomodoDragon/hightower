#!/usr/bin/env python3
"""Relay signed transactions both ways with a live pinned Geth execution node.

The genesis fixes Osaka execution rules; its fork ID identifies peers before
eth/69 Status accepts pool data. A transaction must enter the shared pool
before payload building can select it. Geth accepts peer announcements after
its Engine fork choice marks the chain synced. Discovery admits at most two
active or pending Hightower peers.

signed ENR -> discv5 -> RLPx/Status -> pool -> payload or Geth pool
"""

import argparse
import json
import pathlib
import secrets
import subprocess
import tempfile
import time
import urllib.error

from test_execution_service import ROOT, SENDER, ZERO, port, request, token, wait_ready


def wait_until(check, label):
    """Poll one bounded local integration assertion."""
    for _ in range(200):
        try:
            if check():
                return
        except (OSError, urllib.error.URLError, AssertionError):
            pass
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {label}")


def geth_has(port_number, tx_hash):
    """Find a pending or queued transaction without Geth's async block index."""
    content = request(port_number, "txpool_content", [])
    return any(tx["hash"].lower() == tx_hash.lower() for section in ("pending", "queued") for sender in content[section].values() for tx in sender.values())


def main():
    """Start Geth with discv5 and verify discovery, pool admission, and relay."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--geth-bin", required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.geth_bin, "version"], text=True)
    assert "1.17.10" in version, version
    with tempfile.TemporaryDirectory() as directory:
        temporary = pathlib.Path(directory)
        secret = secrets.token_bytes(32)
        (temporary / "jwt.hex").write_text(secret.hex())
        genesis = json.loads((ROOT / "docs/engine/osaka-genesis.json").read_text())
        genesis["config"]["chainId"] = 1
        genesis["baseFeePerGas"] = "0x1"
        genesis["alloc"][SENDER[2:]] = {"balance": "0x3b9aca00"}
        genesis_path = temporary / "genesis.json"
        genesis_path.write_text(json.dumps(genesis))
        geth_data = temporary / "geth"
        initialized = subprocess.run([args.geth_bin, "--datadir", str(geth_data), "init", str(genesis_path)], capture_output=True, timeout=30)
        assert initialized.returncode == 0, initialized.stderr.decode()
        geth_rpc, geth_auth, geth_peer, zig_rpc, zig_engine, zig_peer = (port() for _ in range(6))
        geth_log = temporary / "geth.log"
        with geth_log.open("wb") as output:
            geth = subprocess.Popen([
                args.geth_bin, "--datadir", str(geth_data), "--networkid", "1", "--syncmode", "full",
                "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(geth_auth),
                "--authrpc.jwtsecret", str(temporary / "jwt.hex"), "--http", "--http.addr", "127.0.0.1",
                "--http.port", str(geth_rpc), "--http.api", "eth,net,web3,admin,txpool", "--port", str(geth_peer),
                "--nat", "extip:127.0.0.1", "--discovery.v5", "--bootnodes", "", "--maxpeers", "2",
            ], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=output)
        zig = None
        zig_log = temporary / "hightower.log"
        try:
            try:
                wait_until(lambda: geth.poll() is None and request(geth_rpc, "eth_blockNumber", []) == "0x0", "Geth RPC")
            except AssertionError as error:
                raise AssertionError(f"{error}: {geth_log.read_text(errors='replace')[-3000:]}") from error
            genesis_hash = request(geth_rpc, "eth_getBlockByNumber", ["latest", False])["hash"]
            choice = {"headBlockHash": genesis_hash, "safeBlockHash": genesis_hash, "finalizedBlockHash": genesis_hash}
            assert request(geth_auth, "engine_forkchoiceUpdatedV3", [choice, None], token(secret))["payloadStatus"]["status"] == "VALID"
            info = request(geth_rpc, "admin_nodeInfo", [])
            assert info["enr"].startswith("enr:"), info
            config = {
                "genesis": str(genesis_path), "data_dir": str(temporary / "zig"),
                "jwt_secret": str(temporary / "jwt.hex"),
                "trusted_setup": str(ROOT / "src/execution/trusted_setup.txt"),
                "engine_bind": f"127.0.0.1:{zig_engine}", "rpc_bind": f"127.0.0.1:{zig_rpc}",
                "execution_p2p_bind": f"127.0.0.1:{zig_peer}", "execution_bootnodes": [info["enr"]],
            }
            config_path = temporary / "hightower.json"
            config_path.write_text(json.dumps(config))
            mismatch = dict(genesis, extraData="0x01")
            mismatch_path = temporary / "mismatched-genesis.json"
            mismatch_path.write_text(json.dumps(mismatch))
            rejected_config = dict(config, genesis=str(mismatch_path), data_dir=str(temporary / "mismatch-data"))
            rejected_path = temporary / "rejected.json"
            rejected_path.write_text(json.dumps(rejected_config))
            rejected = subprocess.run([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(rejected_path)], cwd=ROOT, capture_output=True, timeout=10)
            assert rejected.returncode != 0 and b"InvalidForkContext" in rejected.stderr, rejected.stderr
            future = json.loads(json.dumps(genesis))
            future["config"]["osakaTime"] = 1
            future_path = temporary / "future-genesis.json"
            future_path.write_text(json.dumps(future))
            rejected_config.update(genesis=str(future_path), data_dir=str(temporary / "future-data"))
            rejected_path.write_text(json.dumps(rejected_config))
            rejected = subprocess.run([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(rejected_path)], cwd=ROOT, capture_output=True, timeout=10)
            assert rejected.returncode != 0 and b"UnsupportedExecutionFork" in rejected.stderr, rejected.stderr
            with zig_log.open("wb") as output:
                zig = subprocess.Popen([str(ROOT / "zig-out/bin/hightower-execution"), "--config", str(config_path)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=output)
            try:
                wait_ready(zig, zig_rpc)
            except AssertionError as error:
                raise AssertionError(f"{error}: {zig_log.read_text(errors='replace')}") from error
            signed = json.loads((ROOT / "src/execution/fixtures/solidity/reference.json").read_text())["signedTransactions"]
            geth_hash = request(geth_rpc, "eth_sendRawTransaction", [signed[0]])
            wait_until(lambda: request(zig_rpc, "eth_getTransactionCount", [SENDER, "pending"]) == "0x1", "Geth transaction in Hightower pool")
            parent = request(zig_rpc, "eth_getBlockByNumber", ["latest", False])
            choice = {"headBlockHash": parent["hash"], "safeBlockHash": parent["hash"], "finalizedBlockHash": parent["hash"]}
            attributes = {"timestamp": hex(int(parent["timestamp"], 16) + 1), "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [], "parentBeaconBlockRoot": ZERO}
            update = request(zig_engine, "engine_forkchoiceUpdatedV3", [choice, attributes], token(secret))
            payload = request(zig_engine, "engine_getPayloadV5", [update["payloadId"]], token(secret))["executionPayload"]
            assert signed[0].lower() in {raw.lower() for raw in payload["transactions"]}
            assert geth_has(geth_rpc, geth_hash)
            zig_hash = request(zig_rpc, "eth_sendRawTransaction", [signed[1]])
            try:
                wait_until(lambda: geth_has(geth_rpc, zig_hash), "Hightower transaction in Geth pool")
            except AssertionError as error:
                raise AssertionError(f"{error}\nHightower: {zig_log.read_text(errors='replace')}\nGeth log tail: {geth_log.read_text(errors='replace')[-2000:]}") from error
        finally:
            for process in (zig, geth):
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            if zig_log.exists():
                assert secret.hex() not in zig_log.read_text()
    print("live Geth execution gossip: ok")


if __name__ == "__main__":
    main()

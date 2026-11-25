#!/usr/bin/env python3
"""Check Zig RLPx transaction gossip against Geth's devp2p implementation."""

import json
import pathlib
import socket
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    """Build the Go fixture, then exchange one signed transaction over eth/69."""
    transaction = json.loads((ROOT / "src/execution/fixtures/solidity/reference.json").read_text())["signedTransactions"][0]
    with tempfile.TemporaryDirectory() as temporary:
        go_fixture = pathlib.Path(temporary) / "geth-rlpx-fixture"
        subprocess.run(["go", "build", "-o", str(go_fixture), "./rlpx-gossip-fixture"], cwd=ROOT / "scripts/geth-discovery-probe", check=True)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        server = subprocess.Popen([str(go_fixture), "--listen", f"127.0.0.1:{port}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert server.stdout.readline().strip() == "ready", "Geth fixture failed to start"
            client = subprocess.run([str(ROOT / "zig-out/bin/hightower-execution-rlpx-fixture"), str(port), transaction], capture_output=True, text=True, timeout=20)
            assert client.returncode == 0, client.stderr
            assert server.stdout.readline().strip() == "ok", server.stderr.read()
            assert server.wait(timeout=5) == 0, server.stderr.read()
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
    print("execution RLPx eth/69 interoperability: ok")


if __name__ == "__main__":
    main()

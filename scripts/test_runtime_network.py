#!/usr/bin/env python3
"""Exercise two live Hightower processes on the pinned local Fulu chain."""

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent.parent
NODE = ROOT / "zig-out/bin/hightower"
ENGINE = ROOT / "zig-out/bin/hightower-engine-test-server"
FIXTURE = ROOT / "zig-out/bin/hightower-runtime-fixture"
KEY_A = "0" * 63 + "1"
KEY_B = "0" * 63 + "2"
JWT = "0" * 63 + "3"


def port():
    """Choose a free local TCP port for one test process."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(check, processes, timeout=30):
    """Wait for a condition while failing promptly if a child exits."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"{process.args[0]} exited {process.returncode}")
        result = check()
        if result:
            return result
        time.sleep(0.2)
    raise TimeoutError("runtime network did not converge")


def head(port_number):
    """Read the selected head root and slot from the Beacon API."""
    try:
        with urlopen(f"http://127.0.0.1:{port_number}/eth/v1/beacon/blocks/head/root", timeout=1) as reply:
            root = json.load(reply)["data"]["root"]
        with urlopen(f"http://127.0.0.1:{port_number}/metrics", timeout=1) as reply:
            slot = re.search(r"^hightower_head_slot (\d+)$", reply.read().decode(), re.MULTILINE)
            return root, int(slot.group(1))
    except (OSError, KeyError, ValueError):
        return None


def listening(port_number):
    """Report when a local Engine listener accepts connections."""
    try:
        with socket.create_connection(("127.0.0.1", port_number), timeout=1):
            return True
    except OSError:
        return False


def start(command, log, env=None):
    """Start one child with captured output for failure diagnostics."""
    with log.open("wb") as output:
        return subprocess.Popen(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, env=env)


def stop(process):
    """Stop one child and wait for it to release its sockets."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def reject_config(path, config, env, expected_error, port_number):
    """Check a bad live startup fails before binding and hides credentials."""
    path.write_text(json.dumps(config))
    result = subprocess.run([NODE, "--config", os.path.relpath(path, ROOT)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
    output = result.stdout + result.stderr
    assert KEY_A not in output and KEY_B not in output and JWT not in output, "credential leaked on startup"
    assert result.returncode != 0 and expected_error in output, output
    assert not listening(port_number), "invalid config opened a listener"


def main():
    """Seed the source, import two blocks, and resume the target from disk."""
    with tempfile.TemporaryDirectory(prefix="hightower-network-", dir=ROOT / ".zig-cache") as name:
        work = Path(name)
        relative = lambda path: os.path.relpath(path, ROOT)
        expected = subprocess.check_output([FIXTURE, relative(work)], cwd=ROOT, text=True).strip()
        assert (work / "anchor-state.ssz").exists(), f"fixture missing from {work}"
        (work / "jwt").write_text(JWT + "\n")
        ports = [port() for _ in range(4)]
        base = {
            "anchor_state": relative(work / "anchor-state.ssz"),
            "anchor_block": relative(work / "anchor-block.ssz"),
            "trusted_setup": "src/execution/trusted_setup.txt",
        }
        configs = []
        for i, label in enumerate("ab"):
            config = dict(base, listen_address=f"127.0.0.1:{ports[i]}", data_dir=relative(work / ("source" if i == 0 else "target")), engine_url=f"http://127.0.0.1:{ports[i + 2]}", bootstrap_enr="")
            path = work / f"{label}.json"
            path.write_text(json.dumps(config))
            configs.append(path)
        source_env = dict(os.environ, HIGHTOWER_NODE_KEY=KEY_A, HIGHTOWER_ENGINE_JWT_SECRET=JWT)
        invalid = work / "invalid.json"
        live_config = json.loads(configs[0].read_text())
        for variable in ("HIGHTOWER_NODE_KEY", "HIGHTOWER_ENGINE_JWT_SECRET"):
            name = "NodeKey" if variable == "HIGHTOWER_NODE_KEY" else "EngineJwtSecret"
            reject_config(invalid, live_config, {k: v for k, v in source_env.items() if k != variable}, "Missing" + name, ports[0])
            reject_config(invalid, live_config, dict(source_env, **{variable: "zz" * 32}), "Invalid" + name, ports[0])
        for field in ("node_key", "engine_jwt_secret"):
            reject_config(invalid, live_config | {field: None}, source_env, "UnknownField", ports[0])
        processes = []
        try:
            for i in range(2):
                processes.append(start([ENGINE, str(ports[i + 2]), relative(work / "jwt"), "--fixture-hashes", relative(work / "execution.fixture-hashes")], work / f"engine-{i}.log"))
            wait_for(lambda: all(listening(number) for number in ports[2:]), processes)
            source = start([NODE, "--config", relative(configs[0])], work / "source.log", source_env)
            processes.append(source)
            wait_for(lambda: head(ports[0]) == (expected, 2), processes)
            enr = wait_for(lambda: (match.group(1) if (match := re.search(r"local ENR: (enr:[^\s]+)", (work / "source.log").read_text())) else None), processes)
            target_config = json.loads(configs[1].read_text())
            target_config["bootstrap_enr"] = enr
            configs[1].write_text(json.dumps(target_config))
            target_env = dict(os.environ, HIGHTOWER_NODE_KEY=KEY_B, HIGHTOWER_ENGINE_JWT_SECRET=JWT)
            target = start([NODE, "--config", relative(configs[1])], work / "target.log", target_env)
            processes.append(target)
            wait_for(lambda: head(ports[0]) == (expected, 2) and head(ports[1]) == (expected, 2), processes, 60)
            stop(target)
            processes.pop()
            target = start([NODE, "--config", relative(configs[1])], work / "target-restart.log", target_env)
            processes.append(target)
            wait_for(lambda: head(ports[0]) == (expected, 2) and head(ports[1]) == (expected, 2), processes)
            for log in work.glob("*.log"):
                output = log.read_text()
                assert KEY_A not in output and KEY_B not in output and JWT not in output, f"credential leaked in {log.name}"
            print(f"two nodes converged at slot 2, head {expected}; target recovered after restart")
        except Exception:
            for log in work.glob("*.log"):
                output = log.read_text()[-4000:]
                for secret in (KEY_A, KEY_B, JWT):
                    output = output.replace(secret, "[REDACTED]")
                print(f"--- {log.name} ---\n{output}")
            raise
        finally:
            for process in reversed(processes):
                stop(process)


if __name__ == "__main__":
    main()

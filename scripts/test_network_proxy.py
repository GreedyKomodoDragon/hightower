"""Exercise the compiled proxy with real sockets and parse every capture record."""
import concurrent.futures
import json
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = os.path.abspath(sys.argv.pop(1))


class ProxyTests(unittest.TestCase):
    """Verify forwarding, failure accounting, and shutdown on loopback."""

    def setUp(self):
        """Keep each test's capture and child processes independent."""
        self.temp = tempfile.TemporaryDirectory(prefix="hightower-proxy-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def proxy(self, protocol, upstream, name="capture", preexec_fn=None, source=None):
        """Start the proxy and wait for its initialized readiness record."""
        path = self.root / name
        log = open(self.root / (name + ".log"), "w+")
        self.addCleanup(log.close)
        args = [BINARY, protocol, "0", str(upstream), str(path)]
        if source is not None:
            args.append(str(source))
        proc = subprocess.Popen(args, stderr=log, preexec_fn=preexec_fn)
        self.addCleanup(self.stop, proc, False)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                log.seek(0)
                self.fail(log.read())
            try:
                first = json.loads((path / "events.jsonl").read_text().splitlines()[0])
                if first["event"] == "ready":
                    return proc, int(first["listen"].split(":")[1]), path
            except (FileNotFoundError, IndexError, json.JSONDecodeError):
                pass
            time.sleep(.01)
        self.fail("proxy readiness timed out")

    def stop(self, proc, check=True):
        """Terminate gracefully and enforce bounded shutdown."""
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
        code = proc.wait(timeout=5)
        if check:
            self.assertEqual(code, 0)

    def records(self, path):
        """Validate JSON fields and offset ranges for all emitted records."""
        payload = (path / "payload.bin").read_bytes()
        events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
        for event in events:
            self.assertIsInstance(event["timestamp_ns"], int)
            self.assertIsInstance(event["session"], int)
            self.assertIn(event["direction"], ("client_to_upstream", "upstream_to_client"))
            self.assertIn(":", event["upstream"])
            self.assertLessEqual(event["offset"] + event["length"], len(payload))
        return payload, events

    def listener(self, udp=False):
        """Allocate an OS-selected loopback port."""
        sock = socket.socket(type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(10)
        if not udp:
            sock.listen()
        return sock

    def test_tcp_concurrency_half_close_and_exact_recording(self):
        """Echo only after EOF, forcing half-closes and bounded large transfers."""
        server = self.listener()
        payloads = [bytes(range(256)) * (4096 + i) for i in range(4)]
        def echo():
            """Read slowly through EOF, then return the complete binary request."""
            conn, _ = server.accept()
            with conn:
                conn.settimeout(15)
                chunks = []
                while chunk := conn.recv(8192):
                    chunks.append(chunk)
                    time.sleep(.0002)
                conn.sendall(b"".join(chunks))
                conn.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            servers = [pool.submit(echo) for _ in payloads]
            proc, port, path = self.proxy("tcp", server.getsockname()[1])
            def client(data):
                """Check every echoed byte after signaling end of request."""
                with socket.create_connection(("127.0.0.1", port), timeout=15) as conn:
                    conn.sendall(data)
                    conn.shutdown(socket.SHUT_WR)
                    chunks = []
                    while chunk := conn.recv(16384):
                        chunks.append(chunk)
                    self.assertEqual(b"".join(chunks), data)
            clients = [pool.submit(client, data) for data in payloads]
            for future in clients + servers:
                future.result(timeout=25)
        self.stop(proc)
        raw, events = self.records(path)
        sessions = {e["session"] for e in events if e["event"] == "accepted"}
        self.assertEqual(len(sessions), 4)
        reconstructed = []
        for sid in sessions:
            for direction in ("client_to_upstream", "upstream_to_client"):
                streams = []
                for kind in ("received", "forwarded"):
                    streams.append(b"".join(raw[e["offset"]:e["offset"] + e["length"]]
                                            for e in events if e["session"] == sid
                                            and e["direction"] == direction and e["event"] == kind))
                self.assertEqual(*streams)
                self.assertIn(streams[0], payloads)
                if direction == "client_to_upstream":
                    reconstructed.append(streams[0])
        self.assertCountEqual(reconstructed, payloads)
        self.assertEqual(events[-1]["event"], "stopped")

    def test_udp_isolation_empty_and_large_datagrams(self):
        """Two clients retain separate upstream ports and exact datagram boundaries."""
        server = self.listener(True)
        proc, port, path = self.proxy("udp", server.getsockname()[1])
        clients = [self.listener(True), self.listener(True)]
        expected = [b"", bytes(range(256)) * 234, b"second-client"]
        seen = []
        for index, data in enumerate(expected):
            client = clients[index % 2]
            client.sendto(data, ("127.0.0.1", port))
            received, sender = server.recvfrom(65535)
            self.assertEqual(received, data)
            seen.append(sender)
            server.sendto(received, sender)
            self.assertEqual(client.recvfrom(65535)[0], data)
        self.assertEqual(seen[0], seen[2])
        self.assertNotEqual(seen[0], seen[1])
        self.stop(proc)
        raw, events = self.records(path)
        for direction in ("client_to_upstream", "upstream_to_client"):
            for kind in ("received", "forwarded"):
                packets = [raw[e["offset"]:e["offset"] + e["length"]] for e in events
                           if e["event"] == kind and e["direction"] == direction]
                self.assertEqual(packets, expected)

    def test_upstream_failure_and_shutdown_active_connection(self):
        """Refusal is recorded, while SIGTERM closes active sockets and flushes."""
        unused = self.listener()
        port = unused.getsockname()[1]
        unused.close()
        proc, proxy_port, path = self.proxy("tcp", port)
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as conn:
            self.assertEqual(conn.recv(1), b"")
        self.stop(proc)
        _, events = self.records(path)
        self.assertTrue(any(e["error"] for e in events))
        server = self.listener()
        proc, proxy_port, path = self.proxy("tcp", server.getsockname()[1], "active")
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as conn:
            upstream, _ = server.accept()
            with upstream:
                conn.sendall(b"before-shutdown")
                self.assertEqual(upstream.recv(100), b"before-shutdown")
                self.stop(proc)
                self.assertEqual(conn.recv(1), b"")
        _, events = self.records(path)
        self.assertTrue(any(e["event"] == "shutdown" for e in events))

    def test_udp_reserved_source_and_capacity_accounting(self):
        """Reserve the signed source before readiness and retain rejected bytes."""
        server = self.listener(True)
        reservation = self.listener(True)
        source = reservation.getsockname()[1]
        reservation.close()
        proc, port, path = self.proxy("udp", server.getsockname()[1], source=source)
        occupied = subprocess.run([BINARY, "udp", "0", str(server.getsockname()[1]),
                                   str(self.root / "occupied"), str(source)],
                                  capture_output=True, timeout=5)
        self.assertNotEqual(occupied.returncode, 0)
        self.assertNotIn(b"ready", occupied.stderr)
        first, second = self.listener(True), self.listener(True)
        first.sendto(b"first", ("127.0.0.1", port))
        data, sender = server.recvfrom(100)
        self.assertEqual((data, sender[1]), (b"first", source))
        second.sendto(b"rejected", ("127.0.0.1", port))
        self.assertNotEqual(proc.wait(timeout=5), 0)
        raw, events = self.records(path)
        self.assertIn(b"rejected", raw)
        self.assertTrue(any(e["error"] == "SessionCapacityExceeded" for e in events))
        self.assertEqual(sum(e["length"] for e in events if e["event"] == "forwarded"), 5)

    def test_shutdown_with_backpressure_records_unsent_bytes(self):
        """A stalled upstream cannot make shutdown hang or imply delivery."""
        server = self.listener()
        proc, port, path = self.proxy("tcp", server.getsockname()[1])
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            upstream, _ = server.accept()
            with upstream:
                upstream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                client.setblocking(False)
                data = b"z" * 65536
                deadline = time.monotonic() + .5
                while time.monotonic() < deadline:
                    try:
                        client.send(data)
                    except BlockingIOError:
                        time.sleep(.001)
                self.stop(proc)
        raw, events = self.records(path)
        received = sum(e["length"] for e in events if e["event"] == "received")
        forwarded = sum(e["length"] for e in events if e["event"] == "forwarded")
        pending = sum(e["length"] for e in events if e["event"] == "shutdown")
        self.assertEqual(len(raw), received)
        self.assertGreater(pending, 0)
        self.assertEqual(received, forwarded + pending)

    def test_recording_failure_is_fatal_and_existing_output_is_preserved(self):
        """File size limits simulate a full disk after readiness, without root."""
        def limit_file():
            """Allow readiness metadata but fail on the larger payload write."""
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
        server = self.listener()
        proc, port, path = self.proxy("tcp", server.getsockname()[1], preexec_fn=limit_file)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            upstream, _ = server.accept()
            with upstream:
                conn.sendall(b"x" * 10000)
                self.assertNotEqual(proc.wait(timeout=5), 0)
        original = (path / "payload.bin").read_bytes()
        result = subprocess.run([BINARY, "tcp", "0", "1", str(path)], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((path / "payload.bin").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

# Local network diagnostics

Implementation context: [FULU-068 / #137](https://github.com/GreedyKomodoDragon/hightower/issues/137).
The proxy is an executable in the existing Zig project. No extra package or
runtime dependency is needed. CI configuration is unchanged. These instructions
target native macOS clients and loopback IPv4 traffic.

```sh
zig build network-proxy
zig build test-network-proxy
zig build test-network-proxy -Doptimize=ReleaseSafe
./zig-out/bin/hightower-network-proxy tcp 127.0.0.1:19500 127.0.0.1:19000 /tmp/producer-capture
./zig-out/bin/hightower-network-proxy udp 127.0.0.1:19504 127.0.0.1:19004 /tmp/discovery-capture
```

Each invocation forwards one destination. Bare ports use `127.0.0.1`; use port
zero for an OS-selected listening port. Addresses must be numeric IPv4. The
output directory must not exist: captures are never overwritten. The process
prints `ready` and writes a `ready` JSONL event only after binding sockets,
creating files, and syncing the initial record. SIGINT and SIGTERM stop within
one poll interval plus filesystem I/O, close sessions, and sync artifacts.
Recording errors exit nonzero. Upstream failures retire the affected session
and emit an error; the listener remains available.

There are at most 64 simultaneous sessions, with two 65,535-byte buffers each
(about 8 MiB total, plus fixed scratch space and kernel socket buffers). TCP
reads stop while a direction has pending bytes. Partial sends have separate
records, and EOF propagates as a write half-close after prior bytes drain.
UDP preserves empty and large datagrams and uses a distinct connected upstream
socket for each client address/port. UDP sessions expire after 60 idle seconds;
pending TCP connects also time out after 60 seconds. Capacity exhaustion or a
UDP queue overflow stops visibly rather than silently dropping application
bytes. UDP can still lose packets in kernel/network queues. TCP read chunks are
not packet boundaries. Shutdown records do not imply that all received bytes
were delivered: compare `received` and `forwarded` records.

An optional final `UDP_SOURCE_IP:PORT` argument reserves an upstream source
socket before readiness. It permits only one client session and is used by the
discovery interoperability harness to advertise that source in a signed ENR.
Ordinary multi-client UDP captures should omit it.

## Artifacts and reconstruction

`payload.bin` contains complete received payloads in receive order, including
binary zero bytes. `events.jsonl` contains structured records with wall-clock
`timestamp_ns`, a proxy-local `session` ID, `direction`, `client`, `listen`,
`upstream`, `upstream_local`, `event`, byte `offset`, `length`, and nullable `error`.

`received` records refer to bytes saved before forwarding. `forwarded` records
reference the same file offsets for bytes successfully accepted by the outgoing
socket. This means local socket acceptance, not remote application consumption.
For UDP, each record is a whole datagram; an empty datagram has length zero.
Shutdown records reference any remaining unforwarded bytes per direction. Other
session lifecycle and failure records have no payload. Reconstruct one stream
by selecting its session, direction, and event kind, then concatenating slices
in metadata order. Preserve separate slices when inspecting UDP.

```python
import json
from pathlib import Path

capture = Path('/tmp/producer-capture')
payload = (capture / 'payload.bin').read_bytes()
events = [json.loads(line) for line in (capture / 'events.jsonl').read_text().splitlines()]
chunks = [payload[e['offset']:e['offset'] + e['length']] for e in events
          if e['session'] == 1 and e['direction'] == 'client_to_upstream'
          and e['event'] == 'forwarded']
stream = b''.join(chunks)
```

Trace files are enabled with `HIGHTOWER_NETWORK_TRACE=/new/path.jsonl` in the
P2P/discovery fixtures, or `NETWORK_TRACE=1` in the scripts below. Other embedded
users can call `consensus.NetworkTrace.enable` before starting workers and
`close` after workers stop. Events include negotiation starts, authenticated
Noise identities, full authenticated decrypted frames, Yamux headers and stream
flags, status requests/responses/errors, and discovery packets and authenticated
messages. Payloads are losslessly encoded as `payload_hex`; event details
identify peers and streams. Traces never serialize identity private keys,
Noise keys, discovery session keys, or handshake state. Each event is synced;
trace-write errors propagate to the networking caller.

Proxy directories are mode 0700 and files are 0600. Captures include application
payloads: Engine API HTTP captures include short-lived JWT authorization headers.
Treat captures and decoded traces as private local artifacts. Disk usage grows
with traffic; recording failure stops the proxy. SIGKILL or a machine crash
cannot guarantee the last writes were synced.

## Native interoperability comparisons

Prerequisites: Zig 0.16.0, Python 3, OpenSSL, curl, Go suitable for the existing
probe modules, native Geth (Engine harness defaults to v1.17.10), and native
Fulu-capable Prysm `prysmctl`, `beacon-chain`, and `validator`. Set `GETH_BIN` and
`PRYSM_BIN_DIR` to existing binaries. These scripts do not download clients or
start containers. Run from the repository root; run Engine and Prysm harnesses
sequentially because both use the same Engine API ports.

```sh
export GETH_BIN=/path/to/geth
export PRYSM_BIN_DIR=/path/to/prysm-binaries
KEEP_INTEROP_DIR=1 NETWORK_TRACE=1 bash scripts/test_discv5_geth.sh
NETWORK_PROXY=1 NETWORK_TRACE=1 bash scripts/test_discv5_geth.sh
KEEP_INTEROP_DIR=1 bash scripts/test_engine_interop.sh
NETWORK_PROXY=1 bash scripts/test_engine_interop.sh
KEEP_INTEROP_DIR=1 NETWORK_TRACE=1 bash scripts/test_prysm_geth_interop.sh
NETWORK_PROXY=1 NETWORK_TRACE=1 bash scripts/test_prysm_geth_interop.sh
```

Direct connections remain the default. Diagnostics and all failing runs retain
their temporary directory and print its location. `KEEP_INTEROP_DIR=1` also
retains successful direct runs. Cleanup waits for each proxy to flush; a proxy
failure makes the harness fail. Prysm producer/consumer use separate TCP proxies,
and Engine destinations use separate instances of the same executable.

| Traffic | Proxy listener | Upstream destination |
| --- | --- | --- |
| Prysm producer P2P | 19500 | 19000 |
| Prysm consumer P2P | 19501 | 19001 |
| Geth Engine API | 19551 | 18551 |
| Hightower Engine fixture | 19552 | 18552 |
| Hightower discovery | 19504 | 19004 |
| Discovery proxy's upstream source | 19505 | — |

Prysm ENRs remain signed and unchanged. `HIGHTOWER_PRODUCER_PROXY` and
`HIGHTOWER_CONSUMER_PROXY` override only the fixture's TCP socket destination;
Noise still verifies the peer against its original ENR. For discovery the Geth
probe signs its own ENR with the proxy's reserved upstream source port. Its
socket adapter maps only the configured proxy address back to the original
remote endpoint. Hightower's signed-ENR source checks and Geth's cryptographic
identity checks remain enabled; no peer record is edited after signing.

## Packet capture on macOS

Run packet capture separately in another terminal; the Zig proxy stays
unprivileged. Capture both legs to inspect real TCP segments, retransmissions,
FIN/RST ordering, and UDP boundaries. Restrict the filter to the test ports:

```sh
sudo tcpdump -i lo0 -n -s 0 -U -w /tmp/hightower-local.pcap \
  '(tcp and (port 19000 or port 19001 or port 19500 or port 19501 or port 18551 or port 18552 or port 19551 or port 19552)) or (udp and (port 19004 or port 19504 or port 19505))'
```

Stop tcpdump with Ctrl-C after the harness completes so it flushes the pcap.
Inspect with `tcpdump -n -r /tmp/hightower-local.pcap` or a packet analyzer.
The proxy cannot recover TCP segmentation or packets dropped before it received
them; use the pcap for those questions.

For a `StatusTimeout`, align timestamps across `relay.log`, `network-trace.jsonl`,
proxy `events.jsonl`, and the pcap. Look for the authenticated peer, Yamux stream
opening and negotiation bytes, `status_request`, inbound frames and window/FIN
flags, and the final `status_error`. Compare received versus forwarded bytes on
both proxy legs before attributing a missing response to the peer. A timeout
fix is separate from these diagnostics. Proxying and synchronous tracing both
change timing; compare direct and proxied runs, with tracing held constant, and
also reproduce without tracing before drawing timing conclusions.

## Local validation evidence (2026-11-05, macOS arm64)

The default build, proxy/trace tests in Debug and ReleaseSafe, existing consensus
and API tests (`test-transition`) in both modes, and the Go socket-adapter test
passed. Direct and proxied native Geth discovery and Engine API comparisons also
passed. All recorded sessions in these comparisons reconstructed identically
from `received` and `forwarded` records.

The traced direct Prysm run reached `StatusTimeout`. Its trace showed successful
Noise/Yamux negotiation, response bytes on stream 1, a stream-1 window-update FIN,
and then the five-second timeout. The proxied run completed both status
exchanges and fetched the block and columns, then failed at
`ConsumerSubscriptionsNotReady`. Its producer, consumer, and Engine captures had
identical received/forwarded streams (264,936, 2,441, and 328,134 bytes respectively).
These observations narrow the next protocol investigation without asserting a
root cause or a timeout fix. Both failures and their artifacts were preserved.
A subsequent authorized loopback capture reproduced `StatusTimeout` in a proxied
run. Packet-level TCP reassembly matched all 12 directional stream checks across
three proxy sessions, with no overlapping payload bytes or capture gaps in those
streams. For the failing producer session, the proxy forwarded all 670 outbound
and 910 inbound bytes. The authenticated trace observed the status stream's FIN
at +1.916 ms; the timeout occurred at +5002.075 ms. TCP FIN/RST teardown followed
the timeout, rather than preceding it. This points the next investigation toward
application stream handling rather than missing TCP delivery for this run.

Code inspection identifies a candidate path: while `serveRequest` negotiates an
unrelated inbound stream, it queues other streams' data frames but consumes
window-update frames for those streams, including their FIN flags. The capture
shows the status FIN arriving during an overlapping inbound identify request.
The status-stream fix now queues another stream's FIN with its data in all three
inbound request loops. A focused regression test covers the interleaving. In a
new direct native Prysm run, both status exchanges completed; the run continued
to `ConsumerSubscriptionsNotReady`. The status timeout is fixed in that run,
while the subscription failure remains separate work.
